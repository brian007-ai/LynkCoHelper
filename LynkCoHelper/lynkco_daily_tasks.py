# -*- coding: utf-8 -*-
"""
领克App 每日任务编排入口（签到 + 分享 + 积分查询 + 结果通知）。

- run_daily_tasks()：编排"查积分 -> 签到 -> 分享 -> 再查积分对比"，返回结构化结果字典。
- run_and_notify()：加载 token -> 执行每日任务 -> 组装 Markdown -> 推送到飞书。

签到/分享成功后 myEnergy 接口的积分有几秒异步延迟，故查询"之后积分"前会先 sleep。

用法:
    python3 lynkco_daily_tasks.py    # 执行每日任务（签到+分享）并推送结果
"""
import json
import os
import sys
import time

from lynkco_common import env_value, mask_sensitive
from lynkco_login import load_token, get_last_refresh_info
from lynkco_notify import build_markdown_report, build_feishu_card, send_feishu_notification
from lynkco_sign import LynkCoSignClient
from lynkco_share import LynkCoShareClient

# 签到/分享完成后，等待多久再查询"之后积分"，单位秒。经真机验证 3~5 秒足够
# 让服务端把能量体变化同步到 myEnergy 接口，可通过环境变量覆盖。
ENERGY_REFRESH_DELAY_SECONDS = float(env_value("LYNKCO_ENERGY_DELAY", "5"))

EP_MY_ENERGY = "/app/energy/myEnergy"
# 能量体/成长等级接口（与 myEnergy 同网关同签名体系，返回 data.accountLevelVo）
EP_ENERGY_GROWTH = "/app/energy/my/growth"
# 签到任务进度接口（连续7天/月度/季度/年度，data 为任务列表）
EP_TASK_LIST = "/up/api/v1/userReward/getTaskList"


def get_my_energy(client: LynkCoSignClient) -> dict:
    """查询当前账号的能量体积分（GET /app/energy/myEnergy，与签到共用同一网关/签名体系）。"""
    resp = client._request("GET", EP_MY_ENERGY)
    return resp.json()


def get_my_energy_growth(client: LynkCoSignClient) -> dict:
    """查询当前账号的能量体/成长等级（GET /app/energy/my/growth，data.accountLevelVo）。"""
    resp = client._request("GET", EP_ENERGY_GROWTH)
    return resp.json()


def get_task_list(client: LynkCoSignClient) -> dict:
    """查询签到任务进度（GET /up/api/v1/userReward/getTaskList，data 为任务列表）。"""
    resp = client._request("GET", EP_TASK_LIST)
    return resp.json()


def run_daily_tasks(token: str, do_share: bool = True) -> dict:
    """
    编排执行一次完整的"签到 + 分享"流程，返回汇总结果字典：
    {"energy_before", "day_info", "already_signed", "sign_result", "continue_info",
     "share_result", "energy_after", "energy_growth"}（已签到/do_share=False 时对应字段为 None）。

    do_share 默认 True，供需要在测试/脚本中跳过分享的调用方使用；
    正式入口 run_and_notify() 始终以 do_share=True 调用。
    """
    result = {}

    sign_client = LynkCoSignClient(token)

    result["energy_before"] = get_my_energy(sign_client)

    day_info = sign_client.get_sign_day_info()
    result["day_info"] = day_info

    already_signed = (day_info.get("data") or {}).get("signStatus") == 1
    result["already_signed"] = already_signed

    if already_signed:
        result["sign_result"] = None
    else:
        result["sign_result"] = sign_client.do_sign()

    result["continue_info"] = sign_client.get_continue_days()

    if do_share:
        share_client = LynkCoShareClient(token)
        try:
            result["share_result"] = share_client.do_share()
        except Exception as e:
            result["share_result"] = {"ok": False, "detail": {"message": f"分享任务异常: {e}"}}
    else:
        result["share_result"] = None

    # 积分变化有异步延迟，等待片刻再查询，避免看到"没有变化"的假象。
    if not already_signed or (do_share and (result.get("share_result") or {}).get("ok")):
        time.sleep(ENERGY_REFRESH_DELAY_SECONDS)
    result["energy_after"] = get_my_energy(sign_client)

    # 能量体（成长等级）与积分是两套体系，来自独立接口；查询失败不影响主流程。
    try:
        result["energy_growth"] = get_my_energy_growth(sign_client)
    except Exception as e:
        print(f"[警告] 能量体查询失败（不影响签到/分享）: {e}")
        result["energy_growth"] = None

    # 签到任务进度（连续7天/月度/季度/年度），查询失败不影响主流程。
    try:
        result["task_list"] = get_task_list(sign_client)
    except Exception as e:
        print(f"[警告] 任务进度查询失败（不影响签到/分享）: {e}")
        result["task_list"] = None

    return result


def run_and_notify() -> dict:
    """
    完整入口：加载 token -> 执行每日任务(run_daily_tasks) -> 组装 Markdown
    -> 推送到飞书群机器人（lynkco_notify 模块）。

    每日任务固定包含"签到+分享"两项（分享接口每日有加分次数上限，重复
    调用不会重复加分，详见 docs/分享任务接口说明.md）。

    返回值同 run_daily_tasks()，并额外附带 "notify_result" 字段（飞书
    推送接口的响应，或 {"skipped": True}）。
    """
    token = load_token()

    print("=== 执行每日任务（签到+分享）===")
    result = run_daily_tasks(token, do_share=True)
    # CI 每次运行都会用 refreshToken 续期，此处 附上续期返回的过期时间，
    # 供推送卡片展示 refreshToken 剩余天数；命中缓存 token 时为空字典。
    result["token_info"] = get_last_refresh_info()
    print(json.dumps(mask_sensitive(result), ensure_ascii=False, indent=2))

    markdown_body = build_markdown_report(result)
    print("\n=== 推送内容预览 ===")
    print(markdown_body)

    feishu_card = build_feishu_card(result)
    try:
        notify_result = send_feishu_notification(
            title="领克App · 每日任务",
            markdown_body=markdown_body,
            card=feishu_card,
        )
    except Exception as e:
        # 推送失败（网络问题/代理超时等）不应影响签到/分享本身已经成功执行
        # 这一事实，只记录警告，不让整个流程以异常状态退出。
        print(f"[警告] 飞书推送失败（不影响签到/分享结果）: {e}")
        notify_result = {"skipped": True, "error": str(e)}
    print("\n=== 飞书推送结果 ===")
    print(json.dumps(mask_sensitive(notify_result), ensure_ascii=False, indent=2))

    result["notify_result"] = notify_result
    return result


def main():
    try:
        result = run_and_notify()
    except RuntimeError as e:
        print(f"[错误] {e}")
        sys.exit(1)
    except Exception as e:
        print(f"[错误] 执行失败: {e}")
        sys.exit(1)

    # 签到或分享失败时也以非零状态退出，供 CI（daily-tasks.yml）识别并重试。
    # 今日已签到时 sign_result 为 None，不算失败；分享失败用 ok 字段判断。
    sign_result = result.get("sign_result") or {}
    sign_failed = (not result.get("already_signed")) and not sign_result.get("success")
    share_result = result.get("share_result")
    share_failed = share_result is not None and not share_result.get("ok")
    if sign_failed or share_failed:
        print("[错误] 存在失败项（签到/分享），以非零状态退出供 CI 重试")
        sys.exit(1)


if __name__ == "__main__":
    main()

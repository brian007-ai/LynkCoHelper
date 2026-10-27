# -*- coding: utf-8 -*-
"""
推送通知工具模块，提供以下通用能力（不含任何业务逻辑，供
lynkco_daily_tasks.py / lynkco_comment.py 按需调用）：
    - build_markdown_report(result)：把任务结果字典组装成推送文案；
    - send_feishu_notification(...)：把文案通过飞书群机器人推送出去
      （每日签到/分享任务使用）；
    - send_bark_notification(...)：把文案推送到 iOS Bark（图文评论任务
      使用，逐条携带文章跳转链接）。

飞书配置：环境变量 LYNKCO_FEISHU_WEBHOOK（群机器人的完整 webhook 地址，
形如 https://open.feishu.cn/open-apis/bot/v2/hook/xxxx），或 env.json 的
notify.feishuWebhook 字段。若机器人开启了签名校验，额外配置
LYNKCO_FEISHU_SECRET（机器人安全设置页的加签密钥）。未配置 webhook 时
跳过推送并打印提示，不抛异常。
"""
import base64
import hashlib
import hmac
import re
import time
from datetime import datetime, timedelta, timezone

import requests

from lynkco_common import env_value, load_env_data

FEISHU_CONNECT_TIMEOUT = 5
FEISHU_READ_TIMEOUT = 15

# 推送文案统一使用北京时间：GitHub Actions runner 默认 UTC，直接 strftime 会早 8 小时。
BEIJING_TZ = timezone(timedelta(hours=8))

BARK_DEFAULT_BASE = "https://api.day.app"
BARK_CONNECT_TIMEOUT = 5
BARK_READ_TIMEOUT = 15


def _extract_point(energy_resp: dict) -> str:
    """从 myEnergy 响应中安全地取出 point 字段，取不到时返回 '?'。"""
    return str((energy_resp.get("data") or {}).get("point", "?"))


def _extract_expire(energy_resp: dict) -> str:
    """从 myEnergy 响应中安全地取出 expirePoint（即将过期积分）字段，取不到时返回 '?'。"""
    return str((energy_resp.get("data") or {}).get("expirePoint", "?"))


def _extract_growth(growth_resp: dict):
    """从 my/growth 响应中取出 (能量体数值, 等级名)，取不到时对应位置为 None。"""
    level = ((growth_resp or {}).get("data") or {}).get("accountLevelVo") or {}
    return level.get("growth"), level.get("name")


def _format_change(before: str, after: str, with_arrow: bool) -> str:
    """
    把签到前后的数值渲染成对比文案：签到发生时显示 "旧值 → **新值**"，
    已签到（对比无意义）或旧值缺失时只显示当前值。
    """
    if after == "?":
        return "?"
    if with_arrow and before != "?":
        return f"{before} → **{after}**"
    return f"**{after}**"


def _account_metric_lines(result: dict) -> list:
    """
    账户三项数值（Co积分余额 / 能量体 / 即将过期积分），有签到动作时按
    "签到前 → 签到后" 展示真实变化，已签到时只展示当前值。
    """
    with_arrow = (not result.get("already_signed")) and result.get("sign_result") is not None
    lines = []

    point_before = _extract_point(result.get("energy_before") or {})
    point_after = _extract_point(result.get("energy_after") or {})
    if point_after != "?":
        lines.append("Co积分余额：" + _format_change(point_before, point_after, with_arrow))

    growth_before, _ = _extract_growth(result.get("energy_growth_before"))
    growth_after, level_name = _extract_growth(result.get("energy_growth"))
    if growth_after is not None:
        text = _format_change(str(growth_before if growth_before is not None else "?"),
                              str(growth_after), with_arrow)
        if level_name:
            text += f"（{level_name}）"
        lines.append("能量体：" + text)

    expire_before = _extract_expire(result.get("energy_before") or {})
    expire_after = _extract_expire(result.get("energy_after") or {})
    if expire_after != "?":
        lines.append("即将过期积分：" + _format_change(expire_before, expire_after, with_arrow))

    return lines


def _sign_reward_parts(sign_data: dict) -> list:
    """
    签到奖励细分（字段名来自领克签到响应，参考 yujiejobs/lynk_sign_docker）：
    rewardEnergyNumber 是 Co积分（经用户确认）、rewardSignCardNumber 是补签卡；
    rewardPointNumber 的准确含义待真实响应确认，先用中性标签"积分"兜底。
    """
    parts = []
    reward_energy = sign_data.get("rewardEnergyNumber")
    if reward_energy is not None:
        parts.append(f"Co积分 **+{reward_energy}**")
    reward_point = sign_data.get("rewardPointNumber")
    if reward_point is not None:
        parts.append(f"积分 **+{reward_point}**")
    reward_card = sign_data.get("rewardSignCardNumber")
    if reward_card is not None:
        parts.append(f"补签卡 **+{reward_card}**")
    return parts


def _task_progress_lines(task_resp) -> list:
    """
    解析 getTaskList 响应为进度行：data 为任务列表，总天数从 taskName 的
    "X天" 中正则提取，rewardContent 为奖励列表。

    taskProcess 是「剩余天数」而非已签天数（2026-10-23 真实推送数据证实：
    本月度25天任务 taskProcess=2，而本月 23 天均已签到；本季度85天任务
    taskProcess=62，恰为 85-23）。故 已签 = 总天数 - taskProcess。
    """
    if not isinstance(task_resp, dict):
        return []
    tasks = task_resp.get("data")
    if not isinstance(tasks, list):
        return []
    lines = []
    for t in tasks:
        if not isinstance(t, dict):
            continue
        tname = str(t.get("taskName", "?"))
        tproc = t.get("taskProcess")
        tproc_str = str(tproc).strip() if tproc is not None else ""
        reward = ", ".join(t.get("rewardContent") or []) or "无奖励字段"
        matched = re.search(r"(\d+)天", tname)
        if matched and tproc_str.isdigit():
            total = int(matched.group(1))
            remain = int(tproc_str)
            done = total - remain
            display = (f"已签 {done} / {total} 天（已完成）" if remain <= 0
                       else f"已签 {done} / {total} 天，还差 {remain} 天")
        else:
            display = f"进度 {tproc}"
        lines.append(f"- {tname}：`{display}`（{reward}）")
    return lines


TOKEN_EXPIRE_WARN_DAYS = 7


def _token_age_warning(result: dict) -> list:
    """refreshToken 到期提醒正文；剩余天数 > 7 时返回空列表（不打扰）。"""
    age = result.get("token_age") or {}
    remain = age.get("remain_days")
    if remain is None:
        return []
    if remain <= 0:
        return ["🚨 **Secret 里的 refreshToken 已到期**，若不更新 LYNKCO_REFRESH_TOKEN，"
                "下次运行将无法续期、签到会中断。"]
    if remain <= TOKEN_EXPIRE_WARN_DAYS:
        return [f"⚠️ **refreshToken 将在 {remain} 天后到期**（{age.get('expire_date')}），"
                "请及时到仓库 Secrets 更新 LYNKCO_REFRESH_TOKEN。"]
    return []


def _token_age_note(result: dict) -> str:
    """refreshToken 使用情况文案，未启用跟踪时返回空串。"""
    age = result.get("token_age") or {}
    remain = age.get("remain_days")
    if remain is None:
        return ""
    return (f"refreshToken 已用 {age.get('age_days', 0)} 天"
            f"（预计 {age.get('expire_date')} 到期，还剩 {remain} 天）")


def build_markdown_report(result: dict) -> str:
    """把 lynkco_daily_tasks.run_daily_tasks() 返回的结果字典组装成推送文案。"""
    lines = []

    # --- 签到 ---
    if result.get("already_signed"):
        lines.append("### ℹ️ 签到")
        lines.append("- 今日已签到，无需重复签到")
    else:
        sign_result = result.get("sign_result") or {}
        sign_ok = bool(sign_result.get("success"))
        sign_data = sign_result.get("data") or {}
        if sign_ok:
            lines.append("### ✅ 签到成功")
            parts = _sign_reward_parts(sign_data)
            if parts:
                lines.append("- 本次奖励：" + " · ".join(parts))
        else:
            lines.append("### ❌ 签到失败")
            lines.append(f"- {sign_result.get('message', '未知错误')}")

    continue_data = (result.get("continue_info") or {}).get("data") or {}
    continue_days = continue_data.get("continueDays")
    sign_card = continue_data.get("signCardNumber")
    stats = []
    if continue_days is not None:
        stats.append(f"连续签到 **{continue_days} 天**")
    if sign_card is not None:
        stats.append(f"补签卡 **{sign_card} 张**")
    if stats:
        lines.append("- " + " · ".join(stats))

    # --- 分享 ---
    share_result = result.get("share_result")
    if share_result is not None:
        lines.append("\n### 🔗 分享任务")
        if share_result.get("ok"):
            article_title = share_result.get("articleTitle")
            lines.append("- 状态：**上报成功**" + (f"（{article_title}）" if article_title else ""))
        else:
            detail = share_result.get("detail") or {}
            lines.append(f"- 状态：**失败**（{detail.get('message', '详情见日志')}）")

    # --- 账户数值（Co积分余额 / 能量体 / 即将过期积分，含签到前后变化） ---
    metric_lines = _account_metric_lines(result)
    if metric_lines:
        lines.append("\n### 💰 账户数值")
        lines.extend("- " + line for line in metric_lines)

    # --- 签到任务进度 ---
    task_lines = _task_progress_lines(result.get("task_list"))
    if task_lines:
        lines.append("\n### 📋 签到任务进度")
        lines.extend(task_lines)

    # --- refreshToken 使用天数（跟踪的是 Secret 里的旧 token，不是本次续期新签发的） ---
    token_note = _token_age_note(result)
    if token_note:
        lines.append(f"\n> {token_note}")
    for warning in _token_age_warning(result):
        lines.append(f"\n> {warning}")

    return "\n".join(lines)


def _card_header_template(result: dict) -> str:
    """按任务结果挑选卡片 header 颜色：签到失败/已到期红、分享失败或即将到期橙、已签到蓝、全部成功绿。"""
    sign_result = result.get("sign_result") or {}
    sign_failed = (not result.get("already_signed")) and not sign_result.get("success")
    share_result = result.get("share_result")
    share_failed = share_result is not None and not share_result.get("ok")
    remain_days = (result.get("token_age") or {}).get("remain_days")
    if sign_failed:
        return "red"
    if remain_days is not None and remain_days <= 0:
        return "red"
    if share_failed:
        return "yellow"
    if remain_days is not None and remain_days <= TOKEN_EXPIRE_WARN_DAYS:
        return "orange"
    if result.get("already_signed"):
        return "blue"
    return "green"


def build_feishu_card(result: dict, title: str = "领克App · 每日任务") -> dict:
    """
    把任务结果组装成飞书 interactive 卡片消息体（含 header 变色、分区块
    div、三列仪表盘 column_set 与 note 备注），返回值可直接作为飞书
    webhook 的 payload。
    """
    elements = []

    # --- refreshToken 到期提醒（剩余 ≤7 天或已到期时置顶展示） ---
    for warning in _token_age_warning(result):
        elements.append({"tag": "div", "text": {"tag": "lark_md", "content": warning}})
        elements.append({"tag": "hr"})

    # --- 签到区（含账户数值的签到前后真实变化） ---
    sign_lines = []
    if result.get("already_signed"):
        sign_lines.append("ℹ️ **今日已签到**，无需重复签到")
    else:
        sign_result = result.get("sign_result") or {}
        sign_data = sign_result.get("data") or {}
        if sign_result.get("success"):
            sign_lines.append("✅ **签到成功**")
            parts = _sign_reward_parts(sign_data)
            if parts:
                sign_lines.append("本次奖励：" + " · ".join(parts))
        else:
            sign_lines.append("❌ **签到失败**：" + str(sign_result.get("message", "未知错误")))
    metric_lines = _account_metric_lines(result)
    if metric_lines:
        sign_lines.append("")
        sign_lines.extend(metric_lines)
    continue_data = (result.get("continue_info") or {}).get("data") or {}
    stats = []
    if continue_data.get("continueDays") is not None:
        stats.append(f"连续签到 **{continue_data['continueDays']} 天**")
    if continue_data.get("signCardNumber") is not None:
        stats.append(f"补签卡 **{continue_data['signCardNumber']} 张**")
    if stats:
        sign_lines.append(" · ".join(stats))
    elements.append({"tag": "div", "text": {"tag": "lark_md", "content": "\n".join(sign_lines)}})
    elements.append({"tag": "hr"})

    # --- 分享区 ---
    share_result = result.get("share_result")
    if share_result is not None:
        if share_result.get("ok"):
            article_title = share_result.get("articleTitle")
            share_text = "🔗 分享任务：**上报成功**" + (f"（{article_title}）" if article_title else "")
        else:
            detail = share_result.get("detail") or {}
            share_text = "🔗 分享任务：**失败**（" + str(detail.get("message", "详情见日志")) + "）"
        elements.append({"tag": "div", "text": {"tag": "lark_md", "content": share_text}})
        elements.append({"tag": "hr"})

    # --- 签到任务进度 ---
    task_lines = _task_progress_lines(result.get("task_list"))
    if task_lines:
        elements.append({"tag": "div",
                         "text": {"tag": "lark_md",
                                  "content": "📋 **签到任务进度**\n" + "\n".join(task_lines)}})
        elements.append({"tag": "hr"})

    # --- 备注：refreshToken 使用天数 + 北京时间 ---
    note_parts = []
    token_note = _token_age_note(result)
    if token_note:
        note_parts.append(token_note)
    note_parts.append("推送时间 " + datetime.now(BEIJING_TZ).strftime("%Y-%m-%d %H:%M:%S"))
    elements.append({"tag": "note",
                     "elements": [{"tag": "plain_text", "content": " · ".join(note_parts)}]})

    return {
        "msg_type": "interactive",
        "card": {
            "header": {
                "title": {"tag": "plain_text", "content": title},
                "template": _card_header_template(result),
            },
            "elements": elements,
        },
    }


def _to_feishu_lark_md(markdown_body: str) -> str:
    """
    飞书 lark_md 不支持 ### 一级标题语法（会原样显示井号），这里把标题行
    转成加粗行，其余加粗/列表符号 lark_md 均可直接渲染。
    """
    out_lines = []
    for line in markdown_body.splitlines():
        stripped = line.strip()
        if stripped.startswith("### "):
            out_lines.append(f"**{stripped[4:].strip()}**")
        else:
            out_lines.append(line)
    return "\n".join(out_lines)


def _build_sign(timestamp: int, secret: str) -> str:
    """飞书群机器人加签：HMAC-SHA256(f"{timestamp}\\n{secret}") 后 base64。"""
    string_to_sign = f"{timestamp}\n{secret}"
    hmac_code = hmac.new(string_to_sign.encode("utf-8"), digestmod=hashlib.sha256).digest()
    return base64.b64encode(hmac_code).decode("utf-8")


def send_feishu_notification(title: str, markdown_body: str,
                             webhook: str = None, secret: str = None,
                             card: dict = None) -> dict:
    """
    通过飞书群机器人发送一条卡片消息（lark_md 富文本，可显示签到/分享/
    积分明细）。webhook 不传则读取环境变量 LYNKCO_FEISHU_WEBHOOK，未配置
    时返回 {"skipped": True} 且不抛异常。

    card 参数可传入 build_feishu_card() 生成的完整卡片消息体，传入时直接
    使用该卡片（含变色 header、三列仪表盘等）；不传则按 title +
    markdown_body 生成单 div 的基础卡片（供告警等简单场景使用）。
    """
    webhook = (webhook or env_value("LYNKCO_FEISHU_WEBHOOK")
               or load_env_data().get("notify", {}).get("feishuWebhook", "").strip())
    if not webhook:
        print("[提示] 未配置 LYNKCO_FEISHU_WEBHOOK，跳过飞书推送。")
        return {"skipped": True}

    secret = secret or env_value("LYNKCO_FEISHU_SECRET")

    if card is not None:
        payload = dict(card)
    else:
        payload = {
            "msg_type": "interactive",
            "card": {
                "header": {
                    "title": {"tag": "plain_text", "content": title},
                    "template": "blue",
                },
                "elements": [
                    {
                        "tag": "div",
                        "text": {"tag": "lark_md",
                                 "content": _to_feishu_lark_md(markdown_body)},
                    }
                ],
            },
        }
    if secret:
        timestamp = int(time.time())
        payload["timestamp"] = str(timestamp)
        payload["sign"] = _build_sign(timestamp, secret)

    # 飞书 webhook 直连可达，用干净 session 避免继承桌面级代理导致请求挂死。
    session = requests.Session()
    session.trust_env = False
    resp = session.post(
        webhook, json=payload,
        headers={"Content-Type": "application/json; charset=utf-8"},
        timeout=(FEISHU_CONNECT_TIMEOUT, FEISHU_READ_TIMEOUT),
    )
    resp.raise_for_status()
    data = resp.json()
    # 飞书成功返回 {"code":0,"StatusCode":0,...}，失败时 code/StatusCode 非 0。
    if data.get("code") not in (0, None) or data.get("StatusCode") not in (0, None):
        raise RuntimeError(f"飞书机器人返回错误: {data}")
    return data


def send_bark_notification(title: str, markdown_body: str, group: str = "LynkCo签到",
                            icon: str = None, level: str = "active",
                            bark_key: str = None, open_url: str = None) -> dict:
    """
    通过 Bark 发送一条 Markdown 格式的推送通知（图文评论任务使用，逐条
    携带文章跳转链接）。level 可选
    "critical"/"active"/"timeSensitive"/"passive"。bark_key 不传则读取
    环境变量 LYNKCO_BARK_KEY，未配置时返回 {"skipped": True} 且不抛异常。
    """
    bark_key = bark_key or env_value("LYNKCO_BARK_KEY") or load_env_data().get("notify", {}).get("barkKey", "").strip()
    if not bark_key:
        print("[提示] 未配置 LYNKCO_BARK_KEY，跳过 Bark 推送。")
        return {"skipped": True}

    url = f"{BARK_DEFAULT_BASE}/{bark_key}"

    payload = {
        "title": title,
        "markdown": markdown_body,
        "group": group,
        "level": level,
    }
    if icon:
        payload["icon"] = icon
    if open_url:
        payload["url"] = open_url

    # requests may inherit a desktop-wide proxy that can connect but never
    # return Bark's response. Bark is directly reachable, so use a clean
    # session and separate short connect/read timeouts for this notification.
    session = requests.Session()
    session.trust_env = False
    resp = session.post(
        url, json=payload,
        headers={"Content-Type": "application/json; charset=utf-8"},
        timeout=(BARK_CONNECT_TIMEOUT, BARK_READ_TIMEOUT),
    )
    resp.raise_for_status()
    return resp.json()

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""把 auto_checkin.py 的 --json-out 结果渲染成 Markdown，供 GitHub Actions Job Summary 使用。

用法：
    python ci_summary.py logs/result.json >> "$GITHUB_STEP_SUMMARY"
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

STATUS_MAP = {
    "ok": ("✅", "签到成功"),
    "already": ("🟡", "今日已签到"),
    "dry-run": ("🔍", "空跑检查通过（未签到）"),
    "error": ("❌", "签到失败"),
}


def human_quota(value) -> str:
    """New API 的 quota 以 1/500000 美元为单位，这里换算成更直观的额度。"""
    try:
        n = float(value)
    except (TypeError, ValueError):
        return "-"
    return f"{n:,.0f}（≈ ${n / 500000:.2f}）"


def main() -> int:
    if len(sys.argv) < 2:
        print("用法：python ci_summary.py <result.json>", file=sys.stderr)
        return 2

    path = Path(sys.argv[1])
    if not path.exists():
        print("## sheapi.cc 自动签到\n\n❌ 未生成结果文件，流程可能提前中断，请查看运行日志。")
        return 1

    try:
        r = json.loads(path.read_text(encoding="utf-8"))
    except ValueError as exc:
        print(f"## sheapi.cc 自动签到\n\n❌ 结果文件无法解析：{exc}")
        return 1

    icon, label = STATUS_MAP.get(r.get("status", "error"), ("❓", r.get("status", "未知")))
    lines = [
        "## sheapi.cc 自动签到",
        "",
        f"{icon} **{label}**",
        "",
        "| 项目 | 值 |",
        "| --- | --- |",
        f"| 状态 | `{r.get('status')}` |",
        f"| 服务端消息 | {r.get('message') or '-'} |",
        f"| 账号 | {r.get('username') or '-'} |",
        f"| 剩余额度 | {human_quota(r.get('quota'))} |",
        f"| 已用额度 | {human_quota(r.get('used_quota'))} |",
        f"| 执行时间 | {r.get('time') or '-'} |",
    ]

    data = r.get("data")
    if isinstance(data, dict) and data:
        lines += ["", "<details><summary>接口返回 data</summary>", "",
                  "```json", json.dumps(data, ensure_ascii=False, indent=2)[:1500], "```",
                  "", "</details>"]

    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sheapi.cc 自动签到脚本（New API 体系）

流程设计：
    1. 优先读取本地保存的登录态（cookie + access_token）
       - access_token 未过期且可用  -> 直接签到
       - access_token 过期/不可用   -> 用 cookie 调 /api/user/auth/refresh 换新 token
    2. 若 cookie 也失效（refresh 失败），用「账号 + 密码 + 图形验证码」重新登录拿 cookie/token
    3. 用 token 取签到图形验证码，提交 /api/user/checkin 完成签到
    4. 全程把最新的 cookie / token 落盘，供下次运行复用

依赖：
    pip install requests
    可选（验证码自动识别）：pip install ddddocr
    没有 ddddocr 时可用 --captcha-solver manual 手动输入，或用 --captcha-cmd 接自研识别器

用法示例：
    python3 auto_checkin.py --config config.json
    python3 auto_checkin.py --username me@x.com --password 'xxx' --cookie 'session=...'
    python3 auto_checkin.py --dry-run          # 只检查登录态，不真正签到
"""

from __future__ import annotations

import argparse
import base64
import json
import logging
import os
import re
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

try:
    import requests
except ImportError:  # pragma: no cover
    sys.stderr.write("缺少依赖 requests，请先执行：pip install requests\n")
    raise SystemExit(2)

LOG = logging.getLogger("sheapi-checkin")

DEFAULT_BASE_URL = "https://www.sheapi.cc"
DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36 Edg/155.0.0.0"
)

# 判断“该验证码已失效 / 填错”的服务端提示
CAPTCHA_HINT = ("验证码", "captcha")
# 判断“今天已经签到过”的服务端提示
ALREADY_HINT = ("已签到", "已经签到", "重复签到", "already")


# --------------------------------------------------------------------------- #
# 异常
# --------------------------------------------------------------------------- #
class AuthError(Exception):
    """登录态失效且无法自动恢复。"""


class CaptchaError(Exception):
    """验证码获取或识别失败。"""


class CheckinError(Exception):
    """签到接口返回业务失败。"""


# --------------------------------------------------------------------------- #
# 配置
# --------------------------------------------------------------------------- #
@dataclass
class Config:
    base_url: str = DEFAULT_BASE_URL
    username: str = ""
    password: str = ""
    cookie: str = ""              # 初始 cookie，形如 "session=xxx; other=yyy"
    token: str = ""               # 初始 access_token（可选）
    state_file: str = "sheapi_state.json"
    captcha_solver: str = "auto"  # auto | ddddocr | manual | cmd
    captcha_cmd: str = ""         # 例：python3 my_ocr.py {file}
    timeout: int = 20
    retries: int = 3              # 验证码/网络重试次数
    proxy: str = ""
    log_file: str = ""


def _load_config(path: Optional[str]) -> Config:
    cfg = Config()
    data: dict[str, Any] = {}

    # 1) 配置文件
    if path:
        p = Path(path)
        if not p.exists():
            raise SystemExit(f"配置文件不存在：{path}")
        data.update(json.loads(p.read_text(encoding="utf-8")))
    elif Path("config.json").exists():
        data.update(json.loads(Path("config.json").read_text(encoding="utf-8")))

    # 2) 环境变量（优先级高于配置文件，便于放进 CI / 密钥管理）
    env_map = {
        "SHEAPI_BASE_URL": "base_url",
        "SHEAPI_USERNAME": "username",
        "SHEAPI_PASSWORD": "password",
        "SHEAPI_COOKIE": "cookie",
        "SHEAPI_TOKEN": "token",
        "SHEAPI_STATE": "state_file",
        "SHEAPI_CAPTCHA_CMD": "captcha_cmd",
        "SHEAPI_PROXY": "proxy",
    }
    for env_key, attr in env_map.items():
        if os.getenv(env_key):
            data[attr] = os.environ[env_key]

    for key, value in data.items():
        if hasattr(cfg, key) and value is not None:
            setattr(cfg, key, value)

    cfg.base_url = cfg.base_url.rstrip("/")
    return cfg


# --------------------------------------------------------------------------- #
# 工具函数
# --------------------------------------------------------------------------- #
def mask(secret: Optional[str], keep: int = 8) -> str:
    """日志里脱敏 token / 密码。"""
    if not secret:
        return "<empty>"
    if len(secret) <= keep + 6:
        return secret[:2] + "***"
    return f"{secret[:keep]}...{secret[-4:]}(len={len(secret)})"


def jwt_exp(token: str) -> Optional[int]:
    """解析 JWT 的 exp（秒级时间戳），失败返回 None。"""
    try:
        payload_b64 = token.split(".")[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        exp = payload.get("exp")
        return int(exp) if exp else None
    except Exception:
        return None


def data_url_to_bytes(data_url: str) -> bytes:
    """把 data:image/png;base64,xxx 转成 bytes；也兼容直接给 base64。"""
    if "," in data_url and data_url.strip().lower().startswith("data:"):
        data_url = data_url.split(",", 1)[1]
    return base64.b64decode(data_url)


def looks_like_captcha_error(message: str) -> bool:
    low = (message or "").lower()
    return any(h.lower() in low for h in CAPTCHA_HINT)


def looks_like_already(message: str) -> bool:
    low = (message or "").lower()
    return any(h.lower() in low for h in ALREADY_HINT)


# --------------------------------------------------------------------------- #
# 客户端
# --------------------------------------------------------------------------- #
class SheApiClient:
    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.session = requests.Session()
        self.session.headers.update({
            "accept": "application/json, text/plain, */*",
            "accept-language": "zh-CN,zh;q=0.9,en;q=0.8",
            "cache-control": "no-store",
            "user-agent": DEFAULT_UA,
            "origin": cfg.base_url,
        })
        if cfg.proxy:
            self.session.proxies.update({"http": cfg.proxy, "https": cfg.proxy})

        self.access_token: str = ""
        self._ddddocr = None
        # 先应用配置里的初始凭据，再用本地状态文件覆盖
        # （状态文件是上一次运行保存的、更新的登录态，优先级更高）
        if cfg.cookie:
            self._apply_cookie(cfg.cookie)
        if cfg.token:
            self.access_token = cfg.token
        self._load_state()

    # ---------------- 状态持久化 ---------------- #
    @property
    def _state_path(self) -> Path:
        return Path(self.cfg.state_file).expanduser()

    def _load_state(self) -> None:
        p = self._state_path
        if not p.exists():
            return
        try:
            state = json.loads(p.read_text(encoding="utf-8"))
        except Exception as exc:  # 状态文件损坏时不影响主流程
            LOG.warning("状态文件解析失败，忽略：%s", exc)
            return
        self.session.cookies.update(
            requests.utils.cookiejar_from_dict(state.get("cookies") or {})
        )
        if state.get("access_token"):
            self.access_token = state["access_token"]
        if state.get("updated_at"):
            LOG.info("已加载本地登录态（更新时间 %s）", state["updated_at"])
        else:
            LOG.info("已加载本地登录态")

    def save_state(self) -> None:
        p = self._state_path
        p.parent.mkdir(parents=True, exist_ok=True)
        cookies = {c.name: c.value for c in self.session.cookies}
        state = {
            "base_url": self.cfg.base_url,
            "cookies": cookies,
            "access_token": self.access_token,
            "token_exp": jwt_exp(self.access_token) if self.access_token else None,
            "updated_at": datetime.now().isoformat(timespec="seconds"),
        }
        p.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
        try:  # 状态含登录凭据，收紧权限
            os.chmod(p, 0o600)
        except OSError:
            pass

    def _apply_cookie(self, raw: str) -> None:
        for part in raw.split(";"):
            if "=" not in part:
                continue
            k, v = part.split("=", 1)
            self.session.cookies.set(k.strip(), v.strip())

    # ---------------- HTTP 基础 ---------------- #
    def _request(self, method: str, path: str, *, referer: str = "/",
                 auth: bool = True, **kwargs) -> requests.Response:
        url = self.cfg.base_url + path
        headers = dict(kwargs.pop("headers", {}))
        headers["referer"] = self.cfg.base_url + referer
        if auth and self.access_token:
            headers["authorization"] = f"Bearer {self.access_token}"

        last_exc: Optional[Exception] = None
        for attempt in range(1, self.cfg.retries + 1):
            try:
                resp = self.session.request(
                    method, url, headers=headers, timeout=self.cfg.timeout, **kwargs
                )
                return resp
            except requests.RequestException as exc:
                last_exc = exc
                LOG.warning("请求 %s 失败（第 %d/%d 次）：%s",
                            path, attempt, self.cfg.retries, exc)
                time.sleep(min(2 ** attempt, 8))
        raise AuthError(f"网络请求失败：{path} -> {last_exc}")

    @staticmethod
    def _json(resp: requests.Response) -> dict:
        try:
            return resp.json()
        except ValueError:
            raise AuthError(
                f"服务端返回非 JSON（HTTP {resp.status_code}）：{resp.text[:200]}"
            )

    # ---------------- 验证码 ---------------- #
    def fetch_captcha(self, scene: str) -> dict:
        """获取图形验证码，返回 {"id":..., "image": bytes}。"""
        resp = self._request("GET", "/api/captcha", params={"scene": scene},
                             referer="/profile" if scene == "checkin" else "/sign-in")
        body = self._json(resp)
        data = body.get("data") or {}
        cid = data.get("captcha_id") or data.get("id")
        image = data.get("captcha_image") or data.get("image") or data.get("img")
        if not cid or not image:
            raise CaptchaError(
                f"未取到 {scene} 验证码（可能服务端已关闭验证码）：{str(body)[:200]}"
            )
        return {"id": cid, "image": data_url_to_bytes(image)}

    def solve_captcha(self, image: bytes, scene: str) -> str:
        """按配置的识别策略输出验证码答案。"""
        solver = self.cfg.captcha_solver
        if solver in ("auto", "ddddocr"):
            code = self._solve_ddddocr(image)
            if code:
                return code
            if solver == "ddddocr":
                raise CaptchaError("ddddocr 识别失败")
        if solver in ("auto", "cmd") and self.cfg.captcha_cmd:
            code = self._solve_with_cmd(image, scene)
            if code:
                return code
        if solver in ("auto", "manual"):
            code = self._solve_manually(image, scene)
            if code:
                return code
        raise CaptchaError(
            "验证码识别失败：请安装 ddddocr（pip install ddddocr），"
            "或使用 --captcha-solver manual / --captcha-cmd"
        )

    def _solve_ddddocr(self, image: bytes) -> Optional[str]:
        try:
            import ddddocr  # type: ignore
        except ImportError:
            return None
        if self._ddddocr is None:
            try:
                self._ddddocr = ddddocr.DdddOcr(show_ad=False)
            except TypeError:  # 老版本没有 show_ad
                self._ddddocr = ddddocr.DdddOcr()
        try:
            code = self._ddddocr.classification(image)
            return re.sub(r"\s+", "", code or "") or None
        except Exception as exc:
            LOG.warning("ddddocr 识别异常：%s", exc)
            return None

    def _solve_with_cmd(self, image: bytes, scene: str) -> Optional[str]:
        path = Path(f"captcha_{scene}.png").resolve()
        path.write_bytes(image)
        argv = [t.replace("{file}", str(path))
                for t in shlex.split(self.cfg.captcha_cmd)]
        try:
            out = subprocess.run(argv, capture_output=True, text=True, timeout=30)
            code = (out.stdout or "").strip().splitlines()[-1].strip() if out.stdout else ""
            code = re.sub(r"\s+", "", code)
            if code:
                return code
            LOG.warning("--captcha-cmd 无输出：%s", out.stderr[:200])
        except Exception as exc:
            LOG.warning("--captcha-cmd 执行失败：%s", exc)
        return None

    def _solve_manually(self, image: bytes, scene: str) -> Optional[str]:
        path = Path(f"captcha_{scene}.png").resolve()
        path.write_bytes(image)
        if not sys.stdin.isatty():
            LOG.error("当前非交互环境，无法手动输入验证码。图片已保存：%s", path)
            return None
        print(f"\n[验证码] 场景={scene} 图片已保存：{path}", file=sys.stderr)
        try:
            code = input("请输入图片中的验证码：").strip()
        except EOFError:
            return None
        return re.sub(r"\s+", "", code) or None

    # ---------------- 登录态 ---------------- #
    def _verify_token(self) -> bool:
        if not self.access_token:
            return False
        try:
            resp = self._request("GET", "/api/user/self", referer="/dashboard/overview")
        except AuthError:
            return False
        if resp.status_code == 401:
            return False
        body = self._json(resp)
        return bool(body.get("success", resp.status_code == 200))

    def _extract_token(self, body: dict) -> str:
        data = body.get("data")
        if isinstance(data, dict):
            for key in ("access_token", "token", "accessToken"):
                if data.get(key):
                    return str(data[key])
        for key in ("access_token", "token"):
            if body.get(key):
                return str(body[key])
        return ""

    def refresh_token(self) -> Optional[str]:
        """用 cookie 调 /api/user/auth/refresh 换新的 access_token。"""
        if not self.session.cookies:
            return None
        LOG.info("尝试用本地 cookie 刷新 access_token ...")
        resp = self._request("POST", "/api/user/auth/refresh", referer="/sign-in",
                             json=None, data=b"")
        if resp.status_code in (401, 403):
            LOG.info("cookie 已失效（HTTP %s）", resp.status_code)
            return None
        body = self._json(resp)
        token = self._extract_token(body)
        if body.get("success") and token:
            LOG.info("刷新成功，新 token：%s", mask(token))
            self.access_token = token
            self.save_state()
            return token
        LOG.info("刷新未通过：%s", str(body.get("message"))[:120])
        return None

    def login(self) -> str:
        """账号密码 + 图形验证码登录，成功后返回 access_token。"""
        if not (self.cfg.username and self.cfg.password):
            raise AuthError("登录态已失效，且未配置 username / password，无法自动登录")
        LOG.info("开始账号密码登录：%s", self.cfg.username)

        last_msg = ""
        for attempt in range(1, self.cfg.retries + 1):
            cap = self.fetch_captcha("login")
            code = self.solve_captcha(cap["image"], "login")
            payload = {
                "username": self.cfg.username,
                "password": self.cfg.password,
                "captcha_id": cap["id"],
                "captcha_code": code,
            }
            resp = self._request(
                "POST", "/api/user/login", params={"turnstile": ""},
                referer="/sign-in", json=payload,
            )
            body = self._json(resp)
            if body.get("success"):
                token = self._extract_token(body)
                if not token:
                    # 有些版本登录只下发 cookie，token 需再刷新一次
                    token = self.refresh_token() or ""
                if not token:
                    raise AuthError("登录成功但未取得 access_token，请检查站点版本")
                self.access_token = token
                self.save_state()
                LOG.info("登录成功，token：%s", mask(token))
                return token

            last_msg = str(body.get("message") or "")
            if "两步验证" in last_msg or "2fa" in last_msg.lower():
                raise AuthError(
                    "账号开启了两步验证(2FA)，脚本无法自动完成 2FA 登录；"
                    "请先在网页端关闭 2FA，或手动登录后把 cookie 写入配置的 cookie 字段"
                )
            if attempt < self.cfg.retries:
                LOG.warning("登录失败（第 %d/%d 次）：%s，重试中 ...",
                            attempt, self.cfg.retries, last_msg[:120])
                time.sleep(1.0 * attempt)
        raise AuthError(f"登录失败：{last_msg[:200]}")

    def ensure_auth(self) -> str:
        """保证手上有可用的 access_token：本地 token -> cookie 刷新 -> 账号登录。"""
        exp = jwt_exp(self.access_token)
        if self.access_token and (exp is None or exp - time.time() > 60):
            if self._verify_token():
                LOG.info("本地 access_token 可用：%s", mask(self.access_token))
                return self.access_token
            LOG.info("本地 access_token 已失效")
        elif self.access_token:
            LOG.info("本地 access_token 已过期（exp=%s）", exp)

        token = self.refresh_token()
        if token and self._verify_token():
            return token

        token = self.login()
        if self._verify_token():
            return token
        raise AuthError("登录后仍无法通过鉴权，请检查账号状态或被风控拦截")

    # ---------------- 签到 ---------------- #
    def checkin(self) -> dict:
        """取签到验证码 -> 提交签到，返回结果描述。"""
        LOG.info("开始签到 ...")
        last_msg = ""
        cap: Optional[dict] = None
        for attempt in range(1, self.cfg.retries + 1):
            try:
                cap = self.fetch_captcha("checkin")
            except CaptchaError as exc:
                LOG.warning("%s；尝试不带验证码直接签到", exc)
                cap = None

            payload: dict[str, Any] = {}
            if cap:
                code = self.solve_captcha(cap["image"], "checkin")
                payload = {"captcha_id": cap["id"], "captcha_code": code}

            resp = self._request("POST", "/api/user/checkin", referer="/profile",
                                 json=payload)
            if resp.status_code == 401:
                LOG.warning("签到接口返回 401，登录态失效，重新认证 ...")
                self.access_token = ""
                self.ensure_auth()
                continue

            body = self._json(resp)
            msg = str(body.get("message") or "")
            if body.get("success"):
                award = ""
                data = body.get("data")
                if isinstance(data, dict):
                    for k in ("quota_award", "quota", "reward", "points"):
                        if data.get(k) not in (None, 0, ""):
                            award = f"（{k}={data[k]}）"
                            break
                LOG.info("签到成功：%s%s", msg or "OK", award)
                return {"status": "ok", "message": msg, "data": data}
            if looks_like_already(msg):
                LOG.info("今天已经签到过了：%s", msg)
                return {"status": "already", "message": msg, "data": body.get("data")}
            if cap and looks_like_captcha_error(msg) and attempt < self.cfg.retries:
                LOG.warning("验证码错误（第 %d/%d 次）：%s，重新获取验证码",
                            attempt, self.cfg.retries, msg)
                time.sleep(0.8)
                continue
            last_msg = msg
            if attempt >= self.cfg.retries:
                break
            time.sleep(1.0 * attempt)
        raise CheckinError(f"签到失败：{last_msg[:200] or '未知错误'}")

    def monthly_status(self) -> Optional[dict]:
        month = datetime.now().strftime("%Y-%m")
        try:
            resp = self._request("GET", "/api/user/checkin", params={"month": month},
                                 referer="/profile")
            body = self._json(resp)
            return body.get("data") if body.get("success") else None
        except Exception as exc:
            LOG.debug("查询签到日历失败：%s", exc)
            return None

    def quota_info(self) -> Optional[dict]:
        try:
            resp = self._request("GET", "/api/user/self", referer="/dashboard/overview")
            body = self._json(resp)
            data = body.get("data") if body.get("success") else None
            if not isinstance(data, dict):
                return None
            return {
                "username": data.get("username"),
                "quota": data.get("quota"),
                "used_quota": data.get("used_quota"),
                "aff_code": data.get("aff_code"),
            }
        except Exception as exc:
            LOG.debug("查询账户信息失败：%s", exc)
            return None


# --------------------------------------------------------------------------- #
# 入口
# --------------------------------------------------------------------------- #
def setup_logging(verbose: bool, log_file: str) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]
    if log_file:
        p = Path(log_file)
        p.parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(p, encoding="utf-8"))
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=handlers,
    )


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="sheapi.cc 自动签到（默认复用已登录 cookie，失效时自动登录）",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("-c", "--config", help="配置文件路径（JSON）")
    p.add_argument("--base-url", help="站点地址")
    p.add_argument("-u", "--username", help="登录账号")
    p.add_argument("-p", "--password", help="登录密码")
    p.add_argument("--cookie", help="初始 cookie 字符串，如 'session=xxx'")
    p.add_argument("--token", help="初始 access_token（可选）")
    p.add_argument("--state-file", help="登录态保存路径")
    p.add_argument("--captcha-solver", choices=["auto", "ddddocr", "manual", "cmd"],
                   help="验证码识别方式")
    p.add_argument("--captcha-cmd", help="自定义识别命令，{file} 为图片路径")
    p.add_argument("--timeout", type=int, help="单次请求超时（秒）")
    p.add_argument("--retries", type=int, help="失败重试次数")
    p.add_argument("--proxy", help="代理地址，如 http://127.0.0.1:7890")
    p.add_argument("--log-file", help="日志文件路径")
    p.add_argument("--json-out", help="把本次运行结果写成 JSON 文件（供 CI 汇总）")
    p.add_argument("--dry-run", action="store_true", help="只检查登录态，不执行签到")
    p.add_argument("--show-status", action="store_true", help="签到最后打印账户与本月签到情况")
    p.add_argument("-v", "--verbose", action="store_true", help="输出调试日志")
    return p


def write_result(path: str, result: dict) -> None:
    """把运行结果写成机器可读 JSON，便于 CI/监控消费。"""
    try:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception as exc:  # 结果文件写失败不应影响退出码
        LOG.warning("写入结果文件失败：%s", exc)


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    cfg = _load_config(args.config)
    # 命令行参数覆盖配置
    for attr in ("base_url", "username", "password", "cookie", "token",
                 "state_file", "captcha_solver", "captcha_cmd", "timeout", "retries",
                 "proxy", "log_file"):
        val = getattr(args, attr, None)
        if val:
            setattr(cfg, attr, val)
    if args.log_file and not cfg.log_file:
        cfg.log_file = args.log_file
    setup_logging(args.verbose, cfg.log_file)

    client = SheApiClient(cfg)
    try:
        client.ensure_auth()
        if args.dry_run:
            LOG.info("dry-run：登录态有效，未执行签到")
            if args.json_out:
                info = client.quota_info() or {}
                write_result(args.json_out, {
                    "status": "dry-run",
                    "message": "登录态有效，未执行签到",
                    "username": info.get("username"),
                    "quota": info.get("quota"),
                    "used_quota": info.get("used_quota"),
                    "time": datetime.now().isoformat(timespec="seconds"),
                })
            return 0
        result = client.checkin()
        info = (client.quota_info() or {}) if (args.show_status or args.json_out) else {}
        if args.show_status and info:
            LOG.info("账户 %s | 剩余额度 %s | 已用 %s",
                     info.get("username"), info.get("quota"), info.get("used_quota"))
        if args.show_status:
            cal = client.monthly_status()
            if isinstance(cal, dict) and cal:
                LOG.info("本月签到数据：%s", json.dumps(cal, ensure_ascii=False)[:300])
        client.save_state()
        if args.json_out:
            write_result(args.json_out, {
                "status": result["status"],
                "message": result.get("message"),
                "data": result.get("data"),
                "username": info.get("username"),
                "quota": info.get("quota"),
                "used_quota": info.get("used_quota"),
                "time": datetime.now().isoformat(timespec="seconds"),
            })
        return 0 if result["status"] in ("ok", "already") else 1
    except (AuthError, CaptchaError, CheckinError) as exc:
        LOG.error("%s", exc)
        if args.json_out:
            write_result(args.json_out, {"status": "error", "message": str(exc),
                                        "time": datetime.now().isoformat(timespec="seconds")})
        return 1
    except KeyboardInterrupt:
        LOG.warning("已中断")
        return 130
    except Exception as exc:  # 兜底，保证退出码可被调度系统识别
        LOG.exception("未预期错误：%s", exc)
        if args.json_out:
            write_result(args.json_out, {"status": "error", "message": str(exc),
                                        "time": datetime.now().isoformat(timespec="seconds")})
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

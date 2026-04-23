from __future__ import annotations

import logging
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime

import requests

from config import Config


@dataclass
class Alert:
    rule: str
    proc_name: str
    pid: int
    src: str
    dst: str
    detail: str
    timestamp: datetime

    def format_message(self) -> str:
        return (
            f"[NETMON] {self.rule} | proc: {self.proc_name}({self.pid})"
            f" | {self.src}\u2192{self.dst} | {self.detail}"
        )


def dispatch(alert: Alert, cfg: Config, log: logging.Logger) -> None:
    msg = alert.format_message()
    log.warning(msg)
    if cfg.discord_webhook_url:
        _send_discord(alert, cfg.discord_webhook_url, log)
    if cfg.toast_enabled:
        _send_toast(alert, log)


def _send_discord(alert: Alert, webhook_url: str, log: logging.Logger) -> None:
    try:
        resp = requests.post(
            webhook_url,
            json={"content": alert.format_message()},
            timeout=5,
        )
        if resp.status_code not in {200, 204}:
            log.warning("Discord webhook returned %s", resp.status_code)
    except Exception as exc:
        log.warning("Discord send failed: %s", exc)


def _send_toast(alert: Alert, log: logging.Logger) -> None:
    title = f"[NETMON] {alert.rule}"
    msg = f"{alert.proc_name}({alert.pid}) {alert.src}\u2192{alert.dst}\n{alert.detail}"
    try:
        if sys.platform == "win32":
            _toast_windows(title, msg, log)
        elif sys.platform == "darwin":
            _toast_macos(title, msg, log)
        else:
            _toast_linux(title, msg, log)
    except Exception as exc:
        log.warning("toast send failed: %s", exc)


def _toast_windows(title: str, msg: str, log: logging.Logger) -> None:
    try:
        from winotify import Notification, audio  # type: ignore[import]

        toast = Notification(
            app_id="NetMon",
            title=title,
            msg=msg,
            duration="short",
        )
        toast.set_audio(audio.Default, loop=False)
        toast.show()
    except ImportError:
        log.debug("winotify not available; skipping Windows toast")
    except Exception as exc:
        raise exc


def _toast_macos(title: str, msg: str, log: logging.Logger) -> None:
    safe_title = title.replace('"', '\\"')
    safe_msg = msg.replace('"', '\\"')
    subprocess.run(
        ["osascript", "-e", f'display notification "{safe_msg}" with title "{safe_title}"'],
        timeout=5,
        check=False,
    )


def _toast_linux(title: str, msg: str, log: logging.Logger) -> None:
    try:
        subprocess.run(["notify-send", title, msg], timeout=5, check=False)
    except FileNotFoundError:
        log.debug("notify-send not available")

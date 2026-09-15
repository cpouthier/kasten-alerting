"""SMTP email alerting: sends one digest email per poll cycle that found
new alertable actions (see poller.run_once) - a single email listing every
action detected that cycle, rather than one email per action, so an
incident that fails many actions at once (a storage outage, say) can't
flood the inbox. Configured on the Settings page (host/port/security/auth/
addresses in settings.py, the password in a Kubernetes Secret), same split
as cpouthier/malware-scan's own app/alerting.py.
"""
import asyncio
import html
import logging
import smtplib
from email.message import EmailMessage

import k10
import tz

logger = logging.getLogger("kasten-alerting.alerting")

SMTP_SECRET_NAME = "kasten-alerting-smtp"

# Same palette as app/static/index.html's :root{} custom properties (itself
# copied from malware-scan's own palette) - email HTML can't reference CSS
# variables, so these are the same values pasted in literally.
_INK = "#14212a"
_TEXT = "#1c2b33"
_MUTED = "#5d6b75"
_BORDER = "#e2e7ea"
_CARD_BG = "#ffffff"
_PAGE_BG = "#f2f5f7"
_GREEN = "#00b336"
_GREEN_DARK = "#0b7a30"
_GREEN_TINT = "#e6f7ea"
_RED = "#d13438"
_RED_DARK = "#a72125"
_RED_TINT = "#fbebec"
_ORANGE = "#c97a00"
_ORANGE_DARK = "#8a5600"
_ORANGE_TINT = "#faf1e1"
_LOG_BG = "#111c23"
_LOG_TEXT = "#b9c7d0"

_STATUS_STYLE = {
    "Failed": (_RED_TINT, _RED, _RED_DARK),
    "Cancelled": (_ORANGE_TINT, _ORANGE, _ORANGE_DARK),
    "Skipped": (_ORANGE_TINT, _ORANGE, _ORANGE_DARK),
    "Complete": (_GREEN_TINT, _GREEN, _GREEN_DARK),
}


def _html_shell(inner: str) -> str:
    return f"""\
<!DOCTYPE html>
<html>
<body style="margin:0;padding:24px 12px;background:{_PAGE_BG};font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:680px;margin:0 auto;background:{_CARD_BG};border:1px solid {_BORDER};border-radius:6px;overflow:hidden;">
  <tr>
    <td style="background:{_INK};padding:14px 24px;">
      <span style="color:#ffffff;font-size:14px;font-weight:700;">\U0001f514 Kasten Alerting</span>
    </td>
  </tr>
  <tr>
    <td style="padding:24px;">
      {inner}
    </td>
  </tr>
  <tr>
    <td style="padding:14px 24px;border-top:1px solid {_BORDER};color:{_MUTED};font-size:11px;">
      kasten-alerting
    </td>
  </tr>
</table>
</body>
</html>"""


def _status_pill(state: str) -> str:
    bg, border, text = _STATUS_STYLE.get(state, (_ORANGE_TINT, _ORANGE, _ORANGE_DARK))
    return (
        f'<span style="display:inline-block;padding:2px 8px;border-radius:10px;background:{bg};'
        f'border:1px solid {border};color:{text};font-size:11px;font-weight:700;">{html.escape(state)}</span>'
    )


def _counts_by_status(items: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        counts[item["state"]] = counts.get(item["state"], 0) + 1
    return counts


def _subject(items: list[dict]) -> str:
    counts = _counts_by_status(items)
    parts = [f"{n} {state}" for state, n in sorted(counts.items(), key=lambda kv: -kv[1])]
    return f"[Kasten Alerting] {', '.join(parts)} action(s) detected"


def _banner_style(items: list[dict]) -> tuple[str, str, str]:
    states = {item["state"] for item in items}
    if "Failed" in states:
        return _STATUS_STYLE["Failed"]
    if states & {"Cancelled", "Skipped"}:
        return _STATUS_STYLE["Cancelled"]
    return _STATUS_STYLE["Complete"]


def _build_digest_text(items: list[dict]) -> str:
    counts = _counts_by_status(items)
    lines = [
        f"{', '.join(f'{n} {state}' for state, n in counts.items())} action(s) detected",
        "",
    ]
    for item in items:
        lines.append(f"[{item['state']}] {item['kind']} {item['name']}")
        lines.append(f"  Namespace: {item['namespace'] or 'n/a'}")
        if item["policy_name"]:
            lines.append(f"  Policy: {item['policy_name']}")
        if item["location_profile"]:
            lines.append(f"  Location Profile: {item['location_profile']}")
        lines.append(f"  When: {tz.format_local(item['timestamp']) or 'unknown'}")
        if item["error_lines"]:
            lines.append("  Log:")
            lines.extend(f"    {ln}" for ln in item["error_lines"])
        lines.append("")
    return "\n".join(lines)


def _build_digest_html(items: list[dict]) -> str:
    bg, border, text = _banner_style(items)
    counts = _counts_by_status(items)
    summary = ", ".join(f"{n} {state}" for state, n in counts.items())

    # Only added as a column when at least one item actually has one
    # (mainly ExportAction/ImportAction) - an always-present, almost-always-
    # empty column would just crowd the table on every ordinary digest.
    show_profile_column = any(item["location_profile"] for item in items)
    profile_header = (
        f'<td style="padding:6px 10px;font-size:11px;color:{_MUTED};font-weight:700;text-transform:uppercase;">Location Profile</td>'
        if show_profile_column else ""
    )

    def _profile_cell(item: dict) -> str:
        if not show_profile_column:
            return ""
        return f'<td style="padding:8px 10px;border-bottom:1px solid {_BORDER};font-size:12px;color:{_MUTED};">{html.escape(item["location_profile"] or "—")}</td>'

    rows = "".join(f"""
        <tr>
          <td style="padding:8px 10px;border-bottom:1px solid {_BORDER};">{_status_pill(item['state'])}</td>
          <td style="padding:8px 10px;border-bottom:1px solid {_BORDER};font-size:12px;font-weight:600;color:{_TEXT};">{html.escape(item['kind'])}</td>
          <td style="padding:8px 10px;border-bottom:1px solid {_BORDER};font-size:12px;color:{_TEXT};font-family:ui-monospace,Consolas,monospace;">{html.escape(item['name'] or '')}</td>
          <td style="padding:8px 10px;border-bottom:1px solid {_BORDER};font-size:12px;color:{_MUTED};">{html.escape(item['policy_name'] or '—')}</td>
          <td style="padding:8px 10px;border-bottom:1px solid {_BORDER};font-size:12px;color:{_MUTED};font-family:ui-monospace,Consolas,monospace;">{html.escape(item['namespace'] or '—')}</td>
          {_profile_cell(item)}
          <td style="padding:8px 10px;border-bottom:1px solid {_BORDER};font-size:11px;color:{_MUTED};white-space:nowrap;">{html.escape(tz.format_local(item['timestamp']))}</td>
        </tr>""" for item in items)

    parts = [f"""
    <div style="background:{bg};border:1px solid {border};border-radius:4px;padding:12px 16px;margin-bottom:20px;">
      <span style="color:{text};font-size:16px;font-weight:700;">{html.escape(summary)}</span>
    </div>
    <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border:1px solid {_BORDER};border-radius:4px;overflow:hidden;">
      <tr style="background:{_PAGE_BG};">
        <td style="padding:6px 10px;font-size:11px;color:{_MUTED};font-weight:700;text-transform:uppercase;">Status</td>
        <td style="padding:6px 10px;font-size:11px;color:{_MUTED};font-weight:700;text-transform:uppercase;">Type</td>
        <td style="padding:6px 10px;font-size:11px;color:{_MUTED};font-weight:700;text-transform:uppercase;">Action</td>
        <td style="padding:6px 10px;font-size:11px;color:{_MUTED};font-weight:700;text-transform:uppercase;">Policy</td>
        <td style="padding:6px 10px;font-size:11px;color:{_MUTED};font-weight:700;text-transform:uppercase;">Namespace</td>
        {profile_header}
        <td style="padding:6px 10px;font-size:11px;color:{_MUTED};font-weight:700;text-transform:uppercase;">When</td>
      </tr>
      {rows}
    </table>"""]

    errored = [item for item in items if item["error_lines"]]
    if errored:
        blocks = "".join(f"""
        <div style="margin-top:10px;">
          <div style="color:{_TEXT};font-size:12px;font-weight:700;font-family:ui-monospace,Consolas,monospace;">{html.escape(item['kind'])} {html.escape(item['name'] or '')}</div>
          <div style="background:{_LOG_BG};border-radius:4px;padding:10px 12px;margin-top:4px;
                      font-family:ui-monospace,Consolas,monospace;font-size:11px;line-height:1.6;color:{_LOG_TEXT};">
            {'<br>'.join(html.escape(ln) for ln in item['error_lines'])}
          </div>
        </div>""" for item in errored)
        parts.append(f"""
    <div style="margin-top:20px;">
      <div style="color:{_MUTED};font-size:13px;margin-bottom:6px;">Error details</div>
      {blocks}
    </div>""")

    return _html_shell("".join(parts))


def _build_digest_message(cfg: dict, items: list[dict]) -> EmailMessage:
    msg = EmailMessage()
    msg["Subject"] = _subject(items)
    msg["From"] = cfg["from_address"]
    msg["To"] = ", ".join(cfg["to_addresses"])
    msg.set_content(_build_digest_text(items))
    msg.add_alternative(_build_digest_html(items), subtype="html")
    return msg


def _send_sync(cfg: dict, password: str | None, msg: EmailMessage) -> None:
    host, port, security = cfg["smtp_host"], int(cfg["smtp_port"]), cfg["smtp_security"]
    smtp_cls = smtplib.SMTP_SSL if security == "ssl" else smtplib.SMTP
    with smtp_cls(host, port, timeout=20) as smtp:
        if security == "starttls":
            smtp.starttls()
        if cfg.get("smtp_username"):
            smtp.login(cfg["smtp_username"], password or "")
        smtp.send_message(msg)


async def _get_password() -> str | None:
    data = await k10.get_secret_data(k10.APP_NAMESPACE, SMTP_SECRET_NAME)
    return data.get("password") if data else None


async def send_digest(cfg: dict, items: list[dict]) -> None:
    password = await _get_password()
    msg = _build_digest_message(cfg, items)
    logger.info("sending digest email for %d action(s) to %s", len(items), cfg["to_addresses"])
    await asyncio.to_thread(_send_sync, cfg, password, msg)


async def send_test_email(cfg: dict, password: str | None) -> None:
    msg = EmailMessage()
    msg["Subject"] = "[Kasten Alerting] Test email"
    msg["From"] = cfg["from_address"]
    msg["To"] = ", ".join(cfg["to_addresses"])
    msg.set_content(
        "This is a test email from kasten-alerting's settings.\n\n"
        "If you're reading this, SMTP is configured correctly."
    )
    msg.add_alternative(_html_shell(f"""
    <div style="background:{_GREEN_TINT};border:1px solid {_GREEN};border-radius:4px;padding:16px;">
      <div style="color:{_GREEN_DARK};font-size:15px;font-weight:700;margin-bottom:6px;">Test email</div>
      <div style="color:{_TEXT};font-size:13px;">This is a test email from kasten-alerting's settings.<br>If you're reading this, SMTP is configured correctly.</div>
    </div>"""), subtype="html")
    await asyncio.to_thread(_send_sync, cfg, password, msg)

"""사내 메일(SMTP) 발송 — 외부 부서(개발팀 등) 회사 이메일로 전송.

SMTP_HOST가 비어 있으면 '드라이런'으로 동작: 실제 발송 없이 성공 처리(기록만).
이렇게 하면 메일 서버가 없는 환경에서도 기능이 안전하게 돌아간다.
"""
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr

import config


def send_email(to_email: str, subject: str, body: str, to_name: str = "", html: str = "") -> tuple[bool, str]:
    """(성공여부, 상세메시지) 반환. html이 있으면 multipart(평문+HTML)로 발송."""
    if not config.SMTP_HOST:
        return True, "드라이런 (SMTP 미설정 — 실제 발송 안 함, 기록만 저장)"

    if html:
        msg = MIMEMultipart("alternative")
        msg.attach(MIMEText(body or "", "plain", "utf-8"))   # HTML 미지원 클라이언트 폴백
        msg.attach(MIMEText(html, "html", "utf-8"))
    else:
        msg = MIMEText(body or "", "plain", "utf-8")
    msg["Subject"] = subject
    msg["From"] = config.SMTP_FROM
    msg["To"] = formataddr((to_name, to_email)) if to_name else to_email

    try:
        import smtplib
        with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT, timeout=15) as s:
            if config.SMTP_TLS:
                s.starttls()
            if config.SMTP_USER:
                s.login(config.SMTP_USER, config.SMTP_PASSWORD)
            s.sendmail(config.SMTP_FROM, [to_email], msg.as_string())
        return True, "발송 완료"
    except Exception as exc:  # noqa: BLE001
        return False, f"SMTP 발송 실패: {exc}"

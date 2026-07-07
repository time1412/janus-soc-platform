"""소통플랫폼 환경 설정 로더.

소통플랫폼은 분석플랫폼(SOC 플랫폼 개발)과 별도지만, 같은 AI 키를 쓰므로
자체 .env가 없으면 분석플랫폼의 .env를 재사용한다.
"""
import os
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent          # 소통플랫폼/
SOC_DIR = BASE_DIR.parent / "SOC 플랫폼 개발"               # 분석플랫폼/

# 자체 .env 우선, 없으면 분석플랫폼 .env 재사용
_own_env = BASE_DIR / ".env"
_soc_env = SOC_DIR / ".env"
load_dotenv(_own_env if _own_env.exists() else _soc_env)

# --- AI (OpenRouter, OpenAI 호환) ---
AI_API_KEY = os.getenv("GEMINI_API_KEY", "")
AI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
AI_URL = "https://openrouter.ai/api/v1/chat/completions"

# --- 분석플랫폼 연동 (현재는 미연결 — PoC에서는 직접 호출 안 함) ---
ANALYSIS_API = os.getenv("ANALYSIS_API", "http://localhost:8800")

# --- 사내 메일(SMTP) — 외부 부서로 실제 이메일 발송 ---
SMTP_HOST = os.getenv("SMTP_HOST", "")            # 비어 있으면 드라이런(실제 발송 안 함)
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM = os.getenv("SMTP_FROM", "soc-noreply@company.local")
SMTP_TLS = os.getenv("SMTP_TLS", "true").lower() == "true"

# --- 메일 게이트웨이 (janus.com 사용자별 사서함 webmail) ---
# 각 사용자는 <username>@janus.com 사서함을 가지며(가입 비번=메일 비번),
# 백엔드가 그 자격으로 IMAP 수신·SMTP 발송을 대행한다.
MAIL_GATEWAY_HOST = os.getenv("MAIL_GATEWAY_HOST", "192.168.126.222")  # ESXi 이전 시 10.0.10.50
MAIL_DOMAIN = os.getenv("MAIL_DOMAIN", "janus.com")
MAIL_SMTP_PORT = int(os.getenv("MAIL_SMTP_PORT", "25"))       # 25 릴레이(587/465 닫힘)
MAIL_IMAP_PORT = int(os.getenv("MAIL_IMAP_PORT", "993"))      # IMAPS
MAIL_SMTP_STARTTLS = os.getenv("MAIL_SMTP_STARTTLS", "true").lower() == "true"
MAIL_TLS_VERIFY = os.getenv("MAIL_TLS_VERIFY", "false").lower() == "true"  # 자체서명 인증서 허용
# 가입 시 게이트웨이에 사서함 자동 생성 여부(미설정이면 끔 — 수동 생성/바인딩만)
MAIL_PROVISION_ENABLED = os.getenv("MAIL_PROVISION_ENABLED", "false").lower() == "true"
# 자동 생성용 게이트웨이 SSH 자격(랩 한정 — 운영선 제한 권한/프로비저닝 API 권장)
MAIL_SSH_HOST = os.getenv("MAIL_SSH_HOST", "")
MAIL_SSH_PORT = int(os.getenv("MAIL_SSH_PORT", "22"))
MAIL_SSH_USER = os.getenv("MAIL_SSH_USER", "mailadmin")
MAIL_SSH_PASSWORD = os.getenv("MAIL_SSH_PASSWORD", "")

# --- 단계별 외부 알림 (카톡 + 이메일) ---
# 설정이 비어 있으면 드라이런(실제 발송 없이 로그/이력만) — 폐쇄망에서도 안전.
NOTIFY_ENABLED = os.getenv("NOTIFY_ENABLED", "true").lower() == "true"
# 폭주 가드: 팀별 60초 윈도우당 실제 발송 상한(초과분은 요약 1건으로 대체). DDoS/스캔 시 서버 보호.
NOTIFY_RATE_MAX = int(os.getenv("NOTIFY_RATE_MAX", "10"))
COMM_BASE_URL = os.getenv("COMM_BASE_URL", f"http://localhost:{os.getenv('COMM_APP_PORT', '8810')}")

# 카톡 발송 백엔드(공통): (1) 범용 웹훅/제공사 중계 URL  또는  (2) 역할별 Kakao 토큰(나에게 보내기)
KAKAO_NOTIFY_URL = os.getenv("KAKAO_NOTIFY_URL", "")        # 예: 알림톡 제공사(솔라피/알리고/NHN) 또는 사내 중계 서버
KAKAO_NOTIFY_AUTH = os.getenv("KAKAO_NOTIFY_AUTH", "")      # 예: "Bearer xxx" (선택)
KAKAO_NOTIFY_FIELD = os.getenv("KAKAO_NOTIFY_FIELD", "text")  # 웹훅 JSON 본문 메시지 필드명

# 역할별 카톡 수신 식별자(웹훅 방식 — 전화번호/uuid 등 제공사 형식)
KAKAO_TO = {
    "보안관제팀": os.getenv("KAKAO_TO_SOC", ""),
    "웹관리자": os.getenv("KAKAO_TO_WEBADMIN", ""),
    "정보보호팀": os.getenv("KAKAO_TO_INFOSEC", ""),
}
# 역할별 Kakao 액세스 토큰('나에게 보내기' 방식 — 제공사 없이 개인 카톡으로)
# access_token은 ~6시간 만료 → 아래 refresh_token + REST 키가 있으면 자동 갱신해서 지속 사용.
KAKAO_TOKEN = {
    "보안관제팀": os.getenv("KAKAO_TOKEN_SOC", ""),
    "웹관리자": os.getenv("KAKAO_TOKEN_WEBADMIN", ""),
    "정보보호팀": os.getenv("KAKAO_TOKEN_INFOSEC", ""),
}
KAKAO_REST_KEY = os.getenv("KAKAO_REST_KEY", "")     # 카카오 앱 REST API 키(토큰 자동 갱신용)
KAKAO_CLIENT_SECRET = os.getenv("KAKAO_CLIENT_SECRET", "")   # 앱 보안 Client Secret(사용함이면 토큰 요청에 필수)
KAKAO_REFRESH = {                                    # 역할별 refresh_token(약 2개월 유효)
    "보안관제팀": os.getenv("KAKAO_REFRESH_SOC", ""),
    "웹관리자": os.getenv("KAKAO_REFRESH_WEBADMIN", ""),
    "정보보호팀": os.getenv("KAKAO_REFRESH_INFOSEC", ""),
}

# --- 단계 알림 메일 (텔레그램과 동일한 역할 라우팅 — janus.com 게이트웨이로 실발송) ---
# 역할별 수신 사서함. 쉼표로 다중 지정 가능. 대표 계정(soc/admin/web)이 기본값.
NOTIFY_MAIL_FROM = os.getenv("NOTIFY_MAIL_FROM", f"soc-alert@{os.getenv('MAIL_DOMAIN', 'janus.com')}")
NOTIFY_MAIL_TO = {
    "보안관제팀": os.getenv("NOTIFY_MAIL_SOC", f"soc@{os.getenv('MAIL_DOMAIN', 'janus.com')}"),
    "웹관리자": os.getenv("NOTIFY_MAIL_WEBADMIN", f"web@{os.getenv('MAIL_DOMAIN', 'janus.com')}"),
    "정보보호팀": os.getenv("NOTIFY_MAIL_INFOSEC", f"admin@{os.getenv('MAIL_DOMAIN', 'janus.com')}"),
}

# --- 텔레그램 봇 알림 (카톡 대체 — 버튼 강제 없음, HTML 서식) ---
# 봇 토큰이 있으면 카톡 대신 텔레그램으로 발송. 역할별 chat_id로 전송.
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT = {
    "보안관제팀": os.getenv("TELEGRAM_CHAT_SOC", ""),
    "웹관리자": os.getenv("TELEGRAM_CHAT_WEBADMIN", ""),
    "정보보호팀": os.getenv("TELEGRAM_CHAT_INFOSEC", ""),
}

# 이메일 수신처(팀별). 비면 NOTIFY_EMAIL_DEFAULT 사용, 그것도 비면 메일 스킵.
NOTIFY_EMAIL_DEFAULT = os.getenv("NOTIFY_EMAIL_DEFAULT", "")
NOTIFY_EMAILS = {
    "보안관제팀": os.getenv("NOTIFY_EMAIL_SOC", ""),
    "웹관리자": os.getenv("NOTIFY_EMAIL_WEBADMIN", ""),
    "정보보호팀": os.getenv("NOTIFY_EMAIL_INFOSEC", ""),
}

# --- 파일 업로드(이미지) ---
STORAGE_DIR = Path(__file__).resolve().parent / "storage"   # backend/storage
UPLOAD_DIR = STORAGE_DIR / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

# --- 서버 ---
APP_HOST = os.getenv("COMM_APP_HOST", "0.0.0.0")
APP_PORT = int(os.getenv("COMM_APP_PORT", "8810"))  # 분석플랫폼 8800과 분리

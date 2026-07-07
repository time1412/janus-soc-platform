"""티켓 번호/SLA 기한 계산 헬퍼."""
from datetime import datetime, timedelta, timezone

from models import SLA_HOURS

_KST = timezone(timedelta(hours=9))


def make_ticket_no(created_at: datetime, event_id: int) -> str:
    """INC-YYYYMMDD-0042 형식 (날짜는 KST 기준)."""
    dt = created_at if created_at.tzinfo else created_at.replace(tzinfo=timezone.utc)
    date = dt.astimezone(_KST).strftime("%Y%m%d")
    return f"INC-{date}-{event_id:04d}"


def due_from(created_at: datetime, priority: str) -> datetime:
    """생성시각 + 우선순위별 SLA. created_at(naive UTC) 기준으로 naive UTC 반환."""
    return created_at + timedelta(hours=SLA_HOURS.get(priority, 24))

"""시각 변환 유틸 — DB의 naive UTC를 Asia/Seoul(+09:00) ISO 문자열로."""
from datetime import datetime, timedelta, timezone

_KST = timezone(timedelta(hours=9))


def kst_iso(dt: datetime | None) -> str:
    if dt is None:
        return ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(_KST).isoformat()

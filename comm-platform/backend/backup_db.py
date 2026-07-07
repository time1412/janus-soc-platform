"""SQLite 일관성 백업 — 서버 실행 중에도 안전(SQLite 백업 API, WAL 대응).

실행:  python backup_db.py
결과:  backend/storage/backups/comm-YYYYMMDD-HHMMSS.db
정기 실행은 Windows 작업 스케줄러 / cron에 등록하세요.
"""
import sqlite3
from datetime import datetime
from pathlib import Path

from db import DB_PATH

BACKUP_DIR = DB_PATH.parent / "backups"
KEEP = 30  # 최근 N개만 보관


def backup() -> Path:
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    out = BACKUP_DIR / f"comm-{stamp}.db"
    src = sqlite3.connect(str(DB_PATH))
    dst = sqlite3.connect(str(out))
    try:
        with dst:
            src.backup(dst)   # 온라인 일관성 백업(WAL 포함 반영)
    finally:
        src.close()
        dst.close()

    # 오래된 백업 정리
    backups = sorted(BACKUP_DIR.glob("comm-*.db"))
    for old in backups[:-KEEP]:
        old.unlink(missing_ok=True)
    return out


if __name__ == "__main__":
    path = backup()
    size_kb = round(path.stat().st_size / 1024)
    print(f"백업 완료: {path}  ({size_kb}KB)")

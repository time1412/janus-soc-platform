"""MITRE ATT&CK 기법 조회."""
from fastapi import APIRouter

from mitre_data import TACTICS, TECHNIQUES

router = APIRouter(prefix="/api/mitre", tags=["mitre"])


@router.get("")
def list_mitre() -> dict:
    """전체 기법 + 전술 목록 (검색/필터는 프런트에서)."""
    return {"techniques": TECHNIQUES, "tactics": TACTICS, "count": len(TECHNIQUES)}

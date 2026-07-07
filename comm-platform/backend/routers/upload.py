"""이미지 업로드 — 채팅/메신저 첨부용."""
import uuid

from fastapi import APIRouter, File, HTTPException, UploadFile

import config

router = APIRouter(prefix="/api", tags=["upload"])

_ALLOWED = {
    "image/png": "png", "image/jpeg": "jpg", "image/jpg": "jpg",
    "image/gif": "gif", "image/webp": "webp",
}
_MAX_BYTES = 5 * 1024 * 1024  # 5MB


@router.post("/upload")
async def upload(file: UploadFile = File(...)) -> dict:
    ext = _ALLOWED.get((file.content_type or "").lower())
    if not ext:
        raise HTTPException(status_code=400, detail="이미지 파일만 업로드할 수 있습니다 (png/jpg/gif/webp).")
    data = await file.read()
    if len(data) > _MAX_BYTES:
        raise HTTPException(status_code=400, detail="파일이 너무 큽니다 (최대 5MB).")
    name = f"{uuid.uuid4().hex}.{ext}"
    (config.UPLOAD_DIR / name).write_bytes(data)
    return {"url": f"/uploads/{name}", "name": file.filename, "size": len(data)}

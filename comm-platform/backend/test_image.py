"""이미지 업로드 + 채팅/DM 첨부 검증."""
import io

import requests

B = "http://localhost:8810"

# 1x1 PNG
PNG = bytes.fromhex(
    "89504e470d0a1a0a0000000d49484452000000010000000108020000009077"
    "53de0000000c4944415408d7636060606000000005000157a1d0fe0000000049454e44ae426082"
)


def main() -> None:
    u = requests.post(f"{B}/api/signup", json={"username": "imguser", "password": "1234", "display_name": "이미지", "team": "보안관제팀"}).json()
    if not u.get("id"):
        u = requests.post(f"{B}/api/login", json={"username": "imguser", "password": "1234"}).json()

    # 업로드
    up = requests.post(f"{B}/api/upload", files={"file": ("shot.png", io.BytesIO(PNG), "image/png")}).json()
    assert up["url"].startswith("/uploads/"), up
    print(f"✅ 업로드: {up['url']} ({up['size']}B)")

    # 정적 서빙 확인 (SPA 폴백이 아니라 실제 파일)
    r = requests.get(f"{B}{up['url']}")
    assert r.status_code == 200 and r.content[:8] == PNG[:8], (r.status_code, r.headers.get("content-type"))
    print(f"✅ 정적 서빙: {r.status_code}, type={r.headers.get('content-type')}, {len(r.content)}B")

    # 비이미지 거부
    bad = requests.post(f"{B}/api/upload", files={"file": ("x.txt", io.BytesIO(b'hello'), "text/plain")})
    assert bad.status_code == 400
    print(f"✅ 비이미지 거부: {bad.status_code}")

    # 채팅에 이미지 첨부
    ch = requests.get(f"{B}/api/chat/channels").json()[0]
    msg = requests.post(f"{B}/api/chat/channels/{ch['id']}/messages",
                        json={"user_id": u["id"], "body": "스크린샷 공유", "image_url": up["url"]}).json()
    assert msg["image_url"] == up["url"]
    print(f"✅ 채팅 이미지 첨부: image_url={msg['image_url']}")

    # 이미지만(본문 없이) 전송
    only = requests.post(f"{B}/api/chat/channels/{ch['id']}/messages",
                         json={"user_id": u["id"], "body": "", "image_url": up["url"]})
    assert only.status_code == 200
    print("✅ 본문 없이 이미지만 전송 가능")

    # 빈 메시지(본문·이미지 둘 다 없음) 거부
    empty = requests.post(f"{B}/api/chat/channels/{ch['id']}/messages", json={"user_id": u["id"], "body": "  "})
    assert empty.status_code == 400
    print(f"✅ 빈 메시지 거부: {empty.status_code}")

    # DM 이미지 첨부
    u2 = requests.post(f"{B}/api/signup", json={"username": "imgrcv", "password": "1234", "display_name": "수신자", "team": "정보보호팀"}).json()
    if not u2.get("id"):
        u2 = requests.post(f"{B}/api/login", json={"username": "imgrcv", "password": "1234"}).json()
    dm = requests.post(f"{B}/api/dm", json={"sender_id": u["id"], "recipient_id": u2["id"], "body": "", "image_url": up["url"]}).json()
    assert dm["image_url"] == up["url"]
    print(f"✅ DM 이미지 첨부: image_url={dm['image_url']}")

    print("\n🎉 이미지 업로드/첨부 검증 통과")


if __name__ == "__main__":
    main()

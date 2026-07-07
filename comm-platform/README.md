# 소통플랫폼

분석플랫폼(SOC 플랫폼)과 연동되는 별도 플랫폼.

## 목표 구조

```
분석플랫폼(Splunk 로그 수집/탐지)
        │  탐지된 보안 경보
        ▼
 AI 정/오탐 판별 (triage_service)   ← ★ 현재 단계: PoC 완료
        │  정탐(true_positive)만 통과
        ▼
   소통플랫폼 (담당자 전달/협업)
```

분석플랫폼에서 들어온 로그를 AI가 **정탐(실제 공격)** / **오탐(false positive)** 으로
판별하고, **정탐만** 소통플랫폼으로 넘기는 것이 최종 목표.

## 현재 진행 상황

### ✅ 1단계: AI 정/오탐 판별 가능성 검증 (완료)

`backend/triage_service.py` — OpenRouter(Gemini) API로 경보를 분류.
입력 경보의 URI/페이로드를 URL 디코딩해 실제 공격 의도를 분석하고,
아래 구조화된 JSON으로 판정한다.

```json
{
  "verdict": "정탐" | "오탐",
  "confidence": 0-100,
  "attack_type": "...",
  "reasoning": "...",
  "indicators": ["..."],
  "recommended_action": "..."
}
```

**검증 결과: 7/7 정확 (100%)** — `backend/test_triage.py`

| 케이스 | 정답 | AI 판정 | 신뢰도 |
|--------|------|---------|--------|
| SQL Injection (`' AND 1=2`) | 정탐 | 정탐 | 95% |
| SQL Injection (CTXSYS.DRITHSX) | 정탐 | 정탐 | 95% |
| XSS (`<img onerror=...document.cookie>`) | 정탐 | 정탐 | 95% |
| Path Traversal (`../../etc/passwd`) | 정탐 | 정탐 | 95% |
| `;jsessionid=...` (세션ID) | 오탐 | 오탐 | 90% |
| `keyword=콘서트` (정상 검색) | 오탐 | 오탐 | 90% |
| `?page=1&size=10` (정상 페이징) | 오탐 | 오탐 | 90% |

→ **결론: AI 정/오탐 판별 충분히 가능.** 시그니처 이름이 아닌 실제 페이로드를 근거로
   정탐/오탐을 정확히 구분함 (이전에 문제됐던 jsessionid 오탐도 정확히 걸러냄).

### ✅ 2단계: 소통플랫폼 본체 (완료)

보안관제팀 ↔ 정보보호팀이 정탐 이벤트를 함께 검토/승인하고 소통하는 웹 플랫폼.
**FastAPI + SQLite + WebSocket** 백엔드 / **React(Vite)** 프론트엔드.

**핵심 기능**
- **정탐 이벤트 관리** — 분석플랫폼에서 정탐 수신(`POST /api/events/ingest`),
  상태 워크플로(대기→검토중→승인/반려→조치완료), 담당자 배정, 코멘트, 처리 이력(감사 추적)
- **채팅** — 채널 기반, WebSocket 실시간 (관제↔정보보호 협업 채널 등)
- **메일** — 내부 메일(받은/보낸함, 읽음 처리, 안읽음 배지), 정탐 이벤트 연결 공유
- **대시보드** — 상태별 통계, 최근 이벤트, 실시간 토스트 알림
- **로그인** — 두 팀 데모 계정 (비번 `1234`)

**검증: 전체 플로우 7/7 통과** (`backend/smoke_test.py`)
로그인 → 이벤트 수신 → 승인 → 코멘트 → 채팅 → 메일 → 통계

### 구조

```
소통플랫폼/
  backend/
    main.py            FastAPI 앱 (라우터 + WebSocket + SPA 서빙)
    db.py / models.py  SQLite + ORM (User/Event/Chat/Mail)
    schemas.py         Pydantic 스키마
    realtime.py        WebSocket 브로드캐스트 관리자
    seed.py            초기 데모 데이터
    routers/           users / events / chat / mail
    triage_service.py  ★ AI 정/오탐 판별 (1단계)
    triage_queue.py    중복제거 + 배치 큐
  frontend/            React(Vite) — dist/로 빌드되어 FastAPI가 서빙
```

### ⬜ 다음 단계 (예정)

1. **두 플랫폼 연동** — 분석플랫폼이 AI 정탐 판정 후 `POST /api/events/ingest`로 전달
   (현재는 수동/시뮬. triage_queue를 분석플랫폼 alerts에 연결)
2. 판별 정확도 모니터링 (사람의 승인/반려 결과를 AI 피드백 루프로)
3. 실제 메일(SMTP) 연동 옵션, 권한/인증 강화(현재 데모 로그인)

## 실행

```powershell
# 백엔드 (포트 8810)
$venv = ".\.venv\Scripts\python.exe"
$env:PYTHONUTF8 = "1"
cd backend
& $venv -m uvicorn main:app --host 0.0.0.0 --port 8810

# 프론트엔드 빌드 (코드 수정 시)
cd frontend
npm install ; npm run build      # dist/ 생성 → FastAPI가 자동 서빙

# 접속:  http://localhost:8810   (데모 계정 soc_lee / 1234)
```

## 실행

```powershell
# 분석플랫폼 venv 재사용 (requests, dotenv 설치돼 있음)
$venv = "..\SOC 플랫폼 개발\backend\.venv\Scripts\python.exe"
$env:PYTHONUTF8 = "1"
cd backend
& $venv test_triage.py
```

`.env`는 자체 파일이 없으면 분석플랫폼(`../SOC 플랫폼 개발/.env`)의 키를 자동 재사용한다.

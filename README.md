# JANUS SOC Platform

> SOC(보안관제) 통합 플랫폼 — **분석 플랫폼**(Splunk 연동 · AI 정·오탐 판정 · 이벤트 분석 보고서)과
> **소통 플랫폼**(티켓/협업 · 메일)으로 구성된 관제 자동화 프로젝트.

Splunk SIEM이 탐지한 보안 이벤트를 AI(LLM)로 자동 정·오탐 판정하고, **정탐만** 소통 플랫폼으로 전달해
관제 요원이 티켓 기반으로 대응하는 End-to-End 관제 워크플로우를 제공합니다.

---

## 아키텍처

```
   Splunk SIEM (상관탐지 notable)
        │  REST API (8089)
        ▼
  ┌──────────────────────┐        정탐만 전달
  │  분석 플랫폼  :8800   │ ─────(/api/events/ingest)────▶ ┌──────────────────────┐
  │  - AI 정·오탐 판정    │                                 │  소통 플랫폼  :8810   │
  │  - 이벤트 분석 보고서 │                                 │  - 티켓/담당/상태     │
  │  - 위협 지구본/CVE    │                                 │  - 채팅·DM · 웹메일   │
  └──────────────────────┘                                 └──────────────────────┘
        FastAPI + React(CRA)                                    FastAPI + React(Vite)
```

## 주요 기능

### 분석 플랫폼 (Analysis, `:8800`)
- **Splunk 상관탐지(notable) 수집** — REST API 연동
- **AI 자동 정·오탐 판정** — OpenRouter(LLM) 기반, *중복제거 + 배치 + 캐시*로 토큰 비용 절감
- **이벤트 분석 보고서** — HTML/PDF 자동 생성(Jinja2 + Chromium)
- **3D 위협 지구본** — 공격 출발지→관제센터 흐름 시각화(react-globe.gl)
- **CVE 매핑**(NVD) · **위협 인텔**(AbuseIPDB · OTX) · **위협 트렌드/인사이트**
- **정탐 자동 전달** — 판정된 정탐을 소통 플랫폼으로 push

### 소통 플랫폼 (Communication, `:8810`)
- **정탐 티켓 자동 수신**(ingest) 및 티켓/담당자/상태(SLA) 관리
- **이벤트 이력 · 코멘트 · 태스크 · IOC**
- **실시간 채팅(채널)·DM** — WebSocket
- **웹메일** — janus.com 사용자별 IMAP 수신 / SMTP 발송 / 회신(In-Reply-To 스레딩)

## 기술 스택
- **Backend**: Python, FastAPI, Uvicorn, SQLAlchemy, SQLite, WebSocket
- **Frontend**: React (분석=CRA / 소통=Vite), react-globe.gl
- **AI/외부연동**: OpenRouter(Gemini) LLM, Splunk REST, NVD/AbuseIPDB/OTX, IMAP/SMTP
- **보고서**: Jinja2 + Chromium(headless) PDF

## 폴더 구조
```
janus-soc-platform/
├─ analysis-platform/          # 분석 플랫폼 (:8800)
│  ├─ backend/                 # FastAPI (main.py, triage_service, gemini_service, splunk_client, ...)
│  ├─ frontend/                # React (CRA)
│  └─ .env.example
└─ comm-platform/              # 소통 플랫폼 (:8810)
   ├─ backend/                 # FastAPI (main.py, routers/, mail_gateway, ...)
   ├─ frontend/                # React (Vite)
   └─ .env.example
```

## 실행 방법

각 플랫폼(analysis / comm)에 대해 동일한 절차를 수행합니다. (아래는 분석 플랫폼 기준 — 소통은 포트 `8810`)

### 1) 백엔드
```bash
cd analysis-platform/backend
python -m venv .venv
# Windows: .venv\Scripts\activate   |   Linux/Mac: source .venv/bin/activate
pip install -r requirements.txt

cp ../.env.example ../.env          # .env 값 채우기 (Splunk·API 키 등)
uvicorn main:app --host 0.0.0.0 --port 8800     # 소통 플랫폼은 --port 8810
```

### 2) 프론트엔드 (백엔드가 정적 파일로 서빙)
```bash
cd analysis-platform/frontend
npm install
npm run build      # 분석=build/  ·  소통=dist/  를 백엔드가 서빙
```
→ 브라우저에서 `http://localhost:8800` (소통 `http://localhost:8810`) 접속

## 환경변수
`*/.env.example`를 복사해 `.env`로 만들고 값을 채우세요. 주요 항목:

| 플랫폼 | 키 | 설명 |
|---|---|---|
| 분석 | `SPLUNK_HOST/PORT/USERNAME/PASSWORD` | Splunk REST 연동 |
| 분석 | `GEMINI_API_KEY`, `GEMINI_MODEL` | OpenRouter(LLM) 판정·보고서 |
| 분석 | `ABUSEIPDB_API_KEY`, `OTX_API_KEY` | 위협 인텔(선택) |
| 분석 | `COMM_PLATFORM_URL` | 정탐 전달 대상(소통 플랫폼) |
| 분석 | `SOC_MOCK` | `true`면 목데이터로 오프라인 구동 |
| 소통 | `MAIL_GATEWAY_HOST`, `MAIL_IMAP_PORT`, `MAIL_SMTP_PORT` | 메일 게이트웨이 |

## 보안 주의
- **`.env`(시크릿)는 절대 커밋하지 마세요.** `.gitignore`에 제외되어 있으며, 저장소에는 값이 비워진 `.env.example`만 포함됩니다.
- AI 판정/보고서는 **OpenRouter(외부 API)** 를 사용합니다. 폐쇄망에서는 방화벽 허용 또는 **로컬 LLM** 적용이 필요합니다.
- 사용자 계정·메일 비밀번호가 담기는 런타임 DB(`storage/*.db`)도 커밋 대상에서 제외됩니다.

---
*본 저장소는 SOC 관제 실습/데모 목적의 프로젝트입니다.*

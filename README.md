# 🛡️ JANUS AI 보안관제(SOC) 통합 플랫폼

Splunk SIEM이 탐지한 보안 이벤트를 **AI(LLM)가 자동으로 정탐/오탐 판정**하고, **정탐만** 소통 플랫폼으로 전달해 관제 요원이 **티켓 기반으로 즉시 대응**하는 **보안관제(SOC) 실습·교육용 통합 플랫폼**입니다. **분석 플랫폼(:8800)** 과 **소통 플랫폼(:8810)** 으로 구성됩니다.

![Python](https://img.shields.io/badge/Python-3.11-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?logo=fastapi&logoColor=white)
![React](https://img.shields.io/badge/React-CRA%20/%20Vite-61DAFB?logo=react&logoColor=black)
![SQLite](https://img.shields.io/badge/SQLite-3-003B57?logo=sqlite&logoColor=white)
![Splunk](https://img.shields.io/badge/Splunk-SIEM-000000?logo=splunk&logoColor=white)
![LLM](https://img.shields.io/badge/LLM-OpenRouter%20/%20Gemini-412991?logo=openai&logoColor=white)
![License](https://img.shields.io/badge/Use-Educational%20Only-important)

---

## ⚠️ 중요 안내 (반드시 읽어주세요)

> 이 프로젝트는 **보안관제 교육·탐지 실습을 목적**으로 만들어진 데모 플랫폼입니다.
>
> - 🌐 AI 정·오탐 판정과 보고서 생성은 **외부 LLM API(OpenRouter)** 를 호출합니다. **탐지 로그·페이로드가 외부로 전송**되므로, 폐쇄망에서는 **방화벽 허용** 또는 **로컬 LLM** 적용이 필요합니다.
> - 🔐 저장소의 `.env`는 값이 비워진 **예시(`.env.example`)** 이며, API 키·메일 비밀번호 등은 **반드시 본인 값으로 교체**해야 합니다.
> - ✅ **격리된 로컬/폐쇄망 실습 환경**에서 사용하세요.
> - 🗄️ 사용자 계정·메일 비밀번호가 담기는 런타임 DB(`storage/*.db`)는 저장소에 포함되지 않습니다.

---

## 🏗️ 아키텍처 개요

```
 [보안 장비 / WAS 로그]
        │
        ▼
 ┌────────────────────┐   상관탐지(notable)
 │    Splunk SIEM      │  ─── REST API (8089) ───┐
 │  탐지 룰 · 대시보드   │                          │
 └────────────────────┘                          ▼
                                     ┌──────────────────────────────┐
                                     │   🔍 분석 플랫폼  ( :8800 )     │
                                     │  · AI 정·오탐 자동판정(LLM)      │
                                     │  · 이벤트 분석 보고서(HTML/PDF)  │
                                     │  · 위협 지구본 · CVE · 위협인텔   │
                                     └──────────────────────────────┘
                                                    │
                                    정탐만 전달 (POST /api/events/ingest)
                                                    ▼
                                     ┌──────────────────────────────┐
                                     │   💬 소통 플랫폼  ( :8810 )     │
                                     │  · 티켓 · 담당자 · 상태(SLA)     │
                                     │  · 실시간 채팅 · DM (WebSocket)  │
                                     │  · 웹메일 (IMAP 수신/SMTP 발송)  │
                                     └──────────────────────────────┘
```

- **분석 플랫폼**은 Splunk의 상관탐지 이벤트를 수집해 **LLM으로 정탐/오탐을 1차 판정**합니다. (중복제거 + 배치 + 캐시로 토큰 비용 절감)
- **정탐만** 소통 플랫폼으로 자동 전달(ingest)되어 **티켓**으로 생성됩니다.
- 관제 요원은 소통 플랫폼에서 **티켓 · 채팅 · 메일**로 대응을 이어갑니다.

---

## 🛠️ 기술 스택

| 구분 | 사용 기술 |
|------|-----------|
| Language | Python 3.11 |
| Backend | FastAPI 0.115, Uvicorn, Pydantic, SQLAlchemy |
| Frontend (분석) | React (Create React App), react-globe.gl / three.js, axios, react-markdown |
| Frontend (소통) | React (Vite), React Router, lucide-react |
| Database | SQLite (SQLAlchemy ORM) |
| AI / LLM | OpenRouter API (`google/gemini-2.5-flash`), json-repair |
| SIEM / 연동 | Splunk REST, NVD(CVE), AbuseIPDB · OTX(위협 인텔), IMAP/SMTP |
| 실시간 / 보고서 | WebSocket, Jinja2 + Chromium(headless) PDF 렌더 |

---

## ✨ 주요 기능

### 🔍 분석 플랫폼 (`:8800`)
- **Splunk 상관탐지(notable) 수집** — REST API 연동
- **AI 자동 정·오탐 판정** — 중복제거 + 배치 + 캐시로 신규 고유 경보만 LLM 호출(비용 절감)
- **이벤트 분석 보고서** — HTML/PDF 자동 생성(Jinja2 + Chromium)
- **3D 위협 지구본** — 공격 출발지 → 관제센터 흐름 시각화(react-globe.gl)
- **CVE 매핑**(NVD) · **위협 인텔**(AbuseIPDB · OTX) · **위협 트렌드/인사이트**
- **정탐 자동 전달** — 판정된 정탐을 소통 플랫폼으로 push

### 💬 소통 플랫폼 (`:8810`)
- **정탐 티켓 자동 수신**(ingest) 및 티켓 · 담당자 · 상태(SLA) 관리
- **이벤트 이력 · 코멘트 · 태스크 · IOC**
- **실시간 채팅(채널) · DM** — WebSocket
- **웹메일** — 사용자별 IMAP 수신 / SMTP 발송 / 회신(In-Reply-To 스레딩)

---

## 🔎 AI 정·오탐 판정 & 자동 전달 흐름 (SOC)

분석 플랫폼은 SIEM 상관탐지를 **행위·페이로드 기반으로 정탐/오탐 판정**하고, 정탐만 티켓화합니다.

| 단계 | 처리 | 설명 |
|------|------|------|
| 수집 | Splunk `notable` 조회 | 상관탐지 이벤트를 REST로 수집 |
| 그룹핑 | `dedup_key`(룰·출발지·시간) | "한 공격 = 한 인시던트"로 병합, 티켓 폭주 방지 |
| 판정 | LLM 배치 호출 | 신규 고유 그룹만 판정 → 캐시 재사용(비용↓) |
| 보정 | 결정적 규칙 | 명백한 공격 구문·DDoS 볼륨·심각 등급은 안전측(정탐) 보정 |
| 전달 | `/api/events/ingest` | **정탐만** 소통 플랫폼으로 전달(중복 전송 방지) |

> 대표 탐지 유형: SQL Injection · XSS(세션쿠키 탈취) · 웹셸 업로드 · 경로순회 · 인가우회 · 크리덴셜 스터핑 · DDoS 등

---

## 📂 프로젝트 구조

```
janus-soc-platform/
├── analysis-platform/          # 🔍 분석 플랫폼 (:8800)
│   ├── backend/                # FastAPI
│   │   ├── main.py             # 엔드포인트 · 백그라운드 자동판정 루프
│   │   ├── triage_service.py   # AI 정·오탐 판정(배치·캐시·보정)
│   │   ├── gemini_service.py   # LLM 호출 · 챗봇 · 보고서 프롬프트
│   │   ├── splunk_client.py    # Splunk REST 수집
│   │   ├── forwarder_service.py# 정탐 → 소통 전달
│   │   ├── cve_service.py / threat_intel_service.py / insights_service.py
│   │   └── report_templates/   # 이벤트 분석 보고서(HTML/CSS)
│   ├── frontend/               # React (CRA) — 대시보드 · 위협 지구본
│   └── .env.example
└── comm-platform/              # 💬 소통 플랫폼 (:8810)
    ├── backend/                # FastAPI
    │   ├── main.py  models.py  db.py
    │   ├── routers/            # events · chat · dm · mail · users · iocs ...
    │   ├── mail_gateway.py     # IMAP/SMTP 웹메일
    │   └── realtime.py         # WebSocket
    ├── frontend/               # React (Vite) — 티켓 · 채팅 · 메일 UI
    └── .env.example
```

---

## 🚀 실행 방법 (로컬 실습)

> 사전 요구: **Python 3.11+**, **Node.js**, (실데이터 시) **Splunk**, **OpenRouter API 키**
> 아래는 **분석 플랫폼** 기준 — 소통 플랫폼은 경로 `comm-platform`, 포트 `8810`으로 동일 진행

### 1) 환경변수 설정 (필수)
```bash
cp analysis-platform/.env.example analysis-platform/.env
#  SPLUNK_* · GEMINI_API_KEY(OpenRouter) 등 값 채우기
#  (Splunk 없이 체험만: .env 의 SOC_MOCK=true 로 목데이터 구동)
```

### 2) 백엔드
```bash
cd analysis-platform/backend
python -m venv .venv
# Windows: .venv\Scripts\activate   |   Linux/Mac: source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8800      # 소통 플랫폼은 --port 8810
```

### 3) 프론트엔드 (백엔드가 정적 서빙)
```bash
cd analysis-platform/frontend
npm install
npm run build       # 분석 = build/ · 소통 = dist/ 를 백엔드가 서빙
```
→ 브라우저에서 **http://localhost:8800** (소통 **http://localhost:8810**) 접속

---

## 🔒 저장소에서 제외되는 항목

`.gitignore`로 다음과 같은 민감·산출물 파일을 제외합니다.

- **시크릿**: `.env` (API 키·메일 비밀번호 등) — 저장소에는 값이 비워진 `.env.example`만 포함
- **런타임 데이터**: `storage/`, `*.db`(사용자·메일 DB), 업로드·생성 보고서(`pdf_reports/`, `uploads/`)
- **의존성/빌드**: `.venv/`, `node_modules/`, `build/`, `dist/`, `__pycache__/`
- IDE 설정, 로그(`*.log`), 임시 작업 스크립트

---

## 📜 라이선스 / 사용 범위

교육·학습 목적의 팀 실습 산출물입니다. AI 판정 시 **외부 API로 로그가 전송**되므로, **격리 실습 환경**에서만 사용하고 실제 운영 서비스 용도로 사용하지 마세요.

# SOC 분석 플랫폼

인트라넷 구간(10.0.200.0/24)에 배치되어 **Splunk ESM/IDS에서 보안 이벤트를 가져와
Gemini AI로 분석하고, PDF 공격 분석 보고서를 자동 생성**하는 플랫폼입니다.

```
인터넷 ─ DHCP라우터 ─ 방화벽 ─ IPS ─[intra-net 10.0.200.0/24]─ Splunk ESM(.201) / IDS(.200) / DB(.100)
                                              └── 분석 플랫폼 (이 프로젝트)
```

## 디렉토리 구조

```
my-soc-platform/
├── backend/            FastAPI 백엔드
│   ├── main.py             웹훅 수신 + API 라우팅 (사령탑)
│   ├── splunk_client.py    Splunk REST API 호출
│   ├── gemini_service.py   Gemini 프롬프트 조립/통신
│   ├── report_generator.py ReportLab PDF 생성
│   ├── config.py           .env 설정 로더
│   └── requirements.txt
├── frontend/           React 대시보드
│   ├── public/index.html
│   ├── src/App.js          메인 레이아웃
│   ├── src/GlobeComponent.js  3D 지구본(공격 시각화)
│   └── package.json
├── storage/pdf_reports/   생성된 PDF 보고서 저장소
└── .env.example
```

## 실행 방법

### 1) 백엔드
```powershell
cd backend
python -m venv .venv; .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy ..\.env.example ..\.env   # 값 채우기 (Splunk 자격증명, Gemini 키)
python main.py                 # http://0.0.0.0:8800
```

### 2) 프론트엔드
```powershell
cd frontend
npm install
npm start                      # http://localhost:3000 (8800으로 프록시)
```

## 주요 API

| 메서드 | 경로 | 설명 |
|--------|------|------|
| GET  | `/api/alerts`            | 최근 알림 목록 (대시보드) |
| POST | `/api/search`           | 임의 SPL 검색 |
| POST | `/api/analyze`          | 이벤트 AI 분석 + PDF 생성 |
| POST | `/webhook/splunk`       | Splunk alert action 수신 (자동 분석) |
| GET  | `/api/reports`          | 생성된 보고서 목록 |
| GET  | `/api/reports/{file}`   | PDF 다운로드 |

## Splunk 연동
`Settings > Alert actions > Webhook`에서 URL을
`http://<분석플랫폼IP>:8800/webhook/splunk` 로 지정하면
알림 발생 시 자동으로 분석·보고서가 생성됩니다.

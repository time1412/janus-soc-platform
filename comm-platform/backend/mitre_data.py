"""MITRE ATT&CK(Enterprise) 기법 데이터.

기본은 공식 STIX에서 생성한 mitre_enterprise.json(전체)을 사용하고,
파일이 없으면 아래 큐레이티드 핵심 목록으로 폴백한다. (생성: python build_mitre.py)
"""
import json
from pathlib import Path

# (id, 영문명, 전술, 한줄 설명) — 폴백용 핵심 목록
_RAW = [
    # 초기 침투 (Initial Access)
    ("T1190", "Exploit Public-Facing Application", "초기 침투", "공개된 웹/서비스 취약점 악용 (SQLi·RCE 등)"),
    ("T1133", "External Remote Services", "초기 침투", "VPN·RDP 등 외부 원격 서비스로 침투"),
    ("T1566", "Phishing", "초기 침투", "피싱 메일/링크/첨부로 초기 접근 획득"),
    ("T1078", "Valid Accounts", "초기 침투", "유효한(탈취된) 계정으로 정상 접근 위장"),
    ("T1189", "Drive-by Compromise", "초기 침투", "악성 웹사이트 방문만으로 감염"),
    ("T1195", "Supply Chain Compromise", "초기 침투", "공급망(SW·업데이트) 변조로 침투"),
    # 실행 (Execution)
    ("T1059", "Command and Scripting Interpreter", "실행", "셸/스크립트 인터프리터로 명령 실행"),
    ("T1059.001", "PowerShell", "실행", "PowerShell을 통한 명령·스크립트 실행"),
    ("T1059.004", "Unix Shell", "실행", "bash/sh 등 유닉스 셸 명령 실행"),
    ("T1203", "Exploitation for Client Execution", "실행", "클라이언트 SW 취약점 악용 코드 실행"),
    ("T1204", "User Execution", "실행", "사용자가 악성 파일·링크 직접 실행"),
    ("T1053", "Scheduled Task/Job", "실행", "예약 작업(cron/스케줄러)으로 실행·지속"),
    # 지속 (Persistence)
    ("T1505.003", "Web Shell", "지속", "웹서버에 웹셸 설치해 지속 접근"),
    ("T1098", "Account Manipulation", "지속", "계정 권한·자격 변경으로 접근 유지"),
    ("T1136", "Create Account", "지속", "백도어용 신규 계정 생성"),
    ("T1547", "Boot or Logon Autostart Execution", "지속", "부팅/로그온 자동 실행 등록"),
    # 권한 상승 (Privilege Escalation)
    ("T1068", "Exploitation for Privilege Escalation", "권한 상승", "취약점 악용으로 권한 상승"),
    ("T1548", "Abuse Elevation Control Mechanism", "권한 상승", "sudo·UAC 등 권한 통제 우회"),
    # 방어 회피 (Defense Evasion)
    ("T1070", "Indicator Removal", "방어 회피", "로그·흔적 삭제로 탐지 회피"),
    ("T1027", "Obfuscated Files or Information", "방어 회피", "난독화·인코딩으로 탐지 우회"),
    ("T1562", "Impair Defenses", "방어 회피", "보안 솔루션·로깅 비활성화"),
    ("T1055", "Process Injection", "방어 회피", "정상 프로세스에 코드 주입"),
    ("T1140", "Deobfuscate/Decode Files", "방어 회피", "숨긴 페이로드 복호화/디코딩"),
    # 자격 증명 접근 (Credential Access)
    ("T1110", "Brute Force", "자격 증명 접근", "무차별 대입으로 로그인 자격 탈취"),
    ("T1110.001", "Password Guessing", "자격 증명 접근", "흔한 비밀번호 추측 로그인 시도"),
    ("T1003", "OS Credential Dumping", "자격 증명 접근", "OS 자격증명(해시·LSASS 등) 덤프"),
    ("T1555", "Credentials from Password Stores", "자격 증명 접근", "브라우저·키체인 등 저장 암호 탈취"),
    ("T1212", "Exploitation for Credential Access", "자격 증명 접근", "취약점 악용으로 자격증명 획득"),
    ("T1056", "Input Capture", "자격 증명 접근", "키로깅 등 입력 캡처로 자격 탈취"),
    # 탐색 (Discovery)
    ("T1083", "File and Directory Discovery", "탐색", "파일·디렉터리 탐색 (경로 순회 등)"),
    ("T1087", "Account Discovery", "탐색", "계정 목록·정보 수집"),
    ("T1046", "Network Service Discovery", "탐색", "포트스캔 등 네트워크 서비스 탐색"),
    ("T1018", "Remote System Discovery", "탐색", "내부 원격 시스템 식별"),
    ("T1082", "System Information Discovery", "탐색", "OS·호스트 정보 수집"),
    ("T1057", "Process Discovery", "탐색", "실행 중 프로세스 목록 수집"),
    # 내부 확산 (Lateral Movement)
    ("T1021", "Remote Services", "내부 확산", "RDP·SMB·SSH로 내부 이동"),
    ("T1021.001", "Remote Desktop Protocol", "내부 확산", "RDP로 원격 호스트 이동"),
    ("T1021.004", "SSH", "내부 확산", "SSH로 원격 호스트 이동"),
    ("T1570", "Lateral Tool Transfer", "내부 확산", "내부망으로 도구 전송·배포"),
    # 수집 (Collection)
    ("T1005", "Data from Local System", "수집", "로컬 시스템에서 데이터 수집 (/etc/passwd 등)"),
    ("T1039", "Data from Network Shared Drive", "수집", "공유 드라이브에서 데이터 수집"),
    ("T1113", "Screen Capture", "수집", "화면 캡처로 정보 수집"),
    # 명령 제어 (Command and Control)
    ("T1071", "Application Layer Protocol", "명령 제어", "정상 프로토콜로 C2 통신 위장"),
    ("T1071.001", "Web Protocols", "명령 제어", "HTTP/HTTPS로 C2 통신"),
    ("T1105", "Ingress Tool Transfer", "명령 제어", "외부에서 도구·페이로드 다운로드"),
    ("T1090", "Proxy", "명령 제어", "프록시 경유로 출처 은닉"),
    ("T1573", "Encrypted Channel", "명령 제어", "암호화 채널로 C2 트래픽 은닉"),
    # 유출 (Exfiltration)
    ("T1041", "Exfiltration Over C2 Channel", "유출", "C2 채널로 데이터 유출"),
    ("T1048", "Exfiltration Over Alternative Protocol", "유출", "대체 프로토콜(DNS 등)로 유출"),
    ("T1567", "Exfiltration Over Web Service", "유출", "웹서비스(클라우드 등) 통한 유출"),
    # 임팩트 (Impact)
    ("T1486", "Data Encrypted for Impact", "임팩트", "랜섬웨어 데이터 암호화"),
    ("T1490", "Inhibit System Recovery", "임팩트", "백업·복구 차단"),
    ("T1498", "Network Denial of Service", "임팩트", "네트워크 DoS 공격"),
    ("T1499", "Endpoint Denial of Service", "임팩트", "엔드포인트 DoS 공격"),
    ("T1485", "Data Destruction", "임팩트", "데이터 파괴"),
]

_CURATED_TACTICS = ["초기 침투", "실행", "지속", "권한 상승", "방어 회피", "자격 증명 접근",
                    "탐색", "내부 확산", "수집", "명령 제어", "유출", "임팩트"]


def _url(tid: str) -> str:
    return "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"


_FILE = Path(__file__).resolve().parent / "mitre_enterprise.json"
if _FILE.exists():
    _d = json.loads(_FILE.read_text(encoding="utf-8"))
    TECHNIQUES = _d["techniques"]
    TACTICS = _d.get("tactics") or _CURATED_TACTICS
else:
    TACTICS = _CURATED_TACTICS
    TECHNIQUES = [
        {"id": tid, "name": name, "tactic": tactic, "tactics": [tactic], "desc": desc, "url": _url(tid)}
        for (tid, name, tactic, desc) in _RAW
    ]

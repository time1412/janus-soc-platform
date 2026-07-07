"""MITRE ATT&CK Enterprise 공식 STIX → 컴팩트 JSON 생성.

실행: python build_mitre.py
결과: mitre_enterprise.json (id·이름·전술·설명·URL, 폐기/철회 제외)
폐쇄망이면 enterprise-attack.json을 한 번 받아 같이 올린 뒤 LOCAL_PATH로 돌려도 됨.
"""
import json
import re
from pathlib import Path

import requests

URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
OUT = Path(__file__).resolve().parent / "mitre_enterprise.json"

TACTIC_KO = {
    "reconnaissance": "정찰", "resource-development": "자원 개발", "initial-access": "초기 침투",
    "execution": "실행", "persistence": "지속", "privilege-escalation": "권한 상승",
    "defense-evasion": "방어 회피", "credential-access": "자격 증명 접근", "discovery": "탐색",
    "lateral-movement": "내부 확산", "collection": "수집", "command-and-control": "명령 제어",
    "exfiltration": "유출", "impact": "임팩트",
}
ORDER = list(TACTIC_KO.keys())


def clean(s: str) -> str:
    s = re.sub(r"\(Citation:[^)]*\)", "", s or "")
    s = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", s)   # 마크다운 링크 → 텍스트
    s = re.sub(r"<code>|</code>", "", s)
    s = re.sub(r"\s+", " ", s).strip()
    return (s[:200] + "…") if len(s) > 200 else s


def main() -> None:
    print("다운로드 중...", URL)
    data = requests.get(URL, timeout=180).json()
    techs = []
    for obj in data.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        ext = next((r for r in obj.get("external_references", []) if r.get("source_name") == "mitre-attack"), None)
        if not ext or not ext.get("external_id"):
            continue
        tid = ext["external_id"]
        phases = [p["phase_name"] for p in obj.get("kill_chain_phases", []) if p.get("kill_chain_name") == "mitre-attack"]
        tactics = [TACTIC_KO.get(p, p) for p in phases]
        techs.append({
            "id": tid,
            "name": obj.get("name", ""),
            "tactics": tactics,
            "tactic": ", ".join(tactics),
            "desc": clean(obj.get("description", "")),
            "url": ext.get("url") or ("https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"),
            "sub": bool(obj.get("x_mitre_is_subtechnique")),
        })

    def sort_key(t):
        idxs = [ORDER.index(p) for p in TACTIC_KO if TACTIC_KO[p] in t["tactics"]]
        return (min(idxs) if idxs else 99, t["id"])

    techs.sort(key=sort_key)
    OUT.write_text(json.dumps({"techniques": techs, "tactics": list(TACTIC_KO.values())},
                              ensure_ascii=False), encoding="utf-8")
    subs = sum(1 for t in techs if t["sub"])
    print(f"완료: 총 {len(techs)}개 (기법 {len(techs)-subs} + 하위기법 {subs}) → {OUT.name}")


if __name__ == "__main__":
    main()

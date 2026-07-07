# -*- coding: utf-8 -*-
"""상관룰/탐지 이벤트 → 이벤트 분석 보고서 템플릿 변수로 정규화.

- severity → CSS 클래스(severity-high/med/low)
- mitre(T-ID) → 킬체인 단계(mitre_map.json 룩업, 순서 정렬, 마지막=active)
- 공격 유형 → 대응 액션(P1~P3) 룩업
- 동일 출발지 IP 이벤트 그룹핑 → 연계 배너
"""
import json
import re
from datetime import datetime
from pathlib import Path

from markupsafe import Markup, escape

_DIR = Path(__file__).parent / "report_templates"
_MITRE: dict = json.loads((_DIR / "mitre_map.json").read_text(encoding="utf-8"))

_SEV = {"3": ("severity-high", "HIGH"), "2": ("severity-med", "MED"), "1": ("severity-low", "LOW")}
_TID_RE = re.compile(r"T\d{4}(?:\.\d{3})?")


def _sev(ev: dict) -> str:
    return str(ev.get("severity") or "1")


def _tids(mitre) -> list[str]:
    return _TID_RE.findall(str(mitre or ""))


def _fmt_time(v) -> str:
    s = str(v or "")[:19].replace("T", " ")
    return s or "-"


def _mono(s) -> Markup:
    return Markup(f'<span class="mono">{escape(s)}</span>')


def _inline_md(t: str) -> str:
    """인라인 마크다운(**bold**, `code`) → HTML(이스케이프 후)."""
    s = str(escape(t))
    s = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", s)
    s = re.sub(r"`([^`]+)`", r"<code>\1</code>", s)
    return s


def _md_to_html(md: str | None) -> Markup:
    """LLM 마크다운 분석 → 보고서용 HTML(헤더/불릿/굵게/코드)."""
    if not md:
        return Markup("")
    out: list[str] = []
    in_ul = False
    for raw in str(md).split("\n"):
        s = raw.strip()
        if not s or s == "---":
            if in_ul:
                out.append("</ul>"); in_ul = False
            continue
        h = re.match(r"^#{1,6}\s+(.*)$", s)
        if h:
            if in_ul:
                out.append("</ul>"); in_ul = False
            out.append(f"<h3>{_inline_md(h.group(1))}</h3>")
            continue
        b = re.match(r"^[-*]\s+(.*)$", s)
        if b:
            if not in_ul:
                out.append("<ul>"); in_ul = True
            out.append(f"<li>{_inline_md(b.group(1))}</li>")
            continue
        if in_ul:
            out.append("</ul>"); in_ul = False
        out.append(f"<p>{_inline_md(s)}</p>")
    if in_ul:
        out.append("</ul>")
    return Markup("".join(out))


def _killchain(primary: dict) -> list[dict]:
    """대표 이벤트의 MITRE를 '룰이 나열한 순서(=공격 진행 순서)' 그대로 단계화.
    마지막(도달) 단계를 active로 표시. 룩업에 없는 T-ID는 ID를 그대로 표기."""
    stages, seen = [], set()
    for tid in _tids(primary.get("mitre")):
        if tid in seen:
            continue
        seen.add(tid)
        info = _MITRE.get(tid)
        stages.append({"tid": tid, "name": info["name"] if info else tid})
    for i, s in enumerate(stages):
        s["active"] = (i == len(stages) - 1)
    return stages


def _act(cls: str, label: str, text) -> dict:
    return {"prio_class": cls, "prio_label": label, "text": text}


def _actions(primary: dict, src_ip: str) -> list[dict]:
    """공격 유형 기반 대응 액션(P1~P3). 출발지 IP는 모노스페이스로 강조."""
    blob = " ".join(str(primary.get(k) or "") for k in
                    ("ai_attack_type", "signature", "rule_title", "mitre")).lower()
    ip_html = Markup(f'<span class="mono">{escape(src_ip)}</span>') if src_ip else "출발지 IP"

    def has(*ks):
        return any(k in blob for k in ks)

    if has("ddos", "dos", "flood", "denial", "가용성", "t1498", "t1499"):
        return [_act("prio-p1", "P1", "출발지 대역 차단 · 레이트리밋 적용"),
                _act("prio-p2", "P2", "트래픽 패턴 · 증폭 출처 분석"),
                _act("prio-p3", "P3", "가용성 모니터링 · 자동확장 정책 점검")]
    if has("stuffing", "brute", "credential", "스터핑", "브루트", "계정탈취", "t1110"):
        return [_act("prio-p1", "P1", "대상 계정 잠금 · MFA 강제"),
                _act("prio-p2", "P2", "로그인 시도 로그 · 성공 IP 확인"),
                _act("prio-p3", "P3", "비밀번호 정책 · 이상로그인 탐지 점검")]
    if has("ransom", "랜섬", "t1486"):
        return [_act("prio-p1", "P1", "감염 호스트 즉시 격리"),
                _act("prio-p2", "P2", "백업 무결성 확인 · 확산 차단"),
                _act("prio-p3", "P3", "EDR 풀스캔 · 복구 절차 가동")]
    # 웹 공격(웹셸·SQLi·XSS·RCE·LFI·업로드·복합 웹) — 호스트보다 먼저 판정
    if has("sql", "xss", "웹", "web", "업로드", "upload", "웹셸", "웹쉘", "webshell",
           "경로순회", "traversal", "lfi", "rfi", "복합 웹", "킬체인", "killchain",
           "csrf", "t1190", "t1505", "t1059.007"):
        return [_act("prio-p1", "P1", Markup("출발지 IP ") + ip_html + Markup(" 차단")),
                _act("prio-p2", "P2", "대상 서버 웹로그 · 명령 실행 이력 확인"),
                _act("prio-p3", "P3", "웹 애플리케이션 취약점 점검(업로드 · 입력검증)")]
    # 호스트/엔드포인트 공격(권한상승·지속성·C2·리버스셸)
    if has("privesc", "권한상승", "persist", "지속성", "c2", "리버스", "reverse", "backdoor",
           "백도어", "t1068", "t1053", "t1571", "t1003"):
        return [_act("prio-p1", "P1", "해당 호스트 네트워크 격리"),
                _act("prio-p2", "P2", "프로세스 · 지속성 항목 · 외부연결 조사"),
                _act("prio-p3", "P3", "EDR 풀스캔 · 자격증명 회수")]
    # 기본: 출발지 차단 + 로그 확인 + 점검
    return [_act("prio-p1", "P1", Markup("출발지 IP ") + ip_html + Markup(" 차단")),
            _act("prio-p2", "P2", "대상 서버 웹로그 · 명령 실행 이력 확인"),
            _act("prio-p3", "P3", "웹 애플리케이션 취약점 점검(업로드 · 입력검증)")]


def _related(events: list[dict], primary: dict) -> list[Markup]:
    """동일 출발지 IP의 다른 이벤트 → 연계 배너 메시지."""
    src = str(primary.get("src_ip") or "")
    if not src:
        return []
    pid = id(primary)
    out: list[Markup] = []
    seen_rules: set = set()
    for ev in events:
        if id(ev) == pid or str(ev.get("src_ip") or "") != src:
            continue
        rid = str(ev.get("rule_id") or ev.get("signature") or "")
        if rid in seen_rules:
            continue
        seen_rules.add(rid)
        _, sev_txt = _SEV.get(_sev(ev), ("", "LOW"))
        name = str(ev.get("rule_title") or ev.get("signature") or "관련 탐지")
        meta = f"({ev.get('rule_id') or '-'}, {sev_txt})"
        when = _fmt_time(ev.get("_time") or ev.get("Time"))[11:16] or _fmt_time(ev.get("_time"))
        out.append(Markup(
            f'동일 출발지 <span class="mono">{escape(src)}</span> 에서 '
            f'{escape(name)} {escape(meta)} {escape(when)} 선행 탐지 '
            f'— 단일 캠페인으로 상관 분석 권장'))
        if len(out) >= 2:
            break
    return out


def build_context(events: list[dict], title: str | None = None,
                  analysis: str | None = None, doc_no: str | None = None) -> dict:
    """이벤트 목록 → 템플릿 컨텍스트. 최고 위험도 이벤트를 대표로 삼는다."""
    events = [e for e in (events or []) if isinstance(e, dict)]
    if not events:
        raise ValueError("이벤트가 없습니다.")
    primary = max(events, key=lambda e: int(_sev(e)) if _sev(e).isdigit() else 0)

    sev_class, sev_text = _SEV.get(_sev(primary), ("severity-low", "LOW"))
    kc = _killchain(primary)
    sub = " → ".join(s["name"] for s in kc) if kc else \
        str(primary.get("ai_attack_type") or primary.get("signature") or "")

    src_ip = str(primary.get("src_ip") or primary.get("asset") or "-")
    dst = str(primary.get("dest_ip") or "-")
    if dst != "-" and primary.get("dest_port"):
        dst = f"{dst}:{primary['dest_port']}"
    if primary.get("src_port") and src_ip not in ("-", ""):
        src_ip = f"{src_ip}:{primary['src_port']}"

    # 반복 탐지: 병합/중복 건수 + (가능하면) 시간 폭
    count = max(int(primary.get("merged_count") or 0),
                int(primary.get("dup_count") or 0), len(events), 1)
    window = ""
    times = sorted(_fmt_time(e.get("_time") or e.get("Time")) for e in events
                   if (e.get("_time") or e.get("Time")))
    if len(times) >= 2 and times[0] != "-":
        try:
            t0 = datetime.fromisoformat(times[0]); t1 = datetime.fromisoformat(times[-1])
            mins = int((t1 - t0).total_seconds() // 60)
            if mins > 0:
                window = f"{mins}분"
        except Exception:
            window = ""

    uri = str(primary.get("uri") or "").strip()
    payload = str(primary.get("payload") or "").strip()
    if uri:
        target_path, target_label = uri[:48], "in URI"
    elif payload:
        target_path, target_label = payload[:48], "in payload"
    else:
        target_path, target_label = "-", ""

    # ── 상세 데이터 ──
    when = _fmt_time(primary.get("_time") or primary.get("Time"))
    verdict = str(primary.get("ai_verdict") or "").strip()
    conf = primary.get("ai_confidence")
    conf_s = f"{conf}%" if conf not in (None, "", 0, "0") else "-"
    asset_v = _mono(primary.get("asset")) if primary.get("asset") else escape("-")
    detail_rows = [
        {"k": "시그니처",  "v": escape(primary.get("signature") or primary.get("rule_title") or "-")},
        {"k": "탐지 룰",   "v": _mono(primary.get("rule_id") or "-")},
        {"k": "탐지원",    "v": escape(primary.get("source") or primary.get("source_type") or "-")},
        {"k": "탐지 시각", "v": escape(when)},
        {"k": "출발지",    "v": _mono(src_ip)},
        {"k": "목적지",    "v": _mono(dst)},
        {"k": "영향 자산", "v": asset_v},
        {"k": "AI 판정",   "v": escape(verdict or "-")},
        {"k": "신뢰도",    "v": escape(conf_s)},
        {"k": "위험도",    "v": escape(f"{sev_text} (severity {_sev(primary)})")},
        {"k": "MITRE",    "v": _mono(primary.get("mitre") or "-")},
        {"k": "반복 탐지", "v": escape(f"{count}회")},
    ]
    # 킬체인 단계 상세(전술 포함)
    kc_detail, seen_t = [], set()
    for tid in _tids(primary.get("mitre")):
        if tid in seen_t:
            continue
        seen_t.add(tid)
        info = _MITRE.get(tid)
        kc_detail.append({"tid": tid, "name": info["name"] if info else tid,
                          "tactic": info["tactic"] if info else "-"})
    # 증적(기여 이벤트 raw)
    ev_raw = primary.get("evidence") if isinstance(primary.get("evidence"), list) else []
    evidence: list[str] = []
    for e in ev_raw[:6]:
        if not isinstance(e, dict):
            continue
        t = _fmt_time(e.get("time") or e.get("_time"))
        sig = str(e.get("signature") or "")
        body = str(e.get("request_raw") or e.get("raw") or "").strip().replace("\n", " ")[:170]
        line = " · ".join(x for x in [t if t != "-" else "", sig, body] if x)
        if line:
            evidence.append(line)
    if not evidence and str(primary.get("body") or "").strip():
        evidence = [str(primary.get("body")).strip()[:400]]
    reasoning = str(primary.get("ai_reasoning") or "").strip()
    payload_full = str(primary.get("payload") or "").strip()[:800]

    return {
        "title": title or "이벤트 분석 보고서",
        "doc_no": doc_no or f"SOC-IR-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "severity_class": sev_class,
        "severity_text": sev_text,
        "banner_title": str(primary.get("rule_title") or primary.get("signature") or "탐지 이벤트"),
        "banner_sub": sub,
        "rule_id": str(primary.get("rule_id") or primary.get("source") or "-"),
        "when": _fmt_time(primary.get("_time") or primary.get("Time")),
        "flow_src": src_ip,
        "flow_dst": dst,
        "repeat_count": count,
        "repeat_window": window,
        "target_path": target_path,
        "target_label": target_label,
        "killchain": kc,
        "actions": _actions(primary, str(primary.get("src_ip") or "")),
        "related": _related(events, primary),
        "detail_rows": detail_rows,
        "payload": payload_full,
        "reasoning": reasoning,
        "killchain_detail": kc_detail,
        "evidence": evidence,
        "analysis_html": _md_to_html(analysis),
    }

import React, { useMemo, useEffect, useState } from "react";
import CrisisGauge from "./CrisisGauge";

// 시그니처 → 대표 공격유형 정규화
function normType(sig) {
  const s = (sig || "").toLowerCase();
  if (s.includes("sql")) return "SQL Injection";
  if (s.includes("xss") || s.includes("script")) return "XSS";
  if (s.includes("rce") || s.includes("command")) return "RCE";
  if (s.includes("webshell") || s.includes("upload")) return "웹쉘/업로드";
  if (s.includes("traversal") || s.includes("lfi") || s.includes("passwd")) return "경로조작/LFI";
  if (s.includes("ddos") || s.includes("flood")) return "DDoS";
  if (s.includes("scan") || s.includes("recon") || s.includes("nmap")) return "포트스캔";
  if (s.includes("php")) return "PHP Injection";
  if (s.includes("anomaly")) return "이상징후";
  if (s.includes("session")) return "세션";
  return sig || "기타";
}

export default function ThreatTodayPanel({ alerts }) {
  const [open, setOpen] = React.useState(true);
  // 24h 전체 집계(head 100 제한 없음). 실패 시 표시중 alerts로 폴백.
  const [rows, setRows] = useState(null);
  useEffect(() => {
    let alive = true;
    const load = () =>
      fetch("/api/alerts/summary")
        .then((r) => (r.ok ? r.json() : null))
        .then((d) => { if (alive && d) setRows(d.rows || []); })
        .catch(() => {});
    load();
    const t = setInterval(load, 30000);
    return () => { alive = false; clearInterval(t); };
  }, []);

  const stat = useMemo(() => {
    let total = 0, high = 0, mid = 0, low = 0;
    const types = {};
    if (rows) {
      // 전체 24h 집계: count 가중치로 합산
      rows.forEach((x) => {
        const c = Number(x.count) || 0;
        const sev = Number(x.severity) || 0;
        total += c;
        if (sev >= 3) high += c;
        else if (sev >= 2) mid += c;
        else low += c;
        const t = normType(x.signature);
        types[t] = (types[t] || 0) + c;
      });
    } else {
      // 폴백: 표시중 알림(최대 100건)
      const a = alerts || [];
      total = a.length;
      a.forEach((x) => {
        const sev = Number(x.severity) || 0;
        if (sev >= 3) high++;
        else if (sev >= 2) mid++;
        else low++;
        const t = normType(x.signature || x.sourcetype);
        types[t] = (types[t] || 0) + 1;
      });
    }
    const top = Object.entries(types).sort((p, q) => q[1] - p[1]).slice(0, 4);
    return { total, high, mid, low, top };
  }, [rows, alerts]);

  return (
    <div className={"dash-card threat-card" + (open ? "" : " is-collapsed")}>
      <div className="dash-card-head" onClick={() => setOpen((o) => !o)}>
        <span>금일 위협 현황</span>
        <span className="card-meta">
          <span className="dash-sub">최근 24h</span>
          <span className="card-chevron">▼</span>
        </span>
      </div>
      <div className="card-collapse"><div className="card-collapse-in">
      <div className="threat-row">
      <div className="threat-body">
        <div className="threat-total">
          <div className="threat-total-num">{stat.total}</div>
          <div className="threat-total-label">탐지 이벤트</div>
        </div>
        <div className="threat-sev">
          <div className="tsev tsev-h"><b>{stat.high}</b><span>고위험</span></div>
          <div className="tsev tsev-m"><b>{stat.mid}</b><span>주의</span></div>
          <div className="tsev tsev-l"><b>{stat.low}</b><span>낮음</span></div>
        </div>
        <div className="threat-types">
          <div className="threat-types-h">상위 공격 유형</div>
          {stat.top.map(([t, c]) => (
            <div key={t} className="ttype">
              <span className="ttype-label">{t}</span>
              <span className="ttype-cnt">{c}</span>
            </div>
          ))}
          {stat.top.length === 0 && <div className="dash-empty">데이터 없음</div>}
        </div>
      </div>
      <div className="threat-gauge"><CrisisGauge /></div>
      </div>
      </div></div>
    </div>
  );
}

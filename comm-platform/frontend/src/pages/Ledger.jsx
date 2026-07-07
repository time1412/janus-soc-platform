import React, { useEffect, useState } from "react";
import { Download, Search, ClipboardList } from "lucide-react";
import { api } from "../api.js";
import Badge from "../components/Badge.jsx";
import EmptyState from "../components/EmptyState.jsx";

const STATUSES = ["미접수", "접수", "검토", "대응", "승인대기", "오탐요청", "무시종결요청", "종결", "오탐종결", "무시종결"];
const STATUS_COLOR = {
  미접수: "#5b6b7a", 접수: "#2563eb", 검토: "#0891b2", 대응: "#c2740a", 승인대기: "#7c3aed",
  오탐요청: "#b08900", 무시종결요청: "#8a6d1f", 종결: "#15a34a", 오탐종결: "#0f9d8e", 무시종결: "#7a828c",
};
const PRIO_COLOR = { P1: "#dc2626", P2: "#c2740a", P3: "#2563eb", P4: "#7a828c" };

export default function Ledger() {
  const [rows, setRows] = useState([]);
  const [count, setCount] = useState(0);
  const [fStatus, setFStatus] = useState("");
  const [q, setQ] = useState("");
  const [srcIp, setSrcIp] = useState("");
  const [dateFrom, setDateFrom] = useState("");
  const [dateTo, setDateTo] = useState("");

  const buildParams = () => {
    const p = new URLSearchParams();
    if (fStatus) p.set("status", fStatus);
    if (q) p.set("q", q);
    if (srcIp) p.set("src_ip", srcIp);
    if (dateFrom) p.set("date_from", dateFrom);
    if (dateTo) p.set("date_to", dateTo);
    return p;
  };

  const load = () => {
    api(`/api/ledger?${buildParams()}`).then((d) => { setRows(d.rows); setCount(d.count); }).catch(() => {});
  };

  useEffect(() => { load(); }, [fStatus, dateFrom, dateTo]);

  const reset = () => { setFStatus(""); setQ(""); setSrcIp(""); setDateFrom(""); setDateTo(""); };
  const exportCsv = () => window.open(`/api/ledger/export?${buildParams()}`, "_blank");

  return (
    <div>
      <div className="page-head-row">
        <div>
          <h2 className="page-title">탐지이력 관리대장</h2>
          <p className="page-sub">모든 탐지 이벤트의 처리 내역(AI 판정 · 인간 결정 · 담당자 · 조치)을 기록·보관합니다.</p>
        </div>
        <button className="btn" onClick={exportCsv}><Download size={16} />CSV 내보내기</button>
      </div>

      <div className="search-panel">
        <div className="filter-bar" style={{ marginBottom: 10 }}>
          <button className={"chip" + (fStatus === "" ? " on" : "")} onClick={() => setFStatus("")}>전체</button>
          {STATUSES.map((s) => <button key={s} className={"chip" + (fStatus === s ? " on" : "")} onClick={() => setFStatus(s)}>{s}</button>)}
          <span className="ledger-count">총 {count}건</span>
        </div>
        <div className="search-row">
          <div className="search-field">
            <label>검색어</label>
            <input value={q} placeholder="시그니처/IP/URI" onChange={(e) => setQ(e.target.value)} onKeyDown={(e) => e.key === "Enter" && load()} />
          </div>
          <div className="search-field">
            <label>출발지 IP</label>
            <input value={srcIp} placeholder="예: 10.44.44.44" onChange={(e) => setSrcIp(e.target.value)} onKeyDown={(e) => e.key === "Enter" && load()} />
          </div>
          <div className="search-field">
            <label>시작일</label>
            <input type="date" value={dateFrom} onChange={(e) => setDateFrom(e.target.value)} />
          </div>
          <div className="search-field">
            <label>종료일</label>
            <input type="date" value={dateTo} onChange={(e) => setDateTo(e.target.value)} />
          </div>
          <button className="btn" onClick={load}><Search size={15} />검색</button>
          <button className="btn-ghost search-reset" onClick={reset}>초기화</button>
        </div>
      </div>

      <div className="card" style={{ padding: 6, overflowX: "auto" }}>
        <table className="tbl ledger-tbl">
          <thead>
            <tr>
              <th>티켓번호</th><th>우선</th><th>탐지일시</th><th>시그니처</th><th>공격유형</th><th>출발지</th>
              <th>위험도</th><th>AI</th><th>상태</th><th>종결코드</th><th>담당자</th><th>결정일시</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.id}>
                <td className="mono dim nowrap">{r.ticket_no || `#${r.id}`}</td>
                <td><Badge color={PRIO_COLOR[r.priority]} dot={false}>{r.priority}</Badge></td>
                <td className="dim nowrap">{(r.detected_at || "").replace("T", " ").slice(0, 16)}</td>
                <td>{r.signature}{r.dup_count > 1 && <span className="dup">×{r.dup_count}</span>}</td>
                <td>{r.attack_type}</td>
                <td className="mono">{r.src_ip || (r.asset ? `🖥 ${r.asset}` : "-")}</td>
                <td className="nowrap">{r.severity}</td>
                <td className="dim nowrap">{r.ai_verdict} {r.ai_confidence}%</td>
                <td><Badge color={STATUS_COLOR[r.status]}>{r.status}</Badge></td>
                <td className="dim">{r.resolution_code || "-"}</td>
                <td>{r.assignee || "-"}</td>
                <td className="dim nowrap">{r.decided_at ? r.decided_at.replace("T", " ").slice(0, 16) : "-"}</td>
              </tr>
            ))}
            {rows.length === 0 && <tr><td colSpan={12}><EmptyState icon={ClipboardList} title="기록이 없습니다" desc="조건에 맞는 탐지 이력이 없습니다. 필터를 조정해 보세요." /></td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  );
}

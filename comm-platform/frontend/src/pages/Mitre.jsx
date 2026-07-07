import React, { useEffect, useState } from "react";
import { Search, Copy, Crosshair } from "lucide-react";
import { api } from "../api.js";
import EmptyState from "../components/EmptyState.jsx";

const TACTIC_COLOR = {
  "정찰": "#0891b2", "자원 개발": "#0e7490", "초기 침투": "#dc2626", "실행": "#c2740a",
  "지속": "#7c5cd6", "권한 상승": "#d6457c", "방어 회피": "#5b6b7a", "자격 증명 접근": "#2563eb",
  "탐색": "#0891b2", "내부 확산": "#0f9d6b", "수집": "#7a828c", "명령 제어": "#9333ea",
  "유출": "#b45309", "임팩트": "#dc2626",
};

export default function Mitre() {
  const [data, setData] = useState({ techniques: [], tactics: [] });
  const [q, setQ] = useState("");
  const [tactic, setTactic] = useState("");
  const [copied, setCopied] = useState("");

  useEffect(() => { api("/api/mitre").then(setData).catch(() => {}); }, []);

  const filtered = data.techniques.filter((t) =>
    (!tactic || (t.tactics || [t.tactic]).includes(tactic)) &&
    (!q || `${t.id} ${t.name} ${t.desc}`.toLowerCase().includes(q.toLowerCase()))
  );

  const copy = (id) => { navigator.clipboard?.writeText(id); setCopied(id); setTimeout(() => setCopied(""), 1200); };

  return (
    <div>
      <h2 className="page-title">MITRE ATT&CK 조회</h2>
      <p className="page-sub">탐지한 행위를 표준 기법 번호(T####)에 매핑할 때 참고하세요. 번호는 복사해 티켓의 MITRE 칸에 붙여넣을 수 있습니다.</p>

      <div className="search-panel">
        <div className="filter-bar" style={{ marginBottom: 10 }}>
          <button className={"chip" + (tactic === "" ? " on" : "")} onClick={() => setTactic("")}>전체 전술</button>
          {data.tactics.map((t) => <button key={t} className={"chip" + (tactic === t ? " on" : "")} onClick={() => setTactic(t)}>{t}</button>)}
        </div>
        <div className="search-row">
          <div className="search-field" style={{ flex: 1 }}>
            <label>검색</label>
            <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="번호·이름·설명 (예: T1190, brute, 웹)" />
          </div>
          <span className="ledger-count">{filtered.length} / {data.count || data.techniques.length}건</span>
        </div>
      </div>

      <div className="card" style={{ padding: 6, overflowX: "auto" }}>
        <table className="tbl ledger-tbl">
          <thead>
            <tr><th>ID</th><th>이름</th><th>전술</th><th>설명</th><th></th></tr>
          </thead>
          <tbody>
            {filtered.map((t) => (
              <tr key={t.id}>
                <td className="mono"><b>{t.id}</b></td>
                <td>{t.name}</td>
                <td><span className="mitre-tactics">{(t.tactics || [t.tactic]).map((tc) => <span key={tc} className="pill" style={{ background: TACTIC_COLOR[tc] || "#7a828c" }}>{tc}</span>)}</span></td>
                <td className="dim">{t.desc}</td>
                <td className="nowrap">
                  <button className="icon-btn" title={copied === t.id ? "복사됨!" : "번호 복사"} onClick={() => copy(t.id)}><Copy size={14} /></button>
                </td>
              </tr>
            ))}
            {filtered.length === 0 && <tr><td colSpan={5}><EmptyState icon={Crosshair} title="결과 없음" desc="다른 검색어나 전술을 선택해 보세요." /></td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  );
}

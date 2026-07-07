import React, { useCallback, useEffect, useMemo, useState } from "react";
import axios from "axios";

const API = "";
const fmtTime = (t) => String(t || "").replace("T", " ").slice(0, 19);

const PERIODS = [
  ["-24h", "최근 24시간"], ["-7d", "최근 7일"], ["-30d", "최근 30일"],
  ["-90d", "최근 90일"], ["-365d", "최근 1년"],
];

function sevLabel(s) {
  const n = Number(s) || 0;
  if (n >= 3) return ["고위험", "#e5736b"];
  if (n >= 2) return ["주의", "#e0a24a"];
  return ["낮음", "#5aa56b"];
}

export default function RecordsPage({ tabs, activeTab, onTab }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [period, setPeriod] = useState("-90d");
  const [q, setQ] = useState("");
  const [verdict, setVerdict] = useState("all");   // all | tp | fp
  const [sev, setSev] = useState("all");            // all | 3 | 2 | 1
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const [openKey, setOpenKey] = useState(null);
  const [updatedAt, setUpdatedAt] = useState("");

  const load = useCallback(async (earliest) => {
    setLoading(true); setError("");
    try {
      const { data } = await axios.get(`${API}/api/triage/history`, { params: { earliest, head: 5000 } });
      setData(data);
      setUpdatedAt(new Date().toLocaleTimeString("ko-KR"));
    } catch (e) {
      setError(`기록 조회 실패: ${e.response?.data?.detail || e.message}`);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(period); }, [load, period]);

  const ql = q.trim().toLowerCase();
  const filtered = useMemo(() => {
    return (data?.results || []).filter((r) => {
      if (verdict === "tp" && !r.triage.is_true_positive) return false;
      if (verdict === "fp" && r.triage.is_true_positive) return false;
      if (sev !== "all" && String(r.alert.severity) !== sev) return false;
      if (!ql) return true;
      const blob = `${r.alert.signature || ""} ${r.alert.rule_id || ""} ${r.alert.src_ip || ""} ${r.alert.dest_ip || ""} ${r.alert.asset || ""} ${r.triage.attack_type || ""} ${r.triage.reasoning || ""} ${r.alert.mitre || ""}`.toLowerCase();
      return blob.includes(ql);
    });
  }, [data, ql, verdict, sev]);

  useEffect(() => { setPage(1); }, [ql, verdict, sev, pageSize, period]);

  const total = filtered.length;
  const pageCount = Math.max(1, Math.ceil(total / pageSize));
  const cur = Math.min(page, pageCount);
  const slice = filtered.slice((cur - 1) * pageSize, cur * pageSize);

  // 페이지 번호 윈도우(최대 7개)
  const pageNums = [];
  const from = Math.max(1, cur - 3), to = Math.min(pageCount, from + 6);
  for (let p = from; p <= to; p++) pageNums.push(p);

  const counts = data?.counts || {};

  return (
    <div className="records-page">
      {tabs && (
        <div className="tab-bar rec-tabbar">
          {tabs.map((t) => (
            <button key={t.id} className={`tab-btn${activeTab === t.id ? " active" : ""}`}
                    onClick={() => onTab && onTab(t.id)}>
              {t.label}
            </button>
          ))}
        </div>
      )}
      <div className="records-head">
        <h2 style={{ margin: 0, fontSize: 18 }}>탐지 기록 <span style={{ fontSize: 13, color: "#7da6c9", fontWeight: 400 }}>· 전체 데이터베이스</span></h2>
        <div style={{ display: "flex", gap: 14, alignItems: "center" }}>
          <span className="rec-stat"><b style={{ color: "#e5736b" }}>{counts["정탐"] ?? 0}</b> 정탐</span>
          <span className="rec-stat"><b style={{ color: "#9fb6cc" }}>{counts["오탐"] ?? 0}</b> 오탐</span>
          <span className="rec-stat"><b style={{ color: "#7ecfff" }}>{counts.total ?? 0}</b> 전체</span>
          <button className="btn" onClick={() => load(period)} disabled={loading} style={{ fontSize: 12, padding: "6px 12px" }}>
            {loading ? "조회 중..." : "새로고침"}
          </button>
        </div>
      </div>

      <div className="records-controls">
        <input className="records-search" value={q} onChange={(e) => setQ(e.target.value)}
               placeholder="🔍 시그니처 · IP · 자산 · 공격유형 · MITRE · 근거 검색" />
        <select className="rec-sel" value={period} onChange={(e) => setPeriod(e.target.value)}>
          {PERIODS.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
        </select>
        <select className="rec-sel" value={verdict} onChange={(e) => setVerdict(e.target.value)}>
          <option value="all">판정 전체</option><option value="tp">정탐</option><option value="fp">오탐</option>
        </select>
        <select className="rec-sel" value={sev} onChange={(e) => setSev(e.target.value)}>
          <option value="all">위험도 전체</option><option value="3">고위험</option><option value="2">주의</option><option value="1">낮음</option>
        </select>
        <select className="rec-sel" value={pageSize} onChange={(e) => setPageSize(Number(e.target.value))}>
          {[25, 50, 100, 200].map((n) => <option key={n} value={n}>{n}건/페이지</option>)}
        </select>
      </div>

      {error && <div className="ti-error" style={{ marginBottom: 10 }}>{error}</div>}

      <div className="rec-tablewrap">
        <table className="rec-table">
          <thead>
            <tr>
              <th>시각</th><th>룰</th><th>시그니처</th><th>출발지 / 자산</th><th>출발 포트</th><th>목적지</th><th>목적 포트</th>
              <th>위험도</th><th>AI 판정</th><th>신뢰도</th><th>공격유형</th><th>MITRE</th>
            </tr>
          </thead>
          <tbody>
            {slice.map((r, i) => {
              const a = r.alert, t = r.triage;
              const key = `${a.rule_id || ""}|${a.src_ip || a.asset || ""}|${a._time || a.Time || i}|${(cur - 1) * pageSize + i}`;
              const [sl, sc] = sevLabel(a.severity);
              const open = openKey === key;
              return (
                <React.Fragment key={key}>
                  <tr className="rec-row" onClick={() => setOpenKey(open ? null : key)}>
                    <td className="nowrap dim">{fmtTime(a.Time || a._time)}</td>
                    <td className="nowrap" style={{ color: "#8fb3d0" }}>{a.rule_id || "-"}</td>
                    <td>{a.signature || "이벤트"}{a.merged_count > 1 && <span className="rec-merge">×{a.merged_count}</span>}</td>
                    <td className="mono nowrap">{a.asset ? `🖥 ${a.asset}` : (a.src_ip || "-")}</td>
                    <td className="mono nowrap dim">{a.src_port || "-"}</td>
                    <td className="mono nowrap">{a.dest_ip || "-"}</td>
                    <td className="mono nowrap dim">{a.dest_port || "-"}</td>
                    <td className="nowrap"><span style={{ color: sc, fontWeight: 700 }}>{sl}</span></td>
                    <td><span className="rec-verdict" style={{ background: t.is_true_positive ? "#b3261e" : "#5a6b7a" }}>{t.verdict || "?"}</span></td>
                    <td className="nowrap">{t.confidence != null ? `${t.confidence}%` : "-"}</td>
                    <td>{t.attack_type && t.attack_type !== "해당없음" ? t.attack_type : "-"}</td>
                    <td className="nowrap mono" style={{ color: "#9ab0c4" }}>{a.mitre || "-"}</td>
                  </tr>
                  {open && (
                    <tr className="rec-expand">
                      <td colSpan={12}>
                        <div><b style={{ color: "#c9d8e8" }}>판정 근거</b> · {t.reasoning || "-"}</div>
                        {t.confidence_reason && <div style={{ marginTop: 4 }}><b style={{ color: "#8fb3d0" }}>신뢰도 근거</b> · {t.confidence_reason}</div>}
                        {a.merged_count > 1 && (
                          <div style={{ marginTop: 4, color: "#7ecfff" }}>병합 {a.merged_count}건
                            {a.merged_signatures?.length > 1 && <span style={{ color: "#7da6c9" }}> · {a.merged_signatures.join(" / ")}</span>}
                            {a.merged_src_count > 1 && <span style={{ color: "#7da6c9" }}> · 출발지 {a.merged_src_count}개</span>}
                          </div>
                        )}
                        {(t.indicators?.length > 0 || a.payload) && (
                          <div style={{ marginTop: 4, color: "#f8c262", fontFamily: "monospace", wordBreak: "break-all" }}>
                            {(t.indicators?.length ? t.indicators.join("  ·  ") : String(a.payload || "").slice(0, 400))}
                          </div>
                        )}
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              );
            })}
            {slice.length === 0 && !loading && (
              <tr><td colSpan={12} style={{ textAlign: "center", color: "#7da6c9", padding: 30 }}>조건에 맞는 기록이 없습니다.</td></tr>
            )}
            {loading && !data && (
              <tr><td colSpan={12} style={{ textAlign: "center", color: "#7da6c9", padding: 30 }}>탐지 기록을 불러오는 중…</td></tr>
            )}
          </tbody>
        </table>
      </div>

      <div className="rec-pager">
        <span style={{ marginRight: "auto", fontSize: 12, color: "#7da6c9" }}>
          {total > 0 ? `${(cur - 1) * pageSize + 1}–${Math.min(cur * pageSize, total)} / 총 ${total}건` : "0건"}
          {updatedAt && ` · 갱신 ${updatedAt}`}
        </span>
        <button className="rec-pgbtn" onClick={() => setPage(1)} disabled={cur <= 1}>« 처음</button>
        <button className="rec-pgbtn" onClick={() => setPage(cur - 1)} disabled={cur <= 1}>‹ 이전</button>
        {pageNums.map((p) => (
          <button key={p} className={"rec-pgbtn" + (p === cur ? " on" : "")} onClick={() => setPage(p)}>{p}</button>
        ))}
        <button className="rec-pgbtn" onClick={() => setPage(cur + 1)} disabled={cur >= pageCount}>다음 ›</button>
        <button className="rec-pgbtn" onClick={() => setPage(pageCount)} disabled={cur >= pageCount}>끝 »</button>
      </div>
    </div>
  );
}

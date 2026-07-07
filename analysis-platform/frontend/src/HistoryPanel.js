import React, { useCallback, useEffect, useState } from "react";
import axios from "axios";

const API = "";

function VerdictBadge({ v }) {
  const tp = v?.is_true_positive;
  return (
    <span className="sev" style={{ background: tp ? "#b3261e" : "#5a6b7a" }} title={`신뢰도 ${v?.confidence ?? 0}%`}>
      {v?.verdict || "?"} {v?.confidence != null ? `${v.confidence}%` : ""}
    </span>
  );
}

const fmtTime = (t) => String(t || "").replace("T", " ").slice(0, 19);

export default function HistoryPanel() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [filter, setFilter] = useState("all");   // all | tp | fp
  const [q, setQ] = useState("");
  const [updatedAt, setUpdatedAt] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const { data } = await axios.get(`${API}/api/triage/history`, { params: { earliest: "-90d", head: 2000 } });
      setData(data);
      setUpdatedAt(new Date().toLocaleTimeString("ko-KR"));
    } catch (e) {
      const msg = e.response?.data?.detail || e.message;
      setError(`기록 조회 실패: ${msg}`);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const ql = q.trim().toLowerCase();
  const rows = (data?.results || []).filter((r) => {
    if (filter === "tp" && !r.triage.is_true_positive) return false;
    if (filter === "fp" && r.triage.is_true_positive) return false;
    if (!ql) return true;
    const blob = `${r.alert.signature || ""} ${r.alert.rule_id || ""} ${r.alert.src_ip || ""} ${r.alert.dest_ip || ""} ${r.alert.asset || ""} ${r.triage.attack_type || ""} ${r.triage.reasoning || ""}`.toLowerCase();
    return blob.includes(ql);
  });

  const inputStyle = {
    width: "100%", boxSizing: "border-box", background: "#0b1622", color: "#dbe7f2",
    border: "1px solid #1f3242", borderRadius: 4, padding: "7px 10px", fontSize: 13, outline: "none",
  };

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
        <h3 style={{ margin: 0, fontSize: 14 }}>탐지 기록 (전체)</h3>
        <button className="btn" onClick={load} disabled={loading} style={{ fontSize: 12, padding: "5px 10px" }}>
          {loading ? "갱신 중..." : "새로고침"}
        </button>
      </div>
      <p style={{ fontSize: 12, color: "#7da6c9", marginTop: 0 }}>
        기간 내 모든 탐지를 정·오탐 판정과 함께 표시합니다 (100건 제한 없음). {updatedAt && `(갱신 ${updatedAt})`}
      </p>

      {error && <div className="ti-error" style={{ marginBottom: 12 }}>{error}</div>}

      {data && (
        <>
          <div style={{ display: "flex", gap: 8, marginBottom: 10 }}>
            <div className="ti-card" style={{ flex: 1, textAlign: "center" }}>
              <div style={{ fontSize: 20, fontWeight: 700, color: "#e5736b" }}>{data.counts["정탐"]}</div>
              <div style={{ fontSize: 11, color: "#9fb6cc" }}>정탐</div>
            </div>
            <div className="ti-card" style={{ flex: 1, textAlign: "center" }}>
              <div style={{ fontSize: 20, fontWeight: 700, color: "#9fb6cc" }}>{data.counts["오탐"]}</div>
              <div style={{ fontSize: 11, color: "#9fb6cc" }}>오탐</div>
            </div>
            <div className="ti-card" style={{ flex: 1, textAlign: "center" }}>
              <div style={{ fontSize: 20, fontWeight: 700, color: "#7ecfff" }}>{data.counts.total}</div>
              <div style={{ fontSize: 11, color: "#9fb6cc" }}>전체 탐지</div>
            </div>
          </div>

          <input style={inputStyle} value={q} onChange={(e) => setQ(e.target.value)}
                 placeholder="시그니처 · IP · 자산 · 공격유형 · 근거 검색" />

          <div style={{ display: "flex", gap: 6, margin: "10px 0", alignItems: "center" }}>
            {[["all", "전체"], ["tp", "정탐"], ["fp", "오탐"]].map(([k, lbl]) => (
              <button key={k} className="report-period-btn" onClick={() => setFilter(k)}
                      style={filter === k ? { background: "#2e6ca4", borderColor: "#2e6ca4", color: "#fff" } : {}}>
                {lbl}
              </button>
            ))}
            <span style={{ marginLeft: "auto", fontSize: 11, color: "#7da6c9" }}>표시 {rows.length}건</span>
          </div>

          {rows.map((r, i) => (
            <div key={i} className="alert-row" style={{ cursor: "default" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 6 }}>
                <strong>{r.alert.signature || r.alert.sourcetype || "이벤트"}</strong>
                <VerdictBadge v={r.triage} />
              </div>
              <div style={{ fontSize: 11, color: "#7da6c9", margin: "3px 0 1px" }}>
                🕒 {fmtTime(r.alert.Time || r.alert._time)}
                {r.alert.rule_id && <span style={{ color: "#5a7a94" }}> · {r.alert.rule_id}</span>}
              </div>
              <div style={{ fontSize: 12, color: "#9fb6cc", margin: "1px 0" }}>
                {r.alert.asset
                  ? <>🖥 {r.alert.asset}</>
                  : <>{r.alert.src_ip || "?"} → {r.alert.dest_ip || "?"}</>}
                {r.triage.attack_type && r.triage.attack_type !== "해당없음" && ` · ${r.triage.attack_type}`}
                {r.alert.merged_count > 1 && <span style={{ color: "#7ecfff" }}> · 병합 {r.alert.merged_count}건</span>}
              </div>
              <div style={{ fontSize: 12, color: "#c9d8e8", lineHeight: 1.5 }}>{r.triage.reasoning}</div>
            </div>
          ))}
          {rows.length === 0 && !loading && <p style={{ color: "#7da6c9" }}>조건에 맞는 기록이 없습니다.</p>}
        </>
      )}

      {!data && loading && <p style={{ color: "#7da6c9", fontSize: 13 }}>탐지 기록을 불러오는 중... (최초 판정 시 다소 걸릴 수 있습니다)</p>}
    </div>
  );
}

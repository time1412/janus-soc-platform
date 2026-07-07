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

export default function TriagePanel() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [filter, setFilter] = useState("all"); // all | tp | fp
  const [updatedAt, setUpdatedAt] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const { data } = await axios.get(`${API}/api/triage`, { params: { earliest: "-24h" } });
      setData(data);
      setUpdatedAt(new Date().toLocaleTimeString("ko-KR"));
    } catch (e) {
      const msg = e.response?.data?.detail || e.message;
      setError(msg.includes("API_KEY") ? "AI 키 미설정 — .env의 GEMINI_API_KEY 확인" : `판정 조회 실패: ${msg}`);
    } finally {
      setLoading(false);
    }
  }, []);

  // 탭 진입 시 자동 로드 + 60초 주기 자동 갱신 (판정은 백엔드가 경보 유입 시 자동 수행)
  useEffect(() => {
    load();
    const t = setInterval(load, 60000);
    return () => clearInterval(t);
  }, [load]);

  const rows = (data?.results || []).filter((r) => {
    if (filter === "tp") return r.triage.is_true_positive;
    if (filter === "fp") return !r.triage.is_true_positive;
    return true;
  });

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
        <h3 style={{ margin: 0, fontSize: 14 }}>AI 정·오탐 자동 판정</h3>
        <button className="btn" onClick={load} disabled={loading} style={{ fontSize: 12, padding: "5px 10px" }}>
          {loading ? "갱신 중..." : "새로고침"}
        </button>
      </div>
      <p style={{ fontSize: 12, color: "#7da6c9", marginTop: 0 }}>
        경보가 분석플랫폼에 들어오면 자동으로 정탐/오탐을 분류합니다. {updatedAt && `(갱신 ${updatedAt})`}
      </p>

      {error && <div className="ti-error" style={{ marginBottom: 12 }}>{error}</div>}

      {data && (
        <>
          <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
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
              <div style={{ fontSize: 11, color: "#9fb6cc" }}>전체</div>
            </div>
          </div>

          <div style={{ display: "flex", gap: 6, marginBottom: 10 }}>
            {[["all", "전체"], ["tp", "정탐"], ["fp", "오탐"]].map(([k, lbl]) => (
              <button key={k} className="report-period-btn" onClick={() => setFilter(k)}
                      style={filter === k ? { background: "#2e6ca4", borderColor: "#2e6ca4", color: "#fff" } : {}}>
                {lbl}
              </button>
            ))}
          </div>

          {rows.map((r, i) => (
            <div key={i} className="alert-row" style={{ cursor: "default" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 6 }}>
                <strong>{r.alert.signature || r.alert.sourcetype || "이벤트"}</strong>
                <VerdictBadge v={r.triage} />
              </div>
              <div style={{ fontSize: 12, color: "#9fb6cc", margin: "4px 0" }}>
                {r.alert.asset
                  ? <>🖥 {r.alert.asset}</>
                  : <>{r.alert.src_ip || "?"} → {r.alert.dest_ip || "?"}</>}
                {r.triage.attack_type && r.triage.attack_type !== "해당없음" && ` · ${r.triage.attack_type}`}
              </div>
              {r.alert.merged_count > 1 && (
                <div style={{ fontSize: 11, color: "#7ecfff", marginBottom: 4 }}>
                  병합 {r.alert.merged_count}건
                  {r.alert.merged_sources?.length > 0 && ` · ${r.alert.merged_sources.join(", ")}`}
                  {r.alert.merged_signatures?.length > 1 && (
                    <span style={{ color: "#7da6c9" }}> · {r.alert.merged_signatures.join(" / ")}</span>
                  )}
                </div>
              )}
              <div style={{ fontSize: 12, color: "#c9d8e8", lineHeight: 1.5 }}>{r.triage.reasoning}</div>
              {r.triage.confidence_reason && (
                <div style={{ fontSize: 11, color: "#8fb3d0", marginTop: 4 }}>
                  <span style={{ color: "#5a7a94" }}>신뢰도 근거 ·</span> {r.triage.confidence_reason}
                </div>
              )}
              {r.triage.indicators?.length > 0 && (
                <div style={{ fontSize: 11, color: "#f8c262", marginTop: 4, fontFamily: "monospace", wordBreak: "break-all" }}>
                  {r.triage.indicators.join("  ·  ")}
                </div>
              )}
            </div>
          ))}
          {rows.length === 0 && !loading && <p style={{ color: "#7da6c9" }}>해당 판정 결과가 없습니다.</p>}
        </>
      )}

      {!data && loading && <p style={{ color: "#7da6c9", fontSize: 13 }}>자동 판정 결과를 불러오는 중...</p>}
    </div>
  );
}

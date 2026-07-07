import React, { useState, useEffect } from "react";
import axios from "axios";
import ReactMarkdown from "react-markdown";

const API = "";

const SEV_COLOR = { "3": "#b3261e", "2": "#b8860b", "1": "#2e7d32" };
const SEV_LABEL = { "3": "고위험", "2": "주의", "1": "낮음" };

function BarChart({ rows }) {
  const max = Math.max(...rows.map((r) => parseInt(r.count) || 0), 1);
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
      {rows.map((r, i) => {
        const pct = Math.round((parseInt(r.count) / max) * 100);
        return (
          <div key={i}>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, marginBottom: 3 }}>
              <span style={{ color: "#c9d8e8", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", maxWidth: "75%" }}>
                {r.signature}
              </span>
              <span style={{ color: "#7da6c9", flexShrink: 0 }}>
                {parseInt(r.count).toLocaleString()}
              </span>
            </div>
            <div style={{ height: 6, background: "#1a2d3d", borderRadius: 3 }}>
              <div style={{ width: `${pct}%`, height: "100%", background: "#2e6ca4", borderRadius: 3, transition: "width 0.4s" }} />
            </div>
          </div>
        );
      })}
    </div>
  );
}

function SevCards({ rows }) {
  const total = rows.reduce((s, r) => s + (parseInt(r.count) || 0), 0) || 1;
  return (
    <div style={{ display: "flex", gap: 8 }}>
      {[...rows].sort((a, b) => parseInt(b.severity) - parseInt(a.severity)).map((r, i) => {
        const pct = Math.round((parseInt(r.count) / total) * 100);
        const color = SEV_COLOR[r.severity] || "#2e6ca4";
        return (
          <div key={i} className="ti-card" style={{ flex: 1, textAlign: "center", borderColor: color + "66" }}>
            <div style={{ fontSize: 20, fontWeight: 700, color }}>{parseInt(r.count).toLocaleString()}</div>
            <div style={{ fontSize: 11, color: SEV_LABEL[r.severity] ? color : "#9fb6cc", marginTop: 2 }}>
              {SEV_LABEL[r.severity] || `sev${r.severity}`}
            </div>
            <div style={{ fontSize: 11, color: "#7da6c9" }}>{pct}%</div>
          </div>
        );
      })}
    </div>
  );
}

function DailyTrend({ rows }) {
  if (!rows?.length) return null;
  const max = Math.max(...rows.map((r) => parseInt(r.count) || 0), 1);
  return (
    <div style={{ display: "flex", alignItems: "flex-end", gap: 4, height: 60 }}>
      {rows.map((r, i) => {
        const h = Math.max(4, Math.round((parseInt(r.count) / max) * 56));
        const date = (r._time || "").slice(5, 10);
        return (
          <div key={i} style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center", gap: 3 }}>
            <div style={{ width: "100%", height: h, background: "#2e6ca4", borderRadius: "3px 3px 0 0", title: r.count }} />
            <div style={{ fontSize: 9, color: "#4a6b85" }}>{date}</div>
          </div>
        );
      })}
    </div>
  );
}

export default function InsightsPanel() {
  const [trends, setTrends] = useState(null);
  const [trendsError, setTrendsError] = useState("");
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    loadTrends();
  }, []);

  const loadTrends = async () => {
    setLoading(true);
    setTrendsError("");
    try {
      const { data } = await axios.get(`${API}/api/insights/trends?days=7`);
      setTrends(data);
      if (data.gemini_error) {
        const msg = data.gemini_error;
        setTrendsError(msg.includes("API_KEY_INVALID") ? "Gemini API 키 미설정 — AI 해석 없이 통계만 표시합니다." : `AI 해석 실패: ${msg}`);
      }
    } catch (e) {
      const msg = e.response?.data?.detail || e.message;
      setTrendsError(msg.includes("API_KEY_INVALID") ? "Gemini API 키 미설정 — .env의 GEMINI_API_KEY를 입력하세요." : msg);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      {/* 트렌드 섹션 */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
        <h3 style={{ margin: 0, fontSize: 14 }}>7일 공격 트렌드</h3>
        <button className="btn" onClick={loadTrends} disabled={loading} style={{ fontSize: 12, padding: "5px 10px" }}>
          {loading ? "로딩 중..." : "새로고침"}
        </button>
      </div>

      {trendsError && <div className="ti-error" style={{ marginBottom: 12 }}>{trendsError}</div>}

      {trends && (
        <>
          {/* 총계 카드 */}
          <div className="ti-card" style={{ marginBottom: 16, display: "flex", alignItems: "center", gap: 12 }}>
            <div>
              <div style={{ fontSize: 28, fontWeight: 700, color: "#3fa7ff", lineHeight: 1 }}>
                {trends.stats.total.toLocaleString()}
              </div>
              <div style={{ fontSize: 12, color: "#7da6c9", marginTop: 4 }}>7일간 총 이벤트</div>
            </div>
            <div style={{ flex: 1 }}>
              <DailyTrend rows={trends.stats.daily_trend} />
            </div>
          </div>

          {/* 위험도별 */}
          <div style={{ marginBottom: 16 }}>
            <div style={{ fontSize: 12, color: "#7da6c9", marginBottom: 8 }}>위험도별</div>
            <SevCards rows={trends.stats.by_severity} />
          </div>

          {/* 공격 유형별 바 차트 */}
          <div style={{ marginBottom: 16 }}>
            <div style={{ fontSize: 12, color: "#7da6c9", marginBottom: 8 }}>공격 유형별 (상위 10)</div>
            <BarChart rows={trends.stats.by_signature} />
          </div>

          {/* AI 해석 */}
          {trends.interpretation && (
            <div>
              <div style={{ fontSize: 12, color: "#7da6c9", marginBottom: 6 }}>AI 트렌드 해석</div>
              <div className="analysis-box" style={{ fontSize: 12 }}><ReactMarkdown>{trends.interpretation}</ReactMarkdown></div>
            </div>
          )}
        </>
      )}

    </div>
  );
}

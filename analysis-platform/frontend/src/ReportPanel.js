import React, { useState, useEffect } from "react";
import axios from "axios";

const API = "";

async function downloadPDF(filename) {
  const res = await fetch(`${API}/api/reports/${encodeURIComponent(filename)}`);
  if (!res.ok) throw new Error(`서버 오류 ${res.status}`);
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

const PERIOD_PRESETS = [
  { label: "1시간", value: "-1h" },
  { label: "24시간", value: "-24h" },
  { label: "7일", value: "-7d" },
  { label: "직접 입력", value: "custom" },
];

const SEV_LABEL = { "3": "HIGH", "2": "MED", "1": "LOW" };
const SEV_CLASS = { "3": "sev-high", "2": "sev-mid", "1": "sev-low" };

export default function ReportPanel() {
  const [period, setPeriod] = useState("-24h");
  const [customFrom, setCustomFrom] = useState("");
  const [customTo, setCustomTo] = useState("");
  const [sevFilter, setSevFilter] = useState("");

  const [events, setEvents] = useState([]);
  const [fetching, setFetching] = useState(false);
  const [fetchError, setFetchError] = useState("");

  const [selected, setSelected] = useState(new Set());

  const [reportTitle, setReportTitle] = useState("이벤트 분석 보고서");
  const [generating, setGenerating] = useState(false);
  const [genResult, setGenResult] = useState(null);
  const [genError, setGenError] = useState("");

  const [reports, setReports] = useState([]);
  const [dlError, setDlError] = useState("");

  useEffect(() => {
    loadReports();
  }, []);

  const fetchEvents = async () => {
    setFetching(true);
    setFetchError("");
    setEvents([]);
    setSelected(new Set());
    setGenResult(null);

    let earliest = period;
    let latest = "now";
    if (period === "custom") {
      if (!customFrom) {
        setFetchError("시작 일시를 입력하세요.");
        setFetching(false);
        return;
      }
      earliest = customFrom;
      latest = customTo || "now";
    }

    try {
      const { data } = await axios.get(`${API}/api/alerts`, {
        params: { earliest, latest },
      });
      let rows = data.alerts || [];
      if (sevFilter) {
        rows = rows.filter((e) => Number(e.severity) >= Number(sevFilter));
      }
      setEvents(rows);
      // HIGH 이벤트 기본 선택
      setSelected(
        new Set(rows.reduce((acc, ev, i) => {
          if (Number(ev.severity) >= 3) acc.push(i);
          return acc;
        }, []))
      );
    } catch (e) {
      setFetchError(e.response?.data?.detail || e.message);
    } finally {
      setFetching(false);
    }
  };

  const toggleSelect = (i) => {
    setSelected((prev) => {
      const s = new Set(prev);
      s.has(i) ? s.delete(i) : s.add(i);
      return s;
    });
  };

  const selectAll = () => setSelected(new Set(events.map((_, i) => i)));
  const clearAll = () => setSelected(new Set());

  const generate = async () => {
    const selectedEvents = [...selected].sort((a, b) => a - b).map((i) => events[i]);
    if (!selectedEvents.length) {
      setGenError("이벤트를 1개 이상 선택하세요.");
      return;
    }
    setGenerating(true);
    setGenResult(null);
    setGenError("");
    try {
      const { data } = await axios.post(`${API}/api/report/event`, {
        events: selectedEvents,
        title: reportTitle,
      });
      setGenResult(data);
      loadReports();
    } catch (e) {
      setGenError(e.response?.data?.detail || e.message);
    } finally {
      setGenerating(false);
    }
  };

  const loadReports = async () => {
    try {
      const { data } = await axios.get(`${API}/api/reports`);
      setReports(data.reports || []);
    } catch {}
  };

  const formatReportName = (name) =>
    name
      .replace("event_report_", "📋 이벤트 ")
      .replace("incident_report_", "📄 ")
      .replace(".pdf", "")
      .replace(/_/g, " ");

  return (
    <div>
      {/* ── 기간 선택 ── */}
      <h3 style={{ margin: "0 0 10px", fontSize: 14 }}>분석 기간</h3>
      <div className="report-period-btns">
        {PERIOD_PRESETS.map((p) => (
          <button
            key={p.value}
            className={`report-period-btn${period === p.value ? " active" : ""}`}
            onClick={() => setPeriod(p.value)}
          >
            {p.label}
          </button>
        ))}
      </div>

      {period === "custom" && (
        <div style={{ display: "flex", flexDirection: "column", gap: 6, marginTop: 8 }}>
          <div style={{ fontSize: 11, color: "#7da6c9" }}>시작</div>
          <input
            type="datetime-local"
            className="chat-input"
            style={{ padding: "6px 8px", fontSize: 12 }}
            value={customFrom}
            onChange={(e) => setCustomFrom(e.target.value)}
          />
          <div style={{ fontSize: 11, color: "#7da6c9" }}>종료 (비우면 현재)</div>
          <input
            type="datetime-local"
            className="chat-input"
            style={{ padding: "6px 8px", fontSize: 12 }}
            value={customTo}
            onChange={(e) => setCustomTo(e.target.value)}
          />
        </div>
      )}

      {/* ── 위험도 필터 + 조회 버튼 ── */}
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginTop: 12, marginBottom: 4 }}>
        <span style={{ fontSize: 12, color: "#7da6c9", whiteSpace: "nowrap" }}>위험도</span>
        <select
          className="report-select"
          value={sevFilter}
          onChange={(e) => setSevFilter(e.target.value)}
        >
          <option value="">전체</option>
          <option value="3">HIGH만</option>
          <option value="2">MEDIUM 이상</option>
        </select>
        <button
          className="btn"
          style={{ fontSize: 12, padding: "5px 12px", whiteSpace: "nowrap", marginLeft: "auto" }}
          onClick={fetchEvents}
          disabled={fetching}
        >
          {fetching ? "조회 중..." : "이벤트 조회"}
        </button>
      </div>

      {fetchError && (
        <div className="ti-error" style={{ marginTop: 8 }}>
          {fetchError}
        </div>
      )}

      {/* ── 이벤트 목록 ── */}
      {events.length > 0 && (
        <div style={{ marginTop: 12 }}>
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              marginBottom: 6,
            }}
          >
            <span style={{ fontSize: 12, color: "#7da6c9" }}>
              조회 {events.length}건 ·{" "}
              <span style={{ color: "#3fa7ff" }}>선택 {selected.size}건</span>
            </span>
            <div style={{ display: "flex", gap: 5 }}>
              <button className="report-small-btn" onClick={selectAll}>
                전체선택
              </button>
              <button className="report-small-btn" onClick={clearAll}>
                전체해제
              </button>
            </div>
          </div>

          <div className="report-event-list">
            {events.map((ev, i) => (
              <div
                key={i}
                className={`report-event-row${selected.has(i) ? " selected" : ""}`}
                onClick={() => toggleSelect(i)}
              >
                <input
                  type="checkbox"
                  checked={selected.has(i)}
                  onChange={() => toggleSelect(i)}
                  onClick={(e) => e.stopPropagation()}
                  style={{ marginRight: 8, flexShrink: 0, accentColor: "#2e6ca4" }}
                />
                <span
                  className={`sev ${SEV_CLASS[String(ev.severity)] || "sev-low"}`}
                  style={{ fontSize: 10, padding: "1px 5px", marginRight: 6, flexShrink: 0 }}
                >
                  {SEV_LABEL[String(ev.severity)] || "LOW"}
                </span>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div
                    style={{
                      fontSize: 11,
                      color: "#c9d8e8",
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                    }}
                  >
                    {ev.signature || ev.sourcetype || "이벤트"}
                  </div>
                  <div style={{ fontSize: 10, color: "#4a6b85", marginTop: 1 }}>
                    {ev.src_ip || "?"} → {ev.dest_ip || "?"}
                    {ev.Time || ev._time
                      ? "  ·  " + (ev.Time || String(ev._time)).slice(0, 16)
                      : ""}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {events.length === 0 && !fetching && !fetchError && (
        <p style={{ fontSize: 12, color: "#4a6b85", marginTop: 16 }}>
          기간과 위험도를 선택 후 <strong>이벤트 조회</strong>를 눌러주세요.
        </p>
      )}

      {/* ── 보고서 제목 + 생성 버튼 ── */}
      {events.length > 0 && (
        <div
          style={{
            borderTop: "1px solid #1f3242",
            marginTop: 14,
            paddingTop: 12,
          }}
        >
          <div style={{ fontSize: 12, color: "#7da6c9", marginBottom: 5 }}>
            보고서 제목
          </div>
          <input
            className="chat-input"
            style={{
              width: "100%",
              padding: "7px 10px",
              fontSize: 13,
              marginBottom: 10,
              boxSizing: "border-box",
            }}
            value={reportTitle}
            onChange={(e) => setReportTitle(e.target.value)}
          />
          <button
            className="btn"
            style={{ width: "100%", fontWeight: 600 }}
            onClick={generate}
            disabled={generating || selected.size === 0}
          >
            {generating
              ? "보고서 생성 중..."
              : `📄  보고서 생성  (선택 ${selected.size}건)`}
          </button>
          {genError && (
            <div className="ti-error" style={{ marginTop: 8 }}>
              {genError}
            </div>
          )}
        </div>
      )}

      {/* ── 생성 결과 ── */}
      {genResult && (
        <div style={{
          marginTop: 12,
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          background: "#081a0e",
          border: "1px solid #1f6e3a",
          borderRadius: 8,
          padding: "10px 14px",
        }}>
          <span style={{ fontSize: 12, color: "#53a051" }}>
            ✓ 보고서 생성 완료 ({genResult.event_count}건 분석)
          </span>
          <button
            className="btn"
            style={{ fontSize: 12, padding: "6px 12px" }}
            onClick={() => downloadPDF(genResult.report_file).catch(e => setDlError(e.message))}
          >
            📥 PDF 다운로드
          </button>
        </div>
      )}

      {dlError && (
        <div className="ti-error" style={{ marginTop: 8 }}>
          다운로드 실패: {dlError}
        </div>
      )}

      {/* ── 저장된 보고서 목록 ── */}
      <div
        style={{ borderTop: "1px solid #1f3242", marginTop: 18, paddingTop: 12 }}
      >
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            marginBottom: 8,
          }}
        >
          <span style={{ fontSize: 13, fontWeight: 600 }}>저장된 보고서</span>
          <button className="report-small-btn" onClick={loadReports}>
            새로고침
          </button>
        </div>

        {reports.length === 0 && (
          <p style={{ fontSize: 12, color: "#4a6b85" }}>
            생성된 보고서가 없습니다.
          </p>
        )}
        {reports.slice(0, 15).map((name) => (
          <div
            key={name}
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              padding: "6px 0",
              borderBottom: "1px solid #0e1c28",
            }}
          >
            <span
              style={{
                fontSize: 11,
                color: "#9fb6cc",
                overflow: "hidden",
                textOverflow: "ellipsis",
                whiteSpace: "nowrap",
                maxWidth: "68%",
              }}
            >
              📄 {formatReportName(name)}
            </span>
            <button
              className="report-small-btn"
              style={{ flexShrink: 0 }}
              onClick={() => downloadPDF(name).catch(e => setDlError(e.message))}
            >
              📥 다운로드
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}

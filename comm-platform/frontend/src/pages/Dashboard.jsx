import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api, onWS } from "../api.js";
import { useAuth } from "../auth.jsx";
import { useOnline } from "../presence.js";
import Avatar from "../components/Avatar.jsx";
import Badge from "../components/Badge.jsx";

const SEV = { "3": ["고위험", "#dc2626"], "2": ["주의", "#c2740a"], "1": ["낮음", "#15a34a"] };
const STATUS_COLOR = {
  미접수: "#5b6b7a", 접수: "#2563eb", 검토: "#0891b2", 대응: "#c2740a", 승인대기: "#7c3aed",
  오탐요청: "#b08900", 무시종결요청: "#8a6d1f", 종결: "#15a34a", 오탐종결: "#0f9d8e", 무시종결: "#7a828c",
};
const CLOSED = new Set(["종결", "오탐종결", "무시종결"]);

export default function Dashboard() {
  const { user } = useAuth();
  const nav = useNavigate();
  const online = useOnline();
  const [stats, setStats] = useState(null);
  const [metrics, setMetrics] = useState(null);
  const [recent, setRecent] = useState([]);
  const [mine, setMine] = useState([]);
  const [users, setUsers] = useState([]);

  const load = () => {
    api("/api/events/stats").then(setStats).catch(() => {});
    api("/api/events/metrics").then(setMetrics).catch(() => {});
    api("/api/events").then((d) => setRecent(d.slice(0, 7))).catch(() => {});
    api(`/api/events?assignee_id=${user.id}`).then((d) => setMine(d.filter((e) => !CLOSED.has(e.status)))).catch(() => {});
    api("/api/users").then(setUsers).catch(() => {});
  };

  useEffect(() => {
    load();
    return onWS((m) => { if (m.type === "new_event") load(); });
  }, []);

  const hour = new Date().getHours();
  const greet = hour < 12 ? "좋은 아침입니다" : hour < 18 ? "안녕하세요" : "고생 많으십니다";
  const onlineMates = users.filter((u) => u.id !== user.id && online.has(u.id));

  return (
    <div>
      {/* 인사 헤더 */}
      <div className="hello card">
        <Avatar user={user} size={48} showStatus />
        <div className="hello-text">
          <div className="hello-title">{greet}, {user.display_name}님</div>
          <div className="hello-sub">{user.team} · {user.role}</div>
        </div>
        <div className="hello-online">
          <div className="hello-online-label">접속 중인 동료</div>
          <div className="hello-avatars">
            {onlineMates.length === 0 && <span className="dim">없음</span>}
            {onlineMates.map((u) => <Avatar key={u.id} user={u} size={30} showStatus />)}
          </div>
        </div>
      </div>

      {/* 통계 */}
      {stats && (
        <div className="stat-row" style={{ marginTop: 16 }}>
          <div className="stat-card big" onClick={() => nav("/events")} style={{ cursor: "pointer" }}>
            <div className="stat-num">{stats.total}</div>
            <div className="stat-label">전체 정탐 이벤트</div>
          </div>
          {Object.entries(stats.by_status).map(([s, n]) => (
            <div className="stat-card" key={s} onClick={() => nav("/events", { state: { statusFilter: s } })}
                 style={{ cursor: "pointer", borderColor: (STATUS_COLOR[s] || "#1f3242") + "66" }}>
              <div className="stat-num" style={{ color: STATUS_COLOR[s] }}>{n}</div>
              <div className="stat-label">{s}</div>
            </div>
          ))}
        </div>
      )}

      {/* 티켓 지표 */}
      {metrics && (
        <>
          <h3 className="section-title">티켓 지표</h3>
          <div className="metric-row">
            <div className="metric-card">
              <div className="metric-num">{metrics.mttr_hours}<span className="metric-unit">h</span></div>
              <div className="metric-label">평균 처리시간 (MTTR)</div>
            </div>
            <div className="metric-card">
              <div className="metric-num" style={{ color: metrics.sla_rate >= 90 ? "#15a34a" : metrics.sla_rate >= 70 ? "#c2740a" : "#dc2626" }}>{metrics.sla_rate}<span className="metric-unit">%</span></div>
              <div className="metric-label">SLA 준수율</div>
            </div>
            <div className="metric-card">
              <div className="metric-num" style={{ color: metrics.open_overdue ? "#dc2626" : "#15a34a" }}>{metrics.open_overdue}</div>
              <div className="metric-label">SLA 초과(미처리)</div>
            </div>
            <div className="metric-card">
              <div className="metric-num">{metrics.open}<span className="metric-unit"> / {metrics.total}</span></div>
              <div className="metric-label">진행중 / 전체</div>
            </div>
            <div className="metric-card metric-wide">
              <div className="metric-label" style={{ marginBottom: 6 }}>우선순위 분포</div>
              <div className="prio-bar">
                {["P1", "P2", "P3", "P4"].map((p) => (
                  <span key={p} className="prio-seg" style={{ flex: Math.max(metrics.by_priority[p] || 0, 0.001), background: { P1: "#dc2626", P2: "#c2740a", P3: "#2563eb", P4: "#7a828c" }[p] }} title={`${p}: ${metrics.by_priority[p] || 0}`} />
                ))}
              </div>
              <div className="prio-legend">
                {["P1", "P2", "P3", "P4"].map((p) => <span key={p}>{p} {metrics.by_priority[p] || 0}</span>)}
              </div>
            </div>
          </div>
          {metrics.by_assignee.length > 0 && (
            <div className="card" style={{ marginTop: 12 }}>
              <div className="action-label">분석가별 처리 건수</div>
              {metrics.by_assignee.map((a) => (
                <div key={a.name} className="analyst-row">
                  <span>{a.name}</span>
                  <div className="analyst-bar"><span style={{ width: `${(a.count / metrics.by_assignee[0].count) * 100}%` }} /></div>
                  <b>{a.count}</b>
                </div>
              ))}
            </div>
          )}
        </>
      )}

      <div className="dash-cols">
        {/* 내 담당 이벤트 */}
        <div>
          <h3 className="section-title">내 담당 이벤트 {mine.length > 0 && <span className="count-chip">{mine.length}</span>}</h3>
          <div className="card">
            {mine.length === 0 && <div className="empty">배정된 미완료 이벤트가 없습니다.</div>}
            {mine.map((e) => (
              <div key={e.id} className="mine-row" onClick={() => nav("/events")}>
                <Badge color={SEV[e.severity]?.[1]}>{SEV[e.severity]?.[0]}</Badge>
                <span className="mine-sig">{e.signature}</span>
                <span className="mono dim">{e.src_ip}</span>
                <span style={{ marginLeft: "auto" }}><Badge color={STATUS_COLOR[e.status]}>{e.status}</Badge></span>
              </div>
            ))}
          </div>
        </div>

        {/* 최근 정탐 */}
        <div>
          <h3 className="section-title">최근 정탐 이벤트</h3>
          <div className="card">
            <table className="tbl">
              <thead><tr><th>시그니처</th><th>출발지</th><th>위험도</th><th>상태</th></tr></thead>
              <tbody>
                {recent.map((e) => (
                  <tr key={e.id} className="clickable" onClick={() => nav("/events")}>
                    <td>{e.signature}{e.dup_count > 1 && <span className="dup">×{e.dup_count}</span>}</td>
                    <td className="mono">{e.src_ip}</td>
                    <td><Badge color={SEV[e.severity]?.[1] || "#6b7280"}>{SEV[e.severity]?.[0] || e.severity}</Badge></td>
                    <td><Badge color={STATUS_COLOR[e.status]}>{e.status}</Badge></td>
                  </tr>
                ))}
                {recent.length === 0 && <tr><td colSpan={4} className="empty">이벤트가 없습니다.</td></tr>}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}

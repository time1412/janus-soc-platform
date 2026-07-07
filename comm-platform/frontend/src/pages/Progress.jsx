import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api, onWS } from "../api.js";
import Badge from "../components/Badge.jsx";
import EmptyState from "../components/EmptyState.jsx";
import { Activity, Clock, AlertTriangle, CheckCircle2 } from "lucide-react";

const PRIO_COLOR = { P1: "#dc2626", P2: "#c2740a", P3: "#2563eb", P4: "#7a828c" };
const SEV = { "3": ["고위험", "#dc2626"], "2": ["주의", "#c2740a"], "1": ["낮음", "#15a34a"] };
const STAGES = ["미접수", "접수", "검토", "대응", "승인대기", "종결"];

function slaChip(sla) {
  if (!sla) return { text: "SLA 없음", color: "#7a828c" };
  if (sla.state === "종료") return { text: "종료", color: "#7a828c" };
  if (sla.overdue) return { text: `${Math.abs(sla.remaining_hours)}h 초과`, color: "#dc2626" };
  const h = sla.remaining_hours;
  if (h < 1) return { text: `임박 ${Math.max(1, Math.round(h * 60))}분`, color: "#c2740a" };
  if (h < 24) return { text: `${Math.round(h)}시간 남음`, color: "#15a34a" };
  return { text: `${Math.round(h / 24)}일 남음`, color: "#15a34a" };
}

function Stepper({ status }) {
  // 오탐/무시 계열은 본 흐름을 벗어난 종결로 별도 표시
  if (["오탐요청", "무시종결요청", "오탐종결", "무시종결"].includes(status)) {
    return (
      <div className="stepper">
        {STAGES.map((s) => <div key={s} className="step"><span className="step-dot" /><span className="step-label">{s}</span></div>)}
        <span className="step-rejected">{status}</span>
      </div>
    );
  }
  const cur = STAGES.indexOf(status);
  return (
    <div className="stepper">
      {STAGES.map((s, i) => {
        const cls = i < cur ? "done" : i === cur ? "current" : "";
        return (
          <div key={s} className={"step " + cls}>
            <span className="step-dot" />
            <span className="step-label">{s}</span>
          </div>
        );
      })}
    </div>
  );
}

function Bar({ pct, color }) {
  return <div className="pbar"><span className="pbar-fill" style={{ width: `${pct}%`, background: color }} /></div>;
}

export default function Progress() {
  const nav = useNavigate();
  const [scope, setScope] = useState("open");
  const [data, setData] = useState(null);

  const load = () => api(`/api/events/progress?scope=${scope}`).then(setData).catch(() => {});
  useEffect(() => { load(); }, [scope]);
  useEffect(() => onWS((m) => { if (m.type === "new_event") load(); }), [scope]);

  const tickets = data?.tickets || [];
  const sum = data?.summary || { 진행중: 0, 정상: 0, 임박: 0, 초과: 0 };

  return (
    <div>
      <h2 className="page-title">티켓 진척</h2>
      <p className="page-sub">진행 중인 티켓의 처리 단계 · 체크리스트 · SLA 잔여를 한눈에 확인합니다.</p>

      <div className="prog-summary">
        <div className="prog-sumcard"><Activity size={18} className="prog-ico" style={{ color: "#5b5bd6" }} /><div><div className="prog-sumn">{sum.진행중}</div><div className="prog-suml">진행중</div></div></div>
        <div className="prog-sumcard"><CheckCircle2 size={18} className="prog-ico" style={{ color: "#15a34a" }} /><div><div className="prog-sumn" style={{ color: "#15a34a" }}>{sum.정상}</div><div className="prog-suml">SLA 정상</div></div></div>
        <div className="prog-sumcard"><Clock size={18} className="prog-ico" style={{ color: "#c2740a" }} /><div><div className="prog-sumn" style={{ color: "#c2740a" }}>{sum.임박}</div><div className="prog-suml">SLA 임박</div></div></div>
        <div className="prog-sumcard"><AlertTriangle size={18} className="prog-ico" style={{ color: "#dc2626" }} /><div><div className="prog-sumn" style={{ color: "#dc2626" }}>{sum.초과}</div><div className="prog-suml">SLA 초과</div></div></div>
      </div>

      <div className="filter-bar" style={{ margin: "16px 0 12px" }}>
        {[["open", "진행중"], ["all", "전체"]].map(([k, l]) => (
          <button key={k} className={"chip" + (scope === k ? " on" : "")} onClick={() => setScope(k)}>{l}</button>
        ))}
      </div>

      {tickets.length === 0 && (
        <EmptyState icon={Activity} title="표시할 티켓이 없습니다" desc={scope === "open" ? "진행 중인 티켓이 없습니다." : "티켓이 없습니다."} />
      )}

      <div className="prog-list">
        {tickets.map((t) => {
          const chip = slaChip(t.sla);
          return (
            <div key={t.id} className="prog-card" onClick={() => nav("/events", { state: { openId: t.id } })}>
              <div className="prog-head">
                <Badge color={PRIO_COLOR[t.priority]}>{t.priority}</Badge>
                <span className="mono dim prog-ticket">{t.ticket_no}</span>
                <span className="prog-sig">{t.signature}</span>
                {t.attack_type && t.attack_type !== "해당없음" && <span className="prog-tag">{t.attack_type}</span>}
                <span className="mono dim prog-ip">{t.src_ip}</span>
                <span className="prog-spacer" />
                {t.assignee ? <span className="prog-assignee">{t.assignee}</span> : <span className="dim">미배정</span>}
                <span className="sla-chip" style={{ color: chip.color, borderColor: chip.color + "55", background: chip.color + "14" }}>{chip.text}</span>
              </div>

              <Stepper status={t.status} />

              <div className="prog-bars">
                <div className="prog-bcol">
                  <div className="prog-blabel"><span>처리 단계</span><b>{t.status}</b></div>
                  <Bar pct={t.stage_pct} color="#5b5bd6" />
                </div>
                <div className="prog-bcol">
                  <div className="prog-blabel"><span>SLA 경과</span><b style={{ color: chip.color }}>{chip.text}</b></div>
                  <Bar pct={t.sla?.pct ?? 0} color={t.sla?.overdue ? "#dc2626" : t.sla?.state === "임박" ? "#c2740a" : "#2563eb"} />
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

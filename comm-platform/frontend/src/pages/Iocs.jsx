import React, { useEffect, useState } from "react";
import { Plus, Search, Fingerprint } from "lucide-react";
import { api } from "../api.js";
import { useAuth } from "../auth.jsx";
import Badge from "../components/Badge.jsx";
import EmptyState from "../components/EmptyState.jsx";

const TYPES = ["IP", "도메인", "URL", "해시", "이메일", "기타"];
const STATUSES = ["활성", "차단완료", "만료", "오탐제외"];
const STATUS_COLOR = { 활성: "#dc2626", 차단완료: "#15a34a", 만료: "#7a828c", 오탐제외: "#2563eb" };
const SEV = { "3": ["고위험", "#dc2626"], "2": ["주의", "#c2740a"], "1": ["낮음", "#15a34a"] };

export default function Iocs() {
  const { user } = useAuth();
  const [list, setList] = useState([]);
  const [stats, setStats] = useState(null);
  const [fType, setFType] = useState("");
  const [fStatus, setFStatus] = useState("");
  const [q, setQ] = useState("");
  const [dateFrom, setDateFrom] = useState("");
  const [dateTo, setDateTo] = useState("");
  const [adding, setAdding] = useState(false);
  const [detail, setDetail] = useState(null);
  const [form, setForm] = useState({ ioc_type: "IP", value: "", severity: "2", confidence: 70, first_seen: "", description: "" });

  const load = () => {
    const p = new URLSearchParams();
    if (fType) p.set("ioc_type", fType);
    if (fStatus) p.set("status", fStatus);
    if (q) p.set("q", q);
    if (dateFrom) p.set("date_from", dateFrom);
    if (dateTo) p.set("date_to", dateTo);
    api(`/api/iocs?${p}`).then(setList).catch(() => {});
    api("/api/iocs/stats").then(setStats).catch(() => {});
  };

  useEffect(() => { load(); }, [fType, fStatus, dateFrom, dateTo]);
  const reset = () => { setFType(""); setFStatus(""); setQ(""); setDateFrom(""); setDateTo(""); };

  const addIoc = async () => {
    if (!form.value.trim()) return;
    await api("/api/iocs", { body: { ...form, last_seen: form.first_seen, created_by_id: user.id } });
    setAdding(false);
    setForm({ ioc_type: "IP", value: "", severity: "2", confidence: 70, first_seen: "", description: "" });
    load();
  };
  const setStatus = async (id, status) => { await api(`/api/iocs/${id}`, { method: "PATCH", body: { status } }); load(); };
  const del = async (e, id) => { e?.stopPropagation(); if (confirm("이 IOC를 삭제할까요?")) { await api(`/api/iocs/${id}`, { method: "DELETE" }); load(); } };

  return (
    <div>
      <div className="page-head-row">
        <div>
          <h2 className="page-title">IOC 관리</h2>
          <p className="page-sub">확정된 공격에서 추출한 침해지표(악성 IP·URL·해시 등)를 등록하고 차단 상태를 관리합니다.</p>
        </div>
        <button className="btn" onClick={() => setAdding(true)}><Plus size={16} />IOC 추가</button>
      </div>

      {stats && (
        <div className="stat-row" style={{ marginBottom: 18 }}>
          <div className="stat-card big"><div className="stat-num">{stats.total}</div><div className="stat-label">전체 IOC</div></div>
          {Object.entries(stats.by_type).filter(([, n]) => n > 0).map(([t, n]) => (
            <div className="stat-card" key={t}><div className="stat-num">{n}</div><div className="stat-label">{t}</div></div>
          ))}
        </div>
      )}

      <div className="search-panel">
        <div className="filter-bar" style={{ marginBottom: 8 }}>
          <button className={"chip" + (fType === "" ? " on" : "")} onClick={() => setFType("")}>전체 유형</button>
          {TYPES.map((t) => <button key={t} className={"chip" + (fType === t ? " on" : "")} onClick={() => setFType(t)}>{t}</button>)}
        </div>
        <div className="filter-bar" style={{ marginBottom: 10 }}>
          <button className={"chip" + (fStatus === "" ? " on" : "")} onClick={() => setFStatus("")}>전체 상태</button>
          {STATUSES.map((s) => <button key={s} className={"chip" + (fStatus === s ? " on" : "")} onClick={() => setFStatus(s)}>{s}</button>)}
        </div>
        <div className="search-row">
          <div className="search-field">
            <label>값 검색</label>
            <input value={q} placeholder="IP/도메인/URL/설명" onChange={(e) => setQ(e.target.value)} onKeyDown={(e) => e.key === "Enter" && load()} />
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

      <div className="card" style={{ padding: 6 }}>
        <table className="tbl">
          <thead>
            <tr><th>유형</th><th>값</th><th>위험도</th><th>신뢰도</th><th>최초탐지</th><th>상태</th><th>출처</th><th></th></tr>
          </thead>
          <tbody>
            {list.map((i) => (
              <tr key={i.id} className="clickable" onClick={() => setDetail(i)}>
                <td><Badge color="#64748b" dot={false}>{i.ioc_type}</Badge></td>
                <td className="mono ioc-val" title={i.value}>{i.value}</td>
                <td><Badge color={SEV[i.severity]?.[1] || "#6b7280"}>{SEV[i.severity]?.[0] || i.severity}</Badge></td>
                <td>{i.confidence}%</td>
                <td className="dim">{(i.first_seen || "").slice(0, 10) || "-"}</td>
                <td onClick={(e) => e.stopPropagation()}>
                  <select className="status-sel" value={i.status} onChange={(e) => setStatus(i.id, e.target.value)}
                          style={{ color: STATUS_COLOR[i.status] }}>
                    {STATUSES.map((s) => <option key={s} value={s}>{s}</option>)}
                  </select>
                </td>
                <td className="dim">{i.source_event_id ? `이벤트#${i.source_event_id}` : "수동"}</td>
                <td><button className="row-del always" title="삭제" onClick={(e) => del(e, i.id)}>×</button></td>
              </tr>
            ))}
            {list.length === 0 && <tr><td colSpan={8}><EmptyState icon={Fingerprint} title="등록된 IOC가 없습니다" desc="정탐 이벤트에서 'IOC 추출'을 하거나 'IOC 추가'로 직접 등록하세요." /></td></tr>}
          </tbody>
        </table>
      </div>

      {adding && (
        <div className="modal-back" onClick={() => setAdding(false)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <h3>IOC 추가</h3>
            <label>유형</label>
            <select value={form.ioc_type} onChange={(e) => setForm({ ...form, ioc_type: e.target.value })}>
              {TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
            </select>
            <label>값</label>
            <input value={form.value} onChange={(e) => setForm({ ...form, value: e.target.value })}
                   placeholder="예: 203.0.113.9 / evil.com / 해시값" />
            <div style={{ display: "flex", gap: 12 }}>
              <div style={{ flex: 1 }}>
                <label>위험도</label>
                <select value={form.severity} onChange={(e) => setForm({ ...form, severity: e.target.value })}>
                  <option value="3">고위험</option><option value="2">주의</option><option value="1">낮음</option>
                </select>
              </div>
              <div style={{ flex: 1 }}>
                <label>신뢰도(%)</label>
                <input type="number" min="0" max="100" value={form.confidence}
                       onChange={(e) => setForm({ ...form, confidence: Number(e.target.value) })} />
              </div>
              <div style={{ flex: 1 }}>
                <label>최초 탐지일</label>
                <input type="date" value={form.first_seen} onChange={(e) => setForm({ ...form, first_seen: e.target.value })} />
              </div>
            </div>
            <label>설명</label>
            <textarea rows={3} value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })}
                      placeholder="이 지표에 대한 설명/근거 (선택)" />
            <div className="modal-actions">
              <button className="btn-ghost" onClick={() => setAdding(false)}>취소</button>
              <button className="btn" onClick={addIoc}>등록</button>
            </div>
          </div>
        </div>
      )}

      {detail && (
        <div className="modal-back" onClick={() => setDetail(null)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <div className="detail-head">
              <h3 style={{ wordBreak: "break-all" }}>{detail.value}</h3>
              <Badge color={STATUS_COLOR[detail.status]}>{detail.status}</Badge>
            </div>
            <div className="kv">
              <div><span>유형</span><b>{detail.ioc_type}</b></div>
              <div><span>위험도</span><b>{SEV[detail.severity]?.[0] || detail.severity}</b></div>
              <div><span>신뢰도</span><b>{detail.confidence}%</b></div>
              <div><span>출처</span><b>{detail.source_event_id ? `이벤트 #${detail.source_event_id}` : "수동 등록"}</b></div>
              <div><span>최초 탐지</span><b>{(detail.first_seen || "").slice(0, 10) || "-"}</b></div>
              <div><span>최근 탐지</span><b>{(detail.last_seen || "").slice(0, 10) || "-"}</b></div>
            </div>
            <label className="action-label" style={{ display: "block", marginTop: 8 }}>설명</label>
            <div className="mail-body" style={{ marginTop: 4 }}>{detail.description || "(설명 없음)"}</div>
            <div className="modal-actions">
              <button className="btn-ghost" onClick={() => setDetail(null)}>닫기</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

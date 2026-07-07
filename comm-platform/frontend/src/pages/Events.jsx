import React, { useEffect, useRef, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { api, onWS, uploadFile } from "../api.js";
import { useAuth } from "../auth.jsx";
import { fmtDateTime, fmtRelative } from "../fmt.js";
import { X, ShieldAlert, Inbox, Plus, Paperclip } from "lucide-react";
import Avatar from "../components/Avatar.jsx";
import Badge from "../components/Badge.jsx";
import EmptyState from "../components/EmptyState.jsx";

const STATUSES = ["미접수", "접수", "검토", "대응", "승인대기", "오탐요청", "무시종결요청", "종결", "오탐종결", "무시종결"];
const STATUS_COLOR = {
  미접수: "#5b6b7a", 접수: "#2563eb", 검토: "#0891b2", 대응: "#c2740a", 승인대기: "#7c3aed",
  오탐요청: "#b08900", 무시종결요청: "#8a6d1f", 종결: "#15a34a", 오탐종결: "#0f9d8e", 무시종결: "#7a828c",
};
const SEV = { "3": ["고위험", "#dc2626"], "2": ["주의", "#c2740a"], "1": ["낮음", "#15a34a"] };
const PRIORITIES = ["P1", "P2", "P3", "P4"];
const PRIO_COLOR = { P1: "#dc2626", P2: "#c2740a", P3: "#2563eb", P4: "#7a828c" };
const CLOSED = new Set(["종결", "오탐종결", "무시종결"]);
// 최종 승인(종결) 시 정탐/조치 결과
const RESOLUTION_CODES = ["정탐/조치완료", "정탐/조치불요", "과탐/예외처리"];

function slaInfo(due_at, status) {
  if (!due_at) return null;
  if (CLOSED.has(status)) return { label: "종료", color: "#7a828c" };
  const ms = new Date(due_at).getTime() - Date.now();
  if (ms < 0) return { label: "SLA 초과", color: "#dc2626" };
  const h = ms / 3600000;
  if (h < 1) return { label: `임박 ${Math.max(1, Math.round(ms / 60000))}분`, color: "#c2740a" };
  if (h < 24) return { label: `${Math.round(h)}시간 남음`, color: "#15a34a" };
  return { label: `${Math.round(h / 24)}일 남음`, color: "#15a34a" };
}

const BLANK = { signature: "", severity: "2", priority: "", src_ip: "", dest_ip: "", src_port: "", dest_port: "", uri: "", attack_type: "", tags: "", mitre: "", description: "" };

export default function Events() {
  const { user } = useAuth();
  const nav = useNavigate();
  const location = useLocation();
  const [filter, setFilter] = useState("");
  const [list, setList] = useState([]);
  const [sel, setSel] = useState(null);
  const [detail, setDetail] = useState(null);
  const [users, setUsers] = useState([]);
  const [channels, setChannels] = useState([]);
  const [shareOpen, setShareOpen] = useState(false);
  const [creating, setCreating] = useState(false);
  const [form, setForm] = useState(BLANK);
  const [comment, setComment] = useState("");
  const [metaTags, setMetaTags] = useState("");
  const [metaMitre, setMetaMitre] = useState("");
  const [newTask, setNewTask] = useState("");
  const [resolve, setResolve] = useState(null); // { code, rca }
  const [reject, setReject] = useState(null);   // { status, reason } — 반려 사유 필수
  const attRef = useRef(null);
  const historyRef = useRef(null);

  const isSOC = user.team === "보안관제팀";       // 정/오탐 판정
  const isWebAdmin = user.team === "웹관리자";     // 대응
  const isInfoSec = user.team === "정보보호팀";    // 최종 승인

  const loadList = () => {
    const q = filter ? `?status=${encodeURIComponent(filter)}` : "";
    api(`/api/events${q}`).then(setList).catch(() => {});
  };
  const loadDetail = (id) => api(`/api/events/${id}`).then(setDetail).catch(() => {});

  useEffect(() => { loadList(); }, [filter]);
  useEffect(() => { api("/api/users").then(setUsers); api("/api/chat/channels").then(setChannels); }, []);
  useEffect(() => { return onWS((m) => { if (m.type === "new_event") loadList(); }); }, [filter]);
  useEffect(() => { if (sel) loadDetail(sel); }, [sel]);
  // 티켓 진척 페이지에서 넘어온 경우 해당 티켓을 자동 선택
  useEffect(() => { if (location.state?.openId) setSel(location.state.openId); }, [location.state]);
  // 대시보드 상태 카드에서 넘어온 경우 해당 상태로 필터
  useEffect(() => { if (location.state?.statusFilter) setFilter(location.state.statusFilter); }, [location.state]);
  useEffect(() => { setMetaTags(detail?.tags || ""); setMetaMitre(detail?.mitre || ""); }, [detail?.id]);

  const changeStatus = async (status, code = "") => {
    if (status === "종결") { setResolve({ code: RESOLUTION_CODES[0], rca: "" }); return; }  // 최종 승인(종결)은 판정/조치 결과 선택
    await api(`/api/events/${sel}/status`, { body: { user_id: user.id, status, resolution_code: code } }); loadDetail(sel); loadList();
  };
  const submitResolve = async () => {
    await api(`/api/events/${sel}/status`, { body: { user_id: user.id, status: "종결", resolution_code: resolve.code, root_cause: resolve.rca } });
    setResolve(null); loadDetail(sel); loadList();
  };
  const submitReject = async () => {
    if (!reject.reason.trim()) return;   // 반려 사유 필수
    await api(`/api/events/${sel}/status`, { body: { user_id: user.id, status: reject.status, note: `반려 사유: ${reject.reason.trim()}` } });
    setReject(null); loadDetail(sel); loadList();
  };
  // 검토 단계(정보보호) — 웹관리자 대응 요청 / 직접 대응
  const requestWebAdmin = async () => {
    await api(`/api/events/${sel}/assign`, { body: { user_id: user.id, assignee_id: null } });   // 웹관리자 대기(미배정)
    await api(`/api/events/${sel}/status`, { body: { user_id: user.id, status: "대응", note: "웹관리자 대응 요청" } });
    loadDetail(sel); loadList();
  };
  const handleDirect = async () => {
    await api(`/api/events/${sel}/assign`, { body: { user_id: user.id, assignee_id: user.id } });  // 정보보호 직접 처리(본인 배정)
    await api(`/api/events/${sel}/status`, { body: { user_id: user.id, status: "대응", note: "정보보호 직접 대응" } });
    loadDetail(sel); loadList();
  };
  const scrollToHistory = () => historyRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
  const addTask = async () => { if (!newTask.trim()) return; await api(`/api/events/${sel}/tasks`, { body: { user_id: user.id, title: newTask } }); setNewTask(""); loadDetail(sel); };
  const toggleTask = async (t) => { await api(`/api/events/${sel}/tasks/${t.id}`, { method: "PATCH", body: { user_id: user.id, done: !t.done } }); loadDetail(sel); };
  const delTask = async (id) => { await api(`/api/events/${sel}/tasks/${id}`, { method: "DELETE" }); loadDetail(sel); };
  const assign = async (assignee_id) => { await api(`/api/events/${sel}/assign`, { body: { user_id: user.id, assignee_id: assignee_id ? Number(assignee_id) : null } }); loadDetail(sel); loadList(); };
  const setPriority = async (p) => { await api(`/api/events/${sel}/priority`, { body: { user_id: user.id, priority: p } }); loadDetail(sel); loadList(); };
  const saveMeta = async () => { await api(`/api/events/${sel}/meta`, { method: "PATCH", body: { user_id: user.id, tags: metaTags, mitre: metaMitre } }); loadDetail(sel); };
  const addComment = async () => { if (!comment.trim()) return; await api(`/api/events/${sel}/comments`, { body: { user_id: user.id, body: comment } }); setComment(""); loadDetail(sel); };
  const shareByMail = () => nav(`/mail?compose=1&event=${sel}`);
  const extractIoc = async () => {
    const items = await api(`/api/iocs/extract/${sel}?user_id=${user.id}`, { method: "POST" });
    alert(`IOC ${items.length}건 추출 완료:\n` + items.map((i) => `· [${i.ioc_type}] ${i.value}`).join("\n"));
  };
  const shareToChannel = async (channelId) => {
    await api(`/api/chat/channels/${channelId}/messages`, { body: { user_id: user.id, body: `정탐 이벤트 공유: ${detail.signature}`, event_id: sel } });
    setShareOpen(false);
  };
  const createTicket = async () => {
    if (!form.signature.trim()) return alert("제목(유형)을 입력하세요.");
    const res = await api("/api/events/ticket", { body: { user_id: user.id, ...form } });
    setCreating(false); setForm(BLANK); loadList(); setSel(res.id);
  };
  const onAttFile = async (e) => {
    const file = e.target.files?.[0]; e.target.value = "";
    if (!file) return;
    try {
      const up = await uploadFile(file);
      await api(`/api/events/${sel}/attachments`, { body: { user_id: user.id, url: up.url, name: up.name, size: up.size } });
      loadDetail(sel);
    } catch (err) { alert(err.message); }
  };
  const delAtt = async (id) => { await api(`/api/events/${sel}/attachments/${id}`, { method: "DELETE" }); loadDetail(sel); };

  const dsla = detail && slaInfo(detail.due_at, detail.status);

  return (
    <div>
      <div className="page-head-row">
        <div>
          <h2 className="page-title">티켓 관리</h2>
          <p className="page-sub">분석플랫폼 정탐 + 수동 티켓을 우선순위·SLA로 관리하고 관제팀↔정보보호팀이 협업 처리합니다.</p>
        </div>
        {isSOC && <button className="btn" onClick={() => { setForm(BLANK); setCreating(true); }}><Plus size={16} />새 티켓 (생성)</button>}
      </div>

      <div className="filter-bar">
        <button className={"chip" + (filter === "" ? " on" : "")} onClick={() => setFilter("")}>전체</button>
        {STATUSES.map((s) => <button key={s} className={"chip" + (filter === s ? " on" : "")} onClick={() => setFilter(s)}>{s}</button>)}
      </div>

      <div className="split">
        <div className="card list-pane">
          {list.map((e) => {
            const sla = slaInfo(e.due_at, e.status);
            return (
              <div key={e.id} className={"ev-row" + (sel === e.id ? " selected" : "")} onClick={() => setSel(e.id)}>
                <div className="ev-row-top">
                  <span className="ev-sig"><span className="ticket-no">{e.ticket_no}</span> {e.signature}{e.dup_count > 1 && <span className="dup">×{e.dup_count}</span>}</span>
                  <Badge color={STATUS_COLOR[e.status]}>{e.status}</Badge>
                </div>
                <div className="ev-row-bot">
                  <Badge color={PRIO_COLOR[e.priority]} dot={false}>{e.priority}</Badge>
                  <span className="mono">{e.src_ip || "-"}{e.src_port ? `:${e.src_port}` : ""}</span>
                  <Badge color={SEV[e.severity]?.[1]}>{SEV[e.severity]?.[0]}</Badge>
                  {sla && <Badge color={sla.color}>{sla.label}</Badge>}
                  {e.assignee && <span className="dim" style={{ marginLeft: "auto" }}>{e.assignee.display_name}</span>}
                </div>
              </div>
            );
          })}
          {list.length === 0 && <EmptyState icon={Inbox} title="티켓이 없습니다" desc={filter ? "이 상태의 티켓이 없습니다. 필터를 바꿔보세요." : "정탐이 들어오거나 '새 티켓'으로 직접 등록하면 표시됩니다."} />}
        </div>

        <div className="card detail-pane">
          {!detail ? (
            <EmptyState icon={ShieldAlert} title="티켓을 선택하세요" desc="왼쪽 목록에서 티켓을 클릭하면 상세·우선순위·SLA·검토 액션이 표시됩니다." />
          ) : (
            <>
              <div className="detail-head">
                <div>
                  <div className="ticket-meta-line">
                    <span className="mono ticket-no-lg">{detail.ticket_no}</span>
                    <Badge color={PRIO_COLOR[detail.priority]} dot={false}>{detail.priority}</Badge>
                    {dsla && <Badge color={dsla.color}>{dsla.label}</Badge>}
                    <span className="dim">· {detail.origin}</span>
                  </div>
                  <h3 style={{ marginTop: 4 }}>{detail.signature}</h3>
                </div>
                <Badge color={STATUS_COLOR[detail.status]}>{detail.status}</Badge>
              </div>

              <div className="kv">
                {detail.asset
                  ? <div><span>영향 자산</span><b className="mono">🖥 {detail.asset}</b></div>
                  : <div><span>출발지 IP</span><b className="mono">{detail.src_ip || "-"}</b></div>}
                <div><span>출발지 포트</span><b className="mono">{detail.src_port || "-"}</b></div>
                <div><span>목적지 IP</span><b className="mono">{detail.dest_ip || "-"}</b></div>
                <div><span>목적지 포트</span><b className="mono">{detail.dest_port || "-"}</b></div>
                <div><span>위험도</span><b>{SEV[detail.severity]?.[0] || detail.severity}</b></div>
                <div><span>SLA 기한</span><b>{detail.due_at ? fmtDateTime(detail.due_at) : "-"}</b></div>
                <div><span>탐지시각</span><b>{detail.detected_at || "-"}</b></div>
                <div><span>반복 횟수</span><b>{detail.dup_count}회</b></div>
              </div>
              {detail.uri && (
                <div className="payload-row">
                  <div className="payload-label">URI</div>
                  <div className="uri-box mono">{detail.uri}</div>
                </div>
              )}
              {detail.payload && (
                <div className="payload-row">
                  <div className="payload-label">판정 페이로드</div>
                  <div className="uri-box mono payload-box">{detail.payload}</div>
                </div>
              )}

              {detail.origin !== "수동" && (
                <div className="ai-box">
                  <div className="ai-head">AI 판별: <b>{detail.ai_verdict}</b> · {detail.ai_attack_type} · 신뢰도 {detail.ai_confidence}%</div>
                  <div className="ai-reason">{detail.ai_reasoning}</div>
                </div>
              )}
              {detail.origin === "수동" && detail.ai_reasoning && (
                <div className="ai-box"><div className="ai-reason">{detail.ai_reasoning}</div></div>
              )}

              {detail.resolved_at && (
                <div className="resolve-box">
                  <div><b>종결</b> · {detail.resolution_code || "(코드 없음)"} · {fmtDateTime(detail.resolved_at)}</div>
                  {detail.root_cause && <div className="resolve-rca">근본원인: {detail.root_cause}</div>}
                </div>
              )}

              {/* 티켓 속성 변경: 우선순위 + 태그 + MITRE */}
              <div className="action-block meta-edit">
                <div className="action-label">티켓 속성 변경</div>
                <div className="action-row">
                  <label>우선순위</label>
                  <select value={detail.priority} onChange={(e) => setPriority(e.target.value)} style={{ maxWidth: 120 }}>
                    {PRIORITIES.map((p) => <option key={p} value={p}>{p}</option>)}
                  </select>
                  <span className="dim">변경 시 SLA 기한 자동 재계산</span>
                </div>
                <div className="action-row">
                  <label>태그</label>
                  <input value={metaTags} onChange={(e) => setMetaTags(e.target.value)} placeholder="콤마 구분 (예: 외부, 웹공격, 긴급)" />
                </div>
                <div className="action-row">
                  <label>MITRE</label>
                  <input value={metaMitre} onChange={(e) => setMetaMitre(e.target.value)} placeholder="기법 ID 콤마 구분 (예: T1190, T1059)" />
                </div>
                <div className="action-row" style={{ justifyContent: "flex-end" }}>
                  <button className="btn-ghost" onClick={saveMeta}>저장</button>
                </div>
                {(detail.tags || detail.mitre) && (
                  <div className="tag-row">
                    {detail.tags.split(",").filter((t) => t.trim()).map((t, i) => <Badge key={"t" + i} color="#64748b" dot={false}>{t.trim()}</Badge>)}
                    {detail.mitre.split(",").filter((t) => t.trim()).map((t, i) => <Badge key={"m" + i} color="#5b5bd6" dot={false}>{t.trim()}</Badge>)}
                  </div>
                )}
              </div>

              {/* 티켓 상태 변경 (역할 기반 프로세스) */}
              <div className="action-block">
                <div className="action-label">티켓 상태 변경 <span className="dim">· {user.team} · 현재: {detail.status}</span></div>
                <div className="proc-flow">미접수 → <b>접수</b>(관제) → [정탐] <b>검토</b>(정보보호 이관) → 웹관리자 <b>대응</b> 또는 정보보호 직접 대응 → <b>종결</b>(정보보호) &nbsp;|&nbsp; [오탐/무시] 관제 요청 → 정보보호 승인</div>
                <div className="action-btns">
                  {/* 보안관제팀: 접수 · 정/오탐 판정 (정탐은 정보보호로 이관) */}
                  {isSOC && !CLOSED.has(detail.status) && (
                    <>
                      {detail.status === "미접수" && <button className="act act-review" onClick={() => changeStatus("접수")}>접수</button>}
                      {detail.status === "접수" && <button className="act act-approve" onClick={() => changeStatus("검토")} title="정탐 판정 → 정보보호 담당자에게 이관">정탐 → 정보보호 이관</button>}
                      {(detail.status === "접수" || detail.status === "미접수") && <>
                        <button className="act" style={{ background: "#b08900" }} onClick={() => changeStatus("오탐요청")}>오탐 요청</button>
                        <button className="act" style={{ background: "#8a6d1f" }} onClick={() => changeStatus("무시종결요청")}>무시 종결 요청</button>
                      </>}
                    </>
                  )}
                  {/* 정보보호팀: 검토 → 대응 라우팅(웹관리자 요청 / 직접 대응) */}
                  {isInfoSec && detail.status === "검토" && (
                    <>
                      <button className="act act-approve" onClick={requestWebAdmin}>웹관리자 대응 요청</button>
                      <button className="act act-done" onClick={handleDirect}>직접 대응</button>
                      <button className="act act-reject" onClick={() => setReject({ status: "접수", reason: "" })}>반려 (관제 재검토)</button>
                    </>
                  )}
                  {/* 웹관리자: 대응(정보보호가 위임한 건) */}
                  {isWebAdmin && detail.status === "대응" && detail.assignee?.team !== "정보보호팀" && (
                    <button className="act act-done" onClick={() => changeStatus("승인대기")}>대응 완료 → 승인 요청</button>
                  )}
                  {/* 정보보호팀: 직접 대응 완료 → 종결 */}
                  {isInfoSec && detail.status === "대응" && detail.assignee?.team === "정보보호팀" && (
                    <button className="act act-approve" onClick={() => changeStatus("종결")}>직접 대응 완료 → 종결</button>
                  )}
                  {/* 정보보호팀: 웹관리자 대응 결과 최종 승인 */}
                  {isInfoSec && detail.status === "승인대기" && (
                    <>
                      <button className="act act-approve" onClick={() => changeStatus("종결")}>최종 승인 (종결)</button>
                      <button className="act act-reject" onClick={() => setReject({ status: "대응", reason: "" })}>반려 (재대응)</button>
                    </>
                  )}
                  {isInfoSec && detail.status === "오탐요청" && (
                    <>
                      <button className="act" style={{ background: "#0f9d8e" }} onClick={() => changeStatus("오탐종결", "오탐확정")}>오탐 종결 승인</button>
                      <button className="act act-reject" onClick={() => setReject({ status: "접수", reason: "" })}>반려 (재검토)</button>
                    </>
                  )}
                  {isInfoSec && detail.status === "무시종결요청" && (
                    <>
                      <button className="act act-reject" onClick={() => changeStatus("무시종결", "오탐·중복")}>무시 종결 승인</button>
                      <button className="act act-review" onClick={() => setReject({ status: "접수", reason: "" })}>반려 (재검토)</button>
                    </>
                  )}
                  {/* 정보보호팀: 재오픈 (최종 종결 권한자가 재개 → 검토 단계로) */}
                  {isInfoSec && CLOSED.has(detail.status) && (
                    <button className="act act-review" onClick={() => changeStatus("검토")}>재오픈</button>
                  )}
                  <button className="act" onClick={scrollToHistory}>이력</button>
                </div>
                <div className="action-row">
                  <label>담당자 (배정/취소)</label>
                  <select value={detail.assignee?.id || ""} onChange={(e) => assign(e.target.value)}>
                    <option value="">(미배정)</option>
                    {users.map((u) => <option key={u.id} value={u.id}>{u.display_name} ({u.team})</option>)}
                  </select>
                </div>
                <div className="action-row">
                  <button className="btn-ghost" onClick={extractIoc}>IOC 추출</button>
                  <button className="btn-ghost" onClick={() => setShareOpen(true)}>채팅 공유</button>
                  <button className="btn-ghost" onClick={shareByMail}>메일로 공유</button>
                </div>
              </div>

              {/* 대응 작업/체크리스트 */}
              <div className="sub-section">
                <div className="task-head">
                  <div className="action-label" style={{ margin: 0 }}>
                    대응 작업
                    {detail.tasks.length > 0 && <span className="dim"> · {detail.tasks.filter((t) => t.done).length}/{detail.tasks.length} 완료</span>}
                  </div>
                </div>
                {detail.tasks.map((t) => (
                  <div key={t.id} className={"task-row" + (t.done ? " done" : "")}>
                    <input type="checkbox" checked={t.done} onChange={() => toggleTask(t)} />
                    <span className="task-title">{t.title}</span>
                    <button className="att-del" onClick={() => delTask(t.id)} title="삭제"><X size={13} /></button>
                  </div>
                ))}
                <div className="comment-input" style={{ marginTop: 8 }}>
                  <input value={newTask} onChange={(e) => setNewTask(e.target.value)} placeholder="작업 추가..." onKeyDown={(e) => e.key === "Enter" && addTask()} />
                  <button className="btn" onClick={addTask}>추가</button>
                </div>
              </div>

              {/* 첨부 */}
              <div className="sub-section">
                <div className="action-label">첨부 (증적)</div>
                {detail.attachments.map((a) => (
                  <div key={a.id} className="att-row">
                    <Paperclip size={14} className="dim" />
                    <a href={a.url} target="_blank" rel="noreferrer" className="att-name">{a.name || a.url}</a>
                    <span className="dim">{Math.max(1, Math.round(a.size / 1024))}KB</span>
                    <button className="att-del" onClick={() => delAtt(a.id)} title="삭제"><X size={13} /></button>
                  </div>
                ))}
                <input type="file" hidden ref={attRef} onChange={onAttFile} />
                <button className="btn-ghost" style={{ width: "auto", marginTop: 8 }} onClick={() => attRef.current?.click()}>
                  <Paperclip size={14} /> 파일 첨부
                </button>
              </div>

              {/* 코멘트 */}
              <div className="sub-section">
                <div className="action-label">코멘트</div>
                {detail.comments.map((c) => (
                  <div key={c.id} className="comment">
                    <Avatar user={c.user} size={32} showStatus />
                    <div className="comment-main">
                      <div className="comment-head"><b>{c.user.display_name}</b> <span className="dim">{c.user.team}</span><span className="ts">{fmtDateTime(c.created_at)}</span></div>
                      <p>{c.body}</p>
                    </div>
                  </div>
                ))}
                <div className="comment-input">
                  <input value={comment} onChange={(e) => setComment(e.target.value)} placeholder="코멘트 입력..." onKeyDown={(e) => e.key === "Enter" && addComment()} />
                  <button className="btn" onClick={addComment}>등록</button>
                </div>
              </div>

              {/* 이력 */}
              <div className="sub-section" ref={historyRef}>
                <div className="action-label">처리 이력</div>
                <ul className="history">
                  {detail.history.map((h) => (
                    <li key={h.id}><span className="ts">{fmtDateTime(h.created_at)}</span><b>{h.action}</b> {h.detail}{h.user && <span className="dim"> — {h.user.display_name}</span>}</li>
                  ))}
                </ul>
              </div>
            </>
          )}
        </div>
      </div>

      {shareOpen && (
        <div className="modal-back" onClick={() => setShareOpen(false)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <h3>채팅 채널로 공유</h3>
            <p className="dim" style={{ margin: "0 0 10px" }}>이 티켓을 카드로 채널에 공유합니다.</p>
            {channels.map((c) => (
              <button key={c.id} className="channel-pick" onClick={() => shareToChannel(c.id)}>
                <span className="ch-name"># {c.name}</span><span className="ch-desc">{c.description}</span>
              </button>
            ))}
            <div className="modal-actions"><button className="btn-ghost" onClick={() => setShareOpen(false)}>취소</button></div>
          </div>
        </div>
      )}

      {resolve && (
        <div className="modal-back" onClick={() => setResolve(null)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <h3>최종 승인 (정보보호) — 판정/조치 결과</h3>
            <p className="dim" style={{ margin: "0 0 10px" }}>대응 결과를 최종 승인하고 티켓을 종결합니다.</p>
            <label>판정/조치 결과</label>
            <select value={resolve.code} onChange={(e) => setResolve({ ...resolve, code: e.target.value })}>
              {RESOLUTION_CODES.map((c) => <option key={c} value={c}>{c}</option>)}
            </select>
            <label>근본 원인 / 조치 내용 (RCA)</label>
            <textarea rows={4} value={resolve.rca} onChange={(e) => setResolve({ ...resolve, rca: e.target.value })} placeholder="원인·조치 내용 요약" />
            <div className="modal-actions">
              <button className="btn-ghost" onClick={() => setResolve(null)}>취소</button>
              <button className="btn" onClick={submitResolve}>승인 · 종결</button>
            </div>
          </div>
        </div>
      )}

      {reject && (
        <div className="modal-back" onClick={() => setReject(null)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <h3>반려 — 사유 입력 (필수)</h3>
            <p className="dim" style={{ margin: "0 0 10px" }}>티켓을 '{reject.status}' 단계로 되돌립니다. 반려 사유는 처리 이력에 기록됩니다.</p>
            <label>반려 사유 <span style={{ color: "#dc2626" }}>*</span></label>
            <textarea rows={4} value={reject.reason} autoFocus
                      onChange={(e) => setReject({ ...reject, reason: e.target.value })}
                      placeholder="예: 대응 증적 부족 / 추가 분석 필요 / 차단 룰 미적용 등" />
            <div className="modal-actions">
              <button className="btn-ghost" onClick={() => setReject(null)}>취소</button>
              <button className="btn" onClick={submitReject} disabled={!reject.reason.trim()}>반려</button>
            </div>
          </div>
        </div>
      )}

      {creating && (
        <div className="modal-back" onClick={() => setCreating(false)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <h3>새 티켓 생성</h3>
            <label>제목 / 유형</label>
            <input value={form.signature} onChange={(e) => setForm({ ...form, signature: e.target.value })} placeholder="예: 의심스러운 관리자 로그인" autoFocus />
            <div style={{ display: "flex", gap: 10 }}>
              <div style={{ flex: 1 }}>
                <label>위험도</label>
                <select value={form.severity} onChange={(e) => setForm({ ...form, severity: e.target.value })}>
                  <option value="3">고위험</option><option value="2">주의</option><option value="1">낮음</option>
                </select>
              </div>
              <div style={{ flex: 1 }}>
                <label>우선순위 (선택)</label>
                <select value={form.priority} onChange={(e) => setForm({ ...form, priority: e.target.value })}>
                  <option value="">자동(위험도 기반)</option>
                  {PRIORITIES.map((p) => <option key={p} value={p}>{p}</option>)}
                </select>
              </div>
            </div>
            <div style={{ display: "flex", gap: 10 }}>
              <div style={{ flex: 2 }}><label>출발지 IP</label><input value={form.src_ip} onChange={(e) => setForm({ ...form, src_ip: e.target.value })} placeholder="예: 10.44.44.44" /></div>
              <div style={{ flex: 1 }}><label>출발 포트</label><input value={form.src_port} onChange={(e) => setForm({ ...form, src_port: e.target.value })} placeholder="예: 51234" /></div>
              <div style={{ flex: 2 }}><label>목적지 IP</label><input value={form.dest_ip} onChange={(e) => setForm({ ...form, dest_ip: e.target.value })} /></div>
              <div style={{ flex: 1 }}><label>목적 포트</label><input value={form.dest_port} onChange={(e) => setForm({ ...form, dest_port: e.target.value })} placeholder="예: 443" /></div>
            </div>
            <div style={{ display: "flex", gap: 10 }}>
              <div style={{ flex: 1 }}><label>태그</label><input value={form.tags} onChange={(e) => setForm({ ...form, tags: e.target.value })} placeholder="콤마 구분" /></div>
              <div style={{ flex: 1 }}><label>MITRE</label><input value={form.mitre} onChange={(e) => setForm({ ...form, mitre: e.target.value })} placeholder="예: T1078" /></div>
            </div>
            <label>설명</label>
            <textarea rows={4} value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} placeholder="상황·근거" />
            <div className="modal-actions">
              <button className="btn-ghost" onClick={() => setCreating(false)}>취소</button>
              <button className="btn" onClick={createTicket}>티켓 생성</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

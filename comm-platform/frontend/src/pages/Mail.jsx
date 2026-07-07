import React, { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { api } from "../api.js";
import { useAuth } from "../auth.jsx";
import { fmtDateTime, fmtRelative } from "../fmt.js";
import { Plus, MailX, Inbox, RefreshCw, Trash2, RotateCcw, Search, Reply } from "lucide-react";
import Avatar from "../components/Avatar.jsx";
import EmptyState from "../components/EmptyState.jsx";

const BLANK = { mode: "user", to_user: "", to_email: "", subject: "", body: "", reply_to_id: "" };
const mailUser = (name) => ({ id: -1, display_name: name || "(주소 없음)", team: "" });
const DAY = 86400000;
// "이름 <addr@x>" → addr@x (없으면 원문)
const extractEmail = (s) => {
  if (!s) return "";
  const m = String(s).match(/<([^>]+)>/);
  return (m ? m[1] : s).trim();
};

export default function Mail() {
  const { user } = useAuth();
  const [params, setParams] = useSearchParams();
  const [tab, setTab] = useState("inbox");          // inbox | sent | trash (모두 janus.com)
  const [msgs, setMsgs] = useState([]);
  const [q, setQ] = useState("");                   // 검색어
  const [period, setPeriod] = useState("all");      // all|today|3d|7d|30d|custom
  const [from, setFrom] = useState("");             // custom 시작일
  const [to, setTo] = useState("");                 // custom 끝일
  const [acct, setAcct] = useState(null);           // {address, linked}
  const [loading, setLoading] = useState(false);
  const [open, setOpen] = useState(null);
  const [users, setUsers] = useState([]);
  const [composing, setComposing] = useState(false);
  const [form, setForm] = useState(BLANK);
  const [sending, setSending] = useState(false);
  const [atts, setAtts] = useState([]);             // 작성 중 첨부 [{token,name,size}]
  const [uploading, setUploading] = useState(false);

  const isSent = tab === "sent";
  const isTrash = tab === "trash";

  const fmtSize = (n) => (n >= 1048576 ? (n / 1048576).toFixed(1) + "MB" : Math.max(1, Math.round(n / 1024)) + "KB");

  const onPickFiles = async (e) => {
    const files = Array.from(e.target.files || []);
    e.target.value = "";                            // 같은 파일 재선택 허용
    if (!files.length) return;
    setUploading(true);
    for (const f of files) {
      try {
        const fd = new FormData(); fd.append("file", f);
        const res = await fetch("/api/mail/upload", { method: "POST", body: fd });
        if (!res.ok) {
          const d = await res.json().catch(() => ({}));
          alert(`${f.name}: ${d.detail || "업로드 실패"}`); continue;
        }
        const r = await res.json();
        setAtts((a) => [...a, { token: r.token, name: r.name, size: r.size }]);
      } catch {
        alert(`${f.name}: 업로드 실패`);
      }
    }
    setUploading(false);
  };
  const removeAtt = (token) => setAtts((a) => a.filter((x) => x.token !== token));
  const openCompose = (f) => { setForm(f || BLANK); setAtts([]); setComposing(true); };

  const load = () => {
    setLoading(true);
    const ep = isSent ? "sent" : isTrash ? "trash" : "inbox";
    api(`/api/mail/external/${ep}?user_id=${user.id}`)
      .then((r) => setMsgs(r.messages || []))
      .catch(() => setMsgs([]))
      .finally(() => setLoading(false));
  };

  useEffect(() => { load(); setOpen(null); }, [tab]);
  useEffect(() => {
    api("/api/users").then(setUsers).catch(() => {});
    api(`/api/mail/external/account?user_id=${user.id}`).then(setAcct).catch(() => {});
  }, []);

  useEffect(() => {
    if (params.get("compose") === "1") {
      const evId = params.get("event");
      openCompose({ ...BLANK, subject: evId ? `[정탐 이벤트 #${evId}] 검토 요청` : "" });
      setParams({}, { replace: true });
    }
  }, []);

  const sendMail = async () => {
    if (sending) return;                       // 연타 방지
    const dest = form.mode === "user" ? form.to_user : form.to_email.trim();
    if (!dest) return alert(form.mode === "user" ? "받는 사람을 선택하세요." : "받는 이메일을 입력하세요.");
    if (!form.subject.trim()) return alert("제목을 입력하세요.");
    if (uploading) return alert("첨부 업로드가 끝난 뒤 보내주세요.");
    setSending(true);
    try {
      await api("/api/mail/external/send", { body: {
        user_id: user.id, to: dest, subject: form.subject, body: form.body,
        attachments: atts.map((a) => ({ token: a.token, name: a.name })),
        in_reply_to: form.reply_to_id || "",
      } });
    } catch (e) {
      setSending(false);
      return alert("발송 실패: " + e.message);
    }
    setSending(false);
    setComposing(false);
    setForm(BLANK);
    setAtts([]);
    setTab("sent");
    setTimeout(load, 600);
  };

  const openMsg = (m) => {
    setOpen(m);
    // 받은편지함 메일을 열면 서버에 읽음(\Seen) 표시 → 안읽음 배지 감소
    if (m.uid && tab === "inbox") {
      api("/api/mail/external/read", { body: { user_id: user.id, uid: m.uid } })
        .then(() => window.dispatchEvent(new Event("mail-read")))
        .catch(() => {});
    }
  };

  // 회신: 받는사람·제목(Re:)·원문 인용을 채운 작성 모달 열기
  const replyMsg = (m) => {
    const target = extractEmail(isSent ? m.to : m.from);
    const subj = /^\s*re:/i.test(m.subject || "") ? m.subject : `Re: ${m.subject || ""}`;
    const quoted = (m.body || m.preview || "").split("\n").map((l) => "> " + l).join("\n");
    const head = `${m.date ? fmtDateTime(m.date) : ""}, ${m.from || ""} 님이 작성:`;
    openCompose({
      ...BLANK, mode: "email", to_email: target, subject: subj,
      body: `\n\n${head}\n${quoted}`, reply_to_id: m.message_id || "",
    });
  };

  const trashMsg = async (m, e) => {
    e?.stopPropagation();
    try {
      await api("/api/mail/external/trash", { body: { user_id: user.id, uid: m.uid, source: tab } });
    } catch (err) { return alert("삭제 실패: " + err.message); }
    if (open === m) setOpen(null);
    setMsgs((list) => list.filter((x) => x !== m));
    window.dispatchEvent(new Event("mail-read"));
  };

  const restoreMsg = async (m, e) => {
    e?.stopPropagation();
    try {
      await api("/api/mail/external/restore", { body: { user_id: user.id, uid: m.uid } });
    } catch (err) { return alert("복원 실패: " + err.message); }
    if (open === m) setOpen(null);
    setMsgs((list) => list.filter((x) => x !== m));
    window.dispatchEvent(new Event("mail-read"));
  };

  const purgeMsg = async (m, e) => {
    e?.stopPropagation();
    if (!window.confirm("이 메일을 영구 삭제할까요? 복구할 수 없습니다.")) return;
    try {
      await api("/api/mail/external/purge", { body: { user_id: user.id, uid: m.uid } });
    } catch (err) { return alert("영구 삭제 실패: " + err.message); }
    if (open === m) setOpen(null);
    setMsgs((list) => list.filter((x) => x !== m));
  };

  const emptyTrash = async () => {
    if (!window.confirm("휴지통을 비울까요? 모든 메일이 영구 삭제됩니다.")) return;
    try {
      await api("/api/mail/external/purge", { body: { user_id: user.id } });
    } catch (err) { return alert("비우기 실패: " + err.message); }
    setOpen(null);
    setMsgs([]);
  };

  const resetFilter = () => { setQ(""); setPeriod("all"); setFrom(""); setTo(""); };

  const mailUsers = users.filter((u) => u.id !== user.id && u.mail_address);

  // ── 필터: 텍스트 + 기간 ──
  const ql = q.trim().toLowerCase();
  const inPeriod = (m) => {
    if (period === "all") return true;
    const t = m.date ? new Date(m.date).getTime() : NaN;
    if (isNaN(t)) return false;
    const now = Date.now();
    if (period === "today") { const d = new Date(); d.setHours(0, 0, 0, 0); return t >= d.getTime(); }
    if (period === "3d") return t >= now - 3 * DAY;
    if (period === "7d") return t >= now - 7 * DAY;
    if (period === "30d") return t >= now - 30 * DAY;
    if (period === "custom") {
      if (from && t < new Date(from + "T00:00:00").getTime()) return false;
      if (to && t > new Date(to + "T23:59:59").getTime()) return false;
      return true;
    }
    return true;
  };
  const shown = msgs.filter((m) => {
    if (!inPeriod(m)) return false;
    if (!ql) return true;
    return `${m.subject || ""} ${m.from || ""} ${m.to || ""} ${m.preview || ""} ${m.body || ""}`
      .toLowerCase().includes(ql);
  });
  const filtering = ql || period !== "all";

  const emptyTitle = loading ? "불러오는 중…"
    : filtering ? "조건에 맞는 메일이 없습니다"
    : isTrash ? "휴지통이 비어 있습니다"
    : isSent ? "보낸 메일이 없습니다"
    : "받은 메일이 없습니다";

  return (
    <div>
      <div className="page-head-row">
        <h2 className="page-title">메일</h2>
        <button className="btn" onClick={() => openCompose()}><Plus size={16} />새 메일</button>
      </div>

      {/* 편지함 탭 */}
      <div className="filter-bar">
        <button className={"chip" + (tab === "inbox" ? " on" : "")} onClick={() => setTab("inbox")}>받은편지함</button>
        <button className={"chip" + (isSent ? " on" : "")} onClick={() => setTab("sent")}>보낸편지함</button>
        <button className={"chip" + (isTrash ? " on" : "")} onClick={() => setTab("trash")}><Trash2 size={13} style={{ marginRight: 5 }} />휴지통</button>
        <button className="chip" onClick={load} title="새로고침"><RefreshCw size={13} /></button>
        {acct?.address && (
          <span className="dim" style={{ marginLeft: "auto", fontSize: 12.5, alignSelf: "center" }}>
            {acct.address}{acct.linked === false ? " · 연결 실패" : ""}
          </span>
        )}
      </div>

      {/* 검색 + 기간 필터 패널 */}
      <div className="search-panel mail-search">
        <div className="search-row">
          <div className="search-field" style={{ flex: 1, minWidth: 220 }}>
            <label>검색</label>
            <div className="mail-q-wrap">
              <Search size={14} className="mail-q-ic" />
              <input className="mail-q" value={q} onChange={(e) => setQ(e.target.value)} placeholder="제목 · 보낸/받는사람 · 내용" />
            </div>
          </div>
          <div className="search-field">
            <label>기간</label>
            <select className="status-sel" value={period} onChange={(e) => setPeriod(e.target.value)} style={{ padding: "8px 10px" }}>
              <option value="all">전체</option>
              <option value="today">오늘</option>
              <option value="3d">최근 3일</option>
              <option value="7d">최근 7일</option>
              <option value="30d">최근 30일</option>
              <option value="custom">직접 지정</option>
            </select>
          </div>
          {period === "custom" && (
            <>
              <div className="search-field">
                <label>시작일</label>
                <input type="date" value={from} max={to || undefined} onChange={(e) => setFrom(e.target.value)} />
              </div>
              <div className="search-field">
                <label>종료일</label>
                <input type="date" value={to} min={from || undefined} onChange={(e) => setTo(e.target.value)} />
              </div>
            </>
          )}
          {filtering && (
            <button className="btn-ghost search-reset" onClick={resetFilter}>초기화</button>
          )}
          {isTrash && shown.length > 0 && (
            <button className="btn-danger search-reset" style={{ marginLeft: "auto" }} onClick={emptyTrash}>
              <Trash2 size={14} />휴지통 비우기
            </button>
          )}
        </div>
      </div>

      <div className="split">
        <div className="card list-pane">
          {shown.map((m, i) => (
            <div key={m.uid || m.message_id || i} className={"mail-row" + (open === m ? " selected" : "")}
                 onClick={() => openMsg(m)}>
              <Avatar user={mailUser(isSent ? m.to : m.from)} size={36} showStatus={false} />
              <div className="mail-row-main">
                <div className="mail-row-top">
                  <span className="mail-from">{isSent ? `→ ${m.to || "(수신자)"}` : m.from}</span>
                  <span className="mail-row-right">
                    <span className="ts" title={m.date ? fmtDateTime(m.date) : ""}>{m.date ? fmtRelative(m.date) : ""}</span>
                    {isTrash ? (
                      <>
                        <button className="row-act" title="복원" onClick={(e) => restoreMsg(m, e)}><RotateCcw size={15} /></button>
                        <button className="row-del always" title="영구 삭제" onClick={(e) => purgeMsg(m, e)}><Trash2 size={15} /></button>
                      </>
                    ) : (
                      <button className="row-del" title="휴지통으로" onClick={(e) => trashMsg(m, e)}><Trash2 size={15} /></button>
                    )}
                  </span>
                </div>
                <div className="mail-subject">{m.attachments?.length > 0 && "📎 "}{m.subject}</div>
                {m.preview && <div className="dim" style={{ fontSize: 12, marginTop: 2, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{m.preview}</div>}
              </div>
            </div>
          ))}
          {shown.length === 0 && (
            <EmptyState icon={isTrash ? Trash2 : Inbox}
              title={emptyTitle}
              desc={acct?.linked === false ? "사서함 연결에 실패했습니다(계정/비밀번호 확인)."
                : filtering ? "다른 검색어나 기간으로 시도해 보세요."
                : "janus.com 사서함의 메일이 여기에 표시됩니다."} />
          )}
        </div>

        <div className="card detail-pane">
          {!open ? (
            <EmptyState icon={MailX} title="메일을 선택하세요" desc="왼쪽 목록에서 메일을 클릭하면 내용이 표시됩니다." />
          ) : (
            <>
              <div className="detail-head">
                <h3>{open.subject || "(제목 없음)"}</h3>
                <span style={{ display: "inline-flex", gap: 6, flex: "0 0 auto" }}>
                  {isTrash ? (
                    <>
                      <button className="chip" onClick={(e) => restoreMsg(open, e)}><RotateCcw size={14} style={{ marginRight: 4 }} />복원</button>
                      <button className="btn-danger" onClick={(e) => purgeMsg(open, e)}><Trash2 size={14} style={{ marginRight: 4 }} />영구삭제</button>
                    </>
                  ) : (
                    <>
                      <button className="chip" onClick={() => replyMsg(open)}><Reply size={14} style={{ marginRight: 4 }} />회신</button>
                      <button className="btn-danger" onClick={(e) => trashMsg(open, e)}><Trash2 size={14} style={{ marginRight: 4 }} />삭제</button>
                    </>
                  )}
                </span>
              </div>
              <div className="mail-meta-row">
                <Avatar user={mailUser(open.from)} size={40} showStatus={false} />
                <div className="mail-meta">
                  <span>보낸사람 <b>{open.from || "-"}</b></span>
                  <span>받는사람 <b>{open.to || "-"}</b></span>
                  <span className="ts">{open.date ? fmtDateTime(open.date) : ""} · janus.com 메일</span>
                </div>
              </div>
              <div className="ai-box" style={{ fontSize: 12 }}>외부에서 수신한 메일입니다. 링크·첨부는 신뢰 전 주의하세요.</div>
              <div className="mail-body" style={{ whiteSpace: "pre-wrap" }}>{open.body || open.preview || "(내용 없음)"}</div>
              {open.attachments?.length > 0 && (
                <div style={{ marginTop: 14 }}>
                  <div style={{ fontSize: 12.5, fontWeight: 700, color: "var(--text-2)", marginBottom: 6 }}>
                    📎 첨부파일 {open.attachments.length}개
                  </div>
                  {open.attachments.map((at) => (
                    <a key={at.idx} className="att-dl"
                       href={`/api/mail/external/attachment?user_id=${user.id}&uid=${open.uid}&idx=${at.idx}&source=${tab}`}>
                      📎 {at.name} <span className="dim">({fmtSize(at.size || 0)})</span>
                    </a>
                  ))}
                </div>
              )}
            </>
          )}
        </div>
      </div>

      {composing && (
        <div className="modal-back" onClick={() => setComposing(false)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <h3>{form.reply_to_id ? "회신" : "새 메일"}</h3>
            <div className="dim" style={{ fontSize: 12.5, marginBottom: 8 }}>
              보내는 주소: <b>{acct?.address || `${user.username}@janus.com`}</b>
            </div>

            <label>받는 대상</label>
            <div className="filter-bar" style={{ marginBottom: 4 }}>
              <button type="button" className={"chip" + (form.mode === "user" ? " on" : "")} onClick={() => setForm({ ...form, mode: "user" })}>플랫폼 동료</button>
              <button type="button" className={"chip" + (form.mode === "email" ? " on" : "")} onClick={() => setForm({ ...form, mode: "email" })}>직접 입력</button>
            </div>

            {form.mode === "user" ? (
              <>
                <label>받는사람</label>
                <select value={form.to_user} onChange={(e) => setForm({ ...form, to_user: e.target.value })}>
                  <option value="">선택...</option>
                  {mailUsers.map((u) => (
                    <option key={u.id} value={u.mail_address}>{u.display_name} ({u.mail_address})</option>
                  ))}
                </select>
                {mailUsers.length === 0 && <div className="dim" style={{ fontSize: 12 }}>사서함이 연결된 동료가 아직 없습니다.</div>}
              </>
            ) : (
              <>
                <label>받는 이메일</label>
                <input value={form.to_email} onChange={(e) => setForm({ ...form, to_email: e.target.value })} placeholder="예: someone@janus.com" />
              </>
            )}

            <label>제목</label>
            <input value={form.subject} onChange={(e) => setForm({ ...form, subject: e.target.value })} />
            <label>내용</label>
            <textarea rows={6} value={form.body} onChange={(e) => setForm({ ...form, body: e.target.value })} />

            <label>첨부파일 <span className="dim" style={{ fontWeight: 400, fontSize: 11 }}>(파일당 최대 10MB)</span></label>
            <input type="file" multiple onChange={onPickFiles} disabled={uploading} style={{ fontSize: 13 }} />
            {uploading && <span className="dim" style={{ fontSize: 12, marginLeft: 8 }}>업로드 중…</span>}
            {atts.length > 0 && (
              <div style={{ marginTop: 6, display: "flex", flexWrap: "wrap", gap: 6 }}>
                {atts.map((a) => (
                  <span key={a.token} className="att-chip">
                    📎 {a.name} <span className="dim">({fmtSize(a.size)})</span>
                    <button type="button" onClick={() => removeAtt(a.token)} title="제거">✕</button>
                  </span>
                ))}
              </div>
            )}

            <div className="modal-actions">
              <button className="btn-ghost" onClick={() => setComposing(false)} disabled={sending}>취소</button>
              <button className="btn" onClick={sendMail} disabled={sending || uploading}>{sending ? "보내는 중…" : "보내기"}</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

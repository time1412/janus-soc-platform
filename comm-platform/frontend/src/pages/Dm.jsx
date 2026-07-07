import React, { useEffect, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { ImageIcon, X } from "lucide-react";
import { api, onWS, uploadFile } from "../api.js";
import { useAuth } from "../auth.jsx";
import { setActiveDM, useOnline } from "../presence.js";
import { fmtTime } from "../fmt.js";
import Avatar from "../components/Avatar.jsx";

const TEAM_COLOR = { 보안관제팀: "#2563eb", 정보보호팀: "#0f9d6b" };
const fireDmRead = () => window.dispatchEvent(new Event("dm-read"));

export default function Dm() {
  const { user } = useAuth();
  const online = useOnline();
  const [params] = useSearchParams();
  const [users, setUsers] = useState([]);
  const [threads, setThreads] = useState([]);
  const [partner, setPartner] = useState(null);
  const [messages, setMessages] = useState([]);
  const [text, setText] = useState("");
  const [pendingImg, setPendingImg] = useState(null);
  const [uploading, setUploading] = useState(false);
  const listRef = useRef(null);
  const fileRef = useRef(null);

  const loadThreads = () => api(`/api/dm/threads?user_id=${user.id}`).then(setThreads).catch(() => {});
  const loadConvo = (otherId) =>
    api(`/api/dm/conversation?user_id=${user.id}&other_id=${otherId}`).then((m) => { setMessages(m); fireDmRead(); }).catch(() => {});

  useEffect(() => {
    api("/api/users").then((all) => {
      setUsers(all.filter((u) => u.id !== user.id));
      const pre = params.get("to");
      if (pre) {
        const p = all.find((u) => u.id === Number(pre));
        if (p) setPartner(p);
      }
    });
    loadThreads();
    return () => setActiveDM(null);
  }, []);

  useEffect(() => {
    if (partner) {
      loadConvo(partner.id);
      setActiveDM(partner.id);
      loadThreads();
    }
  }, [partner]);

  useEffect(() => {
    return onWS((m) => {
      if (m.type !== "dm") return;
      const mine = m.sender_id === user.id;
      if (partner && (m.sender_id === partner.id || (mine && m.recipient_id === partner.id))) {
        if (m.sender_id === partner.id) {
          loadConvo(partner.id); // 보고 있는 상대의 새 메시지 → 읽음 처리 + 갱신
        } else {
          setMessages((prev) => [...prev, m.message]);
        }
      }
      loadThreads();
    });
  }, [partner]);

  useEffect(() => {
    if (listRef.current) listRef.current.scrollTop = listRef.current.scrollHeight;
  }, [messages]);

  const onPickFile = async (e) => {
    const file = e.target.files?.[0];
    e.target.value = "";
    if (!file) return;
    setUploading(true);
    try {
      const r = await uploadFile(file);
      setPendingImg(r.url);
    } catch (err) {
      alert(err.message);
    } finally {
      setUploading(false);
    }
  };

  const send = async () => {
    const body = text.trim();
    if ((!body && !pendingImg) || !partner) return;
    setText("");
    const img = pendingImg;
    setPendingImg(null);
    await api("/api/dm", { body: { sender_id: user.id, recipient_id: partner.id, body, image_url: img } });
  };

  const threadMap = Object.fromEntries(threads.map((t) => [t.partner.id, t]));
  const ordered = [
    ...threads.map((t) => t.partner),
    ...users.filter((u) => !threadMap[u.id]),
  ];

  return (
    <div className="page-fill">
      <h2 className="page-title">메시지</h2>
      <p className="page-sub">동료와 1:1로 빠르게 소통합니다.</p>
      <div className="chat-layout dm-layout card">
        <div className="ch-list">
          <div className="ch-list-head">다이렉트 메시지</div>
          {ordered.map((u) => {
            const t = threadMap[u.id];
            const un = t?.unread || 0;
            return (
              <div key={u.id} className={"dm-person" + (partner?.id === u.id ? " on" : "")} onClick={() => setPartner(u)}>
                <Avatar user={u} size={36} showStatus />
                <div className="dm-person-info">
                  <div className="dm-person-top">
                    <span className="dm-person-name">{u.display_name}</span>
                    {un > 0 && partner?.id !== u.id && <span className="badge sm">{un}</span>}
                  </div>
                  <div className="dm-person-sub">{t ? t.last_body : u.team}</div>
                </div>
              </div>
            );
          })}
        </div>

        <div className="ch-main">
          {!partner ? (
            <div className="empty" style={{ margin: "auto" }}>왼쪽에서 대화 상대를 선택하세요.</div>
          ) : (
            <>
              <div className="ch-header dm-head">
                <Avatar user={partner} size={32} showStatus />
                <span style={{ color: TEAM_COLOR[partner.team] }}>{partner.display_name}</span>
                <span className="ch-desc">{partner.team} · {partner.role}</span>
              </div>
              <div className="ch-messages" ref={listRef}>
                {messages.map((m) => {
                  const mine = m.sender.id === user.id;
                  return (
                    <div key={m.id} className={"dm-msg" + (mine ? " mine" : "")}>
                      {m.body && <div className="dm-bubble">{m.body}</div>}
                      {m.image_url && <img className="msg-img" src={m.image_url} alt="첨부 이미지" onClick={() => window.open(m.image_url, "_blank")} />}
                      <div className="dm-time">{fmtTime(m.created_at)}</div>
                    </div>
                  );
                })}
                {messages.length === 0 && <div className="empty">첫 메시지를 보내보세요.</div>}
              </div>
              {pendingImg && (
                <div className="attach-preview">
                  <img src={pendingImg} alt="첨부 미리보기" />
                  <button className="attach-clear" onClick={() => setPendingImg(null)} title="첨부 제거"><X size={14} /></button>
                </div>
              )}
              <div className="ch-input">
                <input type="file" accept="image/*" ref={fileRef} style={{ display: "none" }} onChange={onPickFile} />
                <button className="attach-btn" onClick={() => fileRef.current?.click()} disabled={uploading} title="이미지 첨부">
                  <ImageIcon size={18} />
                </button>
                <input value={text} onChange={(e) => setText(e.target.value)}
                       placeholder={uploading ? "이미지 업로드 중..." : `${partner.display_name}님에게 메시지`}
                       onKeyDown={(e) => e.key === "Enter" && send()} />
                <button className="btn" onClick={send}>전송</button>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

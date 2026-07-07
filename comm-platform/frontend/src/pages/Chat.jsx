import React, { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { ImageIcon, X } from "lucide-react";
import { api, onWS, uploadFile } from "../api.js";
import { useAuth } from "../auth.jsx";
import { clearUnread, setActiveChannel, useChatUnread, useOnline } from "../presence.js";
import { fmtTime, kstDayKey } from "../fmt.js";
import Avatar from "../components/Avatar.jsx";
import Badge from "../components/Badge.jsx";

const TEAM_COLOR = { 보안관제팀: "#2563eb", 정보보호팀: "#0f9d6b" };
const SEV = { "3": ["고위험", "#dc2626"], "2": ["주의", "#c2740a"], "1": ["낮음", "#15a34a"] };

function EventCardMini({ event }) {
  const nav = useNavigate();
  return (
    <div className="ev-card" onClick={() => nav("/events")}>
      <div className="ev-card-top">
        <Badge color={SEV[event.severity]?.[1] || "#6b7280"}>{SEV[event.severity]?.[0] || event.severity}</Badge>
        <span className="ev-card-sig">{event.signature}</span>
      </div>
      <div className="ev-card-meta">
        <span className="mono">{event.src_ip}</span>
        <span className="dim">AI {event.ai_verdict} {event.ai_confidence}% · {event.status}</span>
      </div>
    </div>
  );
}

function dayLabel(iso) {
  const key = kstDayKey(iso);
  const today = kstDayKey(new Date().toISOString());
  const y = new Date(); y.setDate(y.getDate() - 1);
  if (key === today) return "오늘";
  if (key === kstDayKey(y.toISOString())) return "어제";
  return new Date(iso).toLocaleDateString("ko-KR", { timeZone: "Asia/Seoul", year: "numeric", month: "long", day: "numeric", weekday: "short" });
}

export default function Chat() {
  const { user } = useAuth();
  const online = useOnline();
  const unread = useChatUnread();
  const [channels, setChannels] = useState([]);
  const [active, setActive] = useState(null);
  const [messages, setMessages] = useState([]);
  const [users, setUsers] = useState([]);
  const [text, setText] = useState("");
  const [pendingImg, setPendingImg] = useState(null);
  const [uploading, setUploading] = useState(false);
  const listRef = useRef(null);
  const fileRef = useRef(null);

  useEffect(() => {
    api("/api/chat/channels").then((c) => {
      setChannels(c);
      if (c.length) setActive(c[0].id);
    });
    api("/api/users").then(setUsers);
    return () => setActiveChannel(null);
  }, []);

  const loadMessages = (id) =>
    api(`/api/chat/channels/${id}/messages`).then(setMessages).catch(() => {});

  useEffect(() => {
    if (active) {
      loadMessages(active);
      setActiveChannel(active);
      clearUnread(active);
    }
  }, [active]);

  useEffect(() => {
    return onWS((m) => {
      if (m.type === "chat_message" && m.channel_id === active) {
        setMessages((prev) => [...prev, m.message]);
        clearUnread(active);
      }
    });
  }, [active]);

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
    if ((!body && !pendingImg) || !active) return;
    setText("");
    const img = pendingImg;
    setPendingImg(null);
    await api(`/api/chat/channels/${active}/messages`, { body: { user_id: user.id, body, image_url: img } });
  };

  const activeCh = channels.find((c) => c.id === active);
  const sortedUsers = [...users].sort((a, b) => (online.has(b.id) ? 1 : 0) - (online.has(a.id) ? 1 : 0));
  const onlineCount = users.filter((u) => online.has(u.id)).length;

  return (
    <div className="page-fill">
      <h2 className="page-title">채팅</h2>
      <div className="chat-layout card">
        {/* 채널 목록 */}
        <div className="ch-list">
          <div className="ch-list-head">채널</div>
          {channels.map((c) => (
            <div key={c.id} className={"ch-item" + (active === c.id ? " on" : "")} onClick={() => setActive(c.id)}>
              <div className="ch-item-row">
                <span className="ch-name"># {c.name}</span>
                {unread[c.id] > 0 && active !== c.id && <span className="badge sm">{unread[c.id]}</span>}
              </div>
              <div className="ch-desc">{c.description}</div>
            </div>
          ))}
        </div>

        {/* 메시지 영역 */}
        <div className="ch-main">
          <div className="ch-header">
            <span># {activeCh?.name}</span>
            <span className="ch-desc">{activeCh?.description}</span>
          </div>
          <div className="ch-messages" ref={listRef}>
            {messages.map((m, i) => {
              const prev = messages[i - 1];
              const mine = m.user.id === user.id;
              const newDay = !prev || kstDayKey(prev.created_at) !== kstDayKey(m.created_at);
              const grouped = prev && !newDay && prev.user.id === m.user.id &&
                (new Date(m.created_at) - new Date(prev.created_at) < 5 * 60 * 1000);
              return (
                <React.Fragment key={m.id}>
                  {newDay && <div className="day-sep"><span>{dayLabel(m.created_at)}</span></div>}
                  <div className={"chatline" + (mine ? " mine" : "") + (grouped ? " grouped" : "")}>
                    <div className="chatline-av">{!grouped && <Avatar user={m.user} size={36} showStatus />}</div>
                    <div className="chatline-body">
                      {!grouped && (
                        <div className="chatline-head">
                          <span className="chatline-name" style={{ color: TEAM_COLOR[m.user.team] }}>{m.user.display_name}</span>
                          <span className="chatline-role">{m.user.team}</span>
                          <span className="chatline-time">{fmtTime(m.created_at)}</span>
                        </div>
                      )}
                      {m.body && <div className="chatline-bubble">{m.body}</div>}
                      {m.image_url && <img className="msg-img" src={m.image_url} alt="첨부 이미지" onClick={() => window.open(m.image_url, "_blank")} />}
                      {m.event && <EventCardMini event={m.event} />}
                    </div>
                  </div>
                </React.Fragment>
              );
            })}
            {messages.length === 0 && <div className="empty">첫 메시지를 남겨보세요.</div>}
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
                   placeholder={uploading ? "이미지 업로드 중..." : `#${activeCh?.name || ""} 에 메시지 보내기`}
                   onKeyDown={(e) => e.key === "Enter" && send()} />
            <button className="btn" onClick={send}>전송</button>
          </div>
        </div>

        {/* 멤버/접속자 */}
        <div className="ch-members">
          <div className="ch-list-head">멤버 · 접속 {onlineCount}/{users.length}</div>
          {sortedUsers.map((u) => (
            <div key={u.id} className={"member" + (online.has(u.id) ? "" : " off")}>
              <Avatar user={u} size={30} showStatus />
              <div className="member-info">
                <div className="member-name">{u.display_name}{u.id === user.id && <span className="me-tag">나</span>}</div>
                <div className="member-team" style={{ color: TEAM_COLOR[u.team] }}>{u.role}</div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

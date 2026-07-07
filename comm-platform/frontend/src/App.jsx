import React, { useEffect, useRef, useState } from "react";
import { NavLink, Navigate, Route, Routes, useNavigate } from "react-router-dom";
import { api, onWS } from "./api.js";
import { useAuth } from "./auth.jsx";
import { setOnline, incUnread, getActiveChannel, getActiveDM, useChatUnread } from "./presence.js";
import { pushNotif, markAllRead, clearNotifs, useNotifs } from "./notif.js";
import { useTheme } from "./theme.js";
import {
  LayoutDashboard, ShieldAlert, Activity, Fingerprint, ClipboardList, Crosshair,
  MessagesSquare, MessageCircle, Mail as MailIcon, Bell, Sun, Moon, Search,
} from "lucide-react";
import Avatar from "./components/Avatar.jsx";
import CommandPalette from "./components/CommandPalette.jsx";

const NAV = [
  { to: "/", label: "대시보드", icon: LayoutDashboard, group: "보안 운영", end: true },
  { to: "/events", label: "티켓 관리", icon: ShieldAlert, group: "보안 운영" },
  { to: "/progress", label: "티켓 진척", icon: Activity, group: "보안 운영" },
  { to: "/iocs", label: "IOC 관리", icon: Fingerprint, group: "보안 운영" },
  { to: "/ledger", label: "탐지이력 대장", icon: ClipboardList, group: "보안 운영" },
  { to: "/mitre", label: "ATT&CK", icon: Crosshair, group: "보안 운영" },
  { to: "/chat", label: "채팅", icon: MessagesSquare, group: "협업" },
  { to: "/dm", label: "메시지", icon: MessageCircle, group: "협업" },
  { to: "/mail", label: "사내 메일", icon: MailIcon, group: "협업" },
];
const NAV_GROUPS = ["보안 운영", "협업"];
import Login from "./pages/Login.jsx";
import Dashboard from "./pages/Dashboard.jsx";
import Events from "./pages/Events.jsx";
import Progress from "./pages/Progress.jsx";
import Iocs from "./pages/Iocs.jsx";
import Ledger from "./pages/Ledger.jsx";
import Mitre from "./pages/Mitre.jsx";
import Chat from "./pages/Chat.jsx";
import Dm from "./pages/Dm.jsx";
import Mail from "./pages/Mail.jsx";

const TEAM_COLOR = { 보안관제팀: "#2563eb", 웹관리자: "#7c3aed", 정보보호팀: "#0f9d6b" };

function timeAgo(iso) {
  const s = Math.floor((Date.now() - new Date(iso)) / 1000);
  if (s < 60) return "방금";
  if (s < 3600) return `${Math.floor(s / 60)}분 전`;
  if (s < 86400) return `${Math.floor(s / 3600)}시간 전`;
  return `${Math.floor(s / 86400)}일 전`;
}

function ThemeToggle() {
  const { theme, toggle } = useTheme();
  return (
    <button className="bell-btn" onClick={toggle} title={theme === "dark" ? "라이트 모드" : "다크 모드"}>
      {theme === "dark" ? <Sun size={19} /> : <Moon size={19} />}
    </button>
  );
}

function NotifBell() {
  const nav = useNavigate();
  const notifs = useNotifs();
  const [open, setOpen] = useState(false);
  const ref = useRef(null);
  const unread = notifs.filter((n) => !n.read).length;

  useEffect(() => {
    const close = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false); };
    document.addEventListener("mousedown", close);
    return () => document.removeEventListener("mousedown", close);
  }, []);

  const toggle = () => {
    const next = !open;
    setOpen(next);
    if (next && unread > 0) setTimeout(markAllRead, 1200);
  };

  return (
    <div className="bell-wrap" ref={ref}>
      <button className="bell-btn" onClick={toggle} title="알림">
        <Bell size={19} />
        {unread > 0 && <span className="bell-badge">{unread}</span>}
      </button>
      {open && (
        <div className="notif-dropdown">
          <div className="notif-head">
            <span>알림</span>
            {notifs.length > 0 && <button className="notif-clear" onClick={clearNotifs}>모두 지우기</button>}
          </div>
          <div className="notif-list">
            {notifs.length === 0 && <div className="empty">새 알림이 없습니다.</div>}
            {notifs.map((n) => (
              <div key={n.id} className={"notif-item" + (n.read ? "" : " unread")}
                   onClick={() => { if (n.link) nav(n.link); setOpen(false); }}>
                <span className={"notif-dot " + n.type} />
                <div className="notif-body">
                  <div className="notif-text">{n.text}</div>
                  <div className="notif-time">{timeAgo(n.ts)}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function Layout({ children }) {
  const { user, logout } = useAuth();
  const nav = useNavigate();
  const [unread, setUnread] = useState(0);
  const [dmUnread, setDmUnread] = useState(0);
  const [toast, setToast] = useState(null);
  const [cmdOpen, setCmdOpen] = useState(false);
  const chatUnread = useChatUnread();
  const chatTotal = Object.values(chatUnread).reduce((a, b) => a + b, 0);

  useEffect(() => {
    const onKey = (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setCmdOpen((v) => !v);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const refreshUnread = () => api(`/api/mail/unread_count?user_id=${user.id}`).then((d) => setUnread(d.unread)).catch(() => {});
  const refreshDm = () => api(`/api/dm/unread_count?user_id=${user.id}`).then((d) => setDmUnread(d.unread)).catch(() => {});

  useEffect(() => {
    refreshUnread();
    refreshDm();
    api("/api/presence").then((d) => setOnline(d.online)).catch(() => {});
    const onRead = () => refreshDm();
    window.addEventListener("dm-read", onRead);
    const onMailRead = () => refreshUnread();   // 메일 읽으면 안읽음 배지 갱신
    window.addEventListener("mail-read", onMailRead);
    const off = onWS((msg) => {
      if (msg.type === "force_logout") {
        localStorage.setItem("comm_logout_reason", msg.reason || "다른 위치에서 로그인되었습니다.");
        logout();
        nav("/login");
      } else if (msg.type === "presence") {
        setOnline(msg.online);
      } else if (msg.type === "new_mail" && msg.recipient_id === user.id) {
        refreshUnread();
        showToast(`새 메일: ${msg.mail.subject}`);
        pushNotif({ type: "mail", text: `새 메일 · ${msg.mail.sender}: ${msg.mail.subject}`, link: "/mail" });
      } else if (msg.type === "new_event") {
        showToast(`신규 정탐: ${msg.event.signature} (${msg.event.src_ip})`);
        pushNotif({ type: "event", text: `신규 정탐 · ${msg.event.signature} (${msg.event.src_ip})`, link: "/events" });
      } else if (msg.type === "ticket_status") {
        // 이관 자동 알림 — 정탐 판정(→대응)은 정보보호·웹관리자, 대응완료(→승인대기)는 정보보호에게
        const ev = msg.event;
        let text = null;
        if (ev.status === "검토" && user.team === "정보보호팀") {
          text = `정탐 판정 · 정보보호 검토 이관 — ${ev.signature} (${ev.ticket_no})`;
        } else if (ev.status === "대응" && ev.assignee_team !== "정보보호팀" && user.team === "웹관리자") {
          text = `정보보호 대응 요청 — ${ev.signature} (${ev.ticket_no})`;
        } else if (ev.status === "승인대기" && user.team === "정보보호팀") {
          text = `대응 완료 · 최종 승인 요청 — ${ev.signature} (${ev.ticket_no})`;
        } else if (ev.status === "오탐요청" && user.team === "정보보호팀") {
          text = `오탐 종결 승인 요청 — ${ev.signature} (${ev.ticket_no})`;
        } else if (ev.status === "무시종결요청" && user.team === "정보보호팀") {
          text = `무시 종결 승인 요청 — ${ev.signature} (${ev.ticket_no})`;
        }
        if (text) { showToast(text); pushNotif({ type: "event", text, link: "/events" }); }
      } else if (msg.type === "chat_message") {
        const m = msg.message;
        if (m.user.id !== user.id && String(msg.channel_id) !== getActiveChannel()) {
          incUnread(msg.channel_id);
        }
      } else if (msg.type === "dm" && msg.recipient_id === user.id) {
        refreshDm();
        if (String(msg.sender_id) !== getActiveDM()) {
          showToast(`${msg.message.sender.display_name}님의 메시지`);
          pushNotif({ type: "dm", text: `${msg.message.sender.display_name}: ${msg.message.body}`, link: "/dm" });
        }
      }
    });
    return () => { off(); window.removeEventListener("dm-read", onRead); window.removeEventListener("mail-read", onMailRead); };
  }, [user.id]);

  let toastTimer;
  const showToast = (text) => {
    setToast(text);
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => setToast(null), 4000);
  };

  const linkClass = ({ isActive }) => "nav-link" + (isActive ? " active" : "");
  const badges = { "/chat": chatTotal, "/dm": dmUnread, "/mail": unread };

  return (
    <div className="layout">
      <aside className="sidebar">
        <div className="ws">
          <div className="ws-mark">보</div>
          <div className="ws-text">
            <div className="ws-name">내부 소통플랫폼</div>
            <div className="ws-sub">보안 협업</div>
          </div>
        </div>
        <nav>
          {NAV_GROUPS.map((g) => (
            <div className="nav-group" key={g}>
              <div className="nav-group-label">{g}</div>
              {NAV.filter((n) => n.group === g).map((n) => {
                const Icon = n.icon;
                const b = badges[n.to] || 0;
                return (
                  <NavLink key={n.to} to={n.to} end={n.end} className={linkClass}>
                    <Icon size={17} /><span className="nav-label">{n.label}</span>
                    {b > 0 && <span className="badge">{b}</span>}
                  </NavLink>
                );
              })}
            </div>
          ))}
        </nav>
        <div className="sidebar-foot">
          <div className="me">
            <Avatar user={user} size={38} showStatus />
            <div className="me-info">
              <div className="me-name">{user.display_name}</div>
              <div className="me-team" style={{ color: TEAM_COLOR[user.team] || "#9fb6cc" }}>
                {user.team} · {user.role}
              </div>
            </div>
          </div>
          <button className="btn-ghost" onClick={() => { logout(); nav("/login"); }}>로그아웃</button>
        </div>
      </aside>

      <header className="topbar">
        <button className="cmdk-trigger" onClick={() => setCmdOpen(true)}>
          <Search size={15} />
          <span>검색 또는 이동...</span>
          <kbd className="cmdk-kbd">Ctrl K</kbd>
        </button>
        <div className="topbar-right">
          <ThemeToggle />
          <NotifBell />
        </div>
      </header>
      <main className="content">{children}</main>
      {toast && <div className="toast">{toast}</div>}
      <CommandPalette open={cmdOpen} onClose={() => setCmdOpen(false)} />
    </div>
  );
}

function Protected({ children }) {
  const { user } = useAuth();
  if (!user) return <Navigate to="/login" replace />;
  return <Layout>{children}</Layout>;
}

export default function App() {
  const { user } = useAuth();
  return (
    <Routes>
      <Route path="/login" element={user ? <Navigate to="/" replace /> : <Login />} />
      <Route path="/" element={<Protected><Dashboard /></Protected>} />
      <Route path="/events" element={<Protected><Events /></Protected>} />
      <Route path="/progress" element={<Protected><Progress /></Protected>} />
      <Route path="/iocs" element={<Protected><Iocs /></Protected>} />
      <Route path="/ledger" element={<Protected><Ledger /></Protected>} />
      <Route path="/mitre" element={<Protected><Mitre /></Protected>} />
      <Route path="/chat" element={<Protected><Chat /></Protected>} />
      <Route path="/dm" element={<Protected><Dm /></Protected>} />
      <Route path="/mail" element={<Protected><Mail /></Protected>} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}

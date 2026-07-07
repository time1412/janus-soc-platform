import React, { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  LayoutDashboard, ShieldAlert, Activity, Fingerprint, ClipboardList, Crosshair,
  MessagesSquare, MessageCircle, Mail, Plus, SunMoon, LogOut, CornerDownLeft,
} from "lucide-react";
import { useAuth } from "../auth.jsx";
import { useTheme } from "../theme.js";

const PAGES = [
  { label: "대시보드", to: "/", icon: LayoutDashboard },
  { label: "티켓 관리", to: "/events", icon: ShieldAlert },
  { label: "티켓 진척", to: "/progress", icon: Activity },
  { label: "IOC 관리", to: "/iocs", icon: Fingerprint },
  { label: "탐지이력 대장", to: "/ledger", icon: ClipboardList },
  { label: "MITRE ATT&CK", to: "/mitre", icon: Crosshair },
  { label: "채팅", to: "/chat", icon: MessagesSquare },
  { label: "메시지(DM)", to: "/dm", icon: MessageCircle },
  { label: "사내 메일", to: "/mail", icon: Mail },
];

export default function CommandPalette({ open, onClose }) {
  const nav = useNavigate();
  const { toggle } = useTheme();
  const { logout } = useAuth();
  const [q, setQ] = useState("");
  const [sel, setSel] = useState(0);
  const inputRef = useRef(null);

  const items = useMemo(() => {
    const pages = PAGES.map((p) => ({ ...p, group: "이동" }));
    const actions = [
      { label: "새 메일 작성", group: "액션", icon: Plus, run: () => nav("/mail?compose=1") },
      { label: "테마 전환 (라이트/다크)", group: "액션", icon: SunMoon, run: toggle },
      { label: "로그아웃", group: "액션", icon: LogOut, run: () => { logout(); nav("/login"); } },
    ];
    return [...pages.map((p) => ({ ...p, run: () => nav(p.to) })), ...actions];
  }, [nav, toggle, logout]);

  const filtered = items.filter((i) => i.label.toLowerCase().includes(q.trim().toLowerCase()));

  useEffect(() => {
    if (open) {
      setQ(""); setSel(0);
      setTimeout(() => inputRef.current?.focus(), 0);
    }
  }, [open]);

  useEffect(() => { setSel(0); }, [q]);

  if (!open) return null;

  const choose = (i) => { i?.run?.(); onClose(); };

  const onKey = (e) => {
    if (e.key === "ArrowDown") { e.preventDefault(); setSel((s) => Math.min(s + 1, filtered.length - 1)); }
    else if (e.key === "ArrowUp") { e.preventDefault(); setSel((s) => Math.max(s - 1, 0)); }
    else if (e.key === "Enter") { e.preventDefault(); choose(filtered[sel]); }
    else if (e.key === "Escape") { e.preventDefault(); onClose(); }
  };

  let lastGroup = null;

  return (
    <div className="cmdk-back" onClick={onClose}>
      <div className="cmdk" onClick={(e) => e.stopPropagation()}>
        <input
          ref={inputRef} className="cmdk-input" value={q} onChange={(e) => setQ(e.target.value)}
          onKeyDown={onKey} placeholder="페이지 이동 또는 명령 검색..."
        />
        <div className="cmdk-list">
          {filtered.length === 0 && <div className="cmdk-empty">결과 없음</div>}
          {filtered.map((i, idx) => {
            const Icon = i.icon;
            const showGroup = i.group !== lastGroup;
            lastGroup = i.group;
            return (
              <React.Fragment key={i.label}>
                {showGroup && <div className="cmdk-group">{i.group}</div>}
                <div
                  className={"cmdk-item" + (idx === sel ? " on" : "")}
                  onMouseEnter={() => setSel(idx)} onClick={() => choose(i)}
                >
                  <Icon size={16} />
                  <span>{i.label}</span>
                  {idx === sel && <CornerDownLeft size={14} className="cmdk-enter" />}
                </div>
              </React.Fragment>
            );
          })}
        </div>
        <div className="cmdk-foot">
          <span><kbd>↑</kbd><kbd>↓</kbd> 이동</span>
          <span><kbd>↵</kbd> 선택</span>
          <span><kbd>Esc</kbd> 닫기</span>
        </div>
      </div>
    </div>
  );
}

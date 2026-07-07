// 접속 현황(presence) + 채팅 안읽음 — 가벼운 구독형 스토어
import { useEffect, useState } from "react";

// ── 온라인 사용자 ──
let online = new Set();
const onlineSubs = new Set();

export function setOnline(ids) {
  online = new Set(ids);
  onlineSubs.forEach((fn) => fn(online));
}
export function useOnline() {
  const [o, setO] = useState(online);
  useEffect(() => {
    onlineSubs.add(setO);
    return () => onlineSubs.delete(setO);
  }, []);
  return o;
}

// ── 채팅 안읽음(채널별) ──
const KEY = "comm_chat_unread";
const ACTIVE = "comm_active_channel";

function read() {
  try {
    return JSON.parse(localStorage.getItem(KEY) || "{}");
  } catch {
    return {};
  }
}
function write(o) {
  localStorage.setItem(KEY, JSON.stringify(o));
  window.dispatchEvent(new Event("chat-unread"));
}
export function incUnread(channelId) {
  const o = read();
  o[channelId] = (o[channelId] || 0) + 1;
  write(o);
}
export function clearUnread(channelId) {
  const o = read();
  if (o[channelId]) {
    delete o[channelId];
    write(o);
  }
}
export function setActiveChannel(channelId) {
  if (channelId == null) localStorage.removeItem(ACTIVE);
  else localStorage.setItem(ACTIVE, String(channelId));
}
export function getActiveChannel() {
  return localStorage.getItem(ACTIVE);
}
export function useChatUnread() {
  const [m, setM] = useState(read());
  useEffect(() => {
    const fn = () => setM(read());
    window.addEventListener("chat-unread", fn);
    return () => window.removeEventListener("chat-unread", fn);
  }, []);
  return m;
}

// ── DM 현재 보고 있는 상대 (읽음 처리 판단용) ──
const DM_ACTIVE = "comm_active_dm";
export function setActiveDM(partnerId) {
  if (partnerId == null) localStorage.removeItem(DM_ACTIVE);
  else localStorage.setItem(DM_ACTIVE, String(partnerId));
}
export function getActiveDM() {
  return localStorage.getItem(DM_ACTIVE);
}

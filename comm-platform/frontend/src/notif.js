// 알림 센터 — localStorage 기반 구독형 스토어
import { useEffect, useState } from "react";

const KEY = "comm_notifs";
const MAX = 50;

function read() {
  try {
    return JSON.parse(localStorage.getItem(KEY) || "[]");
  } catch {
    return [];
  }
}
function write(arr) {
  localStorage.setItem(KEY, JSON.stringify(arr.slice(0, MAX)));
  window.dispatchEvent(new Event("notifs"));
}

export function pushNotif(n) {
  const arr = read();
  const id = `${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
  arr.unshift({ id, read: false, ts: new Date().toISOString(), ...n });
  write(arr);
}
export function markAllRead() {
  write(read().map((n) => ({ ...n, read: true })));
}
export function clearNotifs() {
  write([]);
}
export function useNotifs() {
  const [a, setA] = useState(read());
  useEffect(() => {
    const fn = () => setA(read());
    window.addEventListener("notifs", fn);
    return () => window.removeEventListener("notifs", fn);
  }, []);
  return a;
}

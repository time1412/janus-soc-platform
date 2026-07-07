// REST 헬퍼 + WebSocket 실시간 버스

export async function api(path, opts = {}) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    method: opts.method || (opts.body ? "POST" : "GET"),
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  if (!res.ok) {
    let detail = res.statusText;
    try {
      detail = (await res.json()).detail || detail;
    } catch {}
    throw new Error(detail);
  }
  if (res.status === 204) return null;
  return res.json();
}

// 이미지 업로드 (multipart)
export async function uploadFile(file) {
  const fd = new FormData();
  fd.append("file", file);
  const res = await fetch("/api/upload", { method: "POST", body: fd });
  if (!res.ok) {
    let detail = "업로드 실패";
    try { detail = (await res.json()).detail || detail; } catch {}
    throw new Error(detail);
  }
  return res.json(); // { url, name, size }
}

// ── WebSocket 실시간 알림 ──
let ws = null;
let pingTimer = null;
let wsUserId = null;
let intentional = false; // 의도적 종료(로그아웃/강제로그아웃) 시 자동 재연결 방지
const listeners = new Set();

export function connectWS(userId) {
  intentional = false;
  if (userId != null) wsUserId = userId;
  if (ws && (ws.readyState === WebSocket.CONNECTING || ws.readyState === WebSocket.OPEN)) return;
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const suffix = wsUserId != null ? `?user_id=${wsUserId}` : "";
  ws = new WebSocket(`${proto}://${location.host}/ws${suffix}`);
  ws.onopen = () => {
    clearInterval(pingTimer);
    pingTimer = setInterval(() => {
      if (ws?.readyState === WebSocket.OPEN) ws.send("ping");
    }, 25000);
  };
  ws.onmessage = (e) => {
    let data;
    try {
      data = JSON.parse(e.data);
    } catch {
      return;
    }
    listeners.forEach((fn) => fn(data));
  };
  ws.onclose = () => {
    clearInterval(pingTimer);
    if (!intentional) setTimeout(() => connectWS(), 2000); // 자동 재연결
  };
}

export function disconnectWS() {
  intentional = true;
  wsUserId = null;
  clearInterval(pingTimer);
  if (ws) {
    try { ws.close(); } catch {}
    ws = null;
  }
}

export function onWS(fn) {
  listeners.add(fn);
  return () => listeners.delete(fn);
}

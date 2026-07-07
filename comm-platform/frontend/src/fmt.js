// 모든 시각 표시를 Asia/Seoul 기준으로 통일
const TZ = "Asia/Seoul";

export const fmtDateTime = (iso) =>
  new Date(iso).toLocaleString("ko-KR", {
    timeZone: TZ, year: "numeric", month: "2-digit", day: "2-digit",
    hour: "2-digit", minute: "2-digit",
  });

export const fmtTime = (iso) =>
  new Date(iso).toLocaleTimeString("ko-KR", { timeZone: TZ, hour: "2-digit", minute: "2-digit" });

export const fmtDate = (iso) =>
  new Date(iso).toLocaleDateString("ko-KR", { timeZone: TZ });

// 'YYYY-MM-DD' (KST) — 날짜 비교/구분선용
export const kstDayKey = (iso) =>
  new Date(iso).toLocaleDateString("en-CA", { timeZone: TZ });

// 상대 시간 ("방금 / N분 전 / N시간 전 / N일 전"), 일주일 이상은 날짜
export function fmtRelative(iso) {
  if (!iso) return "";
  const s = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
  if (isNaN(s) || s < 0) return fmtDate(iso);
  if (s < 60) return "방금";
  if (s < 3600) return `${Math.floor(s / 60)}분 전`;
  if (s < 86400) return `${Math.floor(s / 3600)}시간 전`;
  if (s < 604800) return `${Math.floor(s / 86400)}일 전`;
  return fmtDate(iso);
}

// 라이트/다크 테마 토글 (localStorage 보관, index.html에서 초기 적용)
import { useState } from "react";

export function getTheme() {
  return document.documentElement.dataset.theme === "dark" ? "dark" : "light";
}

function applyTheme(t) {
  document.documentElement.dataset.theme = t;
  try { localStorage.setItem("comm_theme", t); } catch {}
}

export function useTheme() {
  const [theme, setTheme] = useState(getTheme());
  const toggle = () => {
    const next = theme === "dark" ? "light" : "dark";
    applyTheme(next);
    setTheme(next);
  };
  return { theme, toggle };
}

import React from "react";

// 소프트 틴티드 라벨 (Linear/GitHub 스타일) — 색조 배경 + 동색 텍스트 + 점
export default function Badge({ color = "#6b7280", children, dot = true }) {
  return (
    <span className="badge-soft" style={{ color, background: color + "1f" }}>
      {dot && <span className="badge-dot" style={{ background: color }} />}
      {children}
    </span>
  );
}

import React, { useEffect, useState } from "react";
import axios from "axios";

// 사이버 위기 경보단계 게이지 (카드 없이 — 다른 패널 안에 삽입용)
const ORDER = ["정상", "관심", "주의", "경계", "심각"];
const COLORS = { 정상: "#18a39a", 관심: "#2b6fb0", 주의: "#d6a221", 경계: "#dd6b20", 심각: "#c5342f" };
const CX = 150, CY = 156, R_OUT = 138, R_IN = 74, R_MID = (138 + 74) / 2;
const pt = (r, deg) => { const a = (deg * Math.PI) / 180; return [CX + r * Math.cos(a), CY - r * Math.sin(a)]; };
const sector = (a1, a2) => {
  const [ox1, oy1] = pt(R_OUT, a1), [ox2, oy2] = pt(R_OUT, a2), [ix2, iy2] = pt(R_IN, a2), [ix1, iy1] = pt(R_IN, a1);
  return `M ${ox1} ${oy1} A ${R_OUT} ${R_OUT} 0 0 1 ${ox2} ${oy2} L ${ix2} ${iy2} A ${R_IN} ${R_IN} 0 0 0 ${ix1} ${iy1} Z`;
};

export default function CrisisGauge() {
  const [d, setD] = useState(null);
  useEffect(() => {
    const load = () => axios.get("/api/crisis-level").then((r) => setD(r.data)).catch(() => {});
    load();
    const t = setInterval(load, 30 * 60 * 1000);
    return () => clearInterval(t);
  }, []);
  if (!d) return null;
  const cur = d.level;

  return (
    <div className="crisis-gauge-wrap">
      <div className="crisis-gauge-label">사이버 위기 경보단계</div>
      <svg className="crisis-gauge-svg" viewBox="0 0 300 168">
        <defs>
          <filter id="crisisGlow2" x="-30%" y="-30%" width="160%" height="160%">
            <feDropShadow dx="0" dy="0" stdDeviation="4" floodColor="#ffffff" floodOpacity="0.9" />
          </filter>
        </defs>
        {ORDER.map((lv, i) => {
          const g = 1.6, a1 = 180 - 36 * i - g, a2 = 180 - 36 * (i + 1) + g, active = lv === cur;
          return (
            <path key={lv} d={sector(a1, a2)} fill={COLORS[lv]} opacity={active ? 1 : 0.82}
              stroke={active ? "#fff" : "rgba(8,18,28,0.85)"} strokeWidth={active ? 3 : 1}
              filter={active ? "url(#crisisGlow2)" : undefined} />
          );
        })}
        {ORDER.map((lv, i) => {
          const mid = 180 - 36 * i - 18;
          const [lx, ly] = pt(R_MID, mid);
          const active = lv === cur;
          return (
            <text key={lv + "t"} x={lx} y={ly} textAnchor="middle" dominantBaseline="central"
              fontSize="15" fontWeight={active ? 800 : 600} fill="#fff" opacity={active ? 1 : 0.92}>{lv}</text>
          );
        })}
      </svg>
      <div className="crisis-now">
        <span className="crisis-dot" style={{ background: COLORS[cur] }} />
        현재 <b style={{ color: COLORS[cur] }}>&nbsp;{cur}&nbsp;</b>
        <span className="crisis-eng">({d.eng})</span>
      </div>
    </div>
  );
}

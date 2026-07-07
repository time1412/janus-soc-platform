import React, { useEffect, useState } from "react";
import axios from "axios";

// 기관 보안 권고·공지 (백엔드 /api/dashboard/advisories — KrCERT 보안공지)
export default function AdvisoryPanel() {
  const [items, setItems] = useState(null);
  const [open, setOpen] = useState(true);

  useEffect(() => {
    const load = () =>
      axios.get("/api/dashboard/advisories").then((r) => setItems(r.data.items || [])).catch(() => setItems([]));
    load();
    const t = setInterval(load, 30 * 60 * 1000);
    return () => clearInterval(t);
  }, []);

  return (
    <div className={"dash-card" + (open ? "" : " is-collapsed")}>
      <div className="dash-card-head" onClick={() => setOpen((o) => !o)}>
        <span>기관 보안 권고 · 공지</span>
        <span className="card-meta">
          <span className="dash-sub">KrCERT</span>
          <span className="card-chevron">▼</span>
        </span>
      </div>
      <div className="card-collapse"><div className="card-collapse-in">
        <div className="dash-list">
          {items === null && <div className="dash-empty">불러오는 중…</div>}
          {items && items.length === 0 && <div className="dash-empty">표시할 공지가 없습니다 (인터넷 연결 확인)</div>}
          {items && items.map((n, i) => (
            <a key={i} className="dash-item" href={n.link} target="_blank" rel="noreferrer" title={n.title}>
              <span className="dash-item-dot adv" />
              <span className="dash-item-title">{n.title}</span>
            </a>
          ))}
        </div>
      </div></div>
    </div>
  );
}

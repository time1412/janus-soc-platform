import React, { useEffect, useState } from "react";
import axios from "axios";

// 보안 뉴스 헤드라인 (백엔드 /api/dashboard/news — 보안뉴스 RSS)
export default function SecurityNewsPanel() {
  const [items, setItems] = useState(null);
  const [open, setOpen] = useState(true);

  useEffect(() => {
    const load = () =>
      axios.get("/api/dashboard/news").then((r) => setItems(r.data.items || [])).catch(() => setItems([]));
    load();
    const t = setInterval(load, 30 * 60 * 1000);
    return () => clearInterval(t);
  }, []);

  return (
    <div className={"dash-card" + (open ? "" : " is-collapsed")}>
      <div className="dash-card-head" onClick={() => setOpen((o) => !o)}>
        <span>보안 뉴스</span>
        <span className="card-meta">
          <span className="dash-sub">보안뉴스</span>
          <span className="card-chevron">▼</span>
        </span>
      </div>
      <div className="card-collapse"><div className="card-collapse-in">
        <div className="dash-list">
          {items === null && <div className="dash-empty">불러오는 중…</div>}
          {items && items.length === 0 && <div className="dash-empty">표시할 뉴스가 없습니다 (인터넷 연결 확인)</div>}
          {items && items.map((n, i) => (
            <a key={i} className="dash-item" href={n.link} target="_blank" rel="noreferrer" title={n.title}>
              <span className="dash-item-dot" />
              <span className="dash-item-title">{n.title}</span>
              {n.date && <span className="dash-item-date">{n.date}</span>}
            </a>
          ))}
        </div>
      </div></div>
    </div>
  );
}

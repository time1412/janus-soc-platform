import React, { useEffect, useState } from "react";
import axios from "axios";

// 보안 뉴스 + 기관 권고를 탭 하나로 통합
export default function FeedsPanel() {
  const [tab, setTab] = useState("news");
  const [news, setNews] = useState(null);
  const [adv, setAdv] = useState(null);
  const [open, setOpen] = useState(true);

  useEffect(() => {
    const load = () => {
      axios.get("/api/dashboard/news").then((r) => setNews(r.data.items || [])).catch(() => setNews([]));
      axios.get("/api/dashboard/advisories").then((r) => setAdv(r.data.items || [])).catch(() => setAdv([]));
    };
    load();
    const t = setInterval(load, 30 * 60 * 1000);
    return () => clearInterval(t);
  }, []);

  const items = tab === "news" ? news : adv;

  return (
    <div className={"dash-card" + (open ? "" : " is-collapsed")}>
      <div className="dash-card-head feeds-head">
        <span className="feeds-tabs">
          <button type="button" className={"feeds-tab" + (tab === "news" ? " on" : "")}
                  onClick={() => setTab("news")}>보안 뉴스</button>
          <button type="button" className={"feeds-tab" + (tab === "adv" ? " on" : "")}
                  onClick={() => setTab("adv")}>기관 권고 · 공지</button>
        </span>
        <span className="card-meta">
          <span className="dash-sub">{tab === "news" ? "보안뉴스" : "KrCERT"}</span>
          <span className="card-chevron" style={{ cursor: "pointer" }} onClick={() => setOpen((o) => !o)}>▼</span>
        </span>
      </div>
      <div className="card-collapse"><div className="card-collapse-in">
        <div className="dash-list feeds-list">
          {items === null && <div className="dash-empty">불러오는 중…</div>}
          {items && items.length === 0 && <div className="dash-empty">표시할 항목이 없습니다 (인터넷 연결 확인)</div>}
          {items && items.map((n, i) => (
            <a key={i} className="dash-item" href={n.link} target="_blank" rel="noreferrer" title={n.title}>
              <span className={"dash-item-dot" + (tab === "adv" ? " adv" : "")} />
              <span className="dash-item-title">{n.title}</span>
              {n.date && <span className="dash-item-date">{n.date}</span>}
            </a>
          ))}
        </div>
      </div></div>
    </div>
  );
}

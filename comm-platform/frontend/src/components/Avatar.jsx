import React from "react";
import { useOnline } from "../presence.js";

const TEAM_COLOR = { 보안관제팀: "#2563eb", 정보보호팀: "#0f9d6b" };

export default function Avatar({ user, size = 34, showStatus = false }) {
  const online = useOnline();
  if (!user) return null;
  const initial = (user.display_name || user.username || "?").trim().slice(0, 1);
  const color = TEAM_COLOR[user.team] || "#8aa6c0";
  const isOn = online.has(user.id);
  return (
    <div className="avatar" style={{ width: size, height: size, fontSize: Math.round(size * 0.42) }}>
      <span className="avatar-circle" style={{ background: color + "26", color, borderColor: color + "55" }}>
        {initial}
      </span>
      {showStatus && <span className={"av-dot " + (isOn ? "on" : "off")} title={isOn ? "온라인" : "오프라인"} />}
    </div>
  );
}

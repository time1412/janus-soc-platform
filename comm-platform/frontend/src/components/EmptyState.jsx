import React from "react";

export default function EmptyState({ icon: Icon, title, desc, action }) {
  return (
    <div className="empty-state">
      {Icon && <Icon size={26} className="empty-ico" strokeWidth={1.6} />}
      {title && <div className="empty-title">{title}</div>}
      {desc && <div className="empty-desc">{desc}</div>}
      {action && <div className="empty-action">{action}</div>}
    </div>
  );
}

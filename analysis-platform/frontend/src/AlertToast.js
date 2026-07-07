import React from "react";

const SEV = {
  3: { color: "#dc4e41", bg: "#1a0808", label: "⚠ HIGH ALERT" },
  2: { color: "#f8be34", bg: "#181200", label: "▲ MEDIUM" },
  1: { color: "#53a051", bg: "#081408", label: "● LOW" },
};

export default function AlertToast({ toasts, onDismiss }) {
  if (!toasts.length) return null;

  return (
    <div className="toast-container">
      {toasts.map((t) => {
        const s = SEV[t.severity] || SEV[1];
        return (
          <div
            key={t.id}
            className="alert-toast"
            style={{ borderLeftColor: s.color, background: s.bg }}
          >
            {/* 헤더: 위험도 + 닫기 */}
            <div className="toast-header">
              <span style={{ color: s.color, fontWeight: 700, fontSize: 11, letterSpacing: "0.05em" }}>
                {s.label}
              </span>
              <button className="toast-close" onClick={() => onDismiss(t.id)}>
                ✕
              </button>
            </div>

            {/* 시그니처 */}
            <div className="toast-sig">{t.signature}</div>

            {/* IP 경로 */}
            <div className="toast-ips">
              <span style={{ color: "#e06c75" }}>{t.src_ip}</span>
              <span style={{ color: "#4a6b85", margin: "0 5px" }}>→</span>
              <span style={{ color: "#9fb6cc" }}>{t.dest_ip}</span>
            </div>

            {/* URI (있을 때만) */}
            {t.uri && t.uri !== "/" && (
              <div className="toast-uri">{t.uri.slice(0, 50)}</div>
            )}

            {/* 발생 시각 */}
            <div className="toast-time">{t.timeStr}</div>
          </div>
        );
      })}
    </div>
  );
}

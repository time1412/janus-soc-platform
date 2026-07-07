import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import axios from "axios";
import GlobeComponent from "./GlobeComponent";
import ChatWidget from "./ChatWidget";
import ThreatTodayPanel from "./ThreatTodayPanel";
import FeedsPanel from "./FeedsPanel";
import ThreatIntelPanel from "./ThreatIntelPanel";
import InsightsPanel from "./InsightsPanel";
import ReportPanel from "./ReportPanel";
import TriagePanel from "./TriagePanel";
import RecordsPage from "./RecordsPage";
import AlertToast from "./AlertToast";

const API = "";

const TABS = [
  { id: "alerts",   label: "알림" },
  { id: "triage",   label: "정·오탐" },
  { id: "history",  label: "기록" },
  { id: "intel",    label: "인텔리전스" },
  { id: "insights", label: "인사이트" },
  { id: "report",   label: "보고서" },
];

function sevClass(sev) {
  const s = Number(sev) || 0;
  if (s >= 3) return "sev sev-high";
  if (s >= 2) return "sev sev-mid";
  return "sev sev-low";
}

function rowSev(sev) {
  const s = Number(sev) || 0;
  if (s >= 3) return "alert-row--high";
  if (s >= 2) return "alert-row--mid";
  return "alert-row--low";
}

// ── '진짜 같은 공격' 중복 로그 묶기 (최근 알림 표시용) ──
// 센서 접미사를 떼어 멀티센서 중복은 합치되, 페이로드(URI/본문)·표적·유형이 다르면 분리.
function baseSig(sig) {
  let s = (sig || "").toString();
  s = s.replace(/\s*\((?:snort|ids|waf)\)\s*$/i, "");          // "...(Snort)" 제거
  s = s.replace(/^\[yanus custom\]\s*\[[^\]]*\]\s*/i, "");      // "[YANUS CUSTOM] [..]" 제거
  return s.trim().toLowerCase();
}
function attackKey(a) {
  const t = a._time || a.Time || "";
  const ep = Date.parse(t);
  const bucket = isNaN(ep) ? t : Math.floor(ep / 1800000);     // 30분 윈도우
  const uri = (a.uri || "").split("#")[0].trim().toLowerCase();
  const body = (a.body || "").trim().toLowerCase();
  return [baseSig(a.signature || a.sourcetype), a.src_ip || "", a.dest_ip || "", uri, body, bucket].join("|");
}

// ── Web Audio API 경보음 ──────────────────────────────────────────
function playBeep(severity) {
  try {
    const ctx = new (window.AudioContext || window.webkitAudioContext)();
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.connect(gain);
    gain.connect(ctx.destination);
    osc.type = "sine";

    if (severity >= 3) {
      // HIGH: 두 번 짧은 고음 비프
      osc.frequency.setValueAtTime(1040, ctx.currentTime);
      gain.gain.setValueAtTime(0.35, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.25);
      osc.start(ctx.currentTime);
      osc.stop(ctx.currentTime + 0.25);

      const osc2 = ctx.createOscillator();
      const gain2 = ctx.createGain();
      osc2.connect(gain2);
      gain2.connect(ctx.destination);
      osc2.type = "sine";
      osc2.frequency.setValueAtTime(1040, ctx.currentTime + 0.35);
      gain2.gain.setValueAtTime(0.35, ctx.currentTime + 0.35);
      gain2.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.65);
      osc2.start(ctx.currentTime + 0.35);
      osc2.stop(ctx.currentTime + 0.65);
    } else {
      // MEDIUM: 한 번 낮은 음
      osc.frequency.setValueAtTime(660, ctx.currentTime);
      gain.gain.setValueAtTime(0.2, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.4);
      osc.start(ctx.currentTime);
      osc.stop(ctx.currentTime + 0.4);
    }
  } catch {
    // AudioContext 미지원 환경 무시
  }
}

// ── 브라우저 알림 ─────────────────────────────────────────────────
function requestNotifPermission() {
  if ("Notification" in window && Notification.permission === "default") {
    Notification.requestPermission();
  }
}

function fireBrowserNotif(event) {
  if (!("Notification" in window) || Notification.permission !== "granted") return;
  const sev = Number(event.severity);
  const title = sev >= 3 ? "⚠ HIGH 보안 경보" : "▲ MEDIUM 보안 이벤트";
  const body = `${event.signature}\n${event.src_ip || "?"} → ${event.dest_ip || "?"}`;
  try {
    new Notification(title, { body, tag: `soc-${event.src_ip}-${event.signature}` });
  } catch {}
}

// ── 이벤트 고유 키 ────────────────────────────────────────────────
function eventKey(a) {
  return `${a._time}|${a.src_ip}|${a.signature}`;
}

export default function App() {
  const [alerts, setAlerts] = useState([]);
  const [status, setStatus] = useState("연결 확인 중...");
  const [activeTab, setActiveTab] = useState("alerts");

  // 알림 토스트
  const [toasts, setToasts] = useState([]);
  const toastIdRef = useRef(0);

  // 미확인 HIGH 카운트 (탭이 백그라운드일 때 누적)
  const [unreadHigh, setUnreadHigh] = useState(0);
  const isPageVisible = useRef(true);

  // 첫 로드 여부: null=아직 첫 로드 전, Set=이미 로드됨
  const seenKeysRef = useRef(null);

  // ── 브라우저 알림 권한 요청 ───────────────────────────────────
  useEffect(() => {
    requestNotifPermission();

    const onVisible = () => {
      isPageVisible.current = !document.hidden;
      if (!document.hidden) {
        setUnreadHigh(0);
        document.title = "SOC 분석 플랫폼";
      }
    };
    document.addEventListener("visibilitychange", onVisible);
    return () => document.removeEventListener("visibilitychange", onVisible);
  }, []);

  // ── 토스트 추가/제거 ──────────────────────────────────────────
  const addToast = useCallback((event) => {
    const id = ++toastIdRef.current;
    const item = {
      id,
      severity: Number(event.severity),
      signature: event.signature || event.sourcetype || "이벤트",
      src_ip: event.src_ip || "?",
      dest_ip: event.dest_ip || "?",
      uri: event.uri || "",
      timeStr: event.Time || String(event._time || "").slice(0, 19),
    };
    setToasts((prev) => [...prev, item]);

    // HIGH 15초, MEDIUM 8초 후 자동 제거
    const delay = item.severity >= 3 ? 15000 : 8000;
    setTimeout(() => setToasts((p) => p.filter((t) => t.id !== id)), delay);
  }, []);

  const dismissToast = useCallback((id) => {
    setToasts((p) => p.filter((t) => t.id !== id));
  }, []);

  // ── 알림 폴링 ─────────────────────────────────────────────────
  const loadAlerts = useCallback(async () => {
    try {
      const { data } = await axios.get(`${API}/api/alerts`, {
        params: { earliest: "-24h" },
      });
      const rows = data.alerts || [];
      setAlerts(rows);
      setStatus(`스플렁크 연결됨 · 알림 ${data.count}건`);

      // 첫 로드: 기존 이벤트를 "이미 봄" 으로 등록만 하고 알림은 띄우지 않음
      if (seenKeysRef.current === null) {
        seenKeysRef.current = new Set(rows.map(eventKey));
        return;
      }

      // 신규 이벤트 탐지
      const newHighs = [];
      const newMeds = [];
      const nextSeen = new Set(seenKeysRef.current);

      rows.forEach((a) => {
        const k = eventKey(a);
        if (!seenKeysRef.current.has(k)) {
          nextSeen.add(k);
          const sev = Number(a.severity);
          if (sev >= 3) newHighs.push(a);
          else if (sev >= 2) newMeds.push(a);
        }
      });
      seenKeysRef.current = nextSeen;

      // HIGH 최대 3개 + MEDIUM 최대 1개만 토스트
      const toNotify = [...newHighs.slice(0, 3), ...newMeds.slice(0, 1)];
      if (toNotify.length === 0) return;

      // 경보음 (가장 높은 위험도 기준)
      const maxSev = Math.max(...toNotify.map((a) => Number(a.severity)));
      playBeep(maxSev);

      // 토스트 추가
      toNotify.forEach(addToast);

      // 브라우저 알림 (탭이 백그라운드일 때만)
      if (!isPageVisible.current) {
        fireBrowserNotif(toNotify[0]);
      }

      // 탭 타이틀 + 미확인 카운트
      if (!isPageVisible.current && newHighs.length > 0) {
        setUnreadHigh((n) => {
          const next = n + newHighs.length;
          document.title = `🔴 ${next}건 | SOC 분석 플랫폼`;
          return next;
        });
      }
    } catch {
      setStatus("스플렁크 연결 실패 — 백엔드/Splunk 설정을 확인하세요");
    }
  }, [addToast]);

  useEffect(() => {
    loadAlerts();
    const t = setInterval(loadAlerts, 30000);
    return () => clearInterval(t);
  }, [loadAlerts]);

  // 사이드바 표시용: 같은 공격의 중복 로그를 1행(×N)으로 묶음. 원본 alerts는 패널에 그대로 전달.
  const groupedAlerts = useMemo(() => {
    const map = new Map();
    const order = [];
    (alerts || []).forEach((a) => {
      const k = attackKey(a);
      if (!map.has(k)) { map.set(k, { ...a, _dupCount: 1 }); order.push(k); }
      else { map.get(k)._dupCount += 1; }
    });
    return order.map((k) => map.get(k));
  }, [alerts]);

  return (
    <div className={"app" + (activeTab === "history" ? " app--records" : "")}>
      <header className="app__header">
        <span className="app__title">🛡 SOC 분석 플랫폼</span>

        {/* 미확인 HIGH 배지 */}
        {unreadHigh > 0 && (
          <span className="unread-badge">🔴 HIGH {unreadHigh}건 미확인</span>
        )}

        <span className="app__status">{status}</span>
      </header>

      <aside className="side-pane">
        {/* 탭 바 */}
        <div className="tab-bar">
          {TABS.map((t) => (
            <button
              key={t.id}
              className={`tab-btn${activeTab === t.id ? " active" : ""}`}
              onClick={() => setActiveTab(t.id)}
            >
              {t.label}
            </button>
          ))}
        </div>

        {/* 알림 탭 — 스플렁크 대시보드의 '보안 이벤트 목록'(soc_base)과 동일 피드 */}
        {activeTab === "alerts" && (
          <>
            <h3 style={{ marginTop: 4, marginBottom: 10 }}>최근 알림</h3>
            {groupedAlerts.map((a, i) => (
              <div key={i} className={`alert-row ${rowSev(a.severity)}`}>
                <div style={{ display: "flex", alignItems: "center", gap: 6, flexWrap: "wrap" }}>
                  <span className={sevClass(a.severity)}>위험도 {a.severity ?? "-"}</span>
                  {(a.source || a.source_type) && <span className="src-tag">{a.source || a.source_type}</span>}
                  <strong>{a.signature || a.sourcetype || "이벤트"}</strong>
                  {a._dupCount > 1 && <span className="dup-badge" title={`동일 공격 로그 ${a._dupCount}건 묶음`}>×{a._dupCount}</span>}
                </div>
                <div style={{ fontSize: 12, color: "#9fb6cc", marginTop: 4 }}>
                  {a.asset
                    ? <>🖥 {a.asset}</>
                    : <>{a.src_ip || "?"}{a.src_port ? `:${a.src_port}` : ""} → {a.dest_ip || "?"}{a.dest_port ? `:${a.dest_port}` : ""}</>} · {a.Time || a._time || ""}
                </div>
              </div>
            ))}
            {groupedAlerts.length === 0 && (
              <p style={{ color: "#7da6c9" }}>표시할 알림이 없습니다.</p>
            )}
          </>
        )}

        {activeTab === "triage"   && <TriagePanel alerts={alerts} />}
        {activeTab === "history"  && (
          <p style={{ color: "#7da6c9", fontSize: 13, marginTop: 8, lineHeight: 1.7 }}>
            전체 탐지 기록을 오른쪽 데이터베이스 화면에서 조회·검색·페이지 이동하세요.
          </p>
        )}
        {activeTab === "intel"    && <ThreatIntelPanel alerts={alerts} />}
        {activeTab === "insights" && <InsightsPanel />}
        {activeTab === "report"   && <ReportPanel />}
      </aside>

      <main className="globe-pane">
        {activeTab === "history" ? (
          <RecordsPage tabs={TABS} activeTab={activeTab} onTab={setActiveTab} />
        ) : (
          <div className="dash">
            <div className="dash-stat">
              <ThreatTodayPanel alerts={alerts} />
            </div>
            <div className="dash-globe">
              <GlobeComponent alerts={alerts} />
            </div>
            <div className="dash-feeds">
              <FeedsPanel />
            </div>
          </div>
        )}
      </main>

      {/* 토스트 알림 */}
      <AlertToast toasts={toasts} onDismiss={dismissToast} />

      {/* 기록(전체 화면 표) 탭에서는 챗봇 버튼이 표를 가리므로 숨김 */}
      {activeTab !== "history" && <ChatWidget />}
    </div>
  );
}

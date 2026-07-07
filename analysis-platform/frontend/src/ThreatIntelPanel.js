import React, { useState } from "react";
import axios from "axios";

const API = "";

function RiskBadge({ score }) {
  const color = score >= 70 ? "#b3261e" : score >= 30 ? "#b8860b" : "#2e7d32";
  const label = score >= 70 ? "고위험" : score >= 30 ? "주의" : "정상";
  return (
    <span className="sev" style={{ background: color }}>
      {label} {score}/100
    </span>
  );
}

function TiRow({ label, value }) {
  return (
    <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12, padding: "4px 0", borderBottom: "1px solid #1a2d3d" }}>
      <span style={{ color: "#7da6c9" }}>{label}</span>
      <span style={{ textAlign: "right", maxWidth: "60%", wordBreak: "break-all" }}>{value || "-"}</span>
    </div>
  );
}

function IpCard({ ip, data, compact = false }) {
  const adb = data.sources?.abuseipdb;
  const otx = data.sources?.otx;
  return (
    <div className="ti-card" style={{ marginBottom: 8 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: compact ? 4 : 8 }}>
        <strong style={{ fontSize: compact ? 13 : 14 }}>{ip}</strong>
        <RiskBadge score={data.risk_score} />
      </div>
      {adb && !adb.error && (
        compact ? (
          <div style={{ fontSize: 12, color: "#9fb6cc" }}>
            {adb.country_code} · {adb.isp} · 신고 {adb.total_reports}건
          </div>
        ) : (
          <div>
            <TiRow label="신고 횟수" value={`${adb.total_reports}건`} />
            <TiRow label="국가" value={adb.country_code} />
            <TiRow label="ISP" value={adb.isp} />
            <TiRow label="용도" value={adb.usage_type} />
            <TiRow label="최근 신고" value={adb.last_reported ? adb.last_reported.slice(0, 10) : "-"} />
          </div>
        )
      )}
      {!compact && otx && !otx.error && otx.pulse_count > 0 && (
        <div style={{ marginTop: 8 }}>
          <div style={{ fontSize: 12, color: "#9fb6cc" }}>OTX 캠페인 {otx.pulse_count}건</div>
          {otx.pulse_names?.map((n, i) => (
            <div key={i} style={{ fontSize: 12, color: "#e6a020", marginTop: 2 }}>• {n}</div>
          ))}
        </div>
      )}
      {data.risk_score === 0 && (
        <div style={{ fontSize: 12, color: "#7da6c9", marginTop: 4 }}>내부망 IP 또는 신고 기록 없음</div>
      )}
    </div>
  );
}

function CveBadge({ severity, score }) {
  const colorMap = {
    CRITICAL: "#dc4e41",
    HIGH:     "#f8be34",
    MEDIUM:   "#2e6ca4",
    LOW:      "#53a051",
  };
  const color = colorMap[String(severity).toUpperCase()] || "#6c757d";
  return (
    <span style={{
      display: "inline-block",
      padding: "1px 7px",
      borderRadius: 4,
      fontSize: 10,
      fontWeight: 700,
      background: color,
      color: "#fff",
      flexShrink: 0,
    }}>
      {severity || "?"} {score != null ? score : ""}
    </span>
  );
}

function CveCard({ cve }) {
  if (cve.error) {
    return (
      <div style={{ fontSize: 11, color: "#e06c75", padding: "6px 0" }}>
        조회 실패: {cve.error}
      </div>
    );
  }
  return (
    <div style={{
      borderLeft: `3px solid ${cve.color || "#6c757d"}`,
      paddingLeft: 10,
      marginBottom: 8,
    }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 6 }}>
        <a
          href={cve.url}
          target="_blank"
          rel="noreferrer"
          style={{ fontSize: 12, fontWeight: 700, color: "#3fa7ff", textDecoration: "none" }}
        >
          {cve.id}
        </a>
        <div style={{ display: "flex", alignItems: "center", gap: 5, flexShrink: 0 }}>
          <CveBadge severity={cve.severity} score={cve.score} />
          <span style={{ fontSize: 10, color: "#4a6b85" }}>{cve.published}</span>
        </div>
      </div>
      <div style={{ fontSize: 11, color: "#9fb6cc", marginTop: 3, lineHeight: 1.4 }}>
        {cve.description}
      </div>
    </div>
  );
}

export default function ThreatIntelPanel({ alerts }) {
  // ── IP 평판 조회 ──
  const [ip, setIp] = useState("");
  const [lookupResult, setLookupResult] = useState(null);
  const [lookupError, setLookupError] = useState("");
  const [loading, setLoading] = useState(false);

  // ── 일괄 보강 ──
  const [enriched, setEnriched] = useState(null);
  const [enrichError, setEnrichError] = useState("");
  const [enrichLoading, setEnrichLoading] = useState(false);

  // ── CVE ──
  const [mappedCves, setMappedCves] = useState(null);
  const [recentCves, setRecentCves] = useState(null);
  const [cveLoading, setCveLoading] = useState(false);
  const [cveError, setCveError] = useState("");

  const lookup = async () => {
    const target = ip.trim();
    if (!target) return;
    setLoading(true);
    setLookupResult(null);
    setLookupError("");
    try {
      const { data } = await axios.get(`${API}/api/intel/ip/${target}`);
      setLookupResult(data);
    } catch (e) {
      setLookupError(e.response?.data?.detail || e.message);
    } finally {
      setLoading(false);
    }
  };

  const enrich = async () => {
    setEnrichLoading(true);
    setEnriched(null);
    setEnrichError("");
    try {
      const { data } = await axios.post(`${API}/api/intel/enrich`, { events: alerts });
      setEnriched(data.enriched);
    } catch (e) {
      setEnrichError(e.response?.data?.detail || e.message);
    } finally {
      setEnrichLoading(false);
    }
  };

  const loadCves = async () => {
    setCveLoading(true);
    setMappedCves(null);
    setRecentCves(null);
    setCveError("");

    // 현재 알림에서 고유 시그니처 추출
    const signatures = [...new Set(alerts.map((a) => a.signature).filter(Boolean))];

    try {
      const [sigRes, recentRes] = await Promise.all([
        signatures.length > 0
          ? axios.post(`${API}/api/cve/by-signatures`, { signatures })
          : Promise.resolve({ data: { mapped: {} } }),
        axios.get(`${API}/api/cve/recent`),
      ]);
      setMappedCves(sigRes.data.mapped || {});
      setRecentCves(recentRes.data.cves || []);
    } catch (e) {
      setCveError(e.response?.data?.detail || e.message);
    } finally {
      setCveLoading(false);
    }
  };

  return (
    <div>
      {/* ── IP 평판 조회 ── */}
      <h3 style={{ marginTop: 0, fontSize: 14 }}>IP 평판 조회</h3>
      <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
        <input
          className="chat-input"
          style={{ flex: 1, padding: "7px 10px", fontSize: 13 }}
          placeholder="예: 45.33.32.156"
          value={ip}
          onChange={(e) => setIp(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && lookup()}
        />
        <button className="btn" onClick={lookup} disabled={loading || !ip.trim()}>
          {loading ? "조회 중..." : "조회"}
        </button>
      </div>
      {lookupError && <div className="ti-error">{lookupError}</div>}
      {lookupResult && <IpCard ip={lookupResult.ip} data={lookupResult} compact={false} />}

      {/* ── 현재 알림 일괄 보강 ── */}
      <div style={{ borderTop: "1px solid #1f3242", marginTop: 20, paddingTop: 16 }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
          <h3 style={{ margin: 0, fontSize: 14 }}>현재 알림 일괄 보강</h3>
          <button
            className="btn"
            onClick={enrich}
            disabled={enrichLoading || !alerts.length}
            style={{ fontSize: 12, padding: "5px 10px" }}
          >
            {enrichLoading ? "조회 중..." : `${alerts.length}건 TI 보강`}
          </button>
        </div>
        <p style={{ fontSize: 12, color: "#7da6c9", margin: "0 0 12px" }}>
          현재 로드된 알림의 외부 IP를 AbuseIPDB / OTX에 일괄 조회합니다.
        </p>
        {enrichError && <div className="ti-error">{enrichError}</div>}
        {enriched && (
          Object.keys(enriched).length === 0 ? (
            <p style={{ fontSize: 12, color: "#7da6c9" }}>외부 IP가 없습니다 (전부 내부망).</p>
          ) : (
            <>
              <div style={{ fontSize: 12, color: "#7da6c9", marginBottom: 8 }}>
                외부 IP {Object.keys(enriched).length}개 조회 완료 ·{" "}
                <span style={{ color: "#b3261e" }}>
                  악성 {Object.values(enriched).filter((d) => d.is_malicious).length}개
                </span>
              </div>
              {Object.entries(enriched)
                .sort((a, b) => b[1].risk_score - a[1].risk_score)
                .map(([ipAddr, data]) => (
                  <IpCard key={ipAddr} ip={ipAddr} data={data} compact={true} />
                ))}
            </>
          )
        )}
      </div>

      {/* ── CVE 취약점 ── */}
      <div style={{ borderTop: "1px solid #1f3242", marginTop: 20, paddingTop: 16 }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4 }}>
          <h3 style={{ margin: 0, fontSize: 14 }}>CVE 취약점 현황</h3>
          <button
            className="btn"
            onClick={loadCves}
            disabled={cveLoading}
            style={{ fontSize: 12, padding: "5px 10px" }}
          >
            {cveLoading ? "조회 중..." : "CVE 조회"}
          </button>
        </div>
        <p style={{ fontSize: 12, color: "#7da6c9", margin: "0 0 12px" }}>
          탐지된 공격 시그니처 관련 CVE 및 최근 30일 고위험 신규 CVE를 NVD에서 조회합니다.
        </p>

        {cveError && <div className="ti-error">{cveError}</div>}

        {!mappedCves && !recentCves && !cveLoading && (
          <p style={{ fontSize: 12, color: "#4a6b85" }}>
            <strong>CVE 조회</strong> 버튼을 눌러 취약점 정보를 불러오세요.
          </p>
        )}

        {/* 탐지 시그니처 관련 CVE */}
        {mappedCves && Object.keys(mappedCves).length > 0 && (
          <div style={{ marginBottom: 16 }}>
            <div style={{ fontSize: 12, fontWeight: 700, color: "#c9d8e8", marginBottom: 10 }}>
              🔍 탐지 시그니처 관련 CVE
            </div>
            {Object.entries(mappedCves).map(([sig, cves]) => (
              <div key={sig} style={{ marginBottom: 14 }}>
                <div style={{
                  fontSize: 11,
                  color: "#f8be34",
                  marginBottom: 6,
                  display: "flex",
                  alignItems: "center",
                  gap: 6,
                }}>
                  <span>▶</span>
                  <span>{sig}</span>
                  <span style={{ color: "#4a6b85" }}>
                    (탐지 {alerts.filter((a) => a.signature === sig).length}건)
                  </span>
                </div>
                {cves.length === 0 ? (
                  <div style={{ fontSize: 11, color: "#4a6b85", paddingLeft: 12 }}>
                    관련 CVE 없음
                  </div>
                ) : (
                  <div style={{ paddingLeft: 12 }}>
                    {cves.map((cve) => (
                      <CveCard key={cve.id || cve.error} cve={cve} />
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}

        {mappedCves && Object.keys(mappedCves).length === 0 && (
          <div style={{ fontSize: 12, color: "#4a6b85", marginBottom: 12 }}>
            매핑 가능한 시그니처가 없습니다.
          </div>
        )}

        {/* 최신 CVE 피드 */}
        {recentCves && (
          <div>
            <div style={{ fontSize: 12, fontWeight: 700, color: "#c9d8e8", marginBottom: 10 }}>
              🆕 신규 고위험 CVE (최근 30일)
            </div>
            {recentCves.length === 0 ? (
              <div style={{ fontSize: 12, color: "#4a6b85" }}>조회된 CVE가 없습니다.</div>
            ) : (
              recentCves.map((cve) => (
                <CveCard key={cve.id || cve.error} cve={cve} />
              ))
            )}
          </div>
        )}
      </div>
    </div>
  );
}

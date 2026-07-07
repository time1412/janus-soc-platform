import React, { useMemo, useRef, useEffect, useCallback, useState } from "react";
import Globe from "react-globe.gl";
import * as THREE from "three";

// 보안 이벤트의 출발지 -> 목적지를 지구본 위 호(arc)로 표현한다.
// 실습망은 전부 사설 IP(10.x)라 실제 GeoIP가 불가능하므로, 데모 시각화를 위해
// 출발지 IP를 "공격 다발 국가" 좌표에 결정적(해시)으로 매핑한다(같은 IP=항상 같은 국가).
// 목적지(보호 자산)는 관제센터(서울)로 수렴시켜 '전 세계 → 관제센터' 공격 흐름을 보여준다.

const SOC_HQ = { lat: 37.5665, lon: 126.978, place: "관제센터(서울)" }; // 목적지(보호 자산)

// 공격 다발 국가(가중치↑ = 더 자주 출현). 좌표 = 대표 도시.
const ATTACK_ORIGINS = [
  { place: "중국 베이징",         lat: 39.9042,  lon: 116.4074, weight: 10 },
  { place: "러시아 모스크바",      lat: 55.7558,  lon: 37.6173,  weight: 9 },
  { place: "북한 평양",           lat: 39.0392,  lon: 125.7625, weight: 7 },
  { place: "미국 애슈번",         lat: 39.0438,  lon: -77.4874, weight: 6 },
  { place: "이란 테헤란",         lat: 35.6892,  lon: 51.3890,  weight: 5 },
  { place: "브라질 상파울루",      lat: -23.5505, lon: -46.6333, weight: 4 },
  { place: "베트남 하노이",        lat: 21.0278,  lon: 105.8342, weight: 4 },
  { place: "인도 뭄바이",         lat: 19.0760,  lon: 72.8777,  weight: 3 },
  { place: "우크라이나 키이우",     lat: 50.4501,  lon: 30.5234,  weight: 3 },
  { place: "네덜란드 암스테르담",   lat: 52.3676,  lon: 4.9041,   weight: 3 },
  { place: "루마니아 부쿠레슈티",   lat: 44.4268,  lon: 26.1025,  weight: 2 },
  { place: "인도네시아 자카르타",   lat: -6.2088,  lon: 106.8456, weight: 2 },
  { place: "튀르키예 이스탄불",     lat: 41.0082,  lon: 28.9784,  weight: 2 },
  { place: "독일 프랑크푸르트",     lat: 50.1109,  lon: 8.6821,   weight: 2 },
  { place: "나이지리아 라고스",     lat: 6.5244,   lon: 3.3792,   weight: 1 },
  { place: "멕시코 멕시코시티",     lat: 19.4326,  lon: -99.1332, weight: 1 },
];

// 가중치만큼 펼친 룩업(해시 인덱싱용)
const WEIGHTED_ORIGINS = ATTACK_ORIGINS.flatMap((o) => Array(o.weight).fill(o));

// 문자열 → 32bit 해시(FNV-1a). 같은 IP는 항상 같은 국가로 매핑(결정적).
function hashStr(s) {
  let h = 2166136261;
  const str = String(s);
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return h >>> 0;
}

const originForIp = (ip) => WEIGHTED_ORIGINS[hashStr(ip) % WEIGHTED_ORIGINS.length];

// DDoS '(분산)' 출발지: 대상 기준으로 서로 다른 국가 k개를 결정적으로 선택
function floodOrigins(destIp, k) {
  const picks = [], seen = new Set();
  for (let i = 0; picks.length < k && i < WEIGHTED_ORIGINS.length * 4; i++) {
    const o = WEIGHTED_ORIGINS[hashStr(`${destIp}#${i}`) % WEIGHTED_ORIGINS.length];
    if (!seen.has(o.place)) { seen.add(o.place); picks.push(o); }
  }
  return picks;
}

// 실제 공인 IP에 고정 좌표가 필요하면 여기에 추가(기본 비움)
const IP_GEO = {};

const DAY_TEX = "//unpkg.com/three-globe/example/img/earth-day.jpg";
const NIGHT_TEX = "//unpkg.com/three-globe/example/img/earth-night.jpg";

function coordOf(ev, prefix) {
  const ip = ev[prefix === "src" ? "src_ip" : "dest_ip"];
  if (ip && IP_GEO[ip]) return IP_GEO[ip];

  // 이벤트에 실제 좌표가 실려오면 우선 사용
  const lat = ev[`${prefix}_lat`];
  const lon = ev[`${prefix}_lon`];
  if (lat != null && lon != null)
    return { lat: Number(lat), lon: Number(lon), place: ev[`${prefix}_country`] || "" };

  // 목적지(보호 자산)는 관제센터(서울)로 수렴
  if (prefix === "dest") return SOC_HQ;

  // 출발지: 흐름(출발지·시그니처·목적지) 단위로 공격 다발 국가에 결정적 매핑.
  // 실습망은 출발지 IP가 소수라, 흐름 단위로 펼쳐 전 세계 분산을 자연스럽게 만든다.
  // (같은 흐름은 항상 같은 국가 → 새로고침해도 일관)
  const key = `${ip || "?"}|${ev.signature || ""}|${ev.dest_ip || ""}`;
  return originForIp(key);
}

function sevColor(sev) {
  const s = Number(sev) || 0;
  if (s >= 3) return ["#ff4d4d", "#ff9999"];
  if (s >= 2) return ["#ffb84d", "#ffe0b3"];
  return ["#4dff88", "#b3ffcc"];
}

// 출발지 파장(ring) 색: 위험도별 RGB
function ringRgb(sev) {
  const s = Number(sev) || 0;
  if (s >= 3) return "255,77,77";
  if (s >= 2) return "255,184,77";
  return "77,255,136";
}

// 주어진 시각(UTC)의 태양 직하점(subsolar point) [경도, 위도] 계산.
// 시각화용 근사: 경도는 UTC 기준, 위도는 태양 적위(declination) 근사식.
function subsolarPoint(date) {
  const utcHours =
    date.getUTCHours() + date.getUTCMinutes() / 60 + date.getUTCSeconds() / 3600;
  let lng = (12 - utcHours) * 15; // 12시 UTC에 0도(그리니치) 상공
  lng = (((lng + 180) % 360) + 360) % 360 - 180; // [-180, 180]로 래핑

  const start = Date.UTC(date.getUTCFullYear(), 0, 0);
  const dayOfYear = Math.floor((date.getTime() - start) / 86400000);
  const lat = -23.44 * Math.cos((2 * Math.PI / 365) * (dayOfYear + 10)); // 적위 근사
  return [lng, lat];
}

export default function GlobeComponent({ alerts }) {
  const globeRef = useRef();
  const wrapRef = useRef();
  const [dims, setDims] = useState({ w: 420, h: 420 });

  // 24h 전체 집계 흐름(출발지→목적지→시그니처). 실패 시 표시중 alerts(최근 100)로 폴백.
  const [flows, setFlows] = useState(null);
  useEffect(() => {
    let alive = true;
    const load = () =>
      fetch("/api/alerts/geo")
        .then((r) => (r.ok ? r.json() : null))
        .then((d) => { if (alive && d && Array.isArray(d.flows)) setFlows(d.flows); })
        .catch(() => {});
    load();
    const t = setInterval(load, 30000);
    return () => { alive = false; clearInterval(t); };
  }, []);

  // 컨테이너 크기에 맞춰 지구본 크기 자동 조절(작게/반응형)
  useEffect(() => {
    if (!wrapRef.current) return;
    const ro = new ResizeObserver((entries) => {
      const { width, height } = entries[0].contentRect;
      setDims({ w: Math.max(220, Math.floor(width)), h: Math.max(220, Math.floor(height)) });
    });
    ro.observe(wrapRef.current);
    return () => ro.disconnect();
  }, []);

  const { arcs, rings } = useMemo(() => {
    // 1) 흐름 목록 구성: 24h 집계(flows) 우선, 없으면 표시중 alerts(최근 100)로 폴백
    let list;
    if (flows) {
      // 백엔드가 이미 출발지→목적지→시그니처로 집계(+DDoS는 대상별 1줄기)
      list = flows.map((f) => ({
        src: coordOf(f, "src"),
        dst: coordOf(f, "dest"),
        src_ip: f.src_ip || "?",
        dest_ip: f.dest_ip || "?",
        signature: f.signature || "event",
        severity: Number(f.severity) || 0,
        count: Number(f.count) || 0,
        src_count: Number(f.src_count) || 0,
      }));
    } else {
      const groups = new Map();
      (alerts || []).forEach((ev) => {
        const key = `${ev.src_ip}|${ev.dest_ip}|${ev.signature}`;
        if (!groups.has(key)) {
          groups.set(key, {
            src: coordOf(ev, "src"),
            dst: coordOf(ev, "dest"),
            src_ip: ev.src_ip || "?",
            dest_ip: ev.dest_ip || "?",
            signature: ev.signature || "event",
            severity: 0,
            count: 0,
            src_count: 0,
          });
        }
        const g = groups.get(key);
        g.count += 1;
        g.severity = Math.max(g.severity, Number(ev.severity) || 0);
      });
      list = [...groups.values()];
    }

    // 1.5) DDoS '(분산)' 흐름은 전 세계 여러 국가에서 들어오는 것처럼 여러 호로 분할
    const expanded = [];
    list.forEach((g) => {
      if (g.src_ip === "(분산)") {
        const k = Math.min(8, Math.max(3, g.src_count || 5));
        const origins = floodOrigins(g.dest_ip, k);
        origins.forEach((o) => expanded.push({
          ...g,
          src: { lat: o.lat, lon: o.lon, place: o.place },
          count: Math.max(1, Math.round(g.count / origins.length)),
          src_count: 0,
        }));
      } else {
        expanded.push(g);
      }
    });
    list = expanded;

    // 2) 같은 출발/도착 좌표를 공유하는 그룹끼리 고도를 분산해 부채꼴로 펼치기(높이 낮춤)
    const byEndpoints = new Map();
    list.forEach((g) => {
      const ek = `${g.src.lat},${g.src.lon}->${g.dst.lat},${g.dst.lon}`;
      if (!byEndpoints.has(ek)) byEndpoints.set(ek, []);
      byEndpoints.get(ek).push(g);
    });
    byEndpoints.forEach((arr) => {
      // 위험도 오름차순 정렬 → 위험도가 높을수록 호 고도가 높게 배치된다
      arr.sort((a, b) => a.severity - b.severity);
      arr.forEach((g, i) => {
        g.altitude = arr.length === 1 ? 0.12 : 0.07 + (0.2 * i) / (arr.length - 1);
      });
    });

    // 3) 건수를 호 두께로 인코딩
    const arcs = list.map((g) => ({
      startLat: g.src.lat,
      startLng: g.src.lon,
      endLat: g.dst.lat,
      endLng: g.dst.lon,
      color: sevColor(g.severity),
      altitude: g.altitude,
      stroke: Math.min(0.35 + Math.log2(g.count + 1) * 0.35, 2.6),
      label: `${g.src.place ? g.src.place + " · " : ""}${g.src_ip} → ${g.dest_ip} | ${g.signature} (${g.count}건${g.src_count > 1 ? `, 출발지 ${g.src_count}개` : ""})`,
    }));

    // 4) 출발지 파장(레이더 핑): 같은 좌표는 최고 위험도로 합쳐 1개만
    const ringMap = new Map();
    list.forEach((g) => {
      const k = `${g.src.lat},${g.src.lon}`;
      const prev = ringMap.get(k);
      if (!prev || g.severity > prev.severity)
        ringMap.set(k, { lat: g.src.lat, lng: g.src.lon, severity: g.severity });
    });
    const rings = [...ringMap.values()].map((r) => ({
      lat: r.lat,
      lng: r.lng,
      rgb: ringRgb(r.severity),
      maxR: r.severity >= 3 ? 5 : r.severity >= 2 ? 4 : 3,   // 위험도↑ = 더 크게 퍼짐
      speed: r.severity >= 3 ? 3 : 2,                         // 위험도↑ = 더 빠르게
      period: r.severity >= 3 ? 700 : 1100,                   // 위험도↑ = 더 자주
    }));

    return { arcs, rings };
  }, [flows, alerts]);

  // 실시간 낮/밤 셰이더 머티리얼 (기본 적용): 낮 텍스처와 밤 텍스처를 태양 방향에 따라 섞는다.
  const globeMaterial = useMemo(() => {
    const loader = new THREE.TextureLoader();
    loader.setCrossOrigin("anonymous");
    return new THREE.ShaderMaterial({
      uniforms: {
        dayTexture: { value: loader.load(DAY_TEX) },
        nightTexture: { value: loader.load(NIGHT_TEX) },
        sunPosition: { value: new THREE.Vector2() },
        globeRotation: { value: new THREE.Vector2() },
      },
      vertexShader: `
        varying vec3 vNormal;
        varying vec2 vUv;
        void main() {
          vNormal = normalize(normalMatrix * normal);
          vUv = uv;
          gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0);
        }
      `,
      fragmentShader: `
        #define PI 3.141592653589793
        uniform sampler2D dayTexture;
        uniform sampler2D nightTexture;
        uniform vec2 sunPosition;
        uniform vec2 globeRotation;
        varying vec3 vNormal;
        varying vec2 vUv;

        float toRad(in float a) { return a * PI / 180.0; }

        vec3 polar2Cartesian(in vec2 c) { // [경도, 위도]
          float theta = toRad(90.0 - c.x);
          float phi = toRad(90.0 - c.y);
          return vec3(sin(phi) * cos(theta), cos(phi), sin(phi) * sin(theta));
        }

        void main() {
          float invLon = toRad(globeRotation.x);
          float invLat = -toRad(globeRotation.y);
          mat3 rotX = mat3(1, 0, 0, 0, cos(invLat), -sin(invLat), 0, sin(invLat), cos(invLat));
          mat3 rotY = mat3(cos(invLon), 0, sin(invLon), 0, 1, 0, -sin(invLon), 0, cos(invLon));
          vec3 sunDir = rotX * rotY * polar2Cartesian(sunPosition);
          float intensity = dot(normalize(vNormal), normalize(sunDir));
          vec4 dayColor = texture2D(dayTexture, vUv);
          vec4 nightColor = texture2D(nightTexture, vUv);
          float blend = smoothstep(-0.1, 0.15, intensity);
          gl_FragColor = mix(nightColor, dayColor, blend);
        }
      `,
    });
  }, []);

  // 태양 위치를 현재 시각으로 주기적으로 갱신
  useEffect(() => {
    const update = () => {
      const [lng, lat] = subsolarPoint(new Date());
      globeMaterial.uniforms.sunPosition.value.set(lng, lat);
    };
    update();
    const id = setInterval(update, 60000); // 1분마다
    return () => clearInterval(id);
  }, [globeMaterial]);

  // 지구본 회전(시점)에 맞춰 태양 방향 보정
  const handleZoom = useCallback(
    (pov) => {
      globeMaterial.uniforms.globeRotation.value.set(pov.lng, pov.lat);
    },
    [globeMaterial]
  );

  useEffect(() => {
    if (globeRef.current) {
      globeRef.current.pointOfView({ lat: SOC_HQ.lat, lng: SOC_HQ.lon, altitude: 1.9 }, 0);
      const controls = globeRef.current.controls();
      controls.autoRotate = true;
      controls.autoRotateSpeed = 0.4;
    }
  }, []);

  return (
    <div ref={wrapRef} style={{ width: "100%", height: "100%", display: "flex", justifyContent: "center", alignItems: "center" }}>
    <Globe
      ref={globeRef}
      width={dims.w}
      height={dims.h}
      globeMaterial={globeMaterial}
      backgroundColor="rgba(0,0,0,0)"
      showAtmosphere={true}
      atmosphereColor="#5aa0ff"
      atmosphereAltitude={0.2}
      onZoom={handleZoom}
      arcsData={arcs}
      arcColor="color"
      arcAltitude="altitude"
      arcStroke="stroke"
      arcDashLength={0.4}
      arcDashGap={0.2}
      arcDashAnimateTime={1500}
      arcLabel="label"
      arcsTransitionDuration={500}
      ringsData={rings}
      ringLat="lat"
      ringLng="lng"
      ringColor={(d) => (t) => `rgba(${d.rgb},${1 - t})`}
      ringMaxRadius="maxR"
      ringPropagationSpeed="speed"
      ringRepeatPeriod="period"
      ringAltitude={0.0015}
    />
    </div>
  );
}

import React, { useEffect, useState } from "react";
import { api } from "../api.js";
import { useAuth } from "../auth.jsx";

const TEAMS = ["보안관제팀", "웹관리자", "정보보호팀"];

export default function Login() {
  const { login } = useAuth();
  const [mode, setMode] = useState("login"); // login | signup
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const [form, setForm] = useState({
    username: "", password: "", display_name: "", team: "보안관제팀", role: "분석가",
    mail_local: "", notify_consent: false,
  });
  const set = (k) => (e) => setForm({ ...form, [k]: e.target.value });

  useEffect(() => {
    const r = localStorage.getItem("comm_logout_reason");
    if (r) {
      setNotice(r);
      localStorage.removeItem("comm_logout_reason");
    }
  }, []);

  const submit = async (e) => {
    e.preventDefault();
    setError("");
    try {
      if (mode === "login") {
        const u = await api("/api/login", { body: { username: form.username, password: form.password } });
        login(u);
      } else {
        const u = await api("/api/signup", { body: form });
        login(u); // 가입 즉시 로그인
      }
    } catch (err) {
      setError(err.message);
    }
  };

  return (
    <div className="login-wrap">
      <form className="login-card" onSubmit={submit}>
        <h1>내부 소통플랫폼</h1>
        <p className="login-sub">보안관제팀 · 웹관리자 · 정보보호팀 협업</p>

        {notice && <div className="login-notice">{notice}</div>}

        <div className="auth-tabs">
          <button type="button" className={"auth-tab" + (mode === "login" ? " on" : "")} onClick={() => { setMode("login"); setError(""); }}>로그인</button>
          <button type="button" className={"auth-tab" + (mode === "signup" ? " on" : "")} onClick={() => { setMode("signup"); setError(""); }}>회원가입</button>
        </div>

        <label>아이디</label>
        <input value={form.username} onChange={set("username")} placeholder="아이디" autoFocus autoComplete="username" />

        <label>비밀번호</label>
        <input type="password" value={form.password} onChange={set("password")} placeholder="비밀번호" autoComplete={mode === "login" ? "current-password" : "new-password"} />

        {mode === "signup" && (
          <>
            <label>이름</label>
            <input value={form.display_name} onChange={set("display_name")} placeholder="표시 이름 (예: 홍길동)" />
            <div style={{ display: "flex", gap: 10 }}>
              <div style={{ flex: 1 }}>
                <label>소속</label>
                <select value={form.team} onChange={set("team")}>
                  {TEAMS.map((t) => <option key={t} value={t}>{t}</option>)}
                </select>
              </div>
              <div style={{ flex: 1 }}>
                <label>직무</label>
                <input value={form.role} onChange={set("role")} placeholder="예: 분석가" />
              </div>
            </div>
            <label>메일 주소 (janus.com 사서함)</label>
            <div style={{ display: "flex", alignItems: "stretch" }}>
              <input style={{ flex: 1, borderTopRightRadius: 0, borderBottomRightRadius: 0, borderRight: "none" }}
                     value={form.mail_local}
                     onChange={(e) => setForm({ ...form, mail_local: e.target.value.replace(/[@\s]/g, "") })}
                     placeholder={form.username || "예: hong"} autoComplete="off" />
              <span style={{ display: "flex", alignItems: "center", padding: "0 12px", background: "#f1f2f6",
                             border: "1px solid var(--line,#d8dbe3)", borderLeft: "none",
                             borderTopRightRadius: 8, borderBottomRightRadius: 8, color: "#5b6b7a", whiteSpace: "nowrap" }}>
                @janus.com
              </span>
            </div>
            <div className="dim" style={{ fontSize: 12, marginTop: 2 }}>비워두면 아이디로 생성됩니다. 이 주소로 메일을 주고받습니다.</div>
            <label className="consent">
              <input type="checkbox" checked={form.notify_consent}
                     onChange={(e) => setForm({ ...form, notify_consent: e.target.checked })} />
              <span>티켓 단계별 알림(텔레그램·이메일) 수신에 동의합니다.</span>
            </label>
          </>
        )}

        {error && <div className="login-error">{error}</div>}
        <button className="btn" type="submit">{mode === "login" ? "로그인" : "회원가입"}</button>

        <div className="login-switch">
          {mode === "login" ? (
            <span>계정이 없으신가요? <a onClick={() => { setMode("signup"); setError(""); }}>회원가입</a></span>
          ) : (
            <span>이미 계정이 있으신가요? <a onClick={() => { setMode("login"); setError(""); }}>로그인</a></span>
          )}
        </div>
      </form>
    </div>
  );
}

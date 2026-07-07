import React, { useState, useRef, useEffect } from "react";
import axios from "axios";
import ReactMarkdown from "react-markdown";

const API = ""; // package.json proxy로 백엔드(8800)에 전달

export default function ChatWidget() {
  const [open, setOpen] = useState(false);
  const [messages, setMessages] = useState([
    { role: "assistant", content: "안녕하세요, 보안 분석 어시스턴트입니다. 수집된 보안 로그에 대해 무엇이든 물어보세요. 예) '오늘 SQL Injection 몇 건이야?'" },
  ]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const listRef = useRef(null);

  useEffect(() => {
    if (listRef.current) listRef.current.scrollTop = listRef.current.scrollHeight;
  }, [messages, open]);

  // 챗봇 열림 → 대시보드가 왼쪽으로 비켜나도록 body에 표시
  useEffect(() => {
    document.body.classList.toggle("chat-open", open);
    return () => document.body.classList.remove("chat-open");
  }, [open]);

  const send = async () => {
    const q = input.trim();
    if (!q || loading) return;
    const history = messages.map((m) => ({ role: m.role === "assistant" ? "model" : "user", content: m.content }));
    setMessages((m) => [...m, { role: "user", content: q }]);
    setInput("");
    setLoading(true);
    try {
      const { data } = await axios.post(`${API}/api/chat`, { question: q, history });
      setMessages((m) => [...m, { role: "assistant", content: data.answer }]);
    } catch (e) {
      const detail = e.response?.data?.detail || e.message;
      setMessages((m) => [...m, { role: "assistant", content: `오류: ${detail}` }]);
    } finally {
      setLoading(false);
    }
  };

  const onKeyDown = (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      send();
    }
  };

  if (!open) {
    return (
      <button className="chat-fab" onClick={() => setOpen(true)}>
        보안 분석 어시스턴트
      </button>
    );
  }

  return (
    <div className="chat-panel">
      <div className="chat-header">
        <span>보안 분석 어시스턴트</span>
        <button className="chat-close" onClick={() => setOpen(false)}>
          ✕
        </button>
      </div>
      <div className="chat-messages" ref={listRef}>
        {messages.map((m, i) => (
          <div key={i} className={`chat-msg chat-msg--${m.role}`}>
            {m.role === "assistant"
              ? <ReactMarkdown>{m.content}</ReactMarkdown>
              : m.content}
          </div>
        ))}
        {loading && <div className="chat-msg chat-msg--assistant">답변 생성 중...</div>}
      </div>
      <div className="chat-input-row">
        <textarea
          className="chat-input"
          rows={1}
          value={input}
          placeholder="질문을 입력하세요 (Enter 전송)"
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={onKeyDown}
        />
        <button className="btn" onClick={send} disabled={loading}>
          전송
        </button>
      </div>
    </div>
  );
}

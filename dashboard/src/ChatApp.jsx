import { useEffect, useRef, useState } from "react";

const API_URL = import.meta.env.VITE_API_URL || "http://localhost:8000";

const STATUS_NOTICE = {
  sanitized: { icon: "⚠", text: "Des données sensibles ont été masquées avant l'envoi au modèle.", tone: "warn" },
  blocked_pii: { icon: "🛑", text: "Message bloqué : données sensibles détectées.", tone: "danger" },
  blocked_injection: { icon: "🛑", text: "Message bloqué par le pare-feu (règles).", tone: "danger" },
  blocked_injection_ia: { icon: "🛑", text: "Message bloqué par le pare-feu (classifieur IA).", tone: "ia" },
};

function Bubble({ msg }) {
  if (msg.role === "user") {
    return (
      <div className="chat-row chat-row--user">
        <div className="chat-bubble chat-bubble--user">{msg.text}</div>
      </div>
    );
  }
  if (msg.role === "blocked") {
    return (
      <div className="chat-row chat-row--system">
        <div className={`chat-bubble chat-bubble--blocked chat-bubble--${msg.tone}`}>
          <span>{msg.icon}</span> {msg.text}
        </div>
      </div>
    );
  }
  if (msg.role === "error") {
    return (
      <div className="chat-row chat-row--system">
        <div className="chat-bubble chat-bubble--blocked chat-bubble--danger">⚠ {msg.text}</div>
      </div>
    );
  }
  return (
    <div className="chat-row chat-row--assistant">
      <div className="chat-bubble chat-bubble--assistant">
        {msg.notice && (
          <div className={`chat-notice chat-notice--${msg.notice.tone}`}>
            {msg.notice.icon} {msg.notice.text}
          </div>
        )}
        <div>{msg.text}</div>
      </div>
    </div>
  );
}

export default function ChatApp() {
  const [messages, setMessages] = useState([
    { role: "assistant", text: "Bonjour ! Posez-moi une question — ce message passera par le pare-feu avant d'atteindre le modèle." },
  ]);
  const [input, setInput] = useState("");
  const [provider, setProvider] = useState("anthropic");
  const [model, setModel] = useState("claude-haiku-4-5-20251001");
  const [showSettings, setShowSettings] = useState(false);
  const [loading, setLoading] = useState(false);
  const bottomRef = useRef(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, loading]);

  async function handleSend(e) {
    e.preventDefault();
    const text = input.trim();
    if (!text || loading) return;
    setMessages((m) => [...m, { role: "user", text }]);
    setInput("");
    setLoading(true);
    try {
      const res = await fetch(`${API_URL}/v1/proxy/chat`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ provider, model, prompt: text }),
      });
      const body = await res.json();
      if (!res.ok) throw new Error(body.detail || "La requête a échoué");

      if (body.status === "blocked_pii" || body.status === "blocked_injection" || body.status === "blocked_injection_ia") {
        const notice = STATUS_NOTICE[body.status];
        setMessages((m) => [...m, { role: "blocked", text: body.detail || notice.text, icon: notice.icon, tone: notice.tone }]);
      } else {
        const notice = body.status === "sanitized" ? STATUS_NOTICE.sanitized : null;
        setMessages((m) => [...m, { role: "assistant", text: body.completion || "(pas de réponse)", notice }]);
      }
    } catch (err) {
      setMessages((m) => [...m, { role: "error", text: err.message || "Erreur de connexion au pare-feu" }]);
    } finally {
      setLoading(false);
    }
  }

  return (
    <section className="chat-app">
      <div className="chat-app__header">
        <div>
          <h2>Application employé</h2>
          <p className="subtitle">simule l'outil interne d'un employé — chaque message passe par le pare-feu</p>
        </div>
        <button type="button" className="preset-btn" onClick={() => setShowSettings((s) => !s)}>
          {showSettings ? "Masquer les options" : "Options du modèle"}
        </button>
      </div>

      {showSettings && (
        <div className="tester-form__row chat-app__settings">
          <label className="field">
            <span className="field-label">Fournisseur</span>
            <select value={provider} onChange={(e) => setProvider(e.target.value)}>
              <option value="openai">openai</option>
              <option value="anthropic">anthropic</option>
            </select>
          </label>
          <label className="field field--grow">
            <span className="field-label">Modèle</span>
            <input type="text" value={model} onChange={(e) => setModel(e.target.value)} />
          </label>
        </div>
      )}

      <div className="chat-window">
        {messages.map((m, i) => (
          <Bubble key={i} msg={m} />
        ))}
        {loading && (
          <div className="chat-row chat-row--assistant">
            <div className="chat-bubble chat-bubble--assistant chat-bubble--loading">
              <span className="live-dot" /> en cours…
            </div>
          </div>
        )}
        <div ref={bottomRef} />
      </div>

      <form className="chat-input-row" onSubmit={handleSend}>
        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="Écrivez un message…"
          autoComplete="off"
        />
        <button type="submit" className="send-btn" disabled={loading || !input.trim()}>
          Envoyer
        </button>
      </form>
    </section>
  );
}

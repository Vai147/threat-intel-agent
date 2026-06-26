import { useState } from "react";
import { login } from "../../lib/api";
import "./auth.css";

interface LoginScreenProps {
  onAuthed: () => void;
}

export function LoginScreen({ onAuthed }: LoginScreenProps) {
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!password || busy) return;
    setBusy(true);
    setError(null);
    try {
      await login(password);
      onAuthed();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Login failed");
      setBusy(false);
    }
  }

  return (
    <div className="login">
      <form className="login__card card" onSubmit={submit}>
        <div className="login__brand">
          <span className="login__logo">TI</span>
          <span className="login__product">Threat Intel</span>
        </div>
        <h1 className="login__title">Sign in</h1>
        <p className="login__sub">Enter the access password to continue.</p>

        <input
          className="login__field"
          type="password"
          placeholder="Password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          autoFocus
          disabled={busy}
        />
        {error && <div className="login__error">⚠ {error}</div>}
        <button className="login__submit" type="submit" disabled={busy || !password}>
          {busy ? "Signing in…" : "Sign in"}
        </button>
      </form>
    </div>
  );
}

import type { AgentEvent, AuthStatus, BackendKind, FeedIOC, IocType } from "./types";

/** Current auth status (whether login is required and whether we're in). */
export async function fetchAuthStatus(): Promise<AuthStatus> {
  const res = await fetch("/api/me", { credentials: "include" });
  if (!res.ok) throw new Error("Failed to read auth status");
  return (await res.json()) as AuthStatus;
}

/** Exchange a password for a session cookie. Throws on bad password. */
export async function login(password: string): Promise<void> {
  const res = await fetch("/api/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "include",
    body: JSON.stringify({ password }),
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.detail ?? "Login failed");
  }
}

export async function logout(): Promise<void> {
  await fetch("/api/logout", { method: "POST", credentials: "include" });
}

/** Fetch recent real IOCs from the backend (ThreatFox). */
export async function fetchFeed(days: number, limit: number): Promise<FeedIOC[]> {
  const qs = new URLSearchParams({ days: String(days), limit: String(limit) });
  const res = await fetch(`/api/feed?${qs}`, { credentials: "include" });
  const body = await res.json();
  if (!res.ok) throw new Error(body.error ?? body.detail ?? "Feed request failed");
  return body.iocs as FeedIOC[];
}

export interface StreamHandlers {
  onEvent: (event: AgentEvent) => void;
  onClose?: () => void;
}

/**
 * Open an SSE stream for an investigation. Returns a cancel function.
 * Closes itself on `done` or `error`.
 */
export function streamInvestigation(
  params: { ioc: string; type: IocType; backend: BackendKind },
  handlers: StreamHandlers,
): () => void {
  const qs = new URLSearchParams(params);
  const source = new EventSource(`/api/investigate/stream?${qs}`);

  source.onmessage = (e: MessageEvent<string>) => {
    let event: AgentEvent;
    try {
      event = JSON.parse(e.data) as AgentEvent;
    } catch {
      return;
    }
    handlers.onEvent(event);
    if (event.type === "done" || event.type === "error") {
      source.close();
      handlers.onClose?.();
    }
  };

  source.onerror = () => {
    source.close();
    handlers.onEvent({ type: "error", message: "Connection to agent lost" });
    handlers.onClose?.();
  };

  return () => source.close();
}

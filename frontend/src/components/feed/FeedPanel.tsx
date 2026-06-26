import { useState } from "react";
import { fetchFeed } from "../../lib/api";
import type { BackendKind, FeedIOC, IocType } from "../../lib/types";
import { FeedTable } from "./FeedTable";
import "./feed.css";

interface FeedPanelProps {
  onInvestigate: (ioc: string, type: IocType, backend: BackendKind) => void;
}

export function FeedPanel({ onInvestigate }: FeedPanelProps) {
  const [days, setDays] = useState(1);
  const [limit, setLimit] = useState(10);
  const [iocs, setIocs] = useState<FeedIOC[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function load() {
    setLoading(true);
    setError(null);
    try {
      setIocs(await fetchFeed(days, limit));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load feed");
      setIocs(null);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="feed">
      <div className="feed__bar">
        <p className="feed__lead">
          Pull real, recent indicators from{" "}
          <a href="https://threatfox.abuse.ch/" target="_blank" rel="noreferrer">
            abuse.ch ThreatFox
          </a>
          . Click any row to investigate it.
        </p>
        <div className="feed__controls">
          <label className="feed__num">
            days
            <input
              type="number"
              min={1}
              max={7}
              value={days}
              onChange={(e) => setDays(Number(e.target.value))}
            />
          </label>
          <label className="feed__num">
            limit
            <input
              type="number"
              min={1}
              max={50}
              value={limit}
              onChange={(e) => setLimit(Number(e.target.value))}
            />
          </label>
          <button className="feed__load" onClick={load} disabled={loading}>
            {loading ? "Loading…" : "Pull IOCs"}
          </button>
        </div>
      </div>

      {error && (
        <div className="feed__error">
          ⚠ {error}
          <span className="muted"> — set THREATFOX_AUTH_KEY in .env (free key).</span>
        </div>
      )}

      {iocs && <FeedTable iocs={iocs} onInvestigate={onInvestigate} />}
      {iocs && iocs.length === 0 && <p className="muted">No IOCs returned.</p>}
    </div>
  );
}

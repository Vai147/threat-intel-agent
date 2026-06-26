import type { Report, Severity } from "../../lib/types";
import { SEVERITY_BG, SEVERITY_VAR, typeLabel } from "../../lib/format";
import "./dashboard.css";

const SEVERITY_ORDER: Severity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "informational",
];

interface DashboardPanelProps {
  history: Report[];
  onOpen: (report: Report) => void;
  onInvestigate: () => void;
}

export function DashboardPanel({
  history,
  onOpen,
  onInvestigate,
}: DashboardPanelProps) {
  const counts = countBySeverity(history);
  const highRisk = (counts.critical ?? 0) + (counts.high ?? 0);
  const avgConfidence =
    history.length > 0
      ? Math.round(
          history.reduce((sum, r) => sum + r.confidence, 0) / history.length,
        )
      : 0;

  return (
    <div className="dashboard">
      <div className="dashboard__stats">
        <Stat label="Investigations" value={String(history.length)} />
        <Stat label="High / critical" value={String(highRisk)} accent="danger" />
        <Stat label="Avg confidence" value={`${avgConfidence}%`} />
        <Stat
          label="Techniques mapped"
          value={String(uniqueTechniques(history))}
        />
      </div>

      <section className="card dashboard__dist">
        <header className="dashboard__head">Severity distribution</header>
        {history.length === 0 ? (
          <p className="muted">No investigations yet.</p>
        ) : (
          <div className="dist">
            {SEVERITY_ORDER.map((sev) => (
              <div key={sev} className="dist__row">
                <span className="dist__label">{sev}</span>
                <div className="dist__track">
                  <div
                    className="dist__fill"
                    style={{
                      width: `${((counts[sev] ?? 0) / history.length) * 100}%`,
                      background: SEVERITY_VAR[sev],
                    }}
                  />
                </div>
                <span className="dist__num mono">{counts[sev] ?? 0}</span>
              </div>
            ))}
          </div>
        )}
      </section>

      <section className="card dashboard__recent">
        <header className="dashboard__head">Recent investigations</header>
        {history.length === 0 ? (
          <div className="dashboard__empty">
            <p className="muted">
              Nothing investigated yet this session. Run one to populate the
              dashboard.
            </p>
            <button className="dashboard__cta" onClick={onInvestigate}>
              Go to Investigate →
            </button>
          </div>
        ) : (
          <ul className="recent">
            {history.map((r, i) => (
              <li key={`${r.ioc}-${i}`}>
                <button className="recent__row" onClick={() => onOpen(r)}>
                  <span
                    className="recent__sev"
                    style={
                      {
                        background: SEVERITY_BG[r.severity],
                        color: SEVERITY_VAR[r.severity],
                      } as React.CSSProperties
                    }
                  >
                    {r.severity}
                  </span>
                  <span className="recent__ioc mono">{r.ioc}</span>
                  <span className="recent__type">{typeLabel(r.ioc_type)}</span>
                  <span className="recent__class">
                    {r.threat_classification}
                  </span>
                  <span className="recent__open">Open →</span>
                </button>
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}

interface StatProps {
  label: string;
  value: string;
  accent?: "danger";
}

function Stat({ label, value, accent }: StatProps) {
  return (
    <div className="card stat">
      <div className="stat__label">{label}</div>
      <div className={`stat__value ${accent === "danger" ? "stat__value--danger" : ""}`}>
        {value}
      </div>
    </div>
  );
}

function countBySeverity(history: Report[]): Partial<Record<Severity, number>> {
  return history.reduce<Partial<Record<Severity, number>>>((acc, r) => {
    acc[r.severity] = (acc[r.severity] ?? 0) + 1;
    return acc;
  }, {});
}

function uniqueTechniques(history: Report[]): number {
  const ids = new Set<string>();
  for (const r of history) {
    for (const t of r.mitre_techniques) ids.add(t.technique_id);
  }
  return ids.size;
}

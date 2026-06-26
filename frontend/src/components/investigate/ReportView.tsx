import type { Report } from "../../lib/types";
import { typeLabel } from "../../lib/format";
import { SeverityBadge } from "./SeverityBadge";
import { MitreTable } from "./MitreTable";
import "./investigate.css";

interface ReportViewProps {
  report: Report;
}

/** Two-column enterprise layout: verdict + MITRE on the left, actions + related on the right. */
export function ReportView({ report }: ReportViewProps) {
  return (
    <div className="report">
      <div className="report__main">
        <section className="verdict card">
          <div className="verdict__top">
            <div>
              <div className="verdict__ioc mono">{report.ioc}</div>
              <div className="verdict__sub">{typeLabel(report.ioc_type)}</div>
            </div>
            <SeverityBadge severity={report.severity} />
          </div>

          <div className="verdict__chips">
            {report.threat_classification && (
              <span className="nchip">{report.threat_classification}</span>
            )}
            <span className="nchip">Confidence {report.confidence}%</span>
            <span className="nchip">{typeLabel(report.ioc_type)}</span>
          </div>

          <p className="verdict__summary">{report.summary}</p>
        </section>

        <section className="panel card">
          <header className="panel__head">MITRE ATT&amp;CK</header>
          <MitreTable techniques={report.mitre_techniques} />
        </section>
      </div>

      <aside className="report__side">
        <section className="card">
          <header className="side__title">Recommended actions</header>
          <ol className="action-list">
            {report.recommended_actions.map((a, i) => (
              <li key={i}>
                <span className="action-list__idx mono">
                  {String(i + 1).padStart(2, "0")}
                </span>
                <span>{a}</span>
              </li>
            ))}
          </ol>
        </section>

        <section className="card related">
          <RelatedGroup label="Related malware" items={report.related_malware} tone="danger" />
          <RelatedGroup
            label="Threat groups"
            items={report.related_threat_groups}
            tone="accent"
          />
          <RelatedGroup label="Related IOCs" items={report.related_iocs} mono />
        </section>
      </aside>
    </div>
  );
}

function RelatedGroup({
  label,
  items,
  tone = "neutral",
  mono,
}: {
  label: string;
  items: string[];
  tone?: "neutral" | "danger" | "accent";
  mono?: boolean;
}) {
  return (
    <div className="related__group">
      <div className="related__label">{label}</div>
      {items && items.length > 0 ? (
        <div className="related__chips">
          {items.map((item, i) => (
            <span key={i} className={`tchip tchip--${tone} ${mono ? "mono" : ""}`}>
              {item}
            </span>
          ))}
        </div>
      ) : (
        <p className="muted">None identified.</p>
      )}
    </div>
  );
}

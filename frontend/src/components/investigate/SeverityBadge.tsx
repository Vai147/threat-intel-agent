import type { Severity } from "../../lib/types";
import { SEVERITY_BG, SEVERITY_VAR } from "../../lib/format";
import "./investigate.css";

interface SeverityBadgeProps {
  severity: Severity;
  /** Optional; the verdict card shows confidence in its chip row instead. */
  confidence?: number;
}

export function SeverityBadge({ severity, confidence }: SeverityBadgeProps) {
  return (
    <div
      className="severity-chip"
      style={
        {
          "--sev": SEVERITY_VAR[severity],
          "--sev-bg": SEVERITY_BG[severity],
        } as React.CSSProperties
      }
    >
      <span className="severity-chip__dot" />
      <span className="severity-chip__label">{severity}</span>
      {confidence !== undefined && (
        <span className="severity-chip__conf mono">{confidence}%</span>
      )}
    </div>
  );
}

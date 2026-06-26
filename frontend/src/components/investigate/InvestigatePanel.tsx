import type { BackendKind, IocType } from "../../lib/types";
import { IocInput } from "./IocInput";
import { AgentStream } from "./AgentStream";
import { ReportView } from "./ReportView";
import type { InvestigationState } from "./useInvestigation";
import "./investigate.css";

interface InvestigatePanelProps {
  investigation: InvestigationState;
}

export function InvestigatePanel({ investigation }: InvestigatePanelProps) {
  const { status, events, report, error, start } = investigation;
  const running = status === "running";

  function submit(ioc: string, type: IocType, backend: BackendKind) {
    start(ioc, type, backend);
  }

  return (
    <div className="investigate">
      <IocInput disabled={running} onSubmit={submit} />

      {error && <div className="investigate__error">⚠ {error}</div>}

      <AgentStream events={events} running={running} />

      {report ? <ReportView report={report} /> : status === "idle" && <EmptyState />}
    </div>
  );
}

function EmptyState() {
  return (
    <div className="investigate__empty">
      <p>
        Submit an indicator and the agent investigates it autonomously —
        querying reputation sources, cross-referencing, and mapping to MITRE
        ATT&CK. Watch the trace build above, then read the report.
      </p>
      <div className="investigate__samples">
        <span className="muted">try:</span>
        <code>203.0.113.42</code>
        <code>secure-bankofamerica-login.com</code>
        <code>d131dd02c5e6eec4693d9a0698aff95c</code>
      </div>
    </div>
  );
}

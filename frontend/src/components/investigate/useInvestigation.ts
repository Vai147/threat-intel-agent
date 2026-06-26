import { useCallback, useEffect, useRef, useState } from "react";
import { streamInvestigation } from "../../lib/api";
import type { AgentEvent, BackendKind, IocType, Report } from "../../lib/types";

type Status = "idle" | "running" | "done" | "error";

export interface InvestigationState {
  status: Status;
  events: AgentEvent[];
  report: Report | null;
  error: string | null;
  start: (ioc: string, type: IocType, backend: BackendKind) => void;
  /** Display a previously completed report without re-running it. */
  show: (report: Report) => void;
}

/** Drives one SSE investigation, accumulating events and the final report. */
export function useInvestigation(): InvestigationState {
  const [status, setStatus] = useState<Status>("idle");
  const [events, setEvents] = useState<AgentEvent[]>([]);
  const [report, setReport] = useState<Report | null>(null);
  const [error, setError] = useState<string | null>(null);
  const cancelRef = useRef<(() => void) | null>(null);

  useEffect(() => () => cancelRef.current?.(), []);

  const start = useCallback(
    (ioc: string, type: IocType, backend: BackendKind) => {
      cancelRef.current?.();
      setStatus("running");
      setEvents([]);
      setReport(null);
      setError(null);

      cancelRef.current = streamInvestigation(
        { ioc, type, backend },
        {
          onEvent: (event) => {
            setEvents((prev) => [...prev, event]);
            if (event.type === "report") setReport(event.report);
            if (event.type === "error") {
              setError(event.message);
              setStatus("error");
            }
            if (event.type === "done") setStatus("done");
          },
        },
      );
    },
    [],
  );

  const show = useCallback((past: Report) => {
    cancelRef.current?.();
    setEvents([]);
    setError(null);
    setReport(past);
    setStatus("done");
  }, []);

  return { status, events, report, error, start, show };
}

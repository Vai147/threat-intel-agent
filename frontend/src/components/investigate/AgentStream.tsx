import type { AgentEvent } from "../../lib/types";
import { toolLabel } from "../../lib/format";
import "./investigate.css";

interface AgentStreamProps {
  events: AgentEvent[];
  running: boolean;
}

/** Live trace of the agent's tool calls as they stream in. */
export function AgentStream({ events, running }: AgentStreamProps) {
  const steps = events.filter(
    (e) => e.type === "tool_call" || e.type === "status",
  );
  if (steps.length === 0 && !running) return null;

  return (
    <div className="agent-stream">
      <div className="agent-stream__head">
        <span className="agent-stream__pulse" data-on={running} />
        <span className="mono">agent trace</span>
      </div>
      <ol className="agent-stream__list">
        {steps.map((e, i) => (
          <li key={i} className="agent-stream__step">
            {e.type === "tool_call" ? (
              <>
                <span className="agent-stream__tool mono">{toolLabel(e.tool)}</span>
                <span className="agent-stream__arg mono">
                  {Object.values(e.input)[0]}
                </span>
              </>
            ) : (
              <span className="agent-stream__status">{e.message}</span>
            )}
          </li>
        ))}
        {running && (
          <li className="agent-stream__step agent-stream__step--live">
            <span className="agent-stream__cursor mono">▌</span>
          </li>
        )}
      </ol>
    </div>
  );
}

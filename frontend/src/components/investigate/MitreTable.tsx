import type { MitreTechnique } from "../../lib/types";
import "./investigate.css";

interface MitreTableProps {
  techniques: MitreTechnique[];
}

export function MitreTable({ techniques }: MitreTableProps) {
  if (techniques.length === 0) {
    return <p className="muted">No techniques mapped.</p>;
  }
  return (
    <table className="mitre-table">
      <thead>
        <tr>
          <th>ID</th>
          <th>Technique</th>
          <th>Tactic</th>
        </tr>
      </thead>
      <tbody>
        {techniques.map((t) => (
          <tr key={t.technique_id}>
            <td>
              <a
                className="mono"
                href={`https://attack.mitre.org/techniques/${t.technique_id.replace(".", "/")}/`}
                target="_blank"
                rel="noreferrer"
              >
                {t.technique_id}
              </a>
            </td>
            <td>{t.technique_name}</td>
            <td className="muted">{t.tactic}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

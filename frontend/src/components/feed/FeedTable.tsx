import type { BackendKind, FeedIOC, IocType } from "../../lib/types";
import { typeLabel } from "../../lib/format";
import "./feed.css";

interface FeedTableProps {
  iocs: FeedIOC[];
  onInvestigate: (ioc: string, type: IocType, backend: BackendKind) => void;
}

export function FeedTable({ iocs, onInvestigate }: FeedTableProps) {
  return (
    <table className="feed-table">
      <thead>
        <tr>
          <th>Indicator</th>
          <th>Type</th>
          <th>Malware</th>
          <th>Conf</th>
          <th />
        </tr>
      </thead>
      <tbody>
        {iocs.map((ioc, i) => (
          <tr key={`${ioc.value}-${i}`}>
            <td className="mono feed-table__ioc">{ioc.value}</td>
            <td className="muted">{typeLabel(ioc.ioc_type)}</td>
            <td>{ioc.malware ?? "—"}</td>
            <td>
              <ConfidenceBar value={ioc.confidence} />
            </td>
            <td className="feed-table__action">
              <button
                onClick={() => onInvestigate(ioc.value, ioc.ioc_type, "live")}
              >
                Investigate →
              </button>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function ConfidenceBar({ value }: { value: number }) {
  return (
    <div className="conf">
      <div className="conf__track">
        <div className="conf__fill" style={{ width: `${value}%` }} />
      </div>
      <span className="conf__num mono">{value}</span>
    </div>
  );
}

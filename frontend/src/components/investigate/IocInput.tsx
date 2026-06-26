import { useState } from "react";
import type { BackendKind, IocType } from "../../lib/types";
import { guessIocType, typeLabel } from "../../lib/format";
import "./investigate.css";

const TYPES: IocType[] = ["ip_address", "file_hash", "domain", "url", "email"];

interface IocInputProps {
  disabled: boolean;
  onSubmit: (ioc: string, type: IocType, backend: BackendKind) => void;
}

export function IocInput({ disabled, onSubmit }: IocInputProps) {
  const [value, setValue] = useState("");
  const [type, setType] = useState<IocType>("ip_address");
  const [autoType, setAutoType] = useState(true);
  const [backend, setBackend] = useState<BackendKind>("mock");

  const effectiveType = autoType && value ? guessIocType(value) : type;

  function submit(e: React.FormEvent) {
    e.preventDefault();
    const ioc = value.trim();
    if (!ioc || disabled) return;
    onSubmit(ioc, effectiveType, backend);
  }

  return (
    <form className="ioc-input" onSubmit={submit}>
      <div className="ioc-input__row">
        <span className="ioc-input__prompt mono">&gt;</span>
        <input
          className="ioc-input__field mono"
          placeholder="enter an IOC — IP, hash, domain, url, email"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          disabled={disabled}
          spellCheck={false}
          autoFocus
        />
        <button className="ioc-input__go" type="submit" disabled={disabled || !value.trim()}>
          {disabled ? "Investigating…" : "Investigate"}
        </button>
      </div>

      <div className="ioc-input__controls">
        <label className="ioc-input__auto">
          <input
            type="checkbox"
            checked={autoType}
            onChange={(e) => setAutoType(e.target.checked)}
          />
          auto-detect type
        </label>

        <select
          className="ioc-input__select mono"
          value={effectiveType}
          disabled={autoType}
          onChange={(e) => setType(e.target.value as IocType)}
        >
          {TYPES.map((t) => (
            <option key={t} value={t}>
              {typeLabel(t)}
            </option>
          ))}
        </select>

        <div className="ioc-input__backend">
          {(["mock", "live"] as BackendKind[]).map((b) => (
            <button
              key={b}
              type="button"
              className={`seg ${backend === b ? "seg--on" : ""}`}
              onClick={() => setBackend(b)}
              disabled={disabled}
            >
              {b}
            </button>
          ))}
        </div>
      </div>
    </form>
  );
}

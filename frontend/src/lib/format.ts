import type { IocType, Severity } from "./types";

export const SEVERITY_VAR: Record<Severity, string> = {
  critical: "var(--sev-critical)",
  high: "var(--sev-high)",
  medium: "var(--sev-medium)",
  low: "var(--sev-low)",
  informational: "var(--sev-info)",
};

/** Tonal (16% alpha) background paired with each severity color. */
export const SEVERITY_BG: Record<Severity, string> = {
  critical: "var(--sev-critical-bg)",
  high: "var(--sev-high-bg)",
  medium: "var(--sev-medium-bg)",
  low: "var(--sev-low-bg)",
  informational: "var(--sev-info-bg)",
};

const TOOL_LABELS: Record<string, string> = {
  lookup_ip_reputation: "IP reputation",
  lookup_file_hash: "File hash",
  lookup_domain: "Domain",
  get_mitre_techniques: "MITRE ATT&CK",
};

export function toolLabel(tool: string): string {
  return TOOL_LABELS[tool] ?? tool;
}

const TYPE_LABELS: Record<IocType, string> = {
  ip_address: "IP address",
  file_hash: "File hash",
  domain: "Domain",
  url: "URL",
  email: "Email",
};

export function typeLabel(type: IocType): string {
  return TYPE_LABELS[type] ?? type;
}

/** Best-effort guess of an IOC type from its raw value. */
export function guessIocType(value: string): IocType {
  const v = value.trim();
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(v)) return "ip_address";
  if (/^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i.test(v)) return "file_hash";
  if (/^https?:\/\//i.test(v)) return "url";
  if (/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(v)) return "email";
  return "domain";
}

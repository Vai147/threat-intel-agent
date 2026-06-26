export type IocType = "ip_address" | "file_hash" | "domain" | "url" | "email";

export type Severity =
  | "critical"
  | "high"
  | "medium"
  | "low"
  | "informational";

export interface MitreTechnique {
  technique_id: string;
  technique_name: string;
  tactic: string;
}

export interface Report {
  ioc: string;
  ioc_type: IocType;
  severity: Severity;
  confidence: number;
  threat_classification: string;
  summary: string;
  related_malware: string[];
  related_threat_groups: string[];
  mitre_techniques: MitreTechnique[];
  recommended_actions: string[];
  related_iocs: string[];
}

export interface FeedIOC {
  value: string;
  ioc_type: IocType;
  malware: string | null;
  confidence: number;
  first_seen: string | null;
}

/** Events streamed from /api/investigate/stream. */
export type AgentEvent =
  | { type: "status"; message: string }
  | { type: "tool_call"; tool: string; input: Record<string, string> }
  | { type: "tool_result"; tool: string }
  | {
      type: "complete";
      analysis: string;
      tool_calls: { tool: string; input: Record<string, string> }[];
      turns_used: number;
      hit_turn_limit: boolean;
    }
  | { type: "report"; report: Report }
  | { type: "done" }
  | { type: "error"; message: string };

export type BackendKind = "mock" | "live";

export interface AuthStatus {
  authenticated: boolean;
  auth_required: boolean;
}

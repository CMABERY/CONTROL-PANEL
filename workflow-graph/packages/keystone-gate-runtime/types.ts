// Phase 1 — Canonical Envelope Types (schema-aligned)
// LOCKED: SPEC_VERSION=1.0.0, CANON_VERSION=1
//
// Note: TypeScript cannot encode JSON Schema regex/length constraints.
// These types are an exact structural match to the Phase 1 Draft 2020-12 schemas.

export const SPEC_VERSION = "1.0.0" as const;
export const CANON_VERSION = "1" as const;

export type SpecVersion = typeof SPEC_VERSION;
export type CanonVersion = typeof CANON_VERSION;

// Shared scalar aliases (schema-constrained at runtime via AJV)
export type Hash256 = string;       // /^[0-9a-f]{64}$/
export type TraceId = string;       // /^(?!0{32})[0-9a-f]{32}$/
export type SpanId = string;        // /^(?!0{16})[0-9a-f]{16}$/
export type Token = string;         // /^[a-z0-9][a-z0-9_\-:.]{0,127}$/
export type Resource = string;      // /^[a-z0-9][a-z0-9_\-:./]{0,255}$/
export type ContentType = string;   // MIME type pattern

export type IntNonNegative = number; // JSON Schema enforces integer + safe range

// Deterministic set encoding: { "key": true }
export type StringSet = Record<string, true>;

export type Producer = {
  layer: Token;
  component: Token;
};

export type Actor = {
  actor_kind: Token;
  actor_id: Resource;
};

export type Credential = {
  credential_kind: Token;
  issuer: string;
  presented_hash_sha256: Hash256;
  verified_at_ms: IntNonNegative;
  expires_at_ms: IntNonNegative;
};

export type PolicyRef = {
  policy_id: Token;
  policy_version: Token;
  policy_sha256: Hash256;
};

export type PolicyRequest = {
  action: Token;
  resource: Resource;
};

export type PolicyDecision = {
  result: "allow" | "deny";
  reason_codes: StringSet;
  obligations: StringSet;
};

export type BlobRef = {
  content_type: ContentType;
  sha256: Hash256;
  size_bytes: IntNonNegative;
};

export type Outcome = {
  status: Token;
};

export type ModelRef = {
  provider: Token;
  model: Token;
};

export type ToolRef = {
  adapter_id: Token;
  tool_name: Token;
};

export type Usage = {
  input_tokens: IntNonNegative;
  output_tokens: IntNonNegative;
  total_tokens: IntNonNegative;
};

// TraceContext (root vs child)
export type RootSpan = {
  trace_id: TraceId;
  span_id: SpanId;
  span_kind: "root";
};

export type ChildSpan = {
  trace_id: TraceId;
  span_id: SpanId;
  span_kind: "child";
  parent_span_id: SpanId;
};

export type TraceContext = RootSpan | ChildSpan;

// Envelope records
export type AuthContext = {
  spec_version: SpecVersion;
  canon_version: CanonVersion;
  record_type: "auth_context";
  ts_ms: IntNonNegative;
  trace: TraceContext;
  producer: { layer: "cpo"; component: Token };
  actor: Actor;
  credential: Credential;
  grants: StringSet;
};

export type PolicyDecisionRecord = {
  spec_version: SpecVersion;
  canon_version: CanonVersion;
  record_type: "policy_decision";
  ts_ms: IntNonNegative;
  trace: TraceContext;
  producer: { layer: "cpo"; component: Token };
  auth_context_envelope_sha256: Hash256;
  policy: PolicyRef;
  request: PolicyRequest;
  decision: PolicyDecision;
};

export type ModelCallRecord = {
  spec_version: SpecVersion;
  canon_version: CanonVersion;
  record_type: "model_call";
  started_at_ms: IntNonNegative;
  ended_at_ms: IntNonNegative;
  trace: TraceContext;
  producer: { layer: "flow"; component: Token };
  auth_context_envelope_sha256: Hash256;
  policy_decision_envelope_sha256: Hash256;
  model: ModelRef;
  request: BlobRef;
  response: BlobRef;
  outcome: Outcome;
  usage?: Usage;
};

export type ToolCallRecord = {
  spec_version: SpecVersion;
  canon_version: CanonVersion;
  record_type: "tool_call";
  started_at_ms: IntNonNegative;
  ended_at_ms: IntNonNegative;
  trace: TraceContext;
  producer: { layer: "adapter"; component: Token };
  auth_context_envelope_sha256: Hash256;
  policy_decision_envelope_sha256: Hash256;
  tool: ToolRef;
  request: BlobRef;
  response: BlobRef;
  outcome: Outcome;
};

export type EnvelopeRecord = AuthContext | PolicyDecisionRecord | ModelCallRecord | ToolCallRecord;

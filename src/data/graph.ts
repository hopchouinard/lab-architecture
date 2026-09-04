// The explorer's graph data.
//
// Two layers — a hand-authored CONCEPTUAL graph (the ideas) and a sanitized
// PHYSICAL graph (the lab's shape, with generic aliases only — no real
// hostnames, IPs, or identifiers) — plus the MAPPINGS that connect a concept to
// the components that realize it. Positions are hand-placed for an intentional
// three-band layout (describe → operate → publish), left to right.
//
// The physical layer is deliberately generic. If the inventory-fed allowlist
// generator is ever built, it could emit this same shape from inventory.yaml;
// until then this curated version keeps the explorer fully testable with nothing
// sensitive. Nodes whose `kind` reads "designed, not built" describe intended
// mechanisms that do not exist yet — keep that label accurate.

export type Boundary = "describe" | "operate" | "publish" | "physical";

export type GraphNode = {
  id: string;
  label: string;
  boundary: Boundary;
  kind: string; // short tag shown above the title in the panel
  summary: string; // one-line gloss
  detail: string; // a sentence or two for the detail panel
  x: number;
  y: number;
  source?: boolean; // the single source-of-truth node (special highlight)
};

export type GraphEdge = {
  id: string;
  source: string;
  target: string;
  label?: string;
};

export type Mapping = {
  concept: string; // a CONCEPTUAL node id
  components: string[]; // PHYSICAL node ids it maps onto
  note?: string;
};

// ── Conceptual layer ────────────────────────────────────────────────────────

export const CONCEPT_NODES: GraphNode[] = [
  // Describe (left band)
  {
    id: "inventory",
    label: "inventory.yaml",
    boundary: "describe",
    kind: "source of truth",
    summary: "The single file the whole lab agrees on.",
    detail:
      "Every host, network segment, service, route, and known issue. It is the only file edited by hand; everything else is generated from it.",
    x: 0,
    y: 120,
    source: true,
  },
  {
    id: "generated-views",
    label: "Generated views",
    boundary: "describe",
    kind: "derived",
    summary: "Docs and diagrams, never authored twice.",
    detail:
      "Reference documentation and a multi-frame architecture diagram, rendered deterministically from the inventory. Two runs produce byte-identical output.",
    x: 0,
    y: 270,
  },
  {
    id: "coherence",
    label: "Coherence checker",
    boundary: "describe",
    kind: "invariant",
    summary: "Every artifact has exactly one home.",
    detail:
      "A checker that fails the build if a generated file was hand-edited or an artifact lives in two places. The discipline is mechanical, not remembered.",
    x: 0,
    y: 420,
  },

  // Operate (middle band)
  {
    id: "agent",
    label: "The agent",
    boundary: "operate",
    kind: "actor",
    summary: "Allowed to act — inside a ceiling it cannot raise.",
    detail:
      "An agent-agnostic operator (today an assistant called Hermes). It can act on the infrastructure, but only through operations the registry permits.",
    x: 360,
    y: 40,
  },
  {
    id: "registry",
    label: "Capability registry",
    boundary: "operate",
    kind: "hard ceiling",
    summary: "The allowlist of everything the agent may ever attempt.",
    detail:
      "The outer bound of autonomy, enforced in code. Anything not enumerated here is uncallable — not discouraged, structurally unreachable.",
    x: 360,
    y: 180,
  },
  {
    id: "policy",
    label: "RBAC + approval",
    boundary: "operate",
    kind: "gate",
    summary: "Which operations run freely, which need a human.",
    detail:
      "Profiles and rules that decide, within the registry's ceiling, what executes automatically and what requires explicit human approval before it runs.",
    x: 360,
    y: 320,
  },
  {
    id: "audit",
    label: "Audit trail",
    boundary: "operate",
    kind: "append-only",
    summary: "Nothing the agent does goes unrecorded.",
    detail:
      "An immutable, append-only record of every attempt and action — the provenance that closes the loop between execution and accountability.",
    x: 360,
    y: 460,
  },
  {
    id: "nats",
    label: "Event runtime",
    boundary: "operate",
    kind: "backbone",
    summary: "Everything that happens is an event.",
    detail:
      "A NATS-based backbone: events carry a schema, travel on named subjects, and are retained in a store. Producers and consumers stay decoupled.",
    x: 540,
    y: 250,
  },
  {
    id: "connectivity",
    label: "Connectivity",
    boundary: "operate",
    kind: "governed access",
    summary: "Governed access to every live wire.",
    detail:
      "The live wires into the infrastructure — SSH to the compute layer, the network controller's API, the metrics store, the event runtime, and the documentation and inventory git remotes — each reached only through a registered capability.",
    x: 540,
    y: 110,
  },

  // Publish (right band)
  {
    id: "allowlist",
    label: "Allowlist export",
    boundary: "publish",
    kind: "designed, not built",
    summary: "Would let only marked fields cross over.",
    detail:
      "A projection of the inventory in which nothing is published unless explicitly allowed, so new fields stay private by default. It does not exist yet: no inventory field carries a publication marker and no generator emits this projection.",
    x: 760,
    y: 130,
  },
  {
    id: "tripwire",
    label: "Tripwire",
    boundary: "publish",
    kind: "designed, not built",
    summary: "Would refuse to ship anything secret-shaped.",
    detail:
      "An independent scan over build output that fails the build on a match, so two guards would have to fail together for a leak to ship. The site's build runs no such scan today.",
    x: 760,
    y: 270,
  },
  {
    id: "site",
    label: "This site",
    boundary: "publish",
    kind: "hand-authored",
    summary: "A public account anyone can read.",
    detail:
      "Written by hand, including this graph. No lab data is imported into it at all — the public build never sees the inventory, directly or indirectly. Static, with no live data and no path back into the lab.",
    x: 760,
    y: 410,
  },
];

export const CONCEPT_EDGES: GraphEdge[] = [
  { id: "c-inv-views", source: "inventory", target: "generated-views", label: "generates" },
  { id: "c-inv-coh", source: "inventory", target: "coherence", label: "checked by" },
  { id: "c-inv-allow", source: "inventory", target: "allowlist", label: "would project" },
  { id: "c-allow-trip", source: "allowlist", target: "tripwire", label: "would be scanned by" },
  { id: "c-trip-site", source: "tripwire", target: "site", label: "would ship" },
  { id: "c-agent-reg", source: "agent", target: "registry", label: "bounded by" },
  { id: "c-reg-pol", source: "registry", target: "policy", label: "within" },
  { id: "c-pol-aud", source: "policy", target: "audit", label: "records" },
  { id: "c-agent-conn", source: "agent", target: "connectivity", label: "acts via" },
  { id: "c-aud-nats", source: "audit", target: "nats", label: "mirrored to" },
  { id: "c-reg-inv", source: "registry", target: "inventory", label: "reads" },
];

// ── Physical layer (sanitized; generic aliases only) ─────────────────────────

export const PHYSICAL_NODES: GraphNode[] = [
  {
    id: "gateway",
    label: "Gateway",
    boundary: "physical",
    kind: "edge router",
    summary: "The router and firewall at the perimeter.",
    detail:
      "Segments the network and enforces the boundaries between zones. The lab has no public ingress; remote access is a zero-trust overlay.",
    x: 0,
    y: 80,
  },
  {
    id: "switches",
    label: "Core switches",
    boundary: "physical",
    kind: "fabric",
    summary: "The wired fabric carrying the segments.",
    detail: "Managed switching that carries the VLAN segments between the gateway and the hosts.",
    x: 0,
    y: 220,
  },
  {
    id: "vlans",
    label: "VLAN segments",
    boundary: "physical",
    kind: "segmentation",
    summary: "Role-based network zones.",
    detail:
      "Traffic is split by role so each workload only sees what it should — management and service zones, with isolated zones for untrusted and backup traffic.",
    x: 0,
    y: 360,
  },
  {
    id: "platform-node",
    label: "Platform node",
    boundary: "physical",
    kind: "compute",
    summary: "Identity, secrets, events, observability.",
    detail:
      "The host that runs the platform services and the operator core — where the registry, policy, audit, and event runtime actually live.",
    x: 360,
    y: 90,
  },
  {
    id: "compute",
    label: "Compute hosts",
    boundary: "physical",
    kind: "compute",
    summary: "Virtualization for the workloads.",
    detail:
      "Hypervisor hosts running the dev and production workloads, the automation, monitoring, and the assistant itself.",
    x: 360,
    y: 250,
  },
  {
    id: "backup",
    label: "Backup server",
    boundary: "physical",
    kind: "storage",
    summary: "Off-host backups on an isolated segment.",
    detail: "Holds backups on a dedicated, isolated network segment, separate from the workloads it protects.",
    x: 360,
    y: 410,
  },
  {
    id: "edge",
    label: "Reverse-proxy edge",
    boundary: "physical",
    kind: "ingress",
    summary: "TLS termination and an internal CA.",
    detail:
      "The single managed entry point in front of the services, terminating TLS with an internal certificate authority.",
    x: 720,
    y: 150,
  },
  {
    id: "remote-access",
    label: "Remote access",
    boundary: "physical",
    kind: "overlay",
    summary: "A zero-trust tunnel, no open ports.",
    detail:
      "Remote reachability is a zero-trust overlay rather than public ingress. Nothing is exposed to the open internet.",
    x: 720,
    y: 300,
  },
];

export const PHYSICAL_EDGES: GraphEdge[] = [
  { id: "p-gw-sw", source: "gateway", target: "switches" },
  { id: "p-sw-vlan", source: "switches", target: "vlans" },
  { id: "p-vlan-plat", source: "vlans", target: "platform-node" },
  { id: "p-vlan-comp", source: "vlans", target: "compute" },
  { id: "p-vlan-bak", source: "vlans", target: "backup" },
  { id: "p-plat-edge", source: "platform-node", target: "edge", label: "behind" },
  { id: "p-edge-remote", source: "edge", target: "remote-access" },
];

// ── Concept ↔ component mappings ─────────────────────────────────────────────

export const MAPPINGS: Mapping[] = [
  { concept: "registry", components: ["platform-node"], note: "The operator core runs on the platform node." },
  { concept: "policy", components: ["platform-node"] },
  { concept: "audit", components: ["platform-node"] },
  { concept: "nats", components: ["platform-node"], note: "The event runtime lives with the platform services." },
  { concept: "agent", components: ["platform-node", "compute"] },
  { concept: "connectivity", components: ["gateway", "switches"], note: "Governed access rides the managed network." },
  { concept: "site", components: ["edge"], note: "Published through the same edge that fronts the lab's services." },
];

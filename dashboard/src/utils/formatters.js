export function formatTimestamp(ts) {
  const d = new Date(ts);
  return d.toLocaleTimeString("en-GB", { hour12: false }) + "." + String(d.getMilliseconds()).padStart(3, "0");
}

export function eventColor(eventType) {
  switch (eventType) {
    case "auth_success":
    case "packet_forwarded":
      return "#4fbf8b";
    case "auth_failure":
    case "replay_rejected":
    case "integrity_violation":
    case "packet_rejected":
    case "rate_limited":
      return "#d95c53";
    case "anomaly_detected":
      return "#d99a3c";
    default:
      return "#7f8b95";
  }
}

export const THREAT_CONTROLS = [
  { key: "auth_failure", control: "F1", label: "Authentication / allowlist", attack: "ATK1, ATK4", tone: "block" },
  { key: "replay_rejected", control: "F3", label: "Anti-replay", attack: "ATK2", tone: "block" },
  { key: "integrity_violation", control: "F2", label: "Integrity (HMAC)", attack: "ATK3", tone: "block" },
  { key: "packet_rejected", control: "IV", label: "Input validation", attack: "ATK5", tone: "block" },
  { key: "rate_limited", control: "F4", label: "Rate limiting", attack: "ATK6", tone: "block" },
  { key: "anomaly_detected", control: "F4", label: "Anomaly detection", attack: "ATK6", tone: "alert" },
];

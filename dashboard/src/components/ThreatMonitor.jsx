import { THREAT_CONTROLS } from "../utils/formatters";

export default function ThreatMonitor({ threats, lastThreatKey, flashId }) {
  const total = THREAT_CONTROLS.reduce((n, c) => n + (threats[c.key] || 0), 0);

  return (
    <div className={`panel threat-monitor${total > 0 ? " active" : ""}`}>
      <h2>Threat Monitor</h2>
      <div className="threat-total">
        <span className="threat-total-num" key={flashId}>{total}</span>
        <span className="threat-total-label">threats caught</span>
      </div>
      <div className="threat-rows">
        {THREAT_CONTROLS.map((c) => {
          const count = threats[c.key] || 0;
          const hot = count > 0;
          const pulse = c.key === lastThreatKey;
          const alert = c.tone === "alert";
          return (
            <div
              key={c.key}
              className={`threat-row${hot ? " hot" : ""}${alert ? " alert" : ""}${pulse ? " pulse" : ""}`}
              style={pulse ? { animationName: `pulse-${flashId % 2}` } : undefined}
            >
              <span className="threat-ctrl">{c.control}</span>
              <span className="threat-label">{c.label}</span>
              <span className="threat-attack">{c.attack}</span>
              <span className="threat-count">{count}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

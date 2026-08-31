import { formatTimestamp } from "../utils/formatters";

export default function CommandStream({ commands }) {
  return (
    <div className="panel">
      <h2>Command Stream</h2>
      <div className="command-list">
        {commands.length === 0 && <div className="muted">Waiting for data...</div>}
        {commands.map((cmd, i) => (
          <div key={i} className={`command-entry${i === 0 ? " new" : ""}`}>
            <span className="ts">{formatTimestamp(cmd.timestamp)}</span>
            <span className="cmd">{cmd.command}</span>
            <span className="device">{cmd.device_id}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

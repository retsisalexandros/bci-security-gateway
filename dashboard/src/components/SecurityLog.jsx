import { formatTimestamp, eventColor } from "../utils/formatters";

export default function SecurityLog({ events }) {
  return (
    <div className="panel">
      <h2>Security Events</h2>
      <div className="log-list">
        {events.length === 0 && <div className="muted">No events yet</div>}
        {events.map((evt, i) => (
          <div key={i} className="log-entry" style={{ color: eventColor(evt.event_type) }}>
            <span className="ts">{formatTimestamp(evt.timestamp)}</span>
            <span className="type">{evt.event_type}</span>
            <span className="detail">{evt.device_id}{evt.details ? ` · ${evt.details}` : ""}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

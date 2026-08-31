import { useState, useCallback, useRef, useEffect } from "react";
import useWebSocket from "./hooks/useWebSocket";
import EEGDisplay from "./components/EEGDisplay";
import CommandStream from "./components/CommandStream";
import ConnectionStatus from "./components/ConnectionStatus";
import SecurityLog from "./components/SecurityLog";
import MetricsPanel from "./components/MetricsPanel";
import ThreatMonitor from "./components/ThreatMonitor";
import "./App.css";

const HUB_WS_URL = "ws://localhost:8002";
const MAX_COMMANDS = 20;
const MAX_EVENTS = 100;
const THREAT_TYPES = ["auth_failure", "replay_rejected", "integrity_violation", "packet_rejected", "rate_limited", "anomaly_detected"];

export default function App() {
  const [packets, setPackets] = useState([]);
  const [commands, setCommands] = useState([]);
  const [events, setEvents] = useState([]);
  const [metrics, setMetrics] = useState({});
  const [threats, setThreats] = useState({});
  const [lastThreatKey, setLastThreatKey] = useState(null);
  const [flashId, setFlashId] = useState(0);
  const [deviceId, setDeviceId] = useState(null);
  const startTimeRef = useRef(null);
  const [startTime, setStartTime] = useState(null);
  const [, forceUpdate] = useState(0);

  useEffect(() => {
    const id = setInterval(() => forceUpdate((n) => n + 1), 1000);
    return () => clearInterval(id);
  }, []);

  const onMessage = useCallback((data) => {
    if (data.event_type) {
      setEvents((prev) => [data, ...prev].slice(0, MAX_EVENTS));
      if (THREAT_TYPES.includes(data.event_type)) {
        setThreats((prev) => ({ ...prev, [data.event_type]: (prev[data.event_type] || 0) + 1 }));
        setLastThreatKey(data.event_type);
        setFlashId((n) => n + 1);
      }
      return;
    }

    if (data.total_packets_received !== undefined) {
      setMetrics(data);
      return;
    }

    if (data.channels) {
      if (!startTimeRef.current) {
        startTimeRef.current = Date.now();
        setStartTime(Date.now());
      }
      setDeviceId(data.device_id);
      setPackets((prev) => {
        const next = [...prev, data];
        return next.length > 500 ? next.slice(-500) : next;
      });

      if (data.command && data.command !== "idle") {
        setCommands((prev) => {
          if (prev.length > 0 && prev[0].command === data.command) return prev;
          return [
            { command: data.command, timestamp: data.timestamp, device_id: data.device_id },
            ...prev,
          ].slice(0, MAX_COMMANDS);
        });
      }
    }
  }, []);

  const { connected } = useWebSocket(HUB_WS_URL, onMessage);

  return (
    <div className="dashboard">
      <header>
        <h1>BCI Security Gateway</h1>
      </header>
      <div className="grid">
        <div className="col-left">
          <EEGDisplay packets={packets} />
          <CommandStream commands={commands} />
        </div>
        <div className="col-right">
          <ConnectionStatus connected={connected} deviceId={deviceId} startTime={startTime} />
          <ThreatMonitor threats={threats} lastThreatKey={lastThreatKey} flashId={flashId} />
          <MetricsPanel metrics={metrics} />
          <SecurityLog events={events} />
        </div>
      </div>
    </div>
  );
}

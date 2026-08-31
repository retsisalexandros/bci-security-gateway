export default function ConnectionStatus({ connected, deviceId, startTime }) {
  const uptime = startTime ? Math.floor((Date.now() - startTime) / 1000) : 0;
  const mins = Math.floor(uptime / 60);
  const secs = uptime % 60;

  return (
    <div className="panel">
      <h2>Connection</h2>
      <div className="status-grid">
        <span>Status</span>
        <span className={connected ? "ok" : "err"}>
          {connected ? "Connected" : "Disconnected"}
        </span>
        <span>Device</span>
        <span>{deviceId || "no device"}</span>
        <span>Uptime</span>
        <span>{mins}m {String(secs).padStart(2, "0")}s</span>
      </div>
    </div>
  );
}

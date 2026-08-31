export default function MetricsPanel({ metrics }) {
  return (
    <div className="panel">
      <h2>Metrics</h2>
      <div className="metrics-grid">
        <span>Received</span>
        <span>{metrics.total_packets_received ?? 0}</span>
        <span>Forwarded</span>
        <span>{metrics.total_packets_forwarded ?? 0}</span>
        <span>Rejected</span>
        <span className={metrics.total_packets_rejected > 0 ? "err" : ""}>
          {metrics.total_packets_rejected ?? 0}
        </span>
        <span>Auth failures</span>
        <span className={metrics.auth_failures > 0 ? "err" : ""}>
          {metrics.auth_failures ?? 0}
        </span>
        <span>Replay rejections</span>
        <span className={metrics.replay_rejections > 0 ? "err" : ""}>
          {metrics.replay_rejections ?? 0}
        </span>
        <span>Malformed packets</span>
        <span className={metrics.malformed_packets > 0 ? "err" : ""}>
          {metrics.malformed_packets ?? 0}
        </span>
        <span>Rate limited</span>
        <span className={metrics.rate_limited > 0 ? "err" : ""}>
          {metrics.rate_limited ?? 0}
        </span>
        <span>Anomalies flagged</span>
        <span className={metrics.anomalies_detected > 0 ? "warn-val" : ""}>
          {metrics.anomalies_detected ?? 0}
        </span>
        <span>Throughput</span>
        <span>{(metrics.packets_per_second ?? 0).toFixed(1)} pkt/s</span>
        <span>Latency avg</span>
        <span>{(metrics.avg_latency_ms ?? 0).toFixed(3)} ms</span>
        <span>Latency p50</span>
        <span>{(metrics.latency_p50_ms ?? 0).toFixed(3)} ms</span>
        <span>Latency p95</span>
        <span>{(metrics.latency_p95_ms ?? 0).toFixed(3)} ms</span>
        <span>Latency p99</span>
        <span>{(metrics.latency_p99_ms ?? 0).toFixed(3)} ms</span>
      </div>
    </div>
  );
}

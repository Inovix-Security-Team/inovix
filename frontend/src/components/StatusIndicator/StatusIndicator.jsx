import "./StatusIndicator.css";

function StatusIndicator({ status = "UNKNOWN" }) {
  return (
    <span className={`status-indicator status-${status.toLowerCase()}`}>
      <span className="status-dot"></span>
      <span>{status}</span>
    </span>
  );
}

export default StatusIndicator;
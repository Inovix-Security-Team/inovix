import "./RiskBadge.css";

function RiskBadge({ status = "UNKNOWN" }) {
  const normalizedStatus = status.toUpperCase();

  return (
    <span className={`risk-badge risk-${normalizedStatus.toLowerCase()}`}>
      {normalizedStatus}
    </span>
  );
}

export default RiskBadge;
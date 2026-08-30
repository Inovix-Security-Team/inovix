import "./SeverityBadge.css";

function SeverityBadge({ level = "LOW" }) {
  return (
    <span className={`severity-badge severity-${level.toLowerCase()}`}>
      {level}
    </span>
  );
}

export default SeverityBadge;
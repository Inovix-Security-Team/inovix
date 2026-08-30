import Card from "../Card/Card";
import RiskBadge from "../RiskBadge/RiskBadge";
import Button from "../Button/Button";
import "./ResultCard.css";

function ResultCard({
  title,
  status = "UNKNOWN",
  description,
  onDetails,
}) {
  return (
    <Card className="result-card">
      <div className="result-header">
        <h3>{title}</h3>
        <RiskBadge status={status} />
      </div>

      {description && (
        <p className="result-description">{description}</p>
      )}

      {onDetails && (
        <Button variant="secondary" onClick={onDetails}>
          View Details
        </Button>
      )}
    </Card>
  );
}

export default ResultCard;
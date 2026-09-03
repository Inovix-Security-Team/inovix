interface RiskScoreCardProps {
  risk: { score?: number; level?: string } | null | undefined;
}

export function RiskScoreCard({ risk }: RiskScoreCardProps) {
  const score = typeof risk?.score === 'number' ? risk.score : null;
  const level = risk?.level ? risk.level.toUpperCase() : 'UNAVAILABLE';

  return (
    <div className="risk-card">
      <div className="risk-score">{score !== null ? `${score} / 100` : 'Not available'}</div>
      <div className="risk-level">{score !== null ? level : 'No risk score available'}</div>
    </div>
  );
}

import type { AnomalyItem } from '../types';

interface AnomalyListProps {
  anomalies: AnomalyItem[];
}

const severityTone: Record<string, string> = {
  LOW: 'severity-low',
  MEDIUM: 'severity-medium',
  HIGH: 'severity-high',
  CRITICAL: 'severity-critical',
  UNKNOWN: 'severity-neutral'
};

export function AnomalyList({ anomalies }: AnomalyListProps) {
  return (
    <div className="anomaly-list">
      {anomalies.map((anomaly, index) => {
        const severity = (anomaly.severity ?? 'UNKNOWN').toString().toUpperCase();
        return (
          <div key={`${anomaly.code ?? 'anomaly'}-${index}`} className="anomaly-item">
            <div className={`severity-pill ${severityTone[severity] ?? 'severity-neutral'}`}>{severity}</div>
            <div className="anomaly-code">{anomaly.code ?? 'UNKNOWN_CODE'}</div>
            <div className="anomaly-description">{anomaly.description ?? 'No description provided.'}</div>
            {anomaly.evidence ? <div className="anomaly-evidence">Evidence: {anomaly.evidence}</div> : null}
          </div>
        );
      })}
    </div>
  );
}

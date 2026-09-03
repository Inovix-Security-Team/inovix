import type { EvidenceItem } from '../types';

interface EvidencePanelProps {
  evidence: EvidenceItem[];
}

export function EvidencePanel({ evidence }: EvidencePanelProps) {
  return (
    <div className="evidence-list">
      {evidence.map((item, index) => (
        <div key={`${item.type ?? 'evidence'}-${index}`} className="evidence-card">
          <div className="evidence-header">
            <strong>{item.type ?? 'Unknown evidence type'}</strong>
          </div>
          <div className="evidence-meta">
            <div><span className="label">Source</span><span className="value">{item.source ?? 'Not available'}</span></div>
            <div><span className="label">Timestamp</span><span className="value">{item.timestamp ?? 'Not available'}</span></div>
          </div>
          <div className="evidence-raw">
            <span className="label">Raw</span>
            <pre>{item.raw ?? 'Not available'}</pre>
          </div>
          {item.description ? <div className="evidence-description">{item.description}</div> : null}
        </div>
      ))}
    </div>
  );
}

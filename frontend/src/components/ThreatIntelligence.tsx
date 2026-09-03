import type { ThreatIntelligenceData } from '../types';

interface ThreatIntelligenceProps {
  data: ThreatIntelligenceData | null;
}

const fmt = (value: string | number | null | undefined) => value ?? 'Not available';

export function ThreatIntelligence({ data }: ThreatIntelligenceProps) {
  if (!data || Object.keys(data).length === 0) {
    return <div className="empty-state-inline">No enrichment available</div>;
  }

  return (
    <div className="threat-grid">
      <div className="field"><span className="label">IP Reputation</span><span className="value">{fmt(data.ip_reputation)}</span></div>
      <div className="field"><span className="label">Domain Reputation</span><span className="value">{fmt(data.domain_reputation)}</span></div>
      <div className="field"><span className="label">Blacklist Hits</span><span className="value">{String(data.blacklist_hits ?? 'Not available')}</span></div>
      <div className="field"><span className="label">Known Campaign</span><span className="value">{fmt(data.known_campaign)}</span></div>
      <div className="field"><span className="label">Related Infrastructure</span><span className="value">{Array.isArray(data.related_infrastructure) && data.related_infrastructure.length > 0 ? data.related_infrastructure.join(', ') : 'Not available'}</span></div>
      <div className="field"><span className="label">Confidence</span><span className="value">{typeof data.confidence === 'number' ? `${Math.round(data.confidence * 100)}%` : 'Not available'}</span></div>
    </div>
  );
}

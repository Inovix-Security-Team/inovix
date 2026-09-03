import type { OriginData } from '../types';

interface OriginIntelligenceProps {
  origin: OriginData | null;
}

const formatConfidence = (value?: number | null) => {
  if (typeof value !== 'number' || Number.isNaN(value)) return 'Not available';
  return `${Math.round(value * 100)}%`;
};

export function OriginIntelligence({ origin }: OriginIntelligenceProps) {
  return (
    <div className="origin-grid">
      <div className="field"><span className="label">IP</span><span className="value">{origin?.ip ?? 'Not available'}</span></div>
      <div className="field"><span className="label">Country</span><span className="value">{origin?.country ?? 'Not available'}</span></div>
      <div className="field"><span className="label">Region</span><span className="value">{origin?.region ?? 'Not available'}</span></div>
      <div className="field"><span className="label">City</span><span className="value">{origin?.city ?? 'Not available'}</span></div>
      <div className="field"><span className="label">ISP</span><span className="value">{origin?.isp ?? 'Not available'}</span></div>
      <div className="field"><span className="label">ASN</span><span className="value">{origin?.asn ?? 'Not available'}</span></div>
      <div className="field"><span className="label">Hosting Provider</span><span className="value">{origin?.hosting_provider ?? 'Not available'}</span></div>
      <div className="field"><span className="label">Confidence</span><span className="value">{formatConfidence(origin?.confidence)}</span></div>
    </div>
  );
}

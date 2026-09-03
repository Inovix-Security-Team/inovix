import type { Verdict } from '../types';

interface VerdictBadgeProps {
  verdict?: Verdict | null;
}

const verdictColors: Record<string, string> = {
  SAFE: 'status-safe',
  SUSPICIOUS: 'status-suspicious',
  MALICIOUS: 'status-malicious',
  IMPERSONATED: 'status-suspicious',
  PHISHING: 'status-malicious',
  FRAUD: 'status-malicious',
  UNKNOWN: 'status-unknown'
};

export function VerdictBadge({ verdict }: VerdictBadgeProps) {
  const normalized = (verdict ?? 'UNKNOWN').toString().toUpperCase();
  const tone = verdictColors[normalized] ?? 'status-unknown';

  return <div className={`verdict-badge ${tone}`}>{normalized || 'Not available'}</div>;
}

import type { IocData } from '../types';

interface IOCSectionProps {
  iocs: IocData | null;
}

const categories = [
  { key: 'ips', label: 'IPs' },
  { key: 'domains', label: 'Domains' },
  { key: 'urls', label: 'URLs' },
  { key: 'hashes', label: 'Hashes' },
  { key: 'emails', label: 'Email addresses' }
] as const;

export function IOCSection({ iocs }: IOCSectionProps) {
  const data = iocs ?? {};

  return (
    <div className="ioc-grid">
      {categories.map((category) => {
        const values = (data[category.key] ?? []) as string[];
        return (
          <div key={category.key} className="ioc-card">
            <div className="ioc-title">{category.label}</div>
            {values && values.length > 0 ? (
              <ul className="ioc-list">
                {values.map((item, idx) => (
                  <li key={`${category.key}-${idx}`}>{item}</li>
                ))}
              </ul>
            ) : (
              <div className="empty-state-inline">No indicators found</div>
            )}
          </div>
        );
      })}
    </div>
  );
}

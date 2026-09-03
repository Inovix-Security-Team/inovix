import type { RelayHop } from '../types';

interface RelayPathProps {
  hops: RelayHop[];
}

export function RelayPath({ hops }: RelayPathProps) {
  if (!hops || hops.length === 0) {
    return <div className="empty-state-inline">No relay path available</div>;
  }

  return (
    <div className="relay-path" aria-label="Relay path timeline">
      {hops.map((hop, index) => (
        <div key={`${hop.hostname ?? 'hop'}-${index}`} className="relay-hop">
          <div className="relay-node">
            <span className="relay-host">[{hop.hostname ?? 'Unknown host'}]</span>
            <span className="relay-ip">{hop.ip ?? 'Not available'}</span>
            <span className="relay-status">{hop.status ?? 'Unknown status'}</span>
          </div>
          {index < hops.length - 1 ? <div className="relay-arrow">↓</div> : null}
        </div>
      ))}
    </div>
  );
}

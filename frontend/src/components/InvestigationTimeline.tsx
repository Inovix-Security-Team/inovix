import type { TimelineEvent } from '../types';

interface InvestigationTimelineProps {
  events: TimelineEvent[];
}

export function InvestigationTimeline({ events }: InvestigationTimelineProps) {
  return (
    <div className="timeline" aria-label="Investigation timeline">
      {events.map((event, index) => (
        <div key={`${event.label ?? 'event'}-${index}`} className="timeline-item">
          <div className="timeline-time">{event.time ?? 'Unknown time'}</div>
          <div className="timeline-line" aria-hidden="true" />
          <div className="timeline-label">{event.label ?? 'Event'}</div>
        </div>
      ))}
    </div>
  );
}

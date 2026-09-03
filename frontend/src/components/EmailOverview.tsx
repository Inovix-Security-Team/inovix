import type { EmailSummary } from '../types';

interface EmailOverviewProps {
  email: EmailSummary;
}

const valueOrMissing = (value?: string | null) => value ?? 'Not available';

export function EmailOverview({ email }: EmailOverviewProps) {
  return (
    <div className="email-overview">
      <div className="section-header">
        <h2>Email Analysis</h2>
      </div>

      <div className="detail-grid">
        <div className="field">
          <span className="label">Subject</span>
          <span className="value">{valueOrMissing(email.subject)}</span>
        </div>
        <div className="field">
          <span className="label">From</span>
          <span className="value">{valueOrMissing(email.from)}</span>
        </div>
        <div className="field">
          <span className="label">To</span>
          <span className="value">{valueOrMissing(email.to)}</span>
        </div>
        <div className="field">
          <span className="label">Date/Time</span>
          <span className="value">{valueOrMissing(email.date)}</span>
        </div>
        <div className="field">
          <span className="label">Reply-To</span>
          <span className="value">{valueOrMissing(email.reply_to)}</span>
        </div>
        <div className="field">
          <span className="label">Return-Path</span>
          <span className="value">{valueOrMissing(email.return_path)}</span>
        </div>
        <div className="field">
          <span className="label">Verdict</span>
          <span className="value">{valueOrMissing(email.verdict || 'UNKNOWN')}</span>
        </div>
        <div className="field">
          <span className="label">Risk</span>
          <span className="value">{email.risk && typeof email.risk.score === 'number' ? `${email.risk.score} / 100` : 'Not available'}</span>
        </div>
        <div className="field">
          <span className="label">Status</span>
          <span className="value">{valueOrMissing(email.status)}</span>
        </div>
      </div>
    </div>
  );
}

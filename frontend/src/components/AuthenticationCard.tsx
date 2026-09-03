import type { AuthenticationData } from '../types';

interface AuthenticationCardProps {
  authentication: AuthenticationData | null;
}

const labelValue = (value?: string) => value ?? 'Not available';

export function AuthenticationCard({ authentication }: AuthenticationCardProps) {
  const spf = authentication?.spf ?? {};
  const dkim = authentication?.dkim ?? {};
  const dmarc = authentication?.dmarc ?? {};

  return (
    <div className="auth-grid">
      <div className="auth-cell">
        <h4>SPF</h4>
        <div className="auth-status">{labelValue(spf.result)}</div>
        {spf.mail_from || spf.domain || spf.details ? (
          <div className="auth-detail">
            {spf.mail_from ? <div>Mail From: {spf.mail_from}</div> : null}
            {spf.domain ? <div>Domain: {spf.domain}</div> : null}
            {spf.details ? <div>{spf.details}</div> : null}
          </div>
        ) : null}
      </div>
      <div className="auth-cell">
        <h4>DKIM</h4>
        <div className="auth-status">{labelValue(dkim.result)}</div>
        {dkim.domain || dkim.selector || dkim.details ? (
          <div className="auth-detail">
            {dkim.domain ? <div>Domain: {dkim.domain}</div> : null}
            {dkim.selector ? <div>Selector: {dkim.selector}</div> : null}
            {dkim.details ? <div>{dkim.details}</div> : null}
          </div>
        ) : null}
      </div>
      <div className="auth-cell">
        <h4>DMARC</h4>
        <div className="auth-status">{labelValue(dmarc.result)}</div>
        {dmarc.header_from || dmarc.policy || dmarc.details ? (
          <div className="auth-detail">
            {dmarc.header_from ? <div>Header From: {dmarc.header_from}</div> : null}
            {dmarc.policy ? <div>Policy: {dmarc.policy}</div> : null}
            {dmarc.details ? <div>{dmarc.details}</div> : null}
          </div>
        ) : null}
      </div>
    </div>
  );
}

interface SenderIdentityProps {
  identity: {
    from_domain?: string;
    reply_to_domain?: string;
    return_path_domain?: string;
    identity_mismatch?: boolean | null;
  } | null;
  email: { from?: string; reply_to?: string; return_path?: string };
}

export function SenderIdentity({ identity, email }: SenderIdentityProps) {
  const fromDomain = identity?.from_domain || email.from || 'Not available';
  const replyToDomain = identity?.reply_to_domain || email.reply_to || 'Not available';
  const returnPathDomain = identity?.return_path_domain || email.return_path || 'Not available';

  return (
    <div className="identity-grid">
      <div className="identity-row">
        <span className="label">From</span>
        <span className="value">{fromDomain}</span>
      </div>
      <div className="identity-row">
        <span className="label">Reply-To</span>
        <span className="value">{replyToDomain}</span>
      </div>
      <div className="identity-row">
        <span className="label">Return-Path</span>
        <span className="value">{returnPathDomain}</span>
      </div>
      <div className="identity-row mismatch-row">
        <span className="label">Identity mismatch</span>
        <span className="value">{identity?.identity_mismatch === true ? 'YES' : identity?.identity_mismatch === false ? 'NO' : 'Not available'}</span>
      </div>
    </div>
  );
}

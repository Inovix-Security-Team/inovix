interface ErrorStateProps {
  message?: string;
  onRetry?: () => void;
}

export function ErrorState({ message = 'Unable to load email analysis.', onRetry }: ErrorStateProps) {
  return (
    <div className="state-shell" data-testid="error-state">
      <div className="state-card error-card">
        <h2>{message}</h2>
        <p>Please try again.</p>
        {onRetry ? (
          <button type="button" className="retry-button" onClick={onRetry}>
            Retry
          </button>
        ) : null}
      </div>
    </div>
  );
}

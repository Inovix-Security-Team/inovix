export function LoadingState() {
  return (
    <div className="state-shell" data-testid="loading-state">
      <div className="state-card">
        <h2>Analyzing email...</h2>
        <ul className="loading-list">
          <li>Parsing headers</li>
          <li>Analyzing sender</li>
          <li>Checking IOCs</li>
          <li>Threat intelligence</li>
          <li>Calculating risk</li>
        </ul>
      </div>
    </div>
  );
}

import "./ComponentShowcase.css";

import SeverityBadge from "./SeverityBadge/SeverityBadge";
import StatusIndicator from "./StatusIndicator/StatusIndicator";

function ComponentShowcase() {
  return (
    <div className="component-showcase">
      <h1>Inovix UI Components</h1>
      <p>Reusable security interface components</p>

      <section>
        <h2>Security Status</h2>

        <div className="showcase-row">
          <StatusIndicator status="SAFE" />
          <StatusIndicator status="SUSPICIOUS" />
          <StatusIndicator status="MALICIOUS" />
          <StatusIndicator status="UNKNOWN" />
        </div>
      </section>

      <section>
        <h2>Severity</h2>

        <div className="showcase-row">
          <SeverityBadge level="LOW" />
          <SeverityBadge level="MEDIUM" />
          <SeverityBadge level="HIGH" />
          <SeverityBadge level="CRITICAL" />
        </div>
      </section>
    </div>
  );
}

export default ComponentShowcase;
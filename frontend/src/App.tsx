import { useMemo, useState } from 'react';
import { emailAnalysisFixture } from './fixtures/emailAnalysisFixture';
import type { EmailAnalysisResponse } from './types';
import { EmailOverview } from './components/EmailOverview';
import { VerdictBadge } from './components/VerdictBadge';
import { RiskScoreCard } from './components/RiskScoreCard';
import { AuthenticationCard } from './components/AuthenticationCard';
import { SenderIdentity } from './components/SenderIdentity';
import { OriginIntelligence } from './components/OriginIntelligence';
import { RelayPath } from './components/RelayPath';
import { IOCSection } from './components/IOCSection';
import { ThreatIntelligence } from './components/ThreatIntelligence';
import { AnomalyList } from './components/AnomalyList';
import { EvidencePanel } from './components/EvidencePanel';
import { InvestigationTimeline } from './components/InvestigationTimeline';
import { LoadingState } from './components/LoadingState';
import { ErrorState } from './components/ErrorState';
import { EmptyState } from './components/EmptyState';

interface AppProps {
  analysis?: EmailAnalysisResponse | null;
  forceLoading?: boolean;
  forceError?: string | null;
}

export default function App({ analysis: initialAnalysis, forceLoading = false, forceError = null }: AppProps) {
  const [analysis, setAnalysis] = useState<EmailAnalysisResponse | null>(initialAnalysis ?? emailAnalysisFixture);
  const [isLoading, setIsLoading] = useState(forceLoading);
  const [error, setError] = useState<string | null>(forceError);

  const summary = useMemo(() => {
    return {
      verdict: analysis?.verdict ?? analysis?.email?.verdict ?? 'UNKNOWN',
      risk: analysis?.risk ?? analysis?.email?.risk ?? { score: 0, level: 'UNKNOWN' },
      authentication: analysis?.authentication ?? null,
      senderIdentity: analysis?.sender_identity ?? null,
      origin: analysis?.origin ?? null,
      relayPath: analysis?.relay_path ?? [],
      iocs: analysis?.iocs ?? null,
      threatIntelligence: analysis?.threat_intelligence ?? null,
      anomalies: analysis?.anomalies ?? [],
      evidence: analysis?.evidence ?? [],
      timeline: analysis?.timeline ?? []
    };
  }, [analysis]);

  const handleRetry = () => {
    setError(null);
    setIsLoading(true);
    setTimeout(() => {
      setAnalysis(initialAnalysis ?? emailAnalysisFixture);
      setIsLoading(false);
    }, 250);
  };

  if (forceLoading || isLoading) {
    return <LoadingState />;
  }

  if (forceError || error) {
    return <ErrorState message={forceError ?? error ?? 'Unable to load email analysis.'} onRetry={handleRetry} />;
  }

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand">INOVIX</div>
        <div className="topbar-title">EMAIL SECURITY</div>
      </header>

      <main className="dashboard">
        <section className="panel overview-panel">
          <EmailOverview email={analysis?.email ?? {}} />
        </section>

        <section className="summary-grid">
          <div className="panel summary-panel">
            <h3>VERDICT</h3>
            <VerdictBadge verdict={summary.verdict} />
          </div>

          <div className="panel summary-panel">
            <h3>RISK SCORE</h3>
            <RiskScoreCard risk={summary.risk} />
          </div>
        </section>

        <section className="panel section-panel">
          <h3>SENDER IDENTITY</h3>
          <SenderIdentity identity={summary.senderIdentity} email={analysis?.email ?? {}} />
        </section>

        <section className="panel section-panel">
          <h3>AUTHENTICATION</h3>
          <AuthenticationCard authentication={summary.authentication} />
        </section>

        <section className="panel section-panel">
          <h3>ORIGIN &amp; LOCATION</h3>
          <OriginIntelligence origin={summary.origin} />
        </section>

        <section className="panel section-panel">
          <h3>RELAY PATH</h3>
          <RelayPath hops={summary.relayPath} />
        </section>

        <section className="panel section-panel">
          <h3>INDICATORS OF COMPROMISE</h3>
          <IOCSection iocs={summary.iocs} />
        </section>

        <section className="panel section-panel">
          <h3>THREAT INTELLIGENCE</h3>
          <ThreatIntelligence data={summary.threatIntelligence} />
        </section>

        <section className="panel section-panel">
          <h3>ANOMALIES</h3>
          {summary.anomalies && summary.anomalies.length > 0 ? (
            <AnomalyList anomalies={summary.anomalies} />
          ) : (
            <EmptyState title="No anomalies detected" description="No anomaly data available for this email." />
          )}
        </section>

        <section className="panel section-panel">
          <h3>FORENSIC EVIDENCE</h3>
          {summary.evidence && summary.evidence.length > 0 ? (
            <EvidencePanel evidence={summary.evidence} />
          ) : (
            <EmptyState title="No forensic evidence available" description="No evidence data available for this email." />
          )}
        </section>

        <section className="panel section-panel">
          <h3>INVESTIGATION TIMELINE</h3>
          {summary.timeline && summary.timeline.length > 0 ? (
            <InvestigationTimeline events={summary.timeline} />
          ) : (
            <EmptyState title="No investigation timeline" description="Timeline data is not available for this email." />
          )}
        </section>
      </main>
    </div>
  );
}

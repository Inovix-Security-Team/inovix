import { render, screen } from '@testing-library/react';
import App from './App';
import { emailAnalysisFixture } from './fixtures/emailAnalysisFixture';

describe('Email Security Dashboard', () => {
  it('renders SAFE verdict for a low-risk result', () => {
    render(
      <App
        analysis={{
          verdict: 'SAFE',
          risk: { score: 12, level: 'LOW' },
          email: { subject: 'Weekly report', from: 'team@example.com', to: 'staff@example.com' },
          authentication: { spf: { result: 'PASS' }, dkim: { result: 'PASS' }, dmarc: { result: 'PASS' } },
          origin: { ip: '8.8.8.8', country: 'United States' },
          iocs: { ips: [], domains: [], urls: [], hashes: [], emails: [] },
          threat_intelligence: null,
          anomalies: [],
          evidence: [],
          timeline: []
        }}
      />
    );

    expect(screen.getByText('SAFE')).toBeInTheDocument();
  });

  it('renders suspicious verdict with medium/high risk', () => {
    render(
      <App
        analysis={{
          verdict: 'SUSPICIOUS',
          risk: { score: 75, level: 'HIGH' },
          email: { subject: 'Action required', from: 'alert@example.com', to: 'analyst@example.com' },
          authentication: { spf: { result: 'FAIL' }, dkim: { result: 'PASS' }, dmarc: { result: 'FAIL' } }
        }}
      />
    );

    expect(screen.getByText('SUSPICIOUS')).toBeInTheDocument();
    expect(screen.getByText('75 / 100')).toBeInTheDocument();
  });

  it('renders malicious verdict for high severity', () => {
    render(
      <App
        analysis={{
          verdict: 'MALICIOUS',
          risk: { score: 96, level: 'CRITICAL' },
          email: { subject: 'Urgent payment', from: 'malware@example.com', to: 'employee@company.com' }
        }}
      />
    );

    expect(screen.getByText('MALICIOUS')).toBeInTheDocument();
    expect(screen.getByText('96 / 100')).toBeInTheDocument();
  });

  it('shows authentication failure results', () => {
    render(
      <App
        analysis={{
          verdict: 'SUSPICIOUS',
          risk: { score: 78, level: 'HIGH' },
          email: { subject: 'Example', from: 'test@example.com', to: 'user@example.com' },
          authentication: {
            spf: { result: 'FAIL', mail_from: 'example.com' },
            dkim: { result: 'FAIL', domain: 'example.com' },
            dmarc: { result: 'FAIL', header_from: 'example.com' }
          }
        }}
      />
    );

    expect(screen.getAllByText('FAIL').length).toBeGreaterThan(0);
  });

  it('renders anomalies with severity and description', () => {
    render(
      <App
        analysis={{
          verdict: 'SUSPICIOUS',
          risk: { score: 60, level: 'MEDIUM' },
          email: { subject: 'Example', from: 'user@example.com', to: 'person@example.com' },
          anomalies: [{ code: 'FROM_REPLY_TO_MISMATCH', severity: 'HIGH', description: 'Sender identity differs between From and Reply-To fields.' }],
          evidence: [],
          timeline: []
        }}
      />
    );

    expect(screen.getByText('FROM_REPLY_TO_MISMATCH')).toBeInTheDocument();
    expect(screen.getByText('Sender identity differs between From and Reply-To fields.')).toBeInTheDocument();
  });

  it('renders missing geolocation safely', () => {
    render(
      <App
        analysis={{
          verdict: 'SUSPICIOUS',
          risk: { score: 45, level: 'MEDIUM' },
          email: { subject: 'Example', from: 'user@example.com', to: 'person@example.com' },
          origin: null,
          iocs: { ips: [], domains: [], urls: [], hashes: [], emails: [] }
        }}
      />
    );

    expect(screen.getAllByText('Not available').length).toBeGreaterThan(0);
  });

  it('renders no enrichment available for missing threat intelligence', () => {
    render(
      <App
        analysis={{
          verdict: 'SAFE',
          risk: { score: 10, level: 'LOW' },
          email: { subject: 'Example', from: 'safe@example.com', to: 'person@example.com' },
          threat_intelligence: {},
          iocs: { ips: [], domains: [], urls: [], hashes: [], emails: [] }
        }}
      />
    );

    expect(screen.getByText('No enrichment available')).toBeInTheDocument();
  });

  it('renders API error state', () => {
    render(<App forceError="Unable to load email analysis." />);

    expect(screen.getByText('Unable to load email analysis.')).toBeInTheDocument();
    expect(screen.getByText('Please try again.')).toBeInTheDocument();
  });

  it('handles empty IOC arrays without crashing', () => {
    render(
      <App
        analysis={{
          verdict: 'SAFE',
          risk: { score: 5, level: 'LOW' },
          email: { subject: 'Example', from: 'safe@example.com', to: 'person@example.com' },
          iocs: { ips: [], domains: [], urls: [], hashes: [], emails: [] }
        }}
      />
    );

    expect(screen.getAllByText('No indicators found').length).toBeGreaterThan(0);
  });

  it('renders incomplete responses safely', () => {
    render(
      <App
        analysis={{
          verdict: 'UNKNOWN',
          email: { subject: 'Example' }
        }}
      />
    );

    expect(screen.getByText('Example')).toBeInTheDocument();
  });

  it('displays untrusted email content as escaped text', () => {
    render(
      <App
        analysis={{
          verdict: 'MALICIOUS',
          risk: { score: 92, level: 'HIGH' },
          email: { subject: '<script>alert(1)</script>', from: 'danger@example.com', to: 'user@example.com' },
          evidence: [{ type: 'Received Header', source: 'mail.example.com', raw: '<script>alert(1)</script>' }]
        }}
      />
    );

    expect(screen.getAllByText(/alert\(1\)/).length).toBeGreaterThan(0);
  });

  it('renders fixture data correctly', () => {
    render(<App analysis={emailAnalysisFixture} />);
    expect(screen.getByText('Urgent Payment Required')).toBeInTheDocument();
    expect(screen.getAllByText('SUSPICIOUS').length).toBeGreaterThan(0);
  });
});

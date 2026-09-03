import type { EmailAnalysisResponse } from '../types';

export const emailAnalysisFixture: EmailAnalysisResponse = {
  analysis_id: 'analysis-001',
  email: {
    subject: 'Urgent Payment Required',
    from: 'finance@example.com',
    to: 'employee@company.com',
    reply_to: 'billing@suspicious.net',
    return_path: 'mail.example.org',
    date: '2026-09-03T09:31:00Z',
    verdict: 'SUSPICIOUS',
    risk: { score: 78, level: 'HIGH' },
    status: 'Analysis Complete'
  },
  verdict: 'SUSPICIOUS',
  risk: { score: 78, level: 'HIGH' },
  authentication: {
    spf: { result: 'FAIL', mail_from: 'example.com' },
    dkim: { result: 'PASS', domain: 'example.com', selector: 'selector1' },
    dmarc: { result: 'FAIL', header_from: 'example.com', policy: 'reject' }
  },
  sender_identity: {
    from_domain: 'example.com',
    reply_to_domain: 'suspicious.net',
    return_path_domain: 'mail.example.org',
    identity_mismatch: true
  },
  origin: {
    ip: '185.23.44.15',
    country: 'Netherlands',
    region: 'North Holland',
    city: 'Amsterdam',
    isp: 'Example Hosting',
    asn: 'AS12345',
    hosting_provider: 'Cloudflare',
    confidence: 0.87
  },
  relay_path: [
    { hostname: 'origin', ip: '185.23.44.15', timestamp: '09:30 UTC', private: false, status: 'External' },
    { hostname: 'mail.example.net', ip: '10.0.0.5', timestamp: '09:31 UTC', private: true, status: 'Private' },
    { hostname: 'relay.example.net', ip: '203.0.113.42', timestamp: '09:31 UTC', private: false, status: 'External' },
    { hostname: 'mx.company.com', ip: '203.0.113.88', timestamp: '09:32 UTC', private: false, status: 'External' }
  ],
  iocs: {
    ips: ['185.23.44.15', '203.0.113.42'],
    domains: ['suspicious.net', 'mail.example.org'],
    urls: ['https://example-alerts[.]com/verify'],
    hashes: ['9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08'],
    emails: ['billing@suspicious.net', 'support@phishing.example']
  },
  threat_intelligence: {
    ip_reputation: 'MALICIOUS',
    domain_reputation: 'SUSPICIOUS',
    blacklist_hits: 3,
    known_campaign: 'Invoice Fraud Campaign',
    confidence: 0.91,
    malicious: true
  },
  anomalies: [
    {
      code: 'FROM_REPLY_TO_MISMATCH',
      severity: 'HIGH',
      description: 'Sender identity differs between From and Reply-To fields.',
      evidence: 'Reply-To domain suspicious.net differs from finance@example.com' 
    }
  ],
  evidence: [
    {
      type: 'Authentication-Results',
      source: 'mail.example.com',
      raw: 'spf=fail smtp.mailfrom=example.com',
      timestamp: '2026-09-03T09:31:14Z',
      description: 'SPF result for inbound message'
    }
  ],
  timeline: [
    { time: '09:31', label: 'Email received' },
    { time: '09:31', label: 'Headers parsed' },
    { time: '09:31', label: 'Authentication analyzed' },
    { time: '09:32', label: 'IOCs extracted' },
    { time: '09:32', label: 'Threat intelligence queried' },
    { time: '09:32', label: 'Risk calculated' },
    { time: '09:32', label: 'Verdict generated' }
  ]
};

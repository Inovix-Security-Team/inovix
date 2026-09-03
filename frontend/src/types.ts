export type Verdict = 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS' | 'IMPERSONATED' | 'PHISHING' | 'FRAUD' | string;

export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | string;

export type AuthenticationStatus = 'PASS' | 'FAIL' | 'UNKNOWN' | string;

export type Severity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | string;

export interface EmailSummary {
  subject?: string;
  from?: string;
  to?: string;
  reply_to?: string;
  return_path?: string;
  date?: string;
  verdict?: Verdict;
  risk?: { score?: number; level?: RiskLevel } | null;
  status?: string;
}

export interface AuthenticationResult {
  result?: AuthenticationStatus;
  mail_from?: string;
  domain?: string;
  selector?: string;
  header_from?: string;
  policy?: string;
  details?: string;
}

export interface AuthenticationData {
  spf?: AuthenticationResult | null;
  dkim?: AuthenticationResult | null;
  dmarc?: AuthenticationResult | null;
}

export interface OriginData {
  ip?: string;
  country?: string;
  region?: string;
  city?: string;
  isp?: string;
  asn?: string;
  hosting_provider?: string;
  confidence?: number | null;
}

export interface RelayHop {
  hostname?: string;
  ip?: string;
  timestamp?: string;
  private?: boolean;
  status?: string;
}

export interface IocData {
  ips?: string[];
  domains?: string[];
  urls?: string[];
  hashes?: string[];
  emails?: string[];
}

export interface ThreatIntelligenceData {
  ip_reputation?: string;
  domain_reputation?: string;
  blacklist_hits?: number | string;
  known_campaign?: string;
  related_infrastructure?: string[];
  confidence?: number | null;
  malicious?: boolean | null;
}

export interface AnomalyItem {
  code?: string;
  severity?: Severity;
  description?: string;
  evidence?: string;
}

export interface EvidenceItem {
  type?: string;
  source?: string;
  raw?: string;
  timestamp?: string;
  description?: string;
}

export interface TimelineEvent {
  time?: string;
  label?: string;
}

export interface EmailAnalysisResponse {
  analysis_id?: string;
  email?: EmailSummary;
  verdict?: Verdict;
  risk?: { score?: number; level?: RiskLevel } | null;
  authentication?: AuthenticationData | null;
  sender_identity?: {
    from_domain?: string;
    reply_to_domain?: string;
    return_path_domain?: string;
    identity_mismatch?: boolean | null;
  } | null;
  origin?: OriginData | null;
  relay_path?: RelayHop[] | null;
  iocs?: IocData | null;
  threat_intelligence?: ThreatIntelligenceData | null;
  anomalies?: AnomalyItem[] | null;
  evidence?: EvidenceItem[] | null;
  timeline?: TimelineEvent[] | null;
  status?: string;
}

export interface DashboardState {
  isLoading: boolean;
  error: string | null;
  hasData: boolean;
}

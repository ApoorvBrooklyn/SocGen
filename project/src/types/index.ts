// TypeScript types for Security Management Platform

// CVE Types
export interface CVE {
  id: string;
  title: string;
  description: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low';
  cvss_score: number;
  published_date: string;
  last_updated: string;
  nvd_status: string;
  cwe_id: string;
  affected_products: string[];
  exploit_available: boolean;
  exploit_complexity: string;
  exploit_maturity: string;
  patch_available: boolean;
  affected_assets: number;
  llm_summary?: string;
  exploit_method?: string;
  business_impact?: string;
  layman_explanation?: string;
  patch_sources?: PatchSource[];
  github_references?: GitHubReference[];
  remediation_steps?: string[];
  confidence_score?: number;
  threat_intelligence?: ThreatIntelligence;
}

export interface PatchSource {
  vendor: string;
  version: string;
  release_date: string;
  download_url?: string;
  patch_notes?: string;
  package_name?: string;
  command?: string;
}

export interface GitHubReference {
  type: 'commit' | 'advisory';
  url: string;
  title: string;
  author?: string;
  date?: string;
  severity?: string;
}

export interface ThreatIntelligence {
  exploit_in_wild: boolean;
  first_seen_exploit?: string;
  attack_vectors: string[];
  targeted_sectors: string[];
  ioc_indicators: string[];
}

// Scan Types
export interface ScanConfig {
  target: string;
  scan_type: 'quick' | 'comprehensive' | 'custom';
  scanner_type: 'openvas' | 'nessus' | 'osquery';
  credentials?: any;
  options?: any;
}

export interface ScanResult {
  id: string;
  target: string;
  scan_type: string;
  status: 'running' | 'completed' | 'failed' | 'cancelled';
  start_time: string;
  end_time?: string;
  vulnerabilities: Vulnerability[];
  summary: ScanSummary;
}

export interface Vulnerability {
  id: string;
  title: string;
  severity: string;
  cvss_score: number;
  description: string;
  affected_assets: string[];
  remediation: string;
  references: string[];
}

export interface ScanSummary {
  total_vulnerabilities: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  risk_score: number;
}

// Patch Types
export interface PatchRecommendation {
  cve_id: string;
  os_type: string;
  patch_command: string;
  confidence_score: number;
  rollback_command: string;
  alternative_approach: string;
  estimated_downtime: string;
  prerequisites: string[];
  verification_command: string;
}

export interface PatchDeployment {
  patch_id: string;
  target_assets: string[];
  deployment_strategy: 'immediate' | 'scheduled' | 'manual';
  schedule_time?: string;
  rollback_plan: string;
}

// Chat Types
export interface ChatSession {
  id: string;
  title: string;
  session_type: 'general' | 'incident_response' | 'threat_hunting' | 'vulnerability_analysis';
  created_at: string;
  updated_at: string;
  message_count: number;
  last_message?: string;
  security_context?: {
    session_type: string;
    active_incidents: number;
    critical_vulnerabilities: number;
    threat_level: 'normal' | 'medium' | 'high';
    [key: string]: any;
  };
}

export interface ChatMessage {
  id: string;
  session_id: string;
  role: 'user' | 'assistant';
  content: string;
  timestamp: string;
  metadata?: {
    model_used?: string;
    context_length?: number;
    security_insights?: string[];
    recommended_actions?: string[];
    [key: string]: any;
  };
  security_context?: {
    session_type?: string;
    detected_keywords?: string[];
    security_insights_count?: number;
    recommended_actions_count?: number;
    [key: string]: any;
  };
}

// Report Types
export interface ReportConfig {
  report_type: 'executive' | 'technical' | 'compliance' | 'metrics' | 'incident' | 'threat_intelligence';
  date_range: {
    start: string;
    end: string;
  };
  assets?: string[];
  vulnerabilities?: string[];
  format: 'pdf' | 'html' | 'json';
  recipients?: string[];
}

export interface Report {
  id: string;
  title: string;
  report_type: string;
  generated_at: string;
  status: 'generating' | 'completed' | 'failed';
  download_url?: string;
  summary: ReportSummary;
}

export interface ReportSummary {
  total_assets: number;
  total_vulnerabilities: number;
  critical_vulnerabilities: number;
  high_vulnerabilities: number;
  risk_score: number;
  recommendations: string[];
}

// LLM Types
export interface LLMStatus {
  status: 'active' | 'inactive';
  model_info: {
    is_loaded: boolean;
    model_name: string;
    model_type: string;
    device: string;
    max_length: number;
    temperature: number;
    top_p: number;
    cuda_available: boolean;
    model_parameters: number;
  };
}

export interface LLMModel {
  name: string;
  description: string;
  size: string;
  type: string;
}

export interface LLMTestResult {
  prompt: string;
  response: string;
  success: boolean;
}

// Simulation Types
export interface SimulationConfig {
  count?: number;
  severity?: string;
  target?: string;
  scan_type?: string;
  threat_type?: string;
}

// Risk Types
export interface RiskAssessment {
  asset_id: string;
  risk_score: number;
  vulnerabilities: string[];
  recommendations: string[];
  priority: 'P1' | 'P2' | 'P3' | 'P4';
}

// Asset Types
export interface Asset {
  id: string;
  name: string;
  type: 'server' | 'workstation' | 'network_device' | 'application' | 'database';
  ip_address: string;
  os_type: string;
  os_version: string;
  status: 'active' | 'inactive' | 'maintenance';
  risk_score: number;
  last_scan: string;
  vulnerabilities: string[];
  tags: string[];
}

// Ticket Types
export interface Ticket {
  id: string;
  title: string;
  description: string;
  priority: 'low' | 'medium' | 'high' | 'critical';
  status: 'open' | 'in_progress' | 'resolved' | 'closed';
  assigned_to?: string;
  created_at: string;
  updated_at: string;
  due_date?: string;
  tags: string[];
  related_assets: string[];
  related_vulnerabilities: string[];
}

// API Response Types
export interface APIResponse<T> {
  data: T;
  message?: string;
  status: 'success' | 'error';
}

export interface PaginatedResponse<T> {
  data: T[];
  total: number;
  page: number;
  per_page: number;
  total_pages: number;
}

// Error Types
export interface APIError {
  detail: string;
  status_code: number;
  timestamp: string;
}

// Health Check Types
export interface HealthStatus {
  status: 'healthy' | 'degraded' | 'unhealthy';
  services: {
    llm_service: string;
    simulator: string;
  };
  timestamp: string;
  error?: string;
} 
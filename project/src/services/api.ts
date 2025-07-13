// API Service Layer for Security Management Platform
const API_BASE_URL = 'http://localhost:8000/api/v1';

// Generic API request function
async function apiRequest(endpoint: string, options: RequestInit = {}) {
  const url = `${API_BASE_URL}${endpoint}`;
  const config: RequestInit = {
    headers: {
      'Content-Type': 'application/json',
      ...options.headers,
    },
    ...options,
  };

  try {
    const response = await fetch(url, config);
    
    if (!response.ok) {
      throw new Error(`API Error: ${response.status} ${response.statusText}`);
    }
    
    return await response.json();
  } catch (error) {
    console.error('API Request failed:', error);
    throw error;
  }
}

// Vulnerable Server API
const VULN_BASE_URL = 'http://localhost:5000';

async function vulnRequest(endpoint: string, options: RequestInit = {}) {
  const url = `${VULN_BASE_URL}${endpoint}`;
  const config: RequestInit = {
    headers: {
      ...options.headers,
    },
    credentials: 'include', // for session/cookies
    ...options,
  };
  try {
    const response = await fetch(url, config);
    // Some endpoints return HTML, some JSON
    const contentType = response.headers.get('content-type');
    if (contentType && contentType.includes('application/json')) {
      return await response.json();
    }
    return await response.text();
  } catch (error) {
    console.error('Vuln API Request failed:', error);
    throw error;
  }
}

export const vulnAPI = {
  // Get users (information disclosure vulnerability)
  getUsers: () => vulnRequest('/api/users'),

  // Login (weak authentication vulnerability)
  login: (username: string, password: string) =>
    vulnRequest('/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ username, password }),
    }),

  // Search (SQL injection vulnerability)
  search: (q: string) => vulnRequest(`/search?q=${encodeURIComponent(q)}`),

  // Get posts (XSS vulnerability)
  getPosts: () => vulnRequest('/posts'),

  // Add post (XSS vulnerability)
  addPost: (title: string, content: string) =>
    vulnRequest('/add_post', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ title, content }),
    }),

  // File upload (insecure file upload vulnerability)
  uploadFile: (file: File) => {
    const formData = new FormData();
    formData.append('file', file);
    return vulnRequest('/upload', {
      method: 'POST',
      body: formData,
      // Don't set Content-Type for FormData
      headers: {},
    });
  },

  // Ping (command injection vulnerability)
  ping: (host: string) => vulnRequest(`/ping?host=${encodeURIComponent(host)}`),

  // File read (path traversal vulnerability)
  readFile: (path: string) => vulnRequest(`/file?path=${encodeURIComponent(path)}`),

  // Get comments (XSS vulnerability)
  getComments: (postId: string) => vulnRequest(`/comments?post_id=${postId}`),

  // Add comment (XSS vulnerability)
  addComment: (postId: string, author: string, content: string) =>
    vulnRequest('/add_comment', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ post_id: postId, author, content }),
    }),

  // Admin panel (IDOR vulnerability)
  getAdminPanel: () => vulnRequest('/admin'),

  // Health check
  health: () => vulnRequest('/health'),
  
  // Get vulnerabilities from vulnerable server
  getVulnerabilities: () => vulnRequest('/api/vulnerabilities'),
  
  // Get active threats from vulnerable server
  getActiveThreats: () => vulnRequest('/api/threats'),
  
  // Generate CVE from vulnerable server
  generateCVE: () => vulnRequest('/api/generate_cve'),
  
  // Get scan status from vulnerable server
  getScanStatus: () => vulnRequest('/api/scan_status'),
  
  // Test specific exploit
  testExploit: (exploitType: string, payload: string) => vulnRequest('/api/exploit_test', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ exploit_type: exploitType, payload }),
  }),
};

// CVE Analysis API
export const cveAPI = {
  // Get all CVEs
  getCVEs: () => apiRequest('/cve/'),
  
  // Get specific CVE
  getCVE: (cveId: string) => apiRequest(`/cve/${cveId}`),
  
  // Analyze CVE with LLM
  analyzeCVE: (cveData: any) => apiRequest('/cve/analyze', {
    method: 'POST',
    body: JSON.stringify(cveData),
  }),
  
  // Correlate CVE with threat intelligence
  correlateCVE: (cveId: string) => apiRequest(`/cve/${cveId}/correlate`, {
    method: 'POST',
  }),
  
  // Get CVE trends
  getTrends: () => apiRequest('/cve/trends'),
};

// Vulnerability Scanner API
export const scannerAPI = {
  // Start vulnerability scan
  startScan: (scanConfig: any) => apiRequest('/scan/', {
    method: 'POST',
    body: JSON.stringify(scanConfig),
  }),
  
  // Get scan results
  getScanResults: (scanId: string) => apiRequest(`/scan/${scanId}`),
  
  // Get all scans
  getAllScans: () => apiRequest('/scan/'),
  
  // Get scan status
  getScanStatus: (scanId: string) => apiRequest(`/scan/${scanId}/status`),
  
  // Cancel scan
  cancelScan: (scanId: string) => apiRequest(`/scan/${scanId}/cancel`, {
    method: 'POST',
  }),
};

// Patch Recommendations API
export const patchAPI = {
  // Generate patch recommendations
  generateRecommendations: (cveData: any, osType: string) => apiRequest('/patches/recommend', {
    method: 'POST',
    body: JSON.stringify({ cve_data: cveData, os_type: osType }),
  }),
  
  // Deploy patches
  deployPatches: (patchData: any) => apiRequest('/patches/deploy', {
    method: 'POST',
    body: JSON.stringify(patchData),
  }),
  
  // Verify patch deployment
  verifyPatches: (verificationData: any) => apiRequest('/patches/verify', {
    method: 'POST',
    body: JSON.stringify(verificationData),
  }),
  
  // Get patch history
  getPatchHistory: () => apiRequest('/patches/history'),
};

// Chat Assistant API for SOC Team
export const chatAPI = {
  // Create chat session
  createSession: (sessionData: any) => apiRequest('/chat/sessions', {
    method: 'POST',
    body: JSON.stringify(sessionData),
  }),
  
  // Send message with context
  sendMessage: (sessionId: string, message: string, contextType?: string) => apiRequest('/chat/messages', {
    method: 'POST',
    body: JSON.stringify({
      session_id: sessionId,
      message: message,
      context_type: contextType,
    }),
  }),
  
  // Get chat history
  getChatHistory: (sessionId: string) => apiRequest(`/chat/sessions/${sessionId}`),
  
  // Get all sessions
  getAllSessions: () => apiRequest('/chat/sessions'),
  
  // Delete session
  deleteSession: (sessionId: string) => apiRequest(`/chat/sessions/${sessionId}`, {
    method: 'DELETE',
  }),
  
  // Add security context to session
  addSecurityContext: (sessionId: string, contextType: string, contextData: any) => apiRequest(`/chat/sessions/${sessionId}/context`, {
    method: 'POST',
    body: JSON.stringify({
      session_id: sessionId,
      context_type: contextType,
      context_data: contextData,
    }),
  }),
  
  // Get security insights
  getSecurityInsights: () => apiRequest('/chat/security-insights'),
  
  // Get quick response
  getQuickResponse: (message: string) => apiRequest('/chat/quick-response', {
    method: 'POST',
    body: JSON.stringify({ message }),
  }),
  
  // Get chat statistics
  getStatistics: () => apiRequest('/chat/statistics'),
  
  // Clear session messages
  clearSession: (sessionId: string) => apiRequest(`/chat/sessions/${sessionId}/clear`, {
    method: 'POST',
  }),
};

// Reports API
export const reportsAPI = {
  // Generate report
  generateReport: (reportConfig: any) => apiRequest('/reports/generate', {
    method: 'POST',
    body: JSON.stringify(reportConfig),
  }),
  
  // Email report
  emailReport: (emailConfig: any) => apiRequest('/reports/email', {
    method: 'POST',
    body: JSON.stringify(emailConfig),
  }),
  
  // Get report templates
  getTemplates: () => apiRequest('/reports/templates'),
  
  // Schedule report
  scheduleReport: (scheduleData: any) => apiRequest('/reports/schedule', {
    method: 'POST',
    body: JSON.stringify(scheduleData),
  }),
  
  // Get scheduled reports
  getScheduledReports: () => apiRequest('/reports/scheduled'),
  
  // Get report history
  getReportHistory: () => apiRequest('/reports/history'),
};

// LLM Management API
export const llmAPI = {
  // Get LLM status
  getStatus: () => apiRequest('/llm/status'),
  
  // Get available models
  getModels: () => apiRequest('/llm/models'),
  
  // Test LLM with prompts
  testModel: (prompts: string[]) => apiRequest('/llm/test', {
    method: 'POST',
    body: JSON.stringify({ test_prompts: prompts }),
  }),
  
  // Get LLM configuration
  getConfig: () => apiRequest('/llm/config'),
};

// Simulation API
export const simulationAPI = {
  // Generate simulated CVE
  generateCVE: (config: any) => apiRequest('/simulation/cve', {
    method: 'POST',
    body: JSON.stringify(config),
  }),
  
  // Simulate vulnerability scan
  simulateScan: (scanConfig: any) => apiRequest('/simulation/scan', {
    method: 'POST',
    body: JSON.stringify(scanConfig),
  }),
  
  // Generate threat intelligence
  generateThreatIntel: (config: any) => apiRequest('/simulation/threat', {
    method: 'POST',
    body: JSON.stringify(config),
  }),
  
  // Generate exploit data
  generateExploit: (config: any) => apiRequest('/simulation/exploit', {
    method: 'POST',
    body: JSON.stringify(config),
  }),
  
  // Generate GitHub advisories
  generateGitHubAdvisory: (config: any) => apiRequest('/simulation/github-advisory', {
    method: 'POST',
    body: JSON.stringify(config),
  }),
};

// Risk Prioritization API
export const riskAPI = {
  // Get risk assessment
  getRiskAssessment: (assetData: any) => apiRequest('/risk/assess', {
    method: 'POST',
    body: JSON.stringify(assetData),
  }),
  
  // Get risk scores
  getRiskScores: () => apiRequest('/risk/scores'),
  
  // Update risk priorities
  updatePriorities: (priorities: any) => apiRequest('/risk/priorities', {
    method: 'POST',
    body: JSON.stringify(priorities),
  }),
  
  // Get real-time risk assessment
  getRealTimeRiskAssessment: () => apiRequest('/risk/real-time'),
  
  // Force recalculate priorities
  forceRecalculatePriorities: () => apiRequest('/risk/recalculate', {
    method: 'POST',
  }),
  
  // Get vulnerability priorities
  getVulnerabilityPriorities: () => apiRequest('/risk/prioritize', {
    method: 'POST',
  }),
  
  // Risk monitoring endpoints
  startRiskMonitoring: () => apiRequest('/risk/monitoring/start', {
    method: 'POST',
  }),
  
  stopRiskMonitoring: () => apiRequest('/risk/monitoring/stop', {
    method: 'POST',
  }),
  
  getRiskMonitoringStatus: () => apiRequest('/risk/monitoring/status'),
  
  manualRiskCheck: () => apiRequest('/risk/monitoring/check', {
    method: 'POST',
  }),
  
  // Get instant threat updates
  getInstantThreats: () => apiRequest('/risk/instant-threats'),
};

// Ticket Management API
export const ticketAPI = {
  // Get all tickets
  getTickets: () => apiRequest('/tickets/'),
  
  // Create ticket
  createTicket: (ticketData: any) => apiRequest('/tickets/', {
    method: 'POST',
    body: JSON.stringify(ticketData),
  }),
  
  // Update ticket
  updateTicket: (ticketId: string, ticketData: any) => apiRequest(`/tickets/${ticketId}`, {
    method: 'PUT',
    body: JSON.stringify(ticketData),
  }),
  
  // Delete ticket
  deleteTicket: (ticketId: string) => apiRequest(`/tickets/${ticketId}`, {
    method: 'DELETE',
  }),
  
  // Get ticket by ID
  getTicket: (ticketId: string) => apiRequest(`/tickets/${ticketId}`),
};

// Health Check API
export const healthAPI = {
  // Get system health
  getHealth: () => apiRequest('/health'),
  
  // Get backend status
  getBackendStatus: () => apiRequest('/'),
};

// System Management API
export const systemAPI = {
  // Reset system - clear vulnerability data, preserve session data
  resetSystem: () => apiRequest('/system/reset', {
    method: 'POST',
  }),
  
  // Reset all data - clear everything including session data
  resetAllData: () => apiRequest('/system/reset-all', {
    method: 'POST',
  }),
};

// Vulnerable Server API (Backend Integration)
export const vulnerableServerAPI = {
  // Get available tests
  getAvailableTests: () => apiRequest('/vulnerable-server/tests'),
  
  // Start vulnerability scan
  startScan: (scanConfig: any) => apiRequest('/vulnerable-server/scan', {
    method: 'POST',
    body: JSON.stringify(scanConfig),
  }),
  
  // Get scan status
  getScanStatus: (scanId: string) => apiRequest(`/vulnerable-server/scan/${scanId}/status`),
  
  // Check vulnerable server health
  checkHealth: (targetUrl?: string) => {
    const params = targetUrl ? `?target_url=${encodeURIComponent(targetUrl)}` : '';
    return apiRequest(`/vulnerable-server/health${params}`);
  },
  
  // Test specific vulnerability
  testSpecificVulnerability: (test: any, targetUrl?: string) => {
    const params = targetUrl ? `?target_url=${encodeURIComponent(targetUrl)}` : '';
    return apiRequest(`/vulnerable-server/test-specific${params}`, {
      method: 'POST',
      body: JSON.stringify(test),
    });
  },
  
  // Quick scan
  quickScan: (targetUrl?: string) => {
    const params = targetUrl ? `?target_url=${encodeURIComponent(targetUrl)}` : '';
    return apiRequest(`/vulnerable-server/quick-scan${params}`);
  },
};

// Export all APIs
export const api = {
  cve: cveAPI,
  scanner: scannerAPI,
  patch: patchAPI,
  chat: chatAPI,
  reports: reportsAPI,
  llm: llmAPI,
  simulation: simulationAPI,
  risk: riskAPI,
  ticket: ticketAPI,
  health: healthAPI,
  system: systemAPI,
  vuln: vulnAPI,
  vulnerableServer: vulnerableServerAPI,
};

export default api; 
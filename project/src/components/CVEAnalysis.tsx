import React, { useState, useEffect } from 'react';
import { Search, AlertTriangle, CheckCircle, Clock, ExternalLink, Download, Bot, Shield, Globe, GitBranch, Zap, Users, TrendingUp, FileText, Eye } from 'lucide-react';

const CVEAnalysis = () => {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedCVE, setSelectedCVE] = useState(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analysisResults, setAnalysisResults] = useState(null);
  const [activeTab, setActiveTab] = useState('overview');

  // Enhanced CVE data with LLM analysis
  const cveData = [
    {
      id: 'CVE-2024-0001',
      title: 'Apache HTTP Server Remote Code Execution',
      severity: 'Critical',
      cvss: '9.8',
      publishedDate: '2024-01-15',
      lastUpdated: '2024-01-15T14:30:00Z',
      nvdStatus: 'Analyzed',
      cweId: 'CWE-78',
      affectedProducts: ['Apache HTTP Server 2.4.0 - 2.4.58'],
      description: 'A critical remote code execution vulnerability in Apache HTTP Server allows attackers to execute arbitrary code through crafted HTTP requests.',
      exploitAvailable: true,
      exploitComplexity: 'Low',
      exploitMaturity: 'Functional',
      patchAvailable: true,
      affectedAssets: 45,
      
      // LLM-Enhanced Analysis
      llmSummary: 'This is a critical vulnerability affecting web servers. Immediate patching is required as public exploits are available. The vulnerability allows remote attackers to execute arbitrary code without authentication.',
      exploitMethod: 'Attackers can exploit this vulnerability by sending specially crafted HTTP requests to vulnerable Apache HTTP Server instances. The vulnerability exists in the request parsing mechanism, allowing for buffer overflow conditions that can be leveraged for code execution.',
      businessImpact: 'High - Could lead to complete server compromise, data theft, and service disruption. Affects customer-facing web applications.',
      laymanExplanation: 'Think of this like a security guard at a building entrance who can be tricked into letting anyone in with fake credentials. Hackers can send special requests to your web server that trick it into running their malicious code, potentially giving them full control of your website and data.',
      
      // Patch Mapping
      patchSources: [
        {
          vendor: 'Apache Software Foundation',
          version: '2.4.59',
          releaseDate: '2024-01-15',
          downloadUrl: 'https://httpd.apache.org/download.cgi',
          patchNotes: 'https://httpd.apache.org/security/vulnerabilities_24.html'
        },
        {
          vendor: 'Ubuntu',
          packageName: 'apache2',
          version: '2.4.59-1ubuntu4.3',
          command: 'sudo apt install apache2=2.4.59-1ubuntu4.3'
        },
        {
          vendor: 'Red Hat',
          packageName: 'httpd',
          version: '2.4.59-1.el8',
          command: 'sudo yum update httpd'
        }
      ],
      
      // GitHub commits and security advisories
      githubReferences: [
        {
          type: 'commit',
          url: 'https://github.com/apache/httpd/commit/abc123',
          title: 'Fix buffer overflow in request parsing',
          author: 'Apache Security Team',
          date: '2024-01-14'
        },
        {
          type: 'advisory',
          url: 'https://github.com/advisories/GHSA-xxxx-yyyy-zzzz',
          title: 'Apache HTTP Server RCE Vulnerability',
          severity: 'Critical'
        }
      ],
      
      remediationSteps: [
        'Upgrade Apache HTTP Server to version 2.4.59 or later',
        'Apply vendor security patches immediately',
        'Implement web application firewall rules as temporary mitigation',
        'Monitor for suspicious HTTP requests in logs'
      ],
      confidenceScore: 95,
      
      // Threat Intelligence
      threatIntelligence: {
        exploitInWild: true,
        firstSeenExploit: '2024-01-15T16:00:00Z',
        attackVectors: ['Remote', 'Network'],
        targetedSectors: ['Technology', 'Financial Services', 'Healthcare'],
        iocIndicators: [
          'Unusual HTTP request patterns',
          'Requests to /.%2e/.%2e/ paths',
          'Suspicious User-Agent strings'
        ]
      }
    },
    {
      id: 'CVE-2024-0002',
      title: 'OpenSSL Buffer Overflow Vulnerability',
      severity: 'High',
      cvss: '8.1',
      publishedDate: '2024-01-12',
      lastUpdated: '2024-01-12T10:15:00Z',
      nvdStatus: 'Analyzed',
      cweId: 'CWE-120',
      affectedProducts: ['OpenSSL 3.0.0 - 3.0.12'],
      description: 'A buffer overflow vulnerability in OpenSSL could allow remote attackers to cause denial of service or potentially execute arbitrary code.',
      exploitAvailable: false,
      exploitComplexity: 'High',
      exploitMaturity: 'Proof of Concept',
      patchAvailable: true,
      affectedAssets: 120,
      
      llmSummary: 'High-severity vulnerability in cryptographic library. While no public exploits exist yet, the potential for code execution makes this a priority for patching.',
      exploitMethod: 'The vulnerability exists in the SSL/TLS handshake processing where insufficient bounds checking can lead to buffer overflow conditions. Exploitation requires specific timing and network conditions.',
      businessImpact: 'Medium - Could affect secure communications and encrypted data. Risk of service disruption and potential data exposure.',
      laymanExplanation: 'This is like having a weak lock on your safe that could potentially be broken by someone with the right tools and knowledge. While it\'s harder to exploit than other vulnerabilities, it could still allow hackers to disrupt your secure communications or potentially access encrypted data.',
      
      patchSources: [
        {
          vendor: 'OpenSSL Project',
          version: '3.0.13',
          releaseDate: '2024-01-12',
          downloadUrl: 'https://www.openssl.org/source/',
          patchNotes: 'https://www.openssl.org/news/secadv/20240112.txt'
        }
      ],
      
      githubReferences: [
        {
          type: 'commit',
          url: 'https://github.com/openssl/openssl/commit/def456',
          title: 'Fix buffer overflow in SSL handshake',
          author: 'OpenSSL Security Team',
          date: '2024-01-11'
        }
      ],
      
      remediationSteps: [
        'Update OpenSSL to version 3.0.13 or later',
        'Restart all services using OpenSSL libraries',
        'Verify certificate validity after update',
        'Test encrypted communications functionality'
      ],
      confidenceScore: 87,
      
      threatIntelligence: {
        exploitInWild: false,
        firstSeenExploit: null,
        attackVectors: ['Network'],
        targetedSectors: ['All sectors using SSL/TLS'],
        iocIndicators: [
          'Unusual SSL handshake patterns',
          'Repeated connection attempts',
          'SSL/TLS errors in logs'
        ]
      }
    }
  ];

  const handleSearch = async (e) => {
    e.preventDefault();
    setIsAnalyzing(true);
    
    // Simulate LLM analysis of CVE
    setTimeout(() => {
      const foundCVE = cveData.find(cve => 
        cve.id.toLowerCase().includes(searchTerm.toLowerCase()) ||
        cve.title.toLowerCase().includes(searchTerm.toLowerCase())
      );
      
      if (foundCVE) {
        setSelectedCVE(foundCVE);
        setAnalysisResults({
          riskScore: foundCVE.severity === 'Critical' ? 95 : 78,
          recommendedAction: foundCVE.severity === 'Critical' ? 'Immediate patching required' : 'Schedule patching within 72 hours',
          businessPriority: foundCVE.severity === 'Critical' ? 'P1 - Critical' : 'P2 - High',
          estimatedImpact: foundCVE.affectedAssets > 50 ? 'High' : 'Medium'
        });
      }
      setIsAnalyzing(false);
    }, 2000);
  };

  const getSeverityColor = (severity) => {
    switch (severity.toLowerCase()) {
      case 'critical':
        return 'text-red-400 bg-red-900/20';
      case 'high':
        return 'text-amber-400 bg-amber-900/20';
      case 'medium':
        return 'text-yellow-400 bg-yellow-900/20';
      case 'low':
        return 'text-green-400 bg-green-900/20';
      default:
        return 'text-gray-400 bg-gray-900/20';
    }
  };

  const getExploitStatusColor = (available) => {
    return available ? 'text-red-400 bg-red-900/20' : 'text-green-400 bg-green-900/20';
  };

  const tabs = [
    { id: 'overview', label: 'Overview', icon: Eye },
    { id: 'technical', label: 'Technical Details', icon: FileText },
    { id: 'patches', label: 'Patches & Fixes', icon: GitBranch },
    { id: 'threat-intel', label: 'Threat Intelligence', icon: Shield },
    { id: 'business', label: 'Business Impact', icon: Users }
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold text-white mb-2">LLM-Driven CVE Analysis</h2>
          <p className="text-gray-400">Intelligent vulnerability analysis with business impact assessment</p>
        </div>
        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-2 text-sm text-gray-400">
            <Bot className="w-4 h-4" />
            <span>AI-Enhanced Analysis</span>
          </div>
          <button className="px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg text-white text-sm font-medium transition-colors">
            Sync NVD Feed
          </button>
        </div>
      </div>

      {/* Search Section */}
      <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
        <form onSubmit={handleSearch} className="flex items-center space-x-4">
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-5 h-5" />
            <input
              type="text"
              placeholder="Enter CVE ID (e.g., CVE-2024-0001) or vulnerability description..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-10 pr-4 py-3 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
          <button
            type="submit"
            disabled={isAnalyzing}
            className="px-6 py-3 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 rounded-lg text-white font-medium transition-colors flex items-center space-x-2"
          >
            {isAnalyzing ? (
              <>
                <Bot className="w-4 h-4 animate-spin" />
                <span>Analyzing...</span>
              </>
            ) : (
              <>
                <Search className="w-4 h-4" />
                <span>Analyze CVE</span>
              </>
            )}
          </button>
        </form>
      </div>

      {/* CVE List */}
      <div className="bg-gray-800 rounded-xl border border-gray-700">
        <div className="p-6 border-b border-gray-700">
          <h3 className="text-xl font-semibold text-white mb-2">Recent CVE Analysis</h3>
          <p className="text-gray-400 text-sm">Latest vulnerabilities with LLM-enhanced analysis</p>
        </div>
        <div className="p-6">
          <div className="space-y-4">
            {cveData.map((cve) => (
              <div
                key={cve.id}
                onClick={() => setSelectedCVE(cve)}
                className={`p-4 rounded-lg border cursor-pointer transition-all ${
                  selectedCVE?.id === cve.id
                    ? 'border-blue-500 bg-blue-900/20'
                    : 'border-gray-600 hover:border-gray-500 bg-gray-700/50'
                }`}
              >
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center space-x-3 mb-2">
                      <span className="text-blue-400 font-mono text-sm">{cve.id}</span>
                      <span className={`px-2 py-1 rounded text-xs font-medium ${getSeverityColor(cve.severity)}`}>
                        {cve.severity}
                      </span>
                      <span className="text-gray-400 text-xs">CVSS {cve.cvss}</span>
                      <span className={`px-2 py-1 rounded text-xs font-medium ${getExploitStatusColor(cve.exploitAvailable)}`}>
                        {cve.exploitAvailable ? 'Exploit Available' : 'No Known Exploit'}
                      </span>
                    </div>
                    <h4 className="text-white font-medium mb-1">{cve.title}</h4>
                    <p className="text-gray-400 text-sm mb-2">{cve.llmSummary}</p>
                    <div className="flex items-center space-x-4 text-xs text-gray-500">
                      <span>Assets: {cve.affectedAssets}</span>
                      <span>Published: {cve.publishedDate}</span>
                      <span>Confidence: {cve.confidenceScore}%</span>
                    </div>
                  </div>
                  <div className="flex items-center space-x-2">
                    {cve.patchAvailable && (
                      <span className="text-green-400">
                        <CheckCircle className="w-4 h-4" />
                      </span>
                    )}
                    {cve.exploitAvailable && (
                      <span className="text-red-400">
                        <Zap className="w-4 h-4" />
                      </span>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Detailed Analysis */}
      {selectedCVE && (
        <div className="bg-gray-800 rounded-xl border border-gray-700">
          <div className="p-6 border-b border-gray-700">
            <div className="flex items-center justify-between">
              <div>
                <h3 className="text-xl font-semibold text-white mb-1">{selectedCVE.title}</h3>
                <div className="flex items-center space-x-3">
                  <span className="text-blue-400 font-mono text-sm">{selectedCVE.id}</span>
                  <span className={`px-2 py-1 rounded text-xs font-medium ${getSeverityColor(selectedCVE.severity)}`}>
                    {selectedCVE.severity}
                  </span>
                  <span className="text-gray-400 text-xs">CVSS {selectedCVE.cvss}</span>
                </div>
              </div>
              <div className="flex items-center space-x-2">
                <button className="px-4 py-2 bg-green-600 hover:bg-green-700 rounded-lg text-white text-sm font-medium transition-colors">
                  Generate Report
                </button>
                <button className="px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg text-white text-sm font-medium transition-colors">
                  Create Ticket
                </button>
              </div>
            </div>
          </div>

          {/* Tabs */}
          <div className="border-b border-gray-700">
            <nav className="flex space-x-8 px-6">
              {tabs.map((tab) => {
                const Icon = tab.icon;
                return (
                  <button
                    key={tab.id}
                    onClick={() => setActiveTab(tab.id)}
                    className={`flex items-center space-x-2 py-4 px-1 border-b-2 font-medium text-sm transition-colors ${
                      activeTab === tab.id
                        ? 'border-blue-500 text-blue-400'
                        : 'border-transparent text-gray-400 hover:text-gray-300'
                    }`}
                  >
                    <Icon className="w-4 h-4" />
                    <span>{tab.label}</span>
                  </button>
                );
              })}
            </nav>
          </div>

          {/* Tab Content */}
          <div className="p-6">
            {activeTab === 'overview' && (
              <div className="space-y-6">
                {/* Quick Stats */}
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  <div className="bg-gray-700/50 p-4 rounded-lg">
                    <div className="text-2xl font-bold text-white">{selectedCVE.affectedAssets}</div>
                    <div className="text-sm text-gray-400">Affected Assets</div>
                  </div>
                  <div className="bg-gray-700/50 p-4 rounded-lg">
                    <div className="text-2xl font-bold text-white">{selectedCVE.confidenceScore}%</div>
                    <div className="text-sm text-gray-400">Confidence Score</div>
                  </div>
                  <div className="bg-gray-700/50 p-4 rounded-lg">
                    <div className="text-2xl font-bold text-white">{selectedCVE.exploitComplexity}</div>
                    <div className="text-sm text-gray-400">Exploit Complexity</div>
                  </div>
                  <div className="bg-gray-700/50 p-4 rounded-lg">
                    <div className="text-2xl font-bold text-white">{selectedCVE.exploitMaturity}</div>
                    <div className="text-sm text-gray-400">Exploit Maturity</div>
                  </div>
                </div>

                {/* LLM Analysis */}
                <div className="bg-gray-700/30 p-4 rounded-lg border border-gray-600">
                  <div className="flex items-center space-x-2 mb-3">
                    <Bot className="w-5 h-5 text-blue-400" />
                    <h4 className="text-white font-medium">AI Analysis Summary</h4>
                  </div>
                  <p className="text-gray-300 leading-relaxed">{selectedCVE.llmSummary}</p>
                </div>

                {/* Business Impact */}
                <div className="bg-gray-700/30 p-4 rounded-lg border border-gray-600">
                  <div className="flex items-center space-x-2 mb-3">
                    <Users className="w-5 h-5 text-amber-400" />
                    <h4 className="text-white font-medium">Business Impact (Layman Terms)</h4>
                  </div>
                  <p className="text-gray-300 leading-relaxed">{selectedCVE.laymanExplanation}</p>
                </div>

                {/* Exploit Method */}
                <div className="bg-gray-700/30 p-4 rounded-lg border border-gray-600">
                  <div className="flex items-center space-x-2 mb-3">
                    <Zap className="w-5 h-5 text-red-400" />
                    <h4 className="text-white font-medium">Exploit Method</h4>
                  </div>
                  <p className="text-gray-300 leading-relaxed">{selectedCVE.exploitMethod}</p>
                </div>
              </div>
            )}

            {activeTab === 'technical' && (
              <div className="space-y-6">
                <div className="grid grid-cols-2 gap-6">
                  <div>
                    <h4 className="text-white font-medium mb-3">Vulnerability Details</h4>
                    <div className="space-y-2 text-sm">
                      <div className="flex justify-between">
                        <span className="text-gray-400">CWE ID:</span>
                        <span className="text-white">{selectedCVE.cweId}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-400">NVD Status:</span>
                        <span className="text-white">{selectedCVE.nvdStatus}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-400">Last Updated:</span>
                        <span className="text-white">{new Date(selectedCVE.lastUpdated).toLocaleString()}</span>
                      </div>
                    </div>
                  </div>
                  <div>
                    <h4 className="text-white font-medium mb-3">Affected Products</h4>
                    <div className="space-y-2">
                      {selectedCVE.affectedProducts.map((product, index) => (
                        <div key={index} className="text-sm text-gray-300 bg-gray-700/50 p-2 rounded">
                          {product}
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
                
                <div>
                  <h4 className="text-white font-medium mb-3">Description</h4>
                  <p className="text-gray-300 leading-relaxed">{selectedCVE.description}</p>
                </div>
              </div>
            )}

            {activeTab === 'patches' && (
              <div className="space-y-6">
                <div>
                  <h4 className="text-white font-medium mb-4">Available Patches</h4>
                  <div className="space-y-4">
                    {selectedCVE.patchSources.map((patch, index) => (
                      <div key={index} className="bg-gray-700/30 p-4 rounded-lg border border-gray-600">
                        <div className="flex items-center justify-between mb-2">
                          <h5 className="text-white font-medium">{patch.vendor}</h5>
                          <span className="text-sm text-gray-400">{patch.releaseDate}</span>
                        </div>
                        <div className="space-y-2">
                          <div className="flex items-center space-x-2">
                            <span className="text-gray-400 text-sm">Version:</span>
                            <span className="text-white text-sm font-mono">{patch.version}</span>
                          </div>
                          {patch.command && (
                            <div className="bg-gray-800 p-3 rounded font-mono text-sm text-green-400">
                              {patch.command}
                            </div>
                          )}
                          {patch.downloadUrl && (
                            <a
                              href={patch.downloadUrl}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="inline-flex items-center space-x-1 text-blue-400 hover:text-blue-300 text-sm"
                            >
                              <ExternalLink className="w-3 h-3" />
                              <span>Download</span>
                            </a>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                <div>
                  <h4 className="text-white font-medium mb-4">GitHub References</h4>
                  <div className="space-y-3">
                    {selectedCVE.githubReferences.map((ref, index) => (
                      <div key={index} className="bg-gray-700/30 p-3 rounded-lg border border-gray-600">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center space-x-2">
                            <GitBranch className="w-4 h-4 text-gray-400" />
                            <span className="text-white text-sm">{ref.title}</span>
                          </div>
                          <a
                            href={ref.url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-blue-400 hover:text-blue-300 text-sm"
                          >
                            <ExternalLink className="w-4 h-4" />
                          </a>
                        </div>
                        <div className="text-xs text-gray-400 mt-1">
                          {ref.type} by {ref.author} on {ref.date}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                <div>
                  <h4 className="text-white font-medium mb-4">Remediation Steps</h4>
                  <div className="space-y-2">
                    {selectedCVE.remediationSteps.map((step, index) => (
                      <div key={index} className="flex items-start space-x-3">
                        <span className="flex-shrink-0 w-6 h-6 bg-blue-600 text-white text-xs rounded-full flex items-center justify-center">
                          {index + 1}
                        </span>
                        <span className="text-gray-300">{step}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {activeTab === 'threat-intel' && (
              <div className="space-y-6">
                <div className="grid grid-cols-2 gap-6">
                  <div className="bg-gray-700/30 p-4 rounded-lg border border-gray-600">
                    <h4 className="text-white font-medium mb-3">Exploit Status</h4>
                    <div className="space-y-2">
                      <div className="flex justify-between">
                        <span className="text-gray-400">In the Wild:</span>
                        <span className={selectedCVE.threatIntelligence.exploitInWild ? 'text-red-400' : 'text-green-400'}>
                          {selectedCVE.threatIntelligence.exploitInWild ? 'Yes' : 'No'}
                        </span>
                      </div>
                      {selectedCVE.threatIntelligence.firstSeenExploit && (
                        <div className="flex justify-between">
                          <span className="text-gray-400">First Seen:</span>
                          <span className="text-white">
                            {new Date(selectedCVE.threatIntelligence.firstSeenExploit).toLocaleString()}
                          </span>
                        </div>
                      )}
                    </div>
                  </div>
                  
                  <div className="bg-gray-700/30 p-4 rounded-lg border border-gray-600">
                    <h4 className="text-white font-medium mb-3">Attack Vectors</h4>
                    <div className="space-y-1">
                      {selectedCVE.threatIntelligence.attackVectors.map((vector, index) => (
                        <span key={index} className="inline-block bg-gray-600 text-white text-xs px-2 py-1 rounded mr-2">
                          {vector}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>

                <div>
                  <h4 className="text-white font-medium mb-3">Targeted Sectors</h4>
                  <div className="flex flex-wrap gap-2">
                    {selectedCVE.threatIntelligence.targetedSectors.map((sector, index) => (
                      <span key={index} className="bg-amber-900/20 text-amber-400 text-sm px-3 py-1 rounded-full">
                        {sector}
                      </span>
                    ))}
                  </div>
                </div>

                <div>
                  <h4 className="text-white font-medium mb-3">Indicators of Compromise (IOCs)</h4>
                  <div className="space-y-2">
                    {selectedCVE.threatIntelligence.iocIndicators.map((ioc, index) => (
                      <div key={index} className="bg-gray-700/50 p-3 rounded-lg">
                        <span className="text-gray-300">{ioc}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {activeTab === 'business' && (
              <div className="space-y-6">
                <div className="bg-gray-700/30 p-4 rounded-lg border border-gray-600">
                  <h4 className="text-white font-medium mb-3">Business Impact Assessment</h4>
                  <p className="text-gray-300 leading-relaxed">{selectedCVE.businessImpact}</p>
                </div>

                <div className="bg-gray-700/30 p-4 rounded-lg border border-gray-600">
                  <h4 className="text-white font-medium mb-3">Executive Summary</h4>
                  <p className="text-gray-300 leading-relaxed">{selectedCVE.laymanExplanation}</p>
                </div>

                {analysisResults && (
                  <div className="grid grid-cols-2 gap-6">
                    <div className="bg-gray-700/30 p-4 rounded-lg border border-gray-600">
                      <h4 className="text-white font-medium mb-3">Risk Assessment</h4>
                      <div className="space-y-2">
                        <div className="flex justify-between">
                          <span className="text-gray-400">Risk Score:</span>
                          <span className="text-white font-bold">{analysisResults.riskScore}/100</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-400">Business Priority:</span>
                          <span className="text-white">{analysisResults.businessPriority}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-gray-400">Estimated Impact:</span>
                          <span className="text-white">{analysisResults.estimatedImpact}</span>
                        </div>
                      </div>
                    </div>

                    <div className="bg-gray-700/30 p-4 rounded-lg border border-gray-600">
                      <h4 className="text-white font-medium mb-3">Recommended Action</h4>
                      <p className="text-gray-300">{analysisResults.recommendedAction}</p>
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

export default CVEAnalysis;
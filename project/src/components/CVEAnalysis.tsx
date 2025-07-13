import React, { useState, useEffect } from 'react';
import { Search, AlertTriangle, CheckCircle, Clock, ExternalLink, Download, Bot, Shield, Globe, GitBranch, Zap, Users, TrendingUp, FileText, Eye, Loader2, RefreshCw, Server } from 'lucide-react';
import { cveAPI, simulationAPI, vulnAPI } from '../services/api';
import { CVE, APIResponse } from '../types';

const CVEAnalysis = () => {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedCVE, setSelectedCVE] = useState<CVE | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analysisResults, setAnalysisResults] = useState<any>(null);
  const [activeTab, setActiveTab] = useState('overview');
  const [cveData, setCveData] = useState<CVE[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [llmAnalysis, setLlmAnalysis] = useState<any>(null);
  const [vulnerableServerData, setVulnerableServerData] = useState<any>(null);
  const [activeThreats, setActiveThreats] = useState<any[]>([]);
  const [isRefreshing, setIsRefreshing] = useState(false);

  // Load CVEs on component mount
  useEffect(() => {
    loadCVEs();
    loadVulnerableServerData();
    
    // Set up periodic refresh of vulnerable server data
    const interval = setInterval(loadVulnerableServerData, 10000); // Every 10 seconds
    return () => clearInterval(interval);
  }, []);

  const loadCVEs = async () => {
    try {
      setLoading(true);
      setError(null);
      
      // Get real CVEs from backend (includes vulnerable server data)
      const response = await cveAPI.getCVEs();
      if (response && response.length > 0) {
        setCveData(response);
      } else {
        // If no real data, generate simulated CVEs
        await generateSimulatedCVEs();
      }
    } catch (err) {
      console.error('Error loading CVEs:', err);
      setError('Failed to load CVE data from backend and vulnerable server.');
      // Fallback to simulated data
      await generateSimulatedCVEs();
    } finally {
      setLoading(false);
    }
  };

  const generateSimulatedCVEs = async () => {
    try {
      const simulationResponse = await simulationAPI.generateCVE({
        count: 5,
        severity: 'mixed'
      });
      
      if (simulationResponse && simulationResponse.cves) {
        setCveData(simulationResponse.cves);
      }
    } catch (err) {
      console.error('Error generating simulated CVEs:', err);
      setError('Failed to load CVE data');
    }
  };

  const loadVulnerableServerData = async () => {
    try {
      setIsRefreshing(true);
      
      // Load vulnerable server status
      const statusData = await vulnAPI.getScanStatus();
      setVulnerableServerData(statusData);
      
      // Load active threats
      const threatsData = await vulnAPI.getActiveThreats();
      if (threatsData && threatsData.active_threats) {
        setActiveThreats(threatsData.active_threats);
      }
      
    } catch (err) {
      console.error('Error loading vulnerable server data:', err);
    } finally {
      setIsRefreshing(false);
    }
  };

  const handleSearch = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!searchTerm.trim()) return;

    setIsAnalyzing(true);
    setError(null);
    
    try {
      // Find CVE in current data
      const foundCVE = cveData.find(cve => 
        cve.id.toLowerCase().includes(searchTerm.toLowerCase()) ||
        cve.title.toLowerCase().includes(searchTerm.toLowerCase())
      );
      
      if (foundCVE) {
        setSelectedCVE(foundCVE);
        
        // Get LLM analysis for the CVE
        const analysisResponse = await cveAPI.analyzeCVE(foundCVE);
        setLlmAnalysis(analysisResponse);
        
        // Set basic analysis results
        setAnalysisResults({
          risk_score: foundCVE.severity === 'Critical' ? 95 : 
                     foundCVE.severity === 'High' ? 78 : 
                     foundCVE.severity === 'Medium' ? 60 : 30,
          recommended_action: foundCVE.severity === 'Critical' ? 'Immediate patching required' : 
                             foundCVE.severity === 'High' ? 'Schedule patching within 72 hours' :
                             foundCVE.severity === 'Medium' ? 'Schedule patching within 1 week' : 'Schedule patching within 2 weeks',
          business_priority: foundCVE.severity === 'Critical' ? 'P1 - Critical' : 
                           foundCVE.severity === 'High' ? 'P2 - High' :
                           foundCVE.severity === 'Medium' ? 'P3 - Medium' : 'P4 - Low',
          estimated_impact: foundCVE.affected_assets > 50 ? 'High' : 
                           foundCVE.affected_assets > 20 ? 'Medium' : 'Low'
        });
      } else {
        setError('CVE not found. Try searching with a different term.');
      }
    } catch (err) {
      console.error('Error analyzing CVE:', err);
      setError('Failed to analyze CVE. Please try again.');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleCorrelateThreats = async (cveId: string) => {
    try {
      setLoading(true);
      const correlationResponse = await cveAPI.correlateCVE(cveId);
      console.log('Threat correlation:', correlationResponse);
      // Update the selected CVE with correlation data
      if (selectedCVE && selectedCVE.id === cveId) {
        setSelectedCVE({
          ...selectedCVE,
          threat_intelligence: correlationResponse.threat_intelligence
        });
      }
    } catch (err) {
      console.error('Error correlating threats:', err);
      setError('Failed to correlate threat intelligence');
    } finally {
      setLoading(false);
    }
  };

  const getSeverityColor = (severity: string) => {
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

  const getExploitStatusColor = (available: boolean) => {
    return available ? 'text-red-400 bg-red-900/20' : 'text-green-400 bg-green-900/20';
  };

  if (loading && cveData.length === 0) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="w-8 h-8 animate-spin text-blue-400" />
        <span className="ml-2 text-gray-300">Loading CVE data...</span>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">CVE Analysis</h1>
          <p className="text-gray-400">Comprehensive vulnerability analysis with AI-powered insights</p>
        </div>
        <div className="flex items-center space-x-2">
          <Bot className="w-5 h-5 text-blue-400" />
          <span className="text-sm text-gray-300">AI-Powered Analysis</span>
        </div>
      </div>

      {/* Error Display */}
      {error && (
        <div className="bg-red-900/20 border border-red-700 rounded-lg p-4">
          <div className="flex items-center">
            <AlertTriangle className="w-5 h-5 text-red-400 mr-2" />
            <span className="text-red-400">{error}</span>
          </div>
        </div>
      )}

      {/* Search Bar */}
      <div className="bg-gray-800 rounded-lg p-6">
        <form onSubmit={handleSearch} className="flex space-x-4">
          <div className="flex-1">
            <input
              type="text"
              placeholder="Search CVEs by ID or title..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full bg-gray-700 border border-gray-600 rounded-lg px-4 py-3 text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>
          <button
            type="submit"
            disabled={isAnalyzing}
            className="bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 px-6 py-3 rounded-lg text-white font-medium flex items-center space-x-2 transition-colors"
          >
            {isAnalyzing ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                <span>Analyzing...</span>
              </>
            ) : (
              <>
                <Search className="w-4 h-4" />
                <span>Search</span>
              </>
            )}
          </button>
        </form>
      </div>

      {/* Vulnerable Server Status */}
      {vulnerableServerData && (
        <div className="bg-gray-800 rounded-lg p-6">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center space-x-2">
              <Server className="w-5 h-5 text-red-400" />
              <h2 className="text-lg font-semibold text-white">Vulnerable Server Status</h2>
            </div>
            <button
              onClick={loadVulnerableServerData}
              disabled={isRefreshing}
              className="flex items-center space-x-2 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 px-3 py-1 rounded text-white text-sm transition-colors"
            >
              <RefreshCw className={`w-4 h-4 ${isRefreshing ? 'animate-spin' : ''}`} />
              <span>Refresh</span>
            </button>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
            <div className="bg-gray-700 rounded-lg p-4">
              <div className="flex items-center space-x-2 mb-2">
                <Shield className="w-4 h-4 text-red-400" />
                <span className="text-gray-300 text-sm">Status</span>
              </div>
              <span className={`text-lg font-bold ${vulnerableServerData.status === 'vulnerable' ? 'text-red-400' : 'text-green-400'}`}>
                {vulnerableServerData.status}
              </span>
            </div>
            <div className="bg-gray-700 rounded-lg p-4">
              <div className="flex items-center space-x-2 mb-2">
                <AlertTriangle className="w-4 h-4 text-orange-400" />
                <span className="text-gray-300 text-sm">Active Threats</span>
              </div>
              <span className="text-lg font-bold text-white">{vulnerableServerData.active_threats}</span>
            </div>
            <div className="bg-gray-700 rounded-lg p-4">
              <div className="flex items-center space-x-2 mb-2">
                <Eye className="w-4 h-4 text-blue-400" />
                <span className="text-gray-300 text-sm">Vulnerabilities</span>
              </div>
              <span className="text-lg font-bold text-white">{vulnerableServerData.vulnerabilities_found}</span>
            </div>
            <div className="bg-gray-700 rounded-lg p-4">
              <div className="flex items-center space-x-2 mb-2">
                <TrendingUp className="w-4 h-4 text-purple-400" />
                <span className="text-gray-300 text-sm">Risk Score</span>
              </div>
              <span className="text-lg font-bold text-white">{vulnerableServerData.risk_score}/100</span>
            </div>
          </div>

          {/* Active Threats */}
          {activeThreats.length > 0 && (
            <div>
              <h3 className="text-white font-medium mb-3">Active Threats</h3>
              <div className="space-y-2 max-h-48 overflow-y-auto">
                {activeThreats.slice(0, 5).map((threat, index) => (
                  <div key={index} className="bg-gray-700 rounded-lg p-3">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-3">
                        <span className={`px-2 py-1 rounded text-xs font-medium ${getSeverityColor(threat.severity)}`}>
                          {threat.severity}
                        </span>
                        <span className="text-white font-medium">{threat.threat_type}</span>
                        <span className="text-green-400 text-xs">ACTIVE</span>
                      </div>
                      <span className="text-gray-400 text-sm">{new Date(threat.created_at).toLocaleTimeString()}</span>
                    </div>
                    <p className="text-gray-300 text-sm mt-1">{threat.description}</p>
                    {threat.target_endpoint && (
                      <div className="mt-2 bg-gray-800 rounded p-2">
                        <span className="text-gray-400 text-xs">Endpoint:</span>
                        <code className="text-blue-400 text-xs block">{threat.target_endpoint}</code>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* CVE List */}
      {!selectedCVE && (
        <div className="bg-gray-800 rounded-lg p-6">
          <h2 className="text-lg font-semibold text-white mb-4">Recent CVEs</h2>
          <div className="space-y-4">
            {cveData.map((cve) => (
              <div
                key={cve.id}
                onClick={() => setSelectedCVE(cve)}
                className="bg-gray-700 rounded-lg p-4 cursor-pointer hover:bg-gray-600 transition-colors"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-3">
                    <span className={`px-2 py-1 rounded text-xs font-medium ${getSeverityColor(cve.severity)}`}>
                      {cve.severity}
                    </span>
                    <div>
                      <h3 className="text-white font-medium">{cve.id}</h3>
                      <p className="text-gray-400 text-sm">{cve.title}</p>
                    </div>
                  </div>
                  <div className="flex items-center space-x-4 text-sm text-gray-400">
                    <span>CVSS: {cve.cvss_score}</span>
                    <span>{cve.affected_assets} assets</span>
                    <span className={`px-2 py-1 rounded ${getExploitStatusColor(cve.exploit_available)}`}>
                      {cve.exploit_available ? 'Exploit Available' : 'No Exploit'}
                    </span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Selected CVE Details */}
      {selectedCVE && (
        <div className="space-y-6">
          {/* CVE Header */}
          <div className="bg-gray-800 rounded-lg p-6">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center space-x-3">
                <span className={`px-3 py-1 rounded text-sm font-medium ${getSeverityColor(selectedCVE.severity)}`}>
                  {selectedCVE.severity}
                </span>
                <h2 className="text-xl font-bold text-white">{selectedCVE.id}</h2>
              </div>
              <button
                onClick={() => setSelectedCVE(null)}
                className="text-gray-400 hover:text-white"
              >
                ×
              </button>
            </div>
            <h3 className="text-lg text-white mb-2">{selectedCVE.title}</h3>
            <p className="text-gray-300 mb-4">{selectedCVE.description}</p>
            
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
              <div>
                <span className="text-gray-400">CVSS Score:</span>
                <span className="text-white ml-2">{selectedCVE.cvss_score}</span>
              </div>
              <div>
                <span className="text-gray-400">Published:</span>
                <span className="text-white ml-2">{selectedCVE.published_date}</span>
              </div>
              <div>
                <span className="text-gray-400">Affected Assets:</span>
                <span className="text-white ml-2">{selectedCVE.affected_assets}</span>
              </div>
              <div>
                <span className="text-gray-400">Exploit:</span>
                <span className={`ml-2 ${getExploitStatusColor(selectedCVE.exploit_available)}`}>
                  {selectedCVE.exploit_available ? 'Available' : 'Not Available'}
                </span>
              </div>
            </div>
          </div>

          {/* Tabs */}
          <div className="bg-gray-800 rounded-lg">
            <div className="border-b border-gray-700">
              <nav className="flex space-x-8 px-6">
                {['overview', 'llm-analysis', 'patches', 'threat-intel', 'github'].map((tab) => (
                  <button
                    key={tab}
                    onClick={() => setActiveTab(tab)}
                    className={`py-4 px-1 border-b-2 font-medium text-sm ${
                      activeTab === tab
                        ? 'border-blue-500 text-blue-400'
                        : 'border-transparent text-gray-400 hover:text-gray-300'
                    }`}
                  >
                    {tab.split('-').map(word => word.charAt(0).toUpperCase() + word.slice(1)).join(' ')}
                  </button>
                ))}
              </nav>
            </div>

            <div className="p-6">
              {/* Overview Tab */}
              {activeTab === 'overview' && (
                <div className="space-y-6">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    <div className="bg-gray-700 rounded-lg p-4">
                      <h4 className="text-white font-medium mb-3">Affected Products</h4>
                      <ul className="space-y-1">
                        {selectedCVE.affected_products.map((product, index) => (
                          <li key={index} className="text-gray-300 text-sm">{product}</li>
                        ))}
                      </ul>
                    </div>
                    <div className="bg-gray-700 rounded-lg p-4">
                      <h4 className="text-white font-medium mb-3">Remediation Steps</h4>
                      <ul className="space-y-2">
                        {selectedCVE.remediation_steps?.map((step, index) => (
                          <li key={index} className="text-gray-300 text-sm flex items-start">
                            <span className="text-blue-400 mr-2">•</span>
                            {step}
                          </li>
                        ))}
                      </ul>
                    </div>
                  </div>
                </div>
              )}

              {/* LLM Analysis Tab */}
              {activeTab === 'llm-analysis' && (
                <div className="space-y-6">
                  {llmAnalysis ? (
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                      <div className="bg-gray-700 rounded-lg p-4">
                        <h4 className="text-white font-medium mb-3 flex items-center">
                          <Bot className="w-4 h-4 mr-2 text-blue-400" />
                          AI Analysis
                        </h4>
                        <div className="space-y-3">
                          <div>
                            <span className="text-gray-400 text-sm">Business Impact:</span>
                            <p className="text-white text-sm mt-1">{llmAnalysis.business_impact}</p>
                          </div>
                          <div>
                            <span className="text-gray-400 text-sm">Risk Assessment:</span>
                            <p className="text-white text-sm mt-1">{llmAnalysis.risk_assessment}</p>
                          </div>
                          <div>
                            <span className="text-gray-400 text-sm">Remediation Priority:</span>
                            <p className="text-white text-sm mt-1">{llmAnalysis.remediation_priority}</p>
                          </div>
                        </div>
                      </div>
                      <div className="bg-gray-700 rounded-lg p-4">
                        <h4 className="text-white font-medium mb-3">Analysis Results</h4>
                        <div className="space-y-3">
                          <div>
                            <span className="text-gray-400 text-sm">Risk Score:</span>
                            <span className="text-white ml-2">{analysisResults?.risk_score}%</span>
                          </div>
                          <div>
                            <span className="text-gray-400 text-sm">Recommended Action:</span>
                            <p className="text-white text-sm mt-1">{analysisResults?.recommended_action}</p>
                          </div>
                          <div>
                            <span className="text-gray-400 text-sm">Business Priority:</span>
                            <p className="text-white text-sm mt-1">{analysisResults?.business_priority}</p>
                          </div>
                        </div>
                      </div>
                    </div>
                  ) : (
                    <div className="text-center py-8">
                      <Bot className="w-12 h-12 text-gray-400 mx-auto mb-4" />
                      <p className="text-gray-400">Click "Search" to get AI-powered analysis</p>
                    </div>
                  )}
                </div>
              )}

              {/* Patches Tab */}
              {activeTab === 'patches' && (
                <div className="space-y-6">
                  {selectedCVE.patch_sources && selectedCVE.patch_sources.length > 0 ? (
                    <div className="space-y-4">
                      {selectedCVE.patch_sources.map((patch, index) => (
                        <div key={index} className="bg-gray-700 rounded-lg p-4">
                          <div className="flex items-center justify-between mb-3">
                            <h4 className="text-white font-medium">{patch.vendor}</h4>
                            <span className="text-gray-400 text-sm">v{patch.version}</span>
                          </div>
                          <div className="space-y-2">
                            {patch.command && (
                              <div className="bg-gray-800 rounded p-3">
                                <span className="text-gray-400 text-sm">Command:</span>
                                <code className="text-green-400 text-sm block mt-1">{patch.command}</code>
                              </div>
                            )}
                            {patch.download_url && (
                              <a
                                href={patch.download_url}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="text-blue-400 hover:text-blue-300 text-sm flex items-center"
                              >
                                <ExternalLink className="w-4 h-4 mr-1" />
                                Download Patch
                              </a>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="text-center py-8">
                      <CheckCircle className="w-12 h-12 text-gray-400 mx-auto mb-4" />
                      <p className="text-gray-400">No patch information available</p>
                    </div>
                  )}
                </div>
              )}

              {/* Threat Intelligence Tab */}
              {activeTab === 'threat-intel' && (
                <div className="space-y-6">
                  {selectedCVE.threat_intelligence ? (
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                      <div className="bg-gray-700 rounded-lg p-4">
                        <h4 className="text-white font-medium mb-3">Threat Status</h4>
                        <div className="space-y-3">
                          <div>
                            <span className="text-gray-400 text-sm">Exploit in Wild:</span>
                            <span className={`ml-2 ${selectedCVE.threat_intelligence.exploit_in_wild ? 'text-red-400' : 'text-green-400'}`}>
                              {selectedCVE.threat_intelligence.exploit_in_wild ? 'Yes' : 'No'}
                            </span>
                          </div>
                          <div>
                            <span className="text-gray-400 text-sm">Attack Vectors:</span>
                            <div className="mt-1">
                              {selectedCVE.threat_intelligence.attack_vectors.map((vector, index) => (
                                <span key={index} className="inline-block bg-gray-600 rounded px-2 py-1 text-xs text-white mr-2 mb-1">
                                  {vector}
                                </span>
                              ))}
                            </div>
                          </div>
                        </div>
                      </div>
                      <div className="bg-gray-700 rounded-lg p-4">
                        <h4 className="text-white font-medium mb-3">Targeted Sectors</h4>
                        <div className="space-y-2">
                          {selectedCVE.threat_intelligence.targeted_sectors.map((sector, index) => (
                            <span key={index} className="inline-block bg-blue-900/20 text-blue-400 rounded px-2 py-1 text-xs mr-2 mb-1">
                              {sector}
                            </span>
                          ))}
                        </div>
                      </div>
                    </div>
                  ) : (
                    <div className="text-center py-8">
                      <Shield className="w-12 h-12 text-gray-400 mx-auto mb-4" />
                      <p className="text-gray-400">No threat intelligence data available</p>
                      <button
                        onClick={() => handleCorrelateThreats(selectedCVE.id)}
                        className="mt-4 bg-blue-600 hover:bg-blue-700 px-4 py-2 rounded text-white text-sm"
                      >
                        Correlate Threats
                      </button>
                    </div>
                  )}
                </div>
              )}

              {/* GitHub Tab */}
              {activeTab === 'github' && (
                <div className="space-y-6">
                  {selectedCVE.github_references && selectedCVE.github_references.length > 0 ? (
                    <div className="space-y-4">
                      {selectedCVE.github_references.map((ref, index) => (
                        <div key={index} className="bg-gray-700 rounded-lg p-4">
                          <div className="flex items-center justify-between mb-2">
                            <div className="flex items-center space-x-2">
                              <GitBranch className="w-4 h-4 text-gray-400" />
                              <span className="text-gray-400 text-sm capitalize">{ref.type}</span>
                              {ref.severity && (
                                <span className={`px-2 py-1 rounded text-xs ${getSeverityColor(ref.severity)}`}>
                                  {ref.severity}
                                </span>
                              )}
                            </div>
                            {ref.date && <span className="text-gray-400 text-sm">{ref.date}</span>}
                          </div>
                          <h4 className="text-white font-medium mb-2">{ref.title}</h4>
                          {ref.author && (
                            <p className="text-gray-400 text-sm mb-3">by {ref.author}</p>
                          )}
                          <a
                            href={ref.url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-blue-400 hover:text-blue-300 text-sm flex items-center"
                          >
                            <ExternalLink className="w-4 h-4 mr-1" />
                            View on GitHub
                          </a>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="text-center py-8">
                      <GitBranch className="w-12 h-12 text-gray-400 mx-auto mb-4" />
                      <p className="text-gray-400">No GitHub references available</p>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default CVEAnalysis;
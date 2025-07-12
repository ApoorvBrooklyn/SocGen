import React, { useState } from 'react';
import { AlertTriangle, TrendingUp, Clock, Target, Filter, Bot } from 'lucide-react';

const RiskPrioritization = () => {
  const [selectedFilter, setSelectedFilter] = useState('all');

  const vulnerabilities = [
    {
      id: 'CVE-2024-0001',
      title: 'Apache HTTP Server Remote Code Execution',
      severity: 'Critical',
      cvss: 9.8,
      riskScore: 95,
      exploitAvailable: true,
      affectedAssets: 45,
      assetValue: 'High',
      businessImpact: 'Critical',
      timeToRemediate: '4 hours',
      priority: 1,
      llmReasoning: 'Highest priority due to critical CVSS score, available public exploits, and high number of affected production assets. Customer-facing web servers at risk.',
      remediationComplexity: 'Low',
      exposure: 'Public-facing'
    },
    {
      id: 'CVE-2024-0002',
      title: 'OpenSSL Buffer Overflow Vulnerability',
      severity: 'High',
      cvss: 8.1,
      riskScore: 78,
      exploitAvailable: false,
      affectedAssets: 120,
      assetValue: 'Medium',
      businessImpact: 'High',
      timeToRemediate: '8 hours',
      priority: 2,
      llmReasoning: 'High priority due to widespread impact across systems. While no public exploits exist, the cryptographic nature increases risk potential.',
      remediationComplexity: 'Medium',
      exposure: 'Internal'
    },
    {
      id: 'CVE-2024-0003',
      title: 'Linux Kernel Privilege Escalation',
      severity: 'High',
      cvss: 7.8,
      riskScore: 72,
      exploitAvailable: true,
      affectedAssets: 89,
      assetValue: 'High',
      businessImpact: 'Medium',
      timeToRemediate: '12 hours',
      priority: 3,
      llmReasoning: 'Medium-high priority. Kernel vulnerabilities are serious but require local access. Schedule during maintenance window.',
      remediationComplexity: 'High',
      exposure: 'Internal'
    },
    {
      id: 'CVE-2024-0004',
      title: 'MySQL SQL Injection Vulnerability',
      severity: 'Medium',
      cvss: 6.5,
      riskScore: 45,
      exploitAvailable: false,
      affectedAssets: 23,
      assetValue: 'Medium',
      businessImpact: 'Low',
      timeToRemediate: '6 hours',
      priority: 4,
      llmReasoning: 'Lower priority due to limited asset exposure and no available exploits. Can be addressed in next maintenance cycle.',
      remediationComplexity: 'Low',
      exposure: 'Internal'
    }
  ];

  const filters = [
    { id: 'all', label: 'All Vulnerabilities' },
    { id: 'critical', label: 'Critical Priority' },
    { id: 'high', label: 'High Priority' },
    { id: 'exploit', label: 'Exploit Available' },
    { id: 'public', label: 'Public Facing' }
  ];

  const getSeverityColor = (severity) => {
    switch (severity.toLowerCase()) {
      case 'critical':
        return 'text-red-400 bg-red-900/20';
      case 'high':
        return 'text-amber-400 bg-amber-900/20';
      case 'medium':
        return 'text-yellow-400 bg-yellow-900/20';
      default:
        return 'text-gray-400 bg-gray-900/20';
    }
  };

  const getRiskScoreColor = (score) => {
    if (score >= 90) return 'text-red-400';
    if (score >= 70) return 'text-amber-400';
    if (score >= 50) return 'text-yellow-400';
    return 'text-green-400';
  };

  const getPriorityColor = (priority) => {
    switch (priority) {
      case 1:
        return 'bg-red-600';
      case 2:
        return 'bg-amber-600';
      case 3:
        return 'bg-yellow-600';
      default:
        return 'bg-green-600';
    }
  };

  const filteredVulnerabilities = vulnerabilities.filter(vuln => {
    switch (selectedFilter) {
      case 'critical':
        return vuln.priority === 1;
      case 'high':
        return vuln.priority <= 2;
      case 'exploit':
        return vuln.exploitAvailable;
      case 'public':
        return vuln.exposure === 'Public-facing';
      default:
        return true;
    }
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold text-white mb-2">Risk Prioritization</h2>
          <p className="text-gray-400">AI-powered vulnerability risk assessment and prioritization</p>
        </div>
        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-2 text-sm text-gray-400">
            <Bot className="w-4 h-4" />
            <span>LLM-Enhanced Scoring</span>
          </div>
          <button className="px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg text-white text-sm font-medium transition-colors">
            Recalculate Priorities
          </button>
        </div>
      </div>

      {/* Risk Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-2xl font-bold text-red-400">23</p>
              <p className="text-sm text-gray-400">Critical Priority</p>
            </div>
            <AlertTriangle className="w-8 h-8 text-red-400" />
          </div>
        </div>
        <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-2xl font-bold text-amber-400">45</p>
              <p className="text-sm text-gray-400">High Priority</p>
            </div>
            <TrendingUp className="w-8 h-8 text-amber-400" />
          </div>
        </div>
        <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-2xl font-bold text-blue-400">2.5</p>
              <p className="text-sm text-gray-400">Avg. Risk Score</p>
            </div>
            <Target className="w-8 h-8 text-blue-400" />
          </div>
        </div>
        <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-2xl font-bold text-green-400">6.2</p>
              <p className="text-sm text-gray-400">Avg. Remediation Time</p>
            </div>
            <Clock className="w-8 h-8 text-green-400" />
          </div>
        </div>
      </div>

      {/* Filters */}
      <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
        <div className="flex items-center space-x-4">
          <Filter className="w-5 h-5 text-gray-400" />
          <span className="text-sm text-gray-400">Filter by:</span>
          <div className="flex space-x-2">
            {filters.map((filter) => (
              <button
                key={filter.id}
                onClick={() => setSelectedFilter(filter.id)}
                className={`px-3 py-1 rounded-full text-sm font-medium transition-colors ${
                  selectedFilter === filter.id
                    ? 'bg-blue-600 text-white'
                    : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
                }`}
              >
                {filter.label}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Vulnerabilities List */}
      <div className="space-y-4">
        {filteredVulnerabilities.map((vuln) => (
          <div key={vuln.id} className="bg-gray-800 rounded-xl p-6 border border-gray-700">
            <div className="flex items-start justify-between">
              <div className="flex-1">
                <div className="flex items-center space-x-4 mb-3">
                  <div className={`w-8 h-8 rounded-full flex items-center justify-center text-white font-bold ${getPriorityColor(vuln.priority)}`}>
                    {vuln.priority}
                  </div>
                  <div className="flex items-center space-x-3">
                    <span className="text-sm font-mono text-gray-400">{vuln.id}</span>
                    <span className={`px-2 py-1 rounded text-xs font-medium ${getSeverityColor(vuln.severity)}`}>
                      {vuln.severity}
                    </span>
                    <span className="text-xs text-gray-400">CVSS: {vuln.cvss}</span>
                  </div>
                </div>

                <h3 className="text-lg font-semibold text-white mb-2">{vuln.title}</h3>

                <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-4">
                  <div>
                    <span className="text-xs text-gray-400">Risk Score</span>
                    <p className={`text-xl font-bold ${getRiskScoreColor(vuln.riskScore)}`}>
                      {vuln.riskScore}
                    </p>
                  </div>
                  <div>
                    <span className="text-xs text-gray-400">Affected Assets</span>
                    <p className="text-white font-medium">{vuln.affectedAssets}</p>
                  </div>
                  <div>
                    <span className="text-xs text-gray-400">Business Impact</span>
                    <p className="text-white font-medium">{vuln.businessImpact}</p>
                  </div>
                  <div>
                    <span className="text-xs text-gray-400">Time to Remediate</span>
                    <p className="text-white font-medium">{vuln.timeToRemediate}</p>
                  </div>
                </div>

                <div className="flex items-center space-x-4 mb-4">
                  <div className="flex items-center space-x-2">
                    <span className="text-xs text-gray-400">Exploit Available:</span>
                    <span className={`px-2 py-1 rounded text-xs font-medium ${
                      vuln.exploitAvailable ? 'bg-red-900/20 text-red-400' : 'bg-green-900/20 text-green-400'
                    }`}>
                      {vuln.exploitAvailable ? 'Yes' : 'No'}
                    </span>
                  </div>
                  <div className="flex items-center space-x-2">
                    <span className="text-xs text-gray-400">Exposure:</span>
                    <span className={`px-2 py-1 rounded text-xs font-medium ${
                      vuln.exposure === 'Public-facing' ? 'bg-red-900/20 text-red-400' : 'bg-gray-600 text-gray-300'
                    }`}>
                      {vuln.exposure}
                    </span>
                  </div>
                  <div className="flex items-center space-x-2">
                    <span className="text-xs text-gray-400">Complexity:</span>
                    <span className="px-2 py-1 bg-gray-600 text-gray-300 rounded text-xs font-medium">
                      {vuln.remediationComplexity}
                    </span>
                  </div>
                </div>

                <div className="p-4 bg-gray-700 rounded-lg">
                  <div className="flex items-center space-x-2 mb-2">
                    <Bot className="w-4 h-4 text-blue-400" />
                    <span className="text-sm font-medium text-blue-400">LLM Risk Assessment</span>
                  </div>
                  <p className="text-sm text-gray-300">{vuln.llmReasoning}</p>
                </div>
              </div>

              <div className="flex flex-col space-y-2 ml-6">
                <button className="px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg text-white text-sm font-medium transition-colors">
                  View Details
                </button>
                <button className="px-4 py-2 bg-green-600 hover:bg-green-700 rounded-lg text-white text-sm font-medium transition-colors">
                  Generate Plan
                </button>
                <button className="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-white text-sm font-medium transition-colors">
                  Create Ticket
                </button>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default RiskPrioritization;
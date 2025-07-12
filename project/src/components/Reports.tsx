import React, { useState } from 'react';
import { Download, Calendar, Clock, Mail, FileText, TrendingUp, Shield, AlertTriangle, CheckCircle } from 'lucide-react';

const Reports = () => {
  const [selectedReport, setSelectedReport] = useState(null);
  const [reportType, setReportType] = useState('executive');

  const reportTemplates = [
    {
      id: 'executive-summary',
      title: 'Executive Security Summary',
      description: 'High-level security overview for leadership',
      type: 'executive',
      frequency: 'Weekly',
      lastGenerated: '2024-01-15',
      recipients: ['CISO', 'CTO', 'CEO'],
      sections: ['Risk Overview', 'Critical Vulnerabilities', 'Patch Status', 'Recommendations']
    },
    {
      id: 'technical-report',
      title: 'Technical Vulnerability Report',
      description: 'Detailed technical analysis for IT teams',
      type: 'technical',
      frequency: 'Daily',
      lastGenerated: '2024-01-15',
      recipients: ['SOC Team', 'System Administrators', 'Security Engineers'],
      sections: ['Vulnerability Details', 'Patch Instructions', 'Risk Assessment', 'Remediation Steps']
    },
    {
      id: 'compliance-report',
      title: 'Compliance Status Report',
      description: 'Regulatory compliance and audit requirements',
      type: 'compliance',
      frequency: 'Monthly',
      lastGenerated: '2024-01-01',
      recipients: ['Compliance Team', 'Legal', 'External Auditors'],
      sections: ['Compliance Status', 'Policy Violations', 'Audit Trail', 'Remediation Actions']
    },
    {
      id: 'metrics-dashboard',
      title: 'Security Metrics Dashboard',
      description: 'KPIs and performance metrics',
      type: 'metrics',
      frequency: 'Weekly',
      lastGenerated: '2024-01-10',
      recipients: ['Management', 'SOC Team', 'IT Leadership'],
      sections: ['Performance Metrics', 'Trend Analysis', 'SLA Compliance', 'Resource Utilization']
    }
  ];

  const reportData = {
    'executive-summary': {
      title: 'Executive Security Summary - Week of Jan 15, 2024',
      generatedDate: '2024-01-15',
      period: 'January 8-15, 2024',
      keyMetrics: [
        { label: 'Critical Vulnerabilities', value: '23', trend: '+5', color: 'text-red-400' },
        { label: 'High Priority Issues', value: '87', trend: '+12', color: 'text-amber-400' },
        { label: 'Patches Applied', value: '156', trend: '+34', color: 'text-green-400' },
        { label: 'Security Score', value: '85%', trend: '+2%', color: 'text-blue-400' }
      ],
      sections: [
        {
          title: 'Executive Summary',
          content: 'This week saw an increase in critical vulnerabilities, primarily affecting web infrastructure. The security team has responded with accelerated patch deployment and temporary mitigations. Overall security posture remains strong with 85% of systems fully patched.'
        },
        {
          title: 'Risk Overview',
          content: 'Primary risks this week include Apache HTTP Server vulnerabilities affecting 45 production systems and OpenSSL issues across 120 servers. Public exploits are available for the Apache vulnerability, requiring immediate attention.'
        },
        {
          title: 'Key Recommendations',
          content: 'Immediate patching of Apache HTTP Server systems, implementation of emergency change procedures for critical vulnerabilities, and evaluation of automated patch management solutions.'
        }
      ]
    },
    'technical-report': {
      title: 'Technical Vulnerability Report - January 15, 2024',
      generatedDate: '2024-01-15',
      period: 'Last 24 hours',
      keyMetrics: [
        { label: 'New CVEs Identified', value: '12', trend: '+3', color: 'text-red-400' },
        { label: 'Patches Available', value: '8', trend: '+2', color: 'text-green-400' },
        { label: 'Systems Scanned', value: '2,347', trend: 'Complete', color: 'text-blue-400' },
        { label: 'False Positives', value: '3%', trend: '-1%', color: 'text-green-400' }
      ],
      sections: [
        {
          title: 'Critical Vulnerabilities Requiring Immediate Action',
          content: 'CVE-2024-0001: Apache HTTP Server RCE - 45 systems affected, public exploit available. Patches must be applied within 24 hours. CVE-2024-0002: OpenSSL buffer overflow - 120 systems affected, patch available.'
        },
        {
          title: 'Patch Deployment Status',
          content: 'Production web servers: 38/45 patched (84%). Database servers: 21/23 patched (91%). Application servers: 52/67 patched (78%). Development environment: 89/89 patched (100%).'
        },
        {
          title: 'Risk Assessment and Mitigation',
          content: 'High-risk systems have been identified and prioritized for immediate patching. Temporary WAF rules deployed for Apache vulnerability. Network segmentation limiting exposure for internal systems.'
        }
      ]
    }
  };

  const handleGenerateReport = (templateId) => {
    setSelectedReport(reportData[templateId] || {
      title: 'Generated Report',
      generatedDate: new Date().toISOString().split('T')[0],
      period: 'Current',
      keyMetrics: [],
      sections: []
    });
  };

  const handleEmailReport = () => {
    alert('Report scheduled for email delivery');
  };

  const handleDownloadReport = () => {
    alert('Report downloaded as PDF');
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold text-white mb-2">Security Reports</h2>
          <p className="text-gray-400">Automated security reporting and analytics</p>
        </div>
        <div className="flex items-center space-x-4">
          <select
            value={reportType}
            onChange={(e) => setReportType(e.target.value)}
            className="px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white text-sm"
          >
            <option value="executive">Executive Reports</option>
            <option value="technical">Technical Reports</option>
            <option value="compliance">Compliance Reports</option>
            <option value="metrics">Metrics Reports</option>
          </select>
          <button className="px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg text-white text-sm font-medium transition-colors">
            Schedule Report
          </button>
        </div>
      </div>

      {/* Report Templates */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {reportTemplates
          .filter(template => reportType === 'all' || template.type === reportType)
          .map((template) => (
            <div key={template.id} className="bg-gray-800 rounded-xl p-6 border border-gray-700">
              <div className="flex items-start justify-between mb-4">
                <div className="flex-1">
                  <h3 className="text-xl font-semibold text-white mb-2">{template.title}</h3>
                  <p className="text-gray-400 text-sm mb-3">{template.description}</p>
                  
                  <div className="space-y-2">
                    <div className="flex items-center space-x-2">
                      <Calendar className="w-4 h-4 text-gray-400" />
                      <span className="text-sm text-gray-300">Frequency: {template.frequency}</span>
                    </div>
                    <div className="flex items-center space-x-2">
                      <Clock className="w-4 h-4 text-gray-400" />
                      <span className="text-sm text-gray-300">Last Generated: {template.lastGenerated}</span>
                    </div>
                  </div>
                </div>
                <div className="flex items-center space-x-2">
                  <span className={`px-2 py-1 rounded text-xs font-medium ${
                    template.type === 'executive' ? 'bg-purple-900/20 text-purple-400' :
                    template.type === 'technical' ? 'bg-blue-900/20 text-blue-400' :
                    template.type === 'compliance' ? 'bg-green-900/20 text-green-400' :
                    'bg-amber-900/20 text-amber-400'
                  }`}>
                    {template.type}
                  </span>
                </div>
              </div>

              <div className="mb-4">
                <p className="text-sm text-gray-400 mb-2">Recipients:</p>
                <div className="flex flex-wrap gap-2">
                  {template.recipients.map((recipient, index) => (
                    <span key={index} className="px-2 py-1 bg-gray-700 text-gray-300 rounded text-xs">
                      {recipient}
                    </span>
                  ))}
                </div>
              </div>

              <div className="mb-4">
                <p className="text-sm text-gray-400 mb-2">Sections:</p>
                <div className="flex flex-wrap gap-2">
                  {template.sections.map((section, index) => (
                    <span key={index} className="px-2 py-1 bg-gray-600 text-gray-300 rounded text-xs">
                      {section}
                    </span>
                  ))}
                </div>
              </div>

              <div className="flex items-center space-x-2">
                <button
                  onClick={() => handleGenerateReport(template.id)}
                  className="flex-1 px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg text-white text-sm font-medium transition-colors"
                >
                  Generate Report
                </button>
                <button
                  onClick={handleEmailReport}
                  className="px-4 py-2 bg-green-600 hover:bg-green-700 rounded-lg text-white text-sm transition-colors"
                >
                  <Mail className="w-4 h-4" />
                </button>
                <button
                  onClick={handleDownloadReport}
                  className="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-white text-sm transition-colors"
                >
                  <Download className="w-4 h-4" />
                </button>
              </div>
            </div>
          ))}
      </div>

      {/* Generated Report Preview */}
      {selectedReport && (
        <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
          <div className="flex items-center justify-between mb-6">
            <div>
              <h3 className="text-2xl font-bold text-white">{selectedReport.title}</h3>
              <p className="text-gray-400">Generated: {selectedReport.generatedDate} | Period: {selectedReport.period}</p>
            </div>
            <div className="flex items-center space-x-2">
              <button
                onClick={handleEmailReport}
                className="px-4 py-2 bg-green-600 hover:bg-green-700 rounded-lg text-white text-sm font-medium transition-colors"
              >
                <Mail className="w-4 h-4 mr-2" />
                Email Report
              </button>
              <button
                onClick={handleDownloadReport}
                className="px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg text-white text-sm font-medium transition-colors"
              >
                <Download className="w-4 h-4 mr-2" />
                Download PDF
              </button>
            </div>
          </div>

          {/* Key Metrics */}
          {selectedReport.keyMetrics && selectedReport.keyMetrics.length > 0 && (
            <div className="mb-6">
              <h4 className="text-lg font-semibold text-white mb-4">Key Metrics</h4>
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                {selectedReport.keyMetrics.map((metric, index) => (
                  <div key={index} className="bg-gray-700 rounded-lg p-4">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className={`text-2xl font-bold ${metric.color}`}>{metric.value}</p>
                        <p className="text-sm text-gray-400">{metric.label}</p>
                      </div>
                      <div className="text-right">
                        <p className="text-sm text-gray-400">{metric.trend}</p>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Report Sections */}
          {selectedReport.sections && selectedReport.sections.length > 0 && (
            <div className="space-y-6">
              {selectedReport.sections.map((section, index) => (
                <div key={index} className="bg-gray-700 rounded-lg p-6">
                  <h4 className="text-lg font-semibold text-white mb-3">{section.title}</h4>
                  <p className="text-gray-300 leading-relaxed">{section.content}</p>
                </div>
              ))}
            </div>
          )}

          {/* Report Footer */}
          <div className="mt-6 pt-6 border-t border-gray-700">
            <div className="flex items-center justify-between">
              <p className="text-sm text-gray-400">
                Generated by PatchMate360 AI Security Platform
              </p>
              <div className="flex items-center space-x-4">
                <div className="flex items-center space-x-2">
                  <Shield className="w-4 h-4 text-green-400" />
                  <span className="text-sm text-gray-400">Automated Analysis</span>
                </div>
                <div className="flex items-center space-x-2">
                  <TrendingUp className="w-4 h-4 text-blue-400" />
                  <span className="text-sm text-gray-400">Real-time Data</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default Reports;
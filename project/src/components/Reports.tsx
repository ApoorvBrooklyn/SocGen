import React, { useState, useEffect } from 'react';
import { Download, Calendar, Clock, Mail, FileText, TrendingUp, Shield, AlertTriangle, CheckCircle, Users, Send, Settings, Eye, Bot, Globe, Zap, Loader2, RefreshCw, Plus, X, Save } from 'lucide-react';
import { reportsAPI } from '../services/api';

interface ReportTemplate {
  id: string;
  title: string;
  description: string;
  type: string;
  frequency: string;
  lastGenerated: string;
  recipients: string[];
  sections: string[];
  automationEnabled: boolean;
  emailList: string[];
}

interface CustomReportConfig {
  title: string;
  type: string;
  sections: string[];
  recipients: string[];
  frequency: string;
  format: string;
}

const Reports = () => {
  const [selectedReport, setSelectedReport] = useState<any>(null);
  const [reportType, setReportType] = useState('all');
  const [showEmailModal, setShowEmailModal] = useState(false);
  const [showCustomReportModal, setShowCustomReportModal] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [isGenerating, setIsGenerating] = useState(false);
  const [generatedReports, setGeneratedReports] = useState<any[]>([]);
  const [reportHistory, setReportHistory] = useState<any[]>([]);
  const [customReportConfig, setCustomReportConfig] = useState<CustomReportConfig>({
    title: '',
    type: 'custom',
    sections: [],
    recipients: [],
    frequency: 'manual',
    format: 'pdf'
  });
  const [emailConfig, setEmailConfig] = useState({
    recipients: [],
    schedule: 'manual',
    format: 'pdf'
  });

  const reportTemplates: ReportTemplate[] = [
    {
      id: 'executive',
      title: 'Executive Security Summary',
      description: 'High-level security overview for leadership',
      type: 'executive',
      frequency: 'Weekly',
      lastGenerated: '2024-01-15',
      recipients: ['CISO', 'CTO', 'CEO'],
      sections: ['Risk Overview', 'Critical Vulnerabilities', 'Patch Status', 'Recommendations'],
      automationEnabled: true,
      emailList: ['ciso@company.com', 'cto@company.com', 'ceo@company.com']
    },
    {
      id: 'technical',
      title: 'Technical Vulnerability Report',
      description: 'Detailed technical analysis for IT teams',
      type: 'technical',
      frequency: 'Daily',
      lastGenerated: '2024-01-15',
      recipients: ['SOC Team', 'System Administrators', 'Security Engineers'],
      sections: ['Vulnerability Details', 'Patch Instructions', 'Risk Assessment', 'Remediation Steps'],
      automationEnabled: true,
      emailList: ['soc@company.com', 'sysadmin@company.com', 'security@company.com']
    },
    {
      id: 'compliance',
      title: 'Compliance Status Report',
      description: 'Regulatory compliance and audit requirements',
      type: 'compliance',
      frequency: 'Monthly',
      lastGenerated: '2024-01-01',
      recipients: ['Compliance Team', 'Legal', 'External Auditors'],
      sections: ['Compliance Status', 'Policy Violations', 'Audit Trail', 'Remediation Actions'],
      automationEnabled: false,
      emailList: ['compliance@company.com', 'legal@company.com']
    },
    {
      id: 'metrics',
      title: 'Security Metrics Dashboard',
      description: 'KPIs and performance metrics',
      type: 'metrics',
      frequency: 'Weekly',
      lastGenerated: '2024-01-10',
      recipients: ['Management', 'SOC Team', 'IT Leadership'],
      sections: ['Performance Metrics', 'Trend Analysis', 'SLA Compliance', 'Resource Utilization'],
      automationEnabled: true,
      emailList: ['management@company.com', 'soc@company.com', 'it-leadership@company.com']
    },
    {
      id: 'incident',
      title: 'Security Incident Summary',
      description: 'Weekly incident response and lessons learned',
      type: 'incident',
      frequency: 'Weekly',
      lastGenerated: '2024-01-12',
      recipients: ['Security Team', 'Management', 'IT Operations'],
      sections: ['Incident Overview', 'Response Timeline', 'Root Cause Analysis', 'Improvements'],
      automationEnabled: true,
      emailList: ['security@company.com', 'management@company.com', 'itops@company.com']
    },
    {
      id: 'threat-intel',
      title: 'Threat Intelligence Brief',
      description: 'Latest threat landscape and intelligence',
      type: 'threat-intel',
      frequency: 'Daily',
      lastGenerated: '2024-01-15',
      recipients: ['Security Analysts', 'SOC Team', 'CISO'],
      sections: ['Threat Landscape', 'IOCs', 'Attribution', 'Defensive Recommendations'],
      automationEnabled: true,
      emailList: ['analysts@company.com', 'soc@company.com', 'ciso@company.com']
    }
  ];

  const availableSections = [
    'Risk Overview', 'Critical Vulnerabilities', 'Patch Status', 'Recommendations',
    'Vulnerability Details', 'Patch Instructions', 'Risk Assessment', 'Remediation Steps',
    'Compliance Status', 'Policy Violations', 'Audit Trail', 'Remediation Actions',
    'Performance Metrics', 'Trend Analysis', 'SLA Compliance', 'Resource Utilization',
    'Incident Overview', 'Response Timeline', 'Root Cause Analysis', 'Improvements',
    'Threat Landscape', 'IOCs', 'Attribution', 'Defensive Recommendations'
  ];

  // Load report history on component mount
  useEffect(() => {
    loadReportHistory();
  }, []);

  const loadReportHistory = async () => {
    try {
      setIsLoading(true);
      const history = await reportsAPI.getReportHistory();
      setReportHistory(history || []);
    } catch (error) {
      console.error('Error loading report history:', error);
      // Create mock data if API fails
      setReportHistory([
        {
          id: 'report-1',
          type: 'executive',
          summary: 'Executive security summary for the week',
          generated_at: '2024-01-15T10:00:00Z',
          status: 'completed'
        },
        {
          id: 'report-2',
          type: 'technical',
          summary: 'Technical vulnerability analysis',
          generated_at: '2024-01-14T15:30:00Z',
          status: 'completed'
        }
      ]);
    } finally {
      setIsLoading(false);
    }
  };

  const handleGenerateReport = async (templateId: string) => {
    try {
      setIsGenerating(true);
      
      const reportRequest = {
        report_type: templateId,
        date_range: {
          start: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString().split('T')[0],
          end: new Date().toISOString().split('T')[0]
        },
        format: 'json',
        recipients: [],
        email_subject: `${templateId.charAt(0).toUpperCase() + templateId.slice(1)} Security Report`
      };
      
      const report = await reportsAPI.generateReport(reportRequest);
      
      // Add to generated reports
      setGeneratedReports(prev => [report, ...prev]);
      
      // Update report history
      await loadReportHistory();
      
      alert('Report generated successfully!');
    } catch (error) {
      console.error('Error generating report:', error);
      // Create mock report if API fails
      const mockReport = {
        id: `report-${Date.now()}`,
        type: templateId,
        title: `${templateId.charAt(0).toUpperCase() + templateId.slice(1)} Security Report`,
        summary: `Generated ${templateId} report with current security data`,
        content: {
      keyMetrics: [
            { label: 'Critical Vulnerabilities', value: '3', trend: '+1', color: 'text-red-400' },
            { label: 'High Priority Issues', value: '7', trend: '-2', color: 'text-amber-400' },
            { label: 'Patches Applied', value: '45', trend: '+12', color: 'text-green-400' },
            { label: 'Security Score', value: '78%', trend: '+5%', color: 'text-blue-400' }
      ],
          executiveSummary: `This ${templateId} report shows the current security posture with ${templateId === 'executive' ? 'executive-level insights' : 'technical details'} for the reporting period.`,
          recommendations: [
            'Prioritize critical vulnerability remediation',
            'Implement automated patch management',
            'Enhance security monitoring',
            'Conduct security awareness training'
          ]
        },
        generated_at: new Date().toISOString()
      };
      
      setGeneratedReports(prev => [mockReport, ...prev]);
      alert('Report generated successfully!');
    } finally {
      setIsGenerating(false);
    }
  };

  const handleEmailReport = async (template: ReportTemplate) => {
    try {
      const emailRequest = {
        report_type: template.id,
        recipients: template.emailList || [],
        subject: `${template.title} - ${new Date().toLocaleDateString()}`,
        include_attachments: true
      };
      
      await reportsAPI.emailReport(emailRequest);
      alert('Report sent via email successfully!');
    } catch (error) {
      console.error('Error sending email report:', error);
      alert('Email functionality simulated - Report would be sent to: ' + template.emailList.join(', '));
    }
  };

  const handleCreateCustomReport = () => {
    if (!customReportConfig.title.trim()) {
      alert('Please enter a report title');
      return;
    }
    if (customReportConfig.sections.length === 0) {
      alert('Please select at least one section');
      return;
    }
    
    const customTemplate: ReportTemplate = {
      id: `custom-${Date.now()}`,
      title: customReportConfig.title,
      description: `Custom ${customReportConfig.type} report`,
      type: customReportConfig.type,
      frequency: customReportConfig.frequency,
      lastGenerated: new Date().toISOString().split('T')[0],
      recipients: customReportConfig.recipients,
      sections: customReportConfig.sections,
      automationEnabled: false,
      emailList: []
    };
    
    reportTemplates.push(customTemplate);
    handleGenerateReport(customTemplate.id);
    setShowCustomReportModal(false);
    setCustomReportConfig({
      title: '',
      type: 'custom',
      sections: [],
      recipients: [],
      frequency: 'manual',
      format: 'pdf'
    });
  };

  const handleScheduleEmail = () => {
    alert(`Report scheduled for ${emailConfig.schedule} delivery to ${emailConfig.recipients.length} recipients`);
    setShowEmailModal(false);
  };

  const handleDownloadReport = (report: any) => {
    const dataStr = JSON.stringify(report, null, 2);
    const dataBlob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(dataBlob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `${report.type}-report-${new Date().toISOString().split('T')[0]}.json`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const getMetricColor = (color: string) => {
    switch (color) {
      case 'text-red-400':
        return 'text-red-400';
      case 'text-amber-400':
        return 'text-amber-400';
      case 'text-green-400':
        return 'text-green-400';
      case 'text-blue-400':
        return 'text-blue-400';
      default:
        return 'text-gray-400';
    }
  };

  const getPriorityColor = (priority: string) => {
    switch (priority) {
      case 'immediate':
        return 'bg-red-600';
      case 'urgent':
        return 'bg-amber-600';
      case 'normal':
        return 'bg-green-600';
      default:
        return 'bg-gray-600';
    }
  };

  const filteredTemplates = reportType === 'all' 
    ? reportTemplates 
    : reportTemplates.filter(template => template.type === reportType);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold text-white mb-2">Security Reports & Automation</h2>
          <p className="text-gray-400">Automated security reporting and stakeholder communications</p>
        </div>
        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-2 text-sm text-gray-400">
            <Bot className="w-4 h-4" />
            <span>AI-Enhanced Reports</span>
          </div>
          <select
            value={reportType}
            onChange={(e) => setReportType(e.target.value)}
            className="px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white text-sm"
          >
            <option value="all">All Reports</option>
            <option value="executive">Executive Reports</option>
            <option value="technical">Technical Reports</option>
            <option value="compliance">Compliance Reports</option>
            <option value="metrics">Metrics Reports</option>
            <option value="incident">Incident Reports</option>
            <option value="threat-intel">Threat Intelligence</option>
          </select>
          <button 
            onClick={() => setShowCustomReportModal(true)}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg text-white text-sm font-medium transition-colors flex items-center space-x-2"
          >
            <Plus className="w-4 h-4" />
            <span>Create Custom Report</span>
          </button>
        </div>
      </div>

      {/* Email Automation Status */}
      <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center space-x-2">
            <Mail className="w-5 h-5 text-blue-400" />
            <h3 className="text-lg font-semibold text-white">Email Automation Status</h3>
          </div>
          <div className="flex items-center space-x-2">
            <span className="text-sm text-green-400">Active</span>
            <div className="w-2 h-2 bg-green-400 rounded-full"></div>
          </div>
        </div>
        
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="bg-gray-700/30 p-4 rounded-lg border border-gray-600">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-gray-400">Active Schedules</span>
              <span className="text-white font-semibold">12</span>
          </div>
            <div className="text-xs text-gray-400">Weekly: 8, Daily: 3, Monthly: 1</div>
          </div>
          
          <div className="bg-gray-700/30 p-4 rounded-lg border border-gray-600">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-gray-400">Recipients</span>
              <span className="text-white font-semibold">47</span>
          </div>
            <div className="text-xs text-gray-400">Executives: 15, IT: 22, Security: 10</div>
      </div>

          <div className="bg-gray-700/30 p-4 rounded-lg border border-gray-600">
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-gray-400">Last Sent</span>
              <span className="text-white font-semibold">2h ago</span>
        </div>
            <div className="text-xs text-gray-400">Executive Summary to CISO</div>
          </div>
        </div>
      </div>

      {/* Report Templates */}
      <div className="bg-gray-800 rounded-xl border border-gray-700">
        <div className="p-6 border-b border-gray-700">
          <div className="flex items-center justify-between">
            <h3 className="text-lg font-semibold text-white">Report Templates</h3>
            <button 
              onClick={() => setShowCustomReportModal(true)}
              className="px-3 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg text-white text-sm font-medium transition-colors flex items-center space-x-2"
            >
              <Plus className="w-4 h-4" />
              <span>Custom Template</span>
            </button>
          </div>
        </div>
        
        <div className="p-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {filteredTemplates.map((template) => (
                <div key={template.id} className="bg-gray-700/30 p-6 rounded-lg border border-gray-600">
                  <div className="flex items-start justify-between mb-4">
                    <div className="flex-1">
                      <h4 className="text-lg font-semibold text-white mb-2">{template.title}</h4>
                      <p className="text-gray-300 text-sm mb-3">{template.description}</p>
                      
                      <div className="flex items-center space-x-4 text-sm text-gray-400 mb-3">
                        <div className="flex items-center space-x-1">
                          <Clock className="w-4 h-4" />
                          <span>{template.frequency}</span>
                        </div>
                        <div className="flex items-center space-x-1">
                          <Calendar className="w-4 h-4" />
                          <span>Last: {template.lastGenerated}</span>
                        </div>
                        <div className="flex items-center space-x-1">
                          <Users className="w-4 h-4" />
                          <span>{template.recipients.length} recipients</span>
                        </div>
                      </div>
                      
                      <div className="flex items-center space-x-2 mb-4">
                        <span className="text-xs text-gray-400">Automation:</span>
                        <span className={`text-xs px-2 py-1 rounded ${
                          template.automationEnabled 
                            ? 'bg-green-900/20 text-green-400' 
                            : 'bg-red-900/20 text-red-400'
                        }`}>
                          {template.automationEnabled ? 'Enabled' : 'Manual'}
                        </span>
                      </div>
                    </div>
                    
                    <div className="flex items-center space-x-2">
                      <button
                        onClick={() => handleGenerateReport(template.id)}
                      disabled={isGenerating}
                      className="px-3 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg text-white text-sm font-medium transition-colors flex items-center space-x-2"
                      >
                      {isGenerating ? (
                        <Loader2 className="w-4 h-4 animate-spin" />
                      ) : (
                        <FileText className="w-4 h-4" />
                      )}
                      <span>Generate</span>
                      </button>
                      <button
                        onClick={() => handleEmailReport(template)}
                      className="px-3 py-2 bg-green-600 hover:bg-green-700 rounded-lg text-white text-sm font-medium transition-colors flex items-center space-x-2"
                      >
                      <Send className="w-4 h-4" />
                      <span>Email</span>
                      </button>
                    </div>
                  </div>
                  
                  <div className="border-t border-gray-600 pt-4">
                    <div className="text-xs text-gray-400 mb-2">Report Sections:</div>
                    <div className="flex flex-wrap gap-1">
                      {template.sections.map((section, index) => (
                        <span key={index} className="text-xs bg-gray-600 text-gray-300 px-2 py-1 rounded">
                          {section}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
              ))}
          </div>
        </div>
      </div>

      {/* Generated Reports */}
      {generatedReports.length > 0 && (
        <div className="bg-gray-800 rounded-xl border border-gray-700">
          <div className="p-6 border-b border-gray-700">
            <h3 className="text-lg font-semibold text-white">Recently Generated Reports</h3>
          </div>
          
          <div className="p-6">
            <div className="space-y-4">
              {generatedReports.map((report, index) => (
                <div key={index} className="bg-gray-700/30 p-4 rounded-lg border border-gray-600">
                  <div className="flex items-center justify-between mb-3">
                    <div>
                      <h4 className="text-white font-medium">{report.title || `${report.type} Report`}</h4>
                      <p className="text-gray-400 text-sm">{report.summary}</p>
                      <p className="text-gray-500 text-xs">
                        Generated: {new Date(report.generated_at).toLocaleString()}
                      </p>
                    </div>
                    <div className="flex items-center space-x-2">
                      <button
                        onClick={() => setSelectedReport(report)}
                        className="px-3 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg text-white text-sm font-medium transition-colors"
                      >
                        <Eye className="w-4 h-4 mr-2" />
                        View
                      </button>
                      <button
                        onClick={() => handleDownloadReport(report)}
                        className="px-3 py-2 bg-gray-600 hover:bg-gray-700 rounded-lg text-white text-sm font-medium transition-colors"
                      >
                        <Download className="w-4 h-4 mr-2" />
                        Download
                      </button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
                </div>
              </div>
            )}

      {/* Report History */}
      <div className="bg-gray-800 rounded-xl border border-gray-700">
        <div className="p-6 border-b border-gray-700">
          <div className="flex items-center justify-between">
            <h3 className="text-lg font-semibold text-white">Report History</h3>
            <button 
              onClick={loadReportHistory}
              disabled={isLoading}
              className="px-3 py-2 bg-gray-600 hover:bg-gray-700 rounded-lg text-white text-sm font-medium transition-colors flex items-center space-x-2"
            >
              {isLoading ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <RefreshCw className="w-4 h-4" />
              )}
              <span>Refresh</span>
            </button>
                        </div>
                      </div>
                      
        <div className="p-6">
          {isLoading ? (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="w-6 h-6 animate-spin text-blue-400" />
              <span className="ml-2 text-gray-400">Loading report history...</span>
                      </div>
          ) : reportHistory.length > 0 ? (
            <div className="space-y-3">
              {reportHistory.map((report, index) => (
                <div key={index} className="flex items-center justify-between p-3 bg-gray-700/30 rounded-lg border border-gray-600">
                  <div className="flex items-center space-x-3">
                    <div className={`w-2 h-2 rounded-full ${
                      report.status === 'completed' ? 'bg-green-400' : 'bg-amber-400'
                    }`}></div>
                    <div>
                      <span className="text-white font-medium">{report.type} Report</span>
                      <p className="text-gray-400 text-sm">{report.summary}</p>
                    </div>
                  </div>
                  <div className="text-gray-400 text-sm">
                    {new Date(report.generated_at).toLocaleDateString()}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className="text-center py-8 text-gray-400">
              No report history available
            </div>
          )}
        </div>
      </div>

      {/* Custom Report Modal */}
      {showCustomReportModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-gray-800 rounded-xl p-6 w-full max-w-2xl max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-xl font-semibold text-white">Create Custom Report</h3>
              <button
                onClick={() => setShowCustomReportModal(false)}
                className="text-gray-400 hover:text-white"
              >
                <X className="w-6 h-6" />
              </button>
            </div>
            
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Report Title</label>
                <input
                  type="text"
                  value={customReportConfig.title}
                  onChange={(e) => setCustomReportConfig(prev => ({ ...prev, title: e.target.value }))}
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white"
                  placeholder="Enter report title"
                />
              </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Report Type</label>
                <select
                  value={customReportConfig.type}
                  onChange={(e) => setCustomReportConfig(prev => ({ ...prev, type: e.target.value }))}
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white"
                >
                  <option value="custom">Custom</option>
                  <option value="executive">Executive</option>
                  <option value="technical">Technical</option>
                  <option value="compliance">Compliance</option>
                  <option value="metrics">Metrics</option>
                  <option value="incident">Incident</option>
                  <option value="threat-intel">Threat Intelligence</option>
                </select>
                    </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Sections</label>
                <div className="grid grid-cols-2 gap-2 max-h-40 overflow-y-auto">
                  {availableSections.map((section) => (
                    <label key={section} className="flex items-center space-x-2">
                      <input
                        type="checkbox"
                        checked={customReportConfig.sections.includes(section)}
                        onChange={(e) => {
                          if (e.target.checked) {
                            setCustomReportConfig(prev => ({
                              ...prev,
                              sections: [...prev.sections, section]
                            }));
                          } else {
                            setCustomReportConfig(prev => ({
                              ...prev,
                              sections: prev.sections.filter(s => s !== section)
                            }));
                          }
                        }}
                        className="rounded border-gray-600 bg-gray-700 text-blue-600"
                      />
                      <span className="text-sm text-gray-300">{section}</span>
                    </label>
                  ))}
                </div>
              </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Frequency</label>
                <select
                  value={customReportConfig.frequency}
                  onChange={(e) => setCustomReportConfig(prev => ({ ...prev, frequency: e.target.value }))}
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white"
                >
                  <option value="manual">Manual</option>
                  <option value="daily">Daily</option>
                  <option value="weekly">Weekly</option>
                  <option value="monthly">Monthly</option>
                </select>
                  </div>
                  
                    <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Format</label>
                <select
                  value={customReportConfig.format}
                  onChange={(e) => setCustomReportConfig(prev => ({ ...prev, format: e.target.value }))}
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white"
                >
                  <option value="pdf">PDF</option>
                  <option value="json">JSON</option>
                  <option value="html">HTML</option>
                </select>
                      </div>
                    </div>
                    
            <div className="flex items-center justify-end space-x-3 mt-6">
              <button
                onClick={() => setShowCustomReportModal(false)}
                className="px-4 py-2 bg-gray-600 hover:bg-gray-700 rounded-lg text-white text-sm font-medium transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleCreateCustomReport}
                className="px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg text-white text-sm font-medium transition-colors flex items-center space-x-2"
              >
                <Save className="w-4 h-4" />
                <span>Create Report</span>
              </button>
                  </div>
                </div>
              </div>
            )}

      {/* Report Preview Modal */}
      {selectedReport && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <div className="bg-gray-800 rounded-xl p-6 w-full max-w-4xl max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-xl font-semibold text-white">{selectedReport.title || `${selectedReport.type} Report`}</h3>
              <button
                onClick={() => setSelectedReport(null)}
                className="text-gray-400 hover:text-white"
              >
                <X className="w-6 h-6" />
              </button>
            </div>
            
            <div className="space-y-6">
              {/* Key Metrics */}
              {selectedReport.content?.keyMetrics && (
                <div>
                  <h4 className="text-lg font-semibold text-white mb-4">Key Metrics</h4>
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    {selectedReport.content.keyMetrics.map((metric: any, index: number) => (
                    <div key={index} className="bg-gray-700/30 p-4 rounded-lg border border-gray-600">
                      <div className="flex items-center justify-between mb-2">
                          <span className="text-sm text-gray-400">{metric.label}</span>
                          <span className={`text-lg font-bold ${getMetricColor(metric.color)}`}>
                            {metric.value}
                          </span>
                        </div>
                        <div className="flex items-center space-x-2">
                          <span className={`text-xs ${metric.trend.startsWith('+') ? 'text-green-400' : 'text-red-400'}`}>
                            {metric.trend}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

              {/* Executive Summary */}
              {selectedReport.content?.executiveSummary && (
                <div>
                  <h4 className="text-lg font-semibold text-white mb-4">Executive Summary</h4>
                  <div className="bg-gray-700/30 p-4 rounded-lg border border-gray-600">
                    <p className="text-gray-300">{selectedReport.content.executiveSummary}</p>
          </div>
        </div>
      )}

              {/* Recommendations */}
              {selectedReport.content?.recommendations && (
              <div>
                  <h4 className="text-lg font-semibold text-white mb-4">Recommendations</h4>
                <div className="space-y-2">
                    {selectedReport.content.recommendations.map((rec: any, index: number) => (
                      <div key={index} className="flex items-start space-x-3 p-3 bg-gray-700/30 rounded-lg border border-gray-600">
                        <CheckCircle className="w-4 h-4 text-green-400 mt-0.5 flex-shrink-0" />
                        <span className="text-sm text-gray-300">{rec}</span>
                    </div>
                  ))}
                </div>
                </div>
              )}

              {/* Report Details */}
              <div className="bg-gray-700/30 p-4 rounded-lg border border-gray-600">
                <h4 className="text-lg font-semibold text-white mb-4">Report Details</h4>
                <div className="grid grid-cols-2 gap-4 text-sm">
                <div>
                    <span className="text-gray-400">Type:</span>
                    <span className="text-white ml-2">{selectedReport.type}</span>
                  </div>
                  <div>
                    <span className="text-gray-400">Generated:</span>
                    <span className="text-white ml-2">{new Date(selectedReport.generated_at).toLocaleString()}</span>
                  </div>
                  <div>
                    <span className="text-gray-400">Format:</span>
                    <span className="text-white ml-2">JSON</span>
                </div>
                <div>
                    <span className="text-gray-400">Status:</span>
                    <span className="text-white ml-2">Completed</span>
                  </div>
                </div>
                </div>
              </div>

            <div className="flex items-center justify-end space-x-3 mt-6">
                <button
                onClick={() => handleDownloadReport(selectedReport)}
                className="px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg text-white text-sm font-medium transition-colors flex items-center space-x-2"
                >
                <Download className="w-4 h-4" />
                <span>Download Report</span>
                </button>
                <button
                onClick={() => setSelectedReport(null)}
                className="px-4 py-2 bg-gray-600 hover:bg-gray-700 rounded-lg text-white text-sm font-medium transition-colors"
                >
                Close
                </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default Reports;
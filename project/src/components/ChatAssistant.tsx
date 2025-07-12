import React, { useState, useRef, useEffect } from 'react';
import { Send, Bot, User, Clock, Shield, AlertTriangle, CheckCircle, Search, FileText, GitBranch, Zap, Globe, Terminal, Eye } from 'lucide-react';

const ChatAssistant = () => {
  const [messages, setMessages] = useState([
    {
      id: 1,
      type: 'assistant',
      content: 'Hello! I\'m your AI Security Assistant. I can help you with vulnerability analysis, patch recommendations, and security best practices. What would you like to know?',
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      suggestions: [
        'What is the best way to patch CVE-2024-0001?',
        'Any known zero-day vulnerabilities for Apache?',
        'Show me critical vulnerabilities for my environment',
        'Generate a security report for management'
      ]
    }
  ]);
  const [inputMessage, setInputMessage] = useState('');
  const [isTyping, setIsTyping] = useState(false);
  const [activeContext, setActiveContext] = useState('general');
  const messagesEndRef = useRef(null);

  const contextOptions = [
    { id: 'general', label: 'General Security', icon: Shield },
    { id: 'cve', label: 'CVE Analysis', icon: AlertTriangle },
    { id: 'patching', label: 'Patch Management', icon: CheckCircle },
    { id: 'threat-intel', label: 'Threat Intelligence', icon: Eye },
    { id: 'compliance', label: 'Compliance', icon: FileText },
    { id: 'incident', label: 'Incident Response', icon: Zap }
  ];

  const quickActions = [
    { label: 'Analyze CVE', icon: AlertTriangle, action: 'analyze-cve', query: 'Analyze the latest critical CVE and provide remediation steps' },
    { label: 'Patch Status', icon: CheckCircle, action: 'patch-status', query: 'What is the current patch status for my environment?' },
    { label: 'Risk Assessment', icon: Shield, action: 'risk-assessment', query: 'Perform a risk assessment of current vulnerabilities' },
    { label: 'Generate Report', icon: FileText, action: 'generate-report', query: 'Generate a security report for management' },
    { label: 'Threat Hunting', icon: Search, action: 'threat-hunting', query: 'Help me hunt for threats in my environment' },
    { label: 'Zero-Day Check', icon: Globe, action: 'zero-day', query: 'Check for any new zero-day vulnerabilities' }
  ];

  const knowledgeBase = {
    'cve-2024-0001': {
      title: 'Apache HTTP Server Remote Code Execution',
      severity: 'Critical',
      cvss: '9.8',
      description: 'A critical remote code execution vulnerability in Apache HTTP Server allows attackers to execute arbitrary code through crafted HTTP requests.',
      patchSteps: [
        'Update Apache HTTP Server to version 2.4.59 or later',
        'sudo apt update && sudo apt install apache2=2.4.59-1ubuntu4.3',
        'sudo systemctl restart apache2',
        'Verify the update: apache2 -v'
      ],
      workarounds: [
        'Implement WAF rules to block malicious requests',
        'Restrict access to Apache servers from untrusted networks',
        'Monitor logs for suspicious HTTP requests'
      ],
      businessImpact: 'High - Could lead to complete server compromise and data theft',
      timeline: 'Immediate patching required within 24 hours'
    },
    'apache-zero-day': {
      title: 'Apache Software Zero-Day Status',
      status: 'No active zero-day vulnerabilities',
      lastChecked: '2024-01-15 15:30:00',
      sources: ['NVD', 'Apache Security Team', 'CISA KEV'],
      recommendations: [
        'Continue monitoring Apache security advisories',
        'Implement defense-in-depth strategies',
        'Regular security scanning and assessments'
      ]
    },
    'centos-patching': {
      title: 'CentOS 7 Patch Management',
      commands: [
        'sudo yum update --security',
        'sudo yum list updates',
        'sudo yum update package-name',
        'sudo systemctl reboot'
      ],
      bestPractices: [
        'Test patches in development environment first',
        'Schedule maintenance windows for production',
        'Create system backups before patching',
        'Monitor system performance post-patch'
      ]
    }
  };

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const handleSendMessage = async (messageText = null) => {
    const message = messageText || inputMessage;
    if (!message.trim()) return;

    const userMessage = {
      id: messages.length + 1,
      type: 'user',
      content: message,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      context: activeContext
    };

    setMessages(prev => [...prev, userMessage]);
    setInputMessage('');
    setIsTyping(true);

    // Simulate AI processing time
    setTimeout(() => {
      const aiResponse = generateAIResponse(message, activeContext);
      setMessages(prev => [...prev, aiResponse]);
      setIsTyping(false);
    }, 1500);
  };

  const generateAIResponse = (query, context) => {
    const lowerQuery = query.toLowerCase();
    
    // CVE-specific responses
    if (lowerQuery.includes('cve-2024-0001') || lowerQuery.includes('apache') && lowerQuery.includes('patch')) {
      const cveInfo = knowledgeBase['cve-2024-0001'];
      return {
        id: messages.length + 2,
        type: 'assistant',
        content: `I found information about CVE-2024-0001 (Apache HTTP Server RCE):

**Severity:** ${cveInfo.severity} (CVSS ${cveInfo.cvss})
**Description:** ${cveInfo.description}

**Immediate Actions Required:**
${cveInfo.patchSteps.map((step, i) => `${i + 1}. ${step}`).join('\n')}

**Business Impact:** ${cveInfo.businessImpact}
**Timeline:** ${cveInfo.timeline}

**Temporary Workarounds:**
${cveInfo.workarounds.map((w, i) => `• ${w}`).join('\n')}

Would you like me to help you create a patch deployment plan or generate a security ticket for this vulnerability?`,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        hasCodeBlock: true,
        codeBlock: `# Apache HTTP Server Update Commands
${cveInfo.patchSteps.slice(1, -1).join('\n')}`,
        hasRecommendations: true,
        recommendations: [
          'Create emergency patch deployment ticket',
          'Implement temporary WAF rules',
          'Schedule immediate maintenance window',
          'Notify security team and management'
        ],
        severity: 'critical'
      };
    }

    // Zero-day check responses
    if (lowerQuery.includes('zero-day') || lowerQuery.includes('zero day')) {
      const zeroInfo = knowledgeBase['apache-zero-day'];
      return {
        id: messages.length + 2,
        type: 'assistant',
        content: `**Zero-Day Vulnerability Status Check**

**Apache Software:** ${zeroInfo.status}
**Last Checked:** ${zeroInfo.lastChecked}
**Sources Monitored:** ${zeroInfo.sources.join(', ')}

**Current Recommendations:**
${zeroInfo.recommendations.map((r, i) => `${i + 1}. ${r}`).join('\n')}

**Real-time Monitoring:**
• CISA Known Exploited Vulnerabilities (KEV) - No new Apache entries
• NVD Recent Publications - No critical Apache CVEs in last 24h
• Vendor Security Advisories - All clear

I'm continuously monitoring threat intelligence feeds. Would you like me to set up automated alerts for Apache-related zero-day discoveries?`,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        hasRecommendations: true,
        recommendations: [
          'Enable automated zero-day monitoring',
          'Review current Apache security hardening',
          'Update incident response procedures'
        ],
        severity: 'info'
      };
    }

    // Patch management responses
    if (lowerQuery.includes('patch') && (lowerQuery.includes('centos') || lowerQuery.includes('rhel'))) {
      const patchInfo = knowledgeBase['centos-patching'];
      return {
        id: messages.length + 2,
        type: 'assistant',
        content: `**CentOS/RHEL Patch Management Guide**

**Security Update Commands:**
${patchInfo.commands.map((cmd, i) => `${i + 1}. ${cmd}`).join('\n')}

**Best Practices:**
${patchInfo.bestPractices.map((bp, i) => `• ${bp}`).join('\n')}

**Recommended Patch Schedule:**
• Critical patches: Within 24-48 hours
• High severity: Within 1 week
• Medium/Low: Next maintenance window

Would you like me to help you create a specific patch deployment plan for your CentOS systems?`,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        hasCodeBlock: true,
        codeBlock: patchInfo.commands.join('\n'),
        hasRecommendations: true,
        recommendations: [
          'Create patch testing environment',
          'Implement automated patch management',
          'Schedule regular maintenance windows'
        ],
        severity: 'medium'
      };
    }

    // Risk assessment responses
    if (lowerQuery.includes('risk') && lowerQuery.includes('assessment')) {
      return {
        id: messages.length + 2,
        type: 'assistant',
        content: `**Current Environment Risk Assessment**

**Critical Risk Factors:**
• 1 Critical vulnerability (CVE-2024-0001) - Apache HTTP Server
• 2 High-severity vulnerabilities requiring attention
• 45 systems potentially affected by critical vulnerability

**Risk Score: 85/100 (High Risk)**

**Immediate Actions Required:**
1. **Priority 1:** Patch Apache HTTP Server vulnerability (CVE-2024-0001)
   - Affects customer-facing web servers
   - Public exploits available
   - Estimated remediation time: 2-4 hours

2. **Priority 2:** Address OpenSSL vulnerability (CVE-2024-0002)
   - Affects internal systems
   - No public exploits currently
   - Estimated remediation time: 1-2 hours

**Risk Mitigation Timeline:**
• Next 24 hours: Address critical vulnerabilities
• Next 72 hours: Implement high-priority patches
• Next week: Complete medium-priority updates

Would you like me to generate a detailed remediation plan or create security tickets for these vulnerabilities?`,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        hasRecommendations: true,
        recommendations: [
          'Execute emergency patch deployment',
          'Implement temporary mitigations',
          'Increase monitoring and alerting',
          'Prepare incident response procedures'
        ],
        severity: 'high'
      };
    }

    // Threat hunting responses
    if (lowerQuery.includes('threat') && lowerQuery.includes('hunt')) {
      return {
        id: messages.length + 2,
        type: 'assistant',
        content: `**Threat Hunting Guidance**

**Current Focus Areas:**
1. **Apache HTTP Server Exploitation Attempts**
   - Look for unusual HTTP request patterns
   - Monitor for requests to /.%2e/.%2e/ paths
   - Check for suspicious User-Agent strings

2. **Privilege Escalation Activities**
   - Monitor sudo usage patterns
   - Check for unusual process executions
   - Review file permission changes

**Recommended Queries:**

**For SIEM/Log Analysis:**
• source="/var/log/apache2/access.log" | search "/.%2e/.%2e/"
• EventCode=4624 AND LogonType=3 | stats count by Account_Name
• process_name="*" AND parent_process="apache2" | rare process_name

**For OSQuery:**
• SELECT * FROM processes WHERE parent=apache2_pid;
• SELECT * FROM file_events WHERE action='CREATED' AND path LIKE '/tmp/%';

**IOCs to Monitor:**
• Unusual outbound connections from web servers
• New user accounts created
• Unexpected file modifications in web directories

Would you like me to help you create custom detection rules or provide more specific hunting queries?`,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        hasCodeBlock: true,
        codeBlock: `# OSQuery Threat Hunting Examples
SELECT * FROM processes WHERE parent IN (SELECT pid FROM processes WHERE name='apache2');
SELECT * FROM file_events WHERE action='CREATED' AND path LIKE '/tmp/%' AND time > (strftime('%s','now') - 3600);
SELECT * FROM socket_events WHERE action='connect' AND remote_port NOT IN (80,443,53,22);`,
        hasRecommendations: true,
        recommendations: [
          'Set up automated threat hunting queries',
          'Configure SIEM correlation rules',
          'Implement behavioral analytics',
          'Create custom IOC feeds'
        ],
        severity: 'info'
      };
    }

    // Report generation responses
    if (lowerQuery.includes('report') && lowerQuery.includes('management')) {
      return {
        id: messages.length + 2,
        type: 'assistant',
        content: `**Executive Security Report - Generated**

**Security Posture Summary:**
• **Overall Risk Level:** High (85/100)
• **Critical Vulnerabilities:** 1 (Immediate action required)
• **High-Priority Issues:** 2 (Address within 72 hours)
• **Systems at Risk:** 45 servers, 120 workstations

**Key Findings:**
1. **Critical Apache Vulnerability (CVE-2024-0001)**
   - **Business Impact:** High - Customer-facing services at risk
   - **Exploitation Risk:** Active exploits in the wild
   - **Recommended Action:** Emergency patching within 24 hours

2. **OpenSSL Security Issue (CVE-2024-0002)**
   - **Business Impact:** Medium - Internal communication security
   - **Exploitation Risk:** Low - No known active exploits
   - **Recommended Action:** Scheduled patching within 1 week

**Resource Requirements:**
• **Immediate:** 2-4 hours for critical patch deployment
• **This Week:** 8-12 hours for comprehensive patching
• **Budget Impact:** Minimal - standard maintenance activities

**Executive Recommendations:**
1. Approve emergency maintenance window for critical patch
2. Increase security monitoring during vulnerable period
3. Consider additional security investments for automation

Would you like me to export this report as a PDF or schedule it for regular delivery?`,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        hasRecommendations: true,
        recommendations: [
          'Schedule emergency patch deployment',
          'Increase security monitoring',
          'Prepare stakeholder communications',
          'Review incident response procedures'
        ],
        severity: 'high'
      };
    }

    // Default contextual responses
    const contextResponses = {
      general: `I can help you with various security tasks including vulnerability analysis, patch management, threat hunting, and compliance. What specific security challenge are you facing?`,
      cve: `I can analyze CVEs, provide patch recommendations, and assess vulnerability impact. Which CVE would you like me to analyze, or would you like me to check for the latest critical vulnerabilities?`,
      patching: `I can help with patch management strategies, deployment commands, and risk assessment. Which systems or software do you need patching guidance for?`,
      'threat-intel': `I can provide threat intelligence analysis, IOC hunting, and attack pattern identification. What threat activity are you investigating?`,
      compliance: `I can assist with compliance requirements, audit preparation, and security control implementation. Which compliance framework are you working with?`,
      incident: `I can help with incident response procedures, forensic analysis, and containment strategies. What type of security incident are you dealing with?`
    };

    return {
      id: messages.length + 2,
      type: 'assistant',
      content: contextResponses[context] || contextResponses.general,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      hasRecommendations: true,
      recommendations: [
        'Ask about specific CVEs or vulnerabilities',
        'Request patch deployment guidance',
        'Get threat hunting assistance',
        'Generate security reports'
      ],
      severity: 'info'
    };
  };

  const handleQuickAction = (action, query) => {
    handleSendMessage(query);
  };

  const handleSuggestionClick = (suggestion) => {
    handleSendMessage(suggestion);
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'critical':
        return 'border-l-red-500';
      case 'high':
        return 'border-l-amber-500';
      case 'medium':
        return 'border-l-yellow-500';
      case 'info':
        return 'border-l-blue-500';
      default:
        return 'border-l-gray-500';
    }
  };

  const formatMessageContent = (content) => {
    // Convert markdown-like formatting to HTML
    return content
      .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
      .replace(/\*(.*?)\*/g, '<em>$1</em>')
      .replace(/`(.*?)`/g, '<code class="bg-gray-700 px-1 rounded">$1</code>')
      .split('\n')
      .map((line, index) => {
        if (line.startsWith('•')) {
          return `<div class="ml-4 mb-1">${line}</div>`;
        }
        if (line.match(/^\d+\./)) {
          return `<div class="ml-4 mb-1">${line}</div>`;
        }
        return line ? `<div class="mb-2">${line}</div>` : '<div class="mb-2"></div>';
      })
      .join('');
  };

  return (
    <div className="h-[calc(100vh-8rem)] flex flex-col">
      {/* Header */}
      <div className="bg-gray-800 rounded-xl p-6 border border-gray-700 mb-6">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-3xl font-bold text-white mb-2">AI Security Assistant</h2>
            <p className="text-gray-400">Advanced LLM-powered security analysis and recommendations</p>
          </div>
          <div className="flex items-center space-x-2">
            <div className="w-3 h-3 bg-green-400 rounded-full animate-pulse"></div>
            <span className="text-sm text-gray-400">Online & Learning</span>
          </div>
        </div>
      </div>

      {/* Context Selector */}
      <div className="bg-gray-800 rounded-xl p-4 border border-gray-700 mb-6">
        <div className="flex items-center space-x-2 mb-3">
          <Bot className="w-4 h-4 text-blue-400" />
          <span className="text-sm text-gray-400">Context:</span>
        </div>
        <div className="flex flex-wrap gap-2">
          {contextOptions.map((context) => {
            const Icon = context.icon;
            return (
              <button
                key={context.id}
                onClick={() => setActiveContext(context.id)}
                className={`flex items-center space-x-2 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                  activeContext === context.id
                    ? 'bg-blue-600 text-white'
                    : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
                }`}
              >
                <Icon className="w-4 h-4" />
                <span>{context.label}</span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Quick Actions */}
      <div className="bg-gray-800 rounded-xl p-4 border border-gray-700 mb-6">
        <p className="text-sm text-gray-400 mb-3">Quick Actions:</p>
        <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
          {quickActions.map((action) => {
            const Icon = action.icon;
            return (
              <button
                key={action.action}
                onClick={() => handleQuickAction(action.action, action.query)}
                className="flex items-center space-x-2 px-3 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-white text-sm transition-colors"
              >
                <Icon className="w-4 h-4" />
                <span>{action.label}</span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Chat Messages */}
      <div className="flex-1 bg-gray-800 rounded-xl border border-gray-700 flex flex-col">
        <div className="flex-1 overflow-y-auto p-6 space-y-4">
          {messages.map((message) => (
            <div
              key={message.id}
              className={`flex ${message.type === 'user' ? 'justify-end' : 'justify-start'}`}
            >
              <div
                className={`max-w-3xl ${
                  message.type === 'user'
                    ? 'bg-blue-600 text-white rounded-l-xl rounded-tr-xl'
                    : `bg-gray-700 text-gray-100 rounded-r-xl rounded-tl-xl border-l-4 ${getSeverityColor(message.severity)}`
                } p-4`}
              >
                <div className="flex items-center space-x-2 mb-2">
                  {message.type === 'user' ? (
                    <User className="w-4 h-4" />
                  ) : (
                    <Bot className="w-4 h-4 text-blue-400" />
                  )}
                  <span className="text-xs opacity-75">{message.timestamp}</span>
                  {message.context && (
                    <span className="text-xs bg-gray-600 px-2 py-1 rounded">
                      {contextOptions.find(c => c.id === message.context)?.label}
                    </span>
                  )}
                </div>
                
                <div 
                  className="text-sm leading-relaxed"
                  dangerouslySetInnerHTML={{ __html: formatMessageContent(message.content) }}
                />

                {message.hasCodeBlock && (
                  <div className="mt-4 bg-gray-900 rounded-lg p-3 border border-gray-600">
                    <div className="flex items-center space-x-2 mb-2">
                      <Terminal className="w-4 h-4 text-green-400" />
                      <span className="text-xs text-green-400">Commands</span>
                    </div>
                    <pre className="text-green-400 text-sm font-mono whitespace-pre-wrap">
                      {message.codeBlock}
                    </pre>
                  </div>
                )}

                {message.hasRecommendations && (
                  <div className="mt-4 space-y-2">
                    <div className="flex items-center space-x-2">
                      <CheckCircle className="w-4 h-4 text-green-400" />
                      <span className="text-xs text-green-400">Recommended Actions</span>
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                      {message.recommendations.map((rec, index) => (
                        <button
                          key={index}
                          onClick={() => handleSendMessage(rec)}
                          className="text-left p-2 bg-gray-600 hover:bg-gray-500 rounded text-xs transition-colors"
                        >
                          {rec}
                        </button>
                      ))}
                    </div>
                  </div>
                )}

                {message.suggestions && (
                  <div className="mt-4 space-y-2">
                    <p className="text-xs text-gray-400">Try asking:</p>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                      {message.suggestions.map((suggestion, index) => (
                        <button
                          key={index}
                          onClick={() => handleSuggestionClick(suggestion)}
                          className="text-left p-2 bg-gray-600 hover:bg-gray-500 rounded text-xs transition-colors"
                        >
                          {suggestion}
                        </button>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          ))}
          
          {isTyping && (
            <div className="flex justify-start">
              <div className="bg-gray-700 rounded-r-xl rounded-tl-xl p-4 border-l-4 border-l-blue-500">
                <div className="flex items-center space-x-2">
                  <Bot className="w-4 h-4 text-blue-400 animate-pulse" />
                  <span className="text-sm text-gray-300">AI is analyzing and generating response...</span>
                </div>
                <div className="flex space-x-1 mt-2">
                  <div className="w-2 h-2 bg-blue-400 rounded-full animate-bounce"></div>
                  <div className="w-2 h-2 bg-blue-400 rounded-full animate-bounce" style={{ animationDelay: '0.1s' }}></div>
                  <div className="w-2 h-2 bg-blue-400 rounded-full animate-bounce" style={{ animationDelay: '0.2s' }}></div>
                </div>
              </div>
            </div>
          )}
          
          <div ref={messagesEndRef} />
        </div>

        {/* Input Area */}
        <div className="border-t border-gray-700 p-4">
          <div className="flex items-center space-x-4">
            <div className="flex-1 relative">
              <input
                type="text"
                value={inputMessage}
                onChange={(e) => setInputMessage(e.target.value)}
                onKeyPress={(e) => e.key === 'Enter' && handleSendMessage()}
                placeholder="Ask about CVEs, patches, threats, or security best practices..."
                className="w-full px-4 py-3 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
                disabled={isTyping}
              />
            </div>
            <button
              onClick={() => handleSendMessage()}
              disabled={isTyping || !inputMessage.trim()}
              className="px-6 py-3 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 rounded-lg text-white font-medium transition-colors flex items-center space-x-2"
            >
              <Send className="w-4 h-4" />
              <span>Send</span>
            </button>
          </div>
          
          <div className="mt-2 text-xs text-gray-500 text-center">
            Powered by advanced LLM • Real-time threat intelligence • Contextual security analysis
          </div>
        </div>
      </div>
    </div>
  );
};

export default ChatAssistant;
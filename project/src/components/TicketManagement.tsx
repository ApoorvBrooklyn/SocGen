import React, { useState } from 'react';
import { FileText, Plus, ExternalLink, Clock, CheckCircle, AlertTriangle, User, Calendar } from 'lucide-react';

const TicketManagement = () => {
  const [selectedTicket, setSelectedTicket] = useState(null);
  const [showCreateForm, setShowCreateForm] = useState(false);

  const tickets = [
    {
      id: 'SEC-2024-001',
      title: 'Critical Apache HTTP Server Security Update',
      cveId: 'CVE-2024-0001',
      status: 'Open',
      priority: 'Critical',
      assignee: 'John Smith',
      reporter: 'Security Team',
      created: '2024-01-15',
      dueDate: '2024-01-16',
      platform: 'JIRA',
      description: 'Urgent security patch required for Apache HTTP Server to address critical remote code execution vulnerability.',
      affectedSystems: ['web-server-01', 'web-server-02', 'web-server-03'],
      estimatedEffort: '4 hours',
      businessJustification: 'Critical security vulnerability with public exploits available. Immediate remediation required to prevent potential compromise.',
      acceptanceCriteria: [
        'Apache HTTP Server updated to version 2.4.59',
        'All web services functioning normally',
        'Security scan confirms vulnerability is patched',
        'Monitoring confirms no performance impact'
      ],
      attachments: ['patch-plan.pdf', 'rollback-procedure.md'],
      comments: [
        {
          author: 'John Smith',
          date: '2024-01-15 10:30',
          message: 'Starting patch deployment process. Maintenance window scheduled for tonight.'
        }
      ]
    },
    {
      id: 'SEC-2024-002',
      title: 'OpenSSL Buffer Overflow Vulnerability Fix',
      cveId: 'CVE-2024-0002',
      status: 'In Progress',
      priority: 'High',
      assignee: 'Sarah Johnson',
      reporter: 'Vulnerability Scanner',
      created: '2024-01-12',
      dueDate: '2024-01-18',
      platform: 'ServiceNow',
      description: 'OpenSSL security update required to address buffer overflow vulnerability affecting multiple systems.',
      affectedSystems: ['all-linux-servers'],
      estimatedEffort: '8 hours',
      businessJustification: 'High-severity vulnerability affecting cryptographic operations. Patch required for compliance.',
      acceptanceCriteria: [
        'OpenSSL updated to version 3.0.13',
        'All SSL/TLS services restarted successfully',
        'Certificate validation tests pass',
        'No encrypted communication disruptions'
      ],
      attachments: ['ssl-test-results.pdf'],
      comments: [
        {
          author: 'Sarah Johnson',
          date: '2024-01-14 15:45',
          message: 'Patch testing completed in dev environment. Proceeding with production deployment.'
        }
      ]
    },
    {
      id: 'SEC-2024-003',
      title: 'Linux Kernel Security Patch Deployment',
      cveId: 'CVE-2024-0003',
      status: 'Resolved',
      priority: 'High',
      assignee: 'Mike Davis',
      reporter: 'System Administrator',
      created: '2024-01-10',
      dueDate: '2024-01-20',
      platform: 'GitHub Issues',
      description: 'Kernel security patch for privilege escalation vulnerability.',
      affectedSystems: ['database-cluster', 'app-servers'],
      estimatedEffort: '12 hours',
      businessJustification: 'Kernel vulnerability requires system reboot. Coordinated deployment during maintenance window.',
      acceptanceCriteria: [
        'Kernel updated to latest security release',
        'All systems rebooted successfully',
        'Application services restored',
        'System performance baseline maintained'
      ],
      attachments: ['kernel-update-log.txt', 'post-patch-verification.pdf'],
      comments: [
        {
          author: 'Mike Davis',
          date: '2024-01-19 08:15',
          message: 'Kernel patch deployment completed successfully. All systems operational.'
        }
      ]
    }
  ];

  const getStatusColor = (status) => {
    switch (status.toLowerCase()) {
      case 'open':
        return 'text-red-400 bg-red-900/20';
      case 'in progress':
        return 'text-yellow-400 bg-yellow-900/20';
      case 'resolved':
        return 'text-green-400 bg-green-900/20';
      default:
        return 'text-gray-400 bg-gray-900/20';
    }
  };

  const getPriorityColor = (priority) => {
    switch (priority.toLowerCase()) {
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

  const getPlatformIcon = (platform) => {
    switch (platform.toLowerCase()) {
      case 'jira':
        return '🔷';
      case 'servicenow':
        return '🔶';
      case 'github issues':
        return '🐙';
      default:
        return '📋';
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold text-white mb-2">Ticket Management</h2>
          <p className="text-gray-400">Automated security ticket generation and tracking</p>
        </div>
        <button
          onClick={() => setShowCreateForm(true)}
          className="flex items-center space-x-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg text-white font-medium transition-colors"
        >
          <Plus className="w-4 h-4" />
          <span>Create Ticket</span>
        </button>
      </div>

      {/* Statistics */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-2xl font-bold text-red-400">8</p>
              <p className="text-sm text-gray-400">Open Tickets</p>
            </div>
            <AlertTriangle className="w-8 h-8 text-red-400" />
          </div>
        </div>
        <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-2xl font-bold text-yellow-400">5</p>
              <p className="text-sm text-gray-400">In Progress</p>
            </div>
            <Clock className="w-8 h-8 text-yellow-400" />
          </div>
        </div>
        <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-2xl font-bold text-green-400">23</p>
              <p className="text-sm text-gray-400">Resolved</p>
            </div>
            <CheckCircle className="w-8 h-8 text-green-400" />
          </div>
        </div>
        <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-2xl font-bold text-blue-400">6.5</p>
              <p className="text-sm text-gray-400">Avg. Resolution Time</p>
            </div>
            <Calendar className="w-8 h-8 text-blue-400" />
          </div>
        </div>
      </div>

      {/* Tickets List */}
      <div className="space-y-4">
        {tickets.map((ticket) => (
          <div key={ticket.id} className="bg-gray-800 rounded-xl p-6 border border-gray-700">
            <div className="flex items-start justify-between">
              <div className="flex-1">
                <div className="flex items-center space-x-4 mb-3">
                  <span className="text-lg font-bold text-white">{ticket.id}</span>
                  <span className={`px-3 py-1 rounded-full text-sm font-medium ${getStatusColor(ticket.status)}`}>
                    {ticket.status}
                  </span>
                  <span className={`px-3 py-1 rounded-full text-sm font-medium ${getPriorityColor(ticket.priority)}`}>
                    {ticket.priority}
                  </span>
                  <div className="flex items-center space-x-2">
                    <span className="text-xl">{getPlatformIcon(ticket.platform)}</span>
                    <span className="text-sm text-gray-400">{ticket.platform}</span>
                  </div>
                </div>

                <h3 className="text-xl font-semibold text-white mb-2">{ticket.title}</h3>
                <p className="text-gray-400 mb-3">{ticket.description}</p>

                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
                  <div className="flex items-center space-x-2">
                    <User className="w-4 h-4 text-gray-400" />
                    <span className="text-sm text-gray-400">Assignee:</span>
                    <span className="text-sm text-white">{ticket.assignee}</span>
                  </div>
                  <div className="flex items-center space-x-2">
                    <Calendar className="w-4 h-4 text-gray-400" />
                    <span className="text-sm text-gray-400">Due:</span>
                    <span className="text-sm text-white">{ticket.dueDate}</span>
                  </div>
                  <div className="flex items-center space-x-2">
                    <Clock className="w-4 h-4 text-gray-400" />
                    <span className="text-sm text-gray-400">Effort:</span>
                    <span className="text-sm text-white">{ticket.estimatedEffort}</span>
                  </div>
                </div>

                <div className="flex items-center space-x-4 mb-4">
                  <span className="text-sm text-gray-400">CVE:</span>
                  <span className="text-sm font-mono text-blue-400">{ticket.cveId}</span>
                  <span className="text-sm text-gray-400">Systems:</span>
                  <span className="text-sm text-white">{ticket.affectedSystems.length} affected</span>
                </div>

                <div className="flex items-center space-x-2">
                  <span className="text-sm text-gray-400">Attachments:</span>
                  {ticket.attachments.map((attachment, index) => (
                    <span key={index} className="text-sm text-blue-400 hover:text-blue-300 cursor-pointer">
                      {attachment}
                    </span>
                  ))}
                </div>
              </div>

              <div className="flex flex-col space-y-2 ml-6">
                <button
                  onClick={() => setSelectedTicket(ticket)}
                  className="px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg text-white text-sm font-medium transition-colors"
                >
                  View Details
                </button>
                <button className="flex items-center space-x-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-white text-sm font-medium transition-colors">
                  <ExternalLink className="w-4 h-4" />
                  <span>Open in {ticket.platform}</span>
                </button>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Ticket Detail Modal */}
      {selectedTicket && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
          <div className="bg-gray-800 rounded-xl max-w-4xl w-full max-h-[90vh] overflow-y-auto">
            <div className="p-6 border-b border-gray-700">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-2xl font-bold text-white">{selectedTicket.title}</h3>
                  <p className="text-gray-400 mt-1">{selectedTicket.id} • {selectedTicket.cveId}</p>
                </div>
                <button
                  onClick={() => setSelectedTicket(null)}
                  className="text-gray-400 hover:text-white text-xl"
                >
                  ×
                </button>
              </div>
            </div>

            <div className="p-6 space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <h4 className="text-lg font-semibold text-white mb-3">Ticket Information</h4>
                  <div className="space-y-3">
                    <div className="flex justify-between">
                      <span className="text-gray-400">Status:</span>
                      <span className={`px-2 py-1 rounded text-sm font-medium ${getStatusColor(selectedTicket.status)}`}>
                        {selectedTicket.status}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">Priority:</span>
                      <span className={`px-2 py-1 rounded text-sm font-medium ${getPriorityColor(selectedTicket.priority)}`}>
                        {selectedTicket.priority}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">Assignee:</span>
                      <span className="text-white">{selectedTicket.assignee}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">Reporter:</span>
                      <span className="text-white">{selectedTicket.reporter}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">Created:</span>
                      <span className="text-white">{selectedTicket.created}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">Due Date:</span>
                      <span className="text-white">{selectedTicket.dueDate}</span>
                    </div>
                  </div>
                </div>

                <div>
                  <h4 className="text-lg font-semibold text-white mb-3">Affected Systems</h4>
                  <div className="space-y-2">
                    {selectedTicket.affectedSystems.map((system, index) => (
                      <div key={index} className="p-2 bg-gray-700 rounded text-sm text-gray-300">
                        {system}
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              <div>
                <h4 className="text-lg font-semibold text-white mb-3">Business Justification</h4>
                <p className="text-gray-300 p-4 bg-gray-700 rounded-lg">{selectedTicket.businessJustification}</p>
              </div>

              <div>
                <h4 className="text-lg font-semibold text-white mb-3">Acceptance Criteria</h4>
                <ul className="space-y-2">
                  {selectedTicket.acceptanceCriteria.map((criteria, index) => (
                    <li key={index} className="flex items-start space-x-2">
                      <CheckCircle className="w-4 h-4 text-green-400 mt-0.5 flex-shrink-0" />
                      <span className="text-gray-300 text-sm">{criteria}</span>
                    </li>
                  ))}
                </ul>
              </div>

              <div>
                <h4 className="text-lg font-semibold text-white mb-3">Comments</h4>
                <div className="space-y-3">
                  {selectedTicket.comments.map((comment, index) => (
                    <div key={index} className="p-4 bg-gray-700 rounded-lg">
                      <div className="flex items-center space-x-2 mb-2">
                        <span className="text-sm font-medium text-white">{comment.author}</span>
                        <span className="text-xs text-gray-400">{comment.date}</span>
                      </div>
                      <p className="text-sm text-gray-300">{comment.message}</p>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Create Ticket Form Modal */}
      {showCreateForm && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
          <div className="bg-gray-800 rounded-xl max-w-2xl w-full max-h-[90vh] overflow-y-auto">
            <div className="p-6 border-b border-gray-700">
              <div className="flex items-center justify-between">
                <h3 className="text-2xl font-bold text-white">Create Security Ticket</h3>
                <button
                  onClick={() => setShowCreateForm(false)}
                  className="text-gray-400 hover:text-white text-xl"
                >
                  ×
                </button>
              </div>
            </div>

            <div className="p-6 space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">CVE ID</label>
                <input
                  type="text"
                  placeholder="CVE-2024-XXXX"
                  className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Title</label>
                <input
                  type="text"
                  placeholder="Security vulnerability title"
                  className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white"
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">Priority</label>
                  <select className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white">
                    <option>Critical</option>
                    <option>High</option>
                    <option>Medium</option>
                    <option>Low</option>
                  </select>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-300 mb-2">Platform</label>
                  <select className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white">
                    <option>JIRA</option>
                    <option>ServiceNow</option>
                    <option>GitHub Issues</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Description</label>
                <textarea
                  rows={4}
                  placeholder="Detailed description of the vulnerability and required actions"
                  className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white"
                />
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Affected Systems</label>
                <input
                  type="text"
                  placeholder="Comma-separated list of affected systems"
                  className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white"
                />
              </div>

              <div className="flex items-center space-x-4 pt-4">
                <button className="px-6 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg text-white font-medium transition-colors">
                  Create Ticket
                </button>
                <button
                  onClick={() => setShowCreateForm(false)}
                  className="px-6 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-white font-medium transition-colors"
                >
                  Cancel
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default TicketManagement;
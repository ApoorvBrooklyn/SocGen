import React from 'react';
import { AlertTriangle, CheckCircle, Clock, Shield, TrendingUp, Server, Users, FileText } from 'lucide-react';

const Dashboard = () => {
  const stats = [
    {
      label: 'Critical Vulnerabilities',
      value: '23',
      change: '+5 from last week',
      icon: AlertTriangle,
      color: 'text-red-400',
      bgColor: 'bg-red-900/20',
    },
    {
      label: 'High Priority',
      value: '87',
      change: '+12 from last week',
      icon: Clock,
      color: 'text-amber-400',
      bgColor: 'bg-amber-900/20',
    },
    {
      label: 'Patches Applied',
      value: '156',
      change: '+34 this week',
      icon: CheckCircle,
      color: 'text-green-400',
      bgColor: 'bg-green-900/20',
    },
    {
      label: 'Assets Protected',
      value: '2,347',
      change: '98.5% coverage',
      icon: Shield,
      color: 'text-blue-400',
      bgColor: 'bg-blue-900/20',
    },
  ];

  const recentVulnerabilities = [
    {
      id: 'CVE-2024-0001',
      title: 'Apache HTTP Server Remote Code Execution',
      severity: 'Critical',
      cvss: '9.8',
      assets: 45,
      status: 'Analyzing',
      color: 'text-red-400',
    },
    {
      id: 'CVE-2024-0002',
      title: 'OpenSSL Buffer Overflow Vulnerability',
      severity: 'High',
      cvss: '8.1',
      assets: 120,
      status: 'Patch Available',
      color: 'text-amber-400',
    },
    {
      id: 'CVE-2024-0003',
      title: 'Linux Kernel Privilege Escalation',
      severity: 'High',
      cvss: '7.8',
      assets: 89,
      status: 'Patching',
      color: 'text-amber-400',
    },
    {
      id: 'CVE-2024-0004',
      title: 'MySQL SQL Injection Vulnerability',
      severity: 'Medium',
      cvss: '6.5',
      assets: 23,
      status: 'Verified',
      color: 'text-yellow-400',
    },
  ];

  const patchingProgress = [
    { system: 'Production Web Servers', total: 45, patched: 38, percentage: 84 },
    { system: 'Database Servers', total: 23, patched: 21, percentage: 91 },
    { system: 'Application Servers', total: 67, patched: 52, percentage: 78 },
    { system: 'Development Environment', total: 89, patched: 89, percentage: 100 },
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold text-white mb-2">Security Dashboard</h2>
          <p className="text-gray-400">Real-time vulnerability management overview</p>
        </div>
        <div className="flex items-center space-x-2 text-sm text-gray-400">
          <TrendingUp className="w-4 h-4" />
          <span>Last updated: 2 minutes ago</span>
        </div>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {stats.map((stat, index) => {
          const Icon = stat.icon;
          return (
            <div key={index} className="bg-gray-800 rounded-xl p-6 border border-gray-700">
              <div className="flex items-center justify-between">
                <div className={`p-3 rounded-lg ${stat.bgColor}`}>
                  <Icon className={`w-6 h-6 ${stat.color}`} />
                </div>
                <div className="text-right">
                  <p className="text-2xl font-bold text-white">{stat.value}</p>
                  <p className="text-sm text-gray-400">{stat.change}</p>
                </div>
              </div>
              <p className="text-sm text-gray-300 mt-4">{stat.label}</p>
            </div>
          );
        })}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recent Vulnerabilities */}
        <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
          <div className="flex items-center justify-between mb-6">
            <h3 className="text-xl font-semibold text-white">Recent Vulnerabilities</h3>
            <button className="text-blue-400 hover:text-blue-300 text-sm">View All</button>
          </div>
          <div className="space-y-4">
            {recentVulnerabilities.map((vuln, index) => (
              <div key={index} className="flex items-center justify-between p-4 bg-gray-700 rounded-lg">
                <div className="flex-1">
                  <div className="flex items-center space-x-3">
                    <span className="text-sm font-mono text-gray-400">{vuln.id}</span>
                    <span className={`px-2 py-1 rounded text-xs font-medium ${vuln.color} bg-gray-600`}>
                      {vuln.severity}
                    </span>
                    <span className="text-xs text-gray-400">CVSS: {vuln.cvss}</span>
                  </div>
                  <p className="text-sm text-white mt-1">{vuln.title}</p>
                  <p className="text-xs text-gray-400 mt-1">{vuln.assets} assets affected</p>
                </div>
                <div className="text-right">
                  <span className="text-xs text-gray-400">{vuln.status}</span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Patching Progress */}
        <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
          <div className="flex items-center justify-between mb-6">
            <h3 className="text-xl font-semibold text-white">Patching Progress</h3>
            <button className="text-blue-400 hover:text-blue-300 text-sm">View Details</button>
          </div>
          <div className="space-y-4">
            {patchingProgress.map((system, index) => (
              <div key={index} className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-gray-300">{system.system}</span>
                  <span className="text-sm text-gray-400">{system.patched}/{system.total}</span>
                </div>
                <div className="w-full bg-gray-700 rounded-full h-2">
                  <div
                    className={`h-2 rounded-full ${
                      system.percentage >= 90 ? 'bg-green-500' : 
                      system.percentage >= 70 ? 'bg-yellow-500' : 'bg-red-500'
                    }`}
                    style={{ width: `${system.percentage}%` }}
                  ></div>
                </div>
                <div className="text-xs text-gray-400 text-right">{system.percentage}% complete</div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Quick Actions */}
      <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
        <h3 className="text-xl font-semibold text-white mb-4">Quick Actions</h3>
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <button className="flex items-center space-x-3 p-4 bg-blue-600 hover:bg-blue-700 rounded-lg transition-colors">
            <AlertTriangle className="w-5 h-5" />
            <span className="text-sm font-medium">Analyze CVE</span>
          </button>
          <button className="flex items-center space-x-3 p-4 bg-green-600 hover:bg-green-700 rounded-lg transition-colors">
            <CheckCircle className="w-5 h-5" />
            <span className="text-sm font-medium">Deploy Patches</span>
          </button>
          <button className="flex items-center space-x-3 p-4 bg-amber-600 hover:bg-amber-700 rounded-lg transition-colors">
            <FileText className="w-5 h-5" />
            <span className="text-sm font-medium">Generate Report</span>
          </button>
          <button className="flex items-center space-x-3 p-4 bg-purple-600 hover:bg-purple-700 rounded-lg transition-colors">
            <Users className="w-5 h-5" />
            <span className="text-sm font-medium">Contact SOC</span>
          </button>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
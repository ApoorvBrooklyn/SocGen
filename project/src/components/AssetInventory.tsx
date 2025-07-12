import React, { useState } from 'react';
import { Server, Monitor, Smartphone, Cloud, Shield, AlertTriangle, CheckCircle, Search, Filter } from 'lucide-react';

const AssetInventory = () => {
  const [selectedAsset, setSelectedAsset] = useState(null);
  const [filterType, setFilterType] = useState('all');
  const [searchTerm, setSearchTerm] = useState('');

  const assets = [
    {
      id: 'WEB-001',
      name: 'web-server-01.prod.local',
      type: 'Server',
      category: 'Web Server',
      os: 'Ubuntu 22.04 LTS',
      ip: '10.0.1.10',
      status: 'Online',
      criticalVulns: 3,
      highVulns: 8,
      mediumVulns: 12,
      lastScan: '2024-01-15 10:30',
      patchStatus: 'Outdated',
      riskScore: 85,
      owner: 'Web Operations Team',
      location: 'Data Center A',
      services: ['Apache HTTP Server 2.4.58', 'PHP 8.1', 'MySQL 8.0'],
      vulnerabilities: [
        { id: 'CVE-2024-0001', severity: 'Critical', description: 'Apache HTTP Server RCE' },
        { id: 'CVE-2024-0005', severity: 'High', description: 'PHP Remote Code Execution' },
        { id: 'CVE-2024-0012', severity: 'Medium', description: 'MySQL Privilege Escalation' }
      ]
    },
    {
      id: 'DB-001',
      name: 'database-primary.prod.local',
      type: 'Server',
      category: 'Database Server',
      os: 'CentOS 8',
      ip: '10.0.2.10',
      status: 'Online',
      criticalVulns: 1,
      highVulns: 3,
      mediumVulns: 5,
      lastScan: '2024-01-15 09:15',
      patchStatus: 'Current',
      riskScore: 45,
      owner: 'Database Team',
      location: 'Data Center B',
      services: ['PostgreSQL 14.9', 'Redis 7.0', 'nginx 1.20'],
      vulnerabilities: [
        { id: 'CVE-2024-0008', severity: 'Critical', description: 'PostgreSQL Buffer Overflow' },
        { id: 'CVE-2024-0015', severity: 'High', description: 'Redis Command Injection' }
      ]
    },
    {
      id: 'APP-001',
      name: 'app-server-01.prod.local',
      type: 'Server',
      category: 'Application Server',
      os: 'Windows Server 2019',
      ip: '10.0.3.10',
      status: 'Online',
      criticalVulns: 0,
      highVulns: 2,
      mediumVulns: 7,
      lastScan: '2024-01-15 08:45',
      patchStatus: 'Current',
      riskScore: 35,
      owner: 'Application Team',
      location: 'Cloud (AWS)',
      services: ['IIS 10.0', '.NET Framework 4.8', 'SQL Server 2019'],
      vulnerabilities: [
        { id: 'CVE-2024-0018', severity: 'High', description: 'IIS Path Traversal' },
        { id: 'CVE-2024-0022', severity: 'Medium', description: '.NET Framework DoS' }
      ]
    },
    {
      id: 'WKS-001',
      name: 'dev-workstation-01',
      type: 'Workstation',
      category: 'Development Machine',
      os: 'macOS 13.6',
      ip: '10.0.4.15',
      status: 'Online',
      criticalVulns: 0,
      highVulns: 1,
      mediumVulns: 3,
      lastScan: '2024-01-15 11:00',
      patchStatus: 'Current',
      riskScore: 25,
      owner: 'Development Team',
      location: 'Office Floor 3',
      services: ['Safari 17.0', 'Chrome 120', 'Node.js 18.19'],
      vulnerabilities: [
        { id: 'CVE-2024-0025', severity: 'High', description: 'Safari WebKit Vulnerability' }
      ]
    }
  ];

  const assetTypes = [
    { id: 'all', label: 'All Assets', count: assets.length },
    { id: 'server', label: 'Servers', count: assets.filter(a => a.type === 'Server').length },
    { id: 'workstation', label: 'Workstations', count: assets.filter(a => a.type === 'Workstation').length },
    { id: 'cloud', label: 'Cloud Resources', count: assets.filter(a => a.location.includes('Cloud')).length }
  ];

  const getStatusColor = (status) => {
    switch (status.toLowerCase()) {
      case 'online':
        return 'text-green-400 bg-green-900/20';
      case 'offline':
        return 'text-red-400 bg-red-900/20';
      case 'maintenance':
        return 'text-yellow-400 bg-yellow-900/20';
      default:
        return 'text-gray-400 bg-gray-900/20';
    }
  };

  const getPatchStatusColor = (status) => {
    switch (status.toLowerCase()) {
      case 'current':
        return 'text-green-400 bg-green-900/20';
      case 'outdated':
        return 'text-red-400 bg-red-900/20';
      case 'pending':
        return 'text-yellow-400 bg-yellow-900/20';
      default:
        return 'text-gray-400 bg-gray-900/20';
    }
  };

  const getRiskScoreColor = (score) => {
    if (score >= 80) return 'text-red-400';
    if (score >= 60) return 'text-amber-400';
    if (score >= 40) return 'text-yellow-400';
    return 'text-green-400';
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

  const getAssetIcon = (type) => {
    switch (type.toLowerCase()) {
      case 'server':
        return Server;
      case 'workstation':
        return Monitor;
      case 'mobile':
        return Smartphone;
      case 'cloud':
        return Cloud;
      default:
        return Monitor;
    }
  };

  const filteredAssets = assets.filter(asset => {
    const matchesType = filterType === 'all' || 
      asset.type.toLowerCase() === filterType ||
      (filterType === 'cloud' && asset.location.includes('Cloud'));
    const matchesSearch = searchTerm === '' || 
      asset.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      asset.ip.includes(searchTerm) ||
      asset.category.toLowerCase().includes(searchTerm.toLowerCase());
    return matchesType && matchesSearch;
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold text-white mb-2">Asset Inventory</h2>
          <p className="text-gray-400">Comprehensive asset management and vulnerability tracking</p>
        </div>
        <div className="flex items-center space-x-4">
          <button className="px-4 py-2 bg-green-600 hover:bg-green-700 rounded-lg text-white text-sm font-medium transition-colors">
            Add Asset
          </button>
          <button className="px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg text-white text-sm font-medium transition-colors">
            Scan Network
          </button>
        </div>
      </div>

      {/* Summary Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-2xl font-bold text-white">{assets.length}</p>
              <p className="text-sm text-gray-400">Total Assets</p>
            </div>
            <Server className="w-8 h-8 text-blue-400" />
          </div>
        </div>
        <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-2xl font-bold text-red-400">{assets.reduce((sum, a) => sum + a.criticalVulns, 0)}</p>
              <p className="text-sm text-gray-400">Critical Vulnerabilities</p>
            </div>
            <AlertTriangle className="w-8 h-8 text-red-400" />
          </div>
        </div>
        <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-2xl font-bold text-green-400">{assets.filter(a => a.patchStatus === 'Current').length}</p>
              <p className="text-sm text-gray-400">Up to Date</p>
            </div>
            <CheckCircle className="w-8 h-8 text-green-400" />
          </div>
        </div>
        <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-2xl font-bold text-yellow-400">{Math.round(assets.reduce((sum, a) => sum + a.riskScore, 0) / assets.length)}</p>
              <p className="text-sm text-gray-400">Avg Risk Score</p>
            </div>
            <Shield className="w-8 h-8 text-yellow-400" />
          </div>
        </div>
      </div>

      {/* Filters and Search */}
      <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
        <div className="flex items-center space-x-4 mb-4">
          <div className="flex items-center space-x-2">
            <Search className="w-5 h-5 text-gray-400" />
            <input
              type="text"
              placeholder="Search assets by name, IP, or category..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-64 px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:border-blue-500"
            />
          </div>
          <div className="flex items-center space-x-2">
            <Filter className="w-5 h-5 text-gray-400" />
            <span className="text-sm text-gray-400">Filter by:</span>
          </div>
        </div>
        <div className="flex space-x-2">
          {assetTypes.map((type) => (
            <button
              key={type.id}
              onClick={() => setFilterType(type.id)}
              className={`px-3 py-1 rounded-full text-sm font-medium transition-colors ${
                filterType === type.id
                  ? 'bg-blue-600 text-white'
                  : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
              }`}
            >
              {type.label} ({type.count})
            </button>
          ))}
        </div>
      </div>

      {/* Assets List */}
      <div className="space-y-4">
        {filteredAssets.map((asset) => {
          const AssetIcon = getAssetIcon(asset.type);
          return (
            <div key={asset.id} className="bg-gray-800 rounded-xl p-6 border border-gray-700">
              <div className="flex items-start justify-between">
                <div className="flex items-start space-x-4 flex-1">
                  <div className="p-3 bg-gray-700 rounded-lg">
                    <AssetIcon className="w-6 h-6 text-blue-400" />
                  </div>
                  <div className="flex-1">
                    <div className="flex items-center space-x-4 mb-2">
                      <h3 className="text-lg font-semibold text-white">{asset.name}</h3>
                      <span className={`px-2 py-1 rounded text-xs font-medium ${getStatusColor(asset.status)}`}>
                        {asset.status}
                      </span>
                      <span className={`px-2 py-1 rounded text-xs font-medium ${getPatchStatusColor(asset.patchStatus)}`}>
                        {asset.patchStatus}
                      </span>
                    </div>
                    
                    <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-4">
                      <div>
                        <span className="text-xs text-gray-400">Asset ID</span>
                        <p className="text-sm font-mono text-white">{asset.id}</p>
                      </div>
                      <div>
                        <span className="text-xs text-gray-400">IP Address</span>
                        <p className="text-sm font-mono text-white">{asset.ip}</p>
                      </div>
                      <div>
                        <span className="text-xs text-gray-400">Operating System</span>
                        <p className="text-sm text-white">{asset.os}</p>
                      </div>
                      <div>
                        <span className="text-xs text-gray-400">Risk Score</span>
                        <p className={`text-sm font-bold ${getRiskScoreColor(asset.riskScore)}`}>{asset.riskScore}</p>
                      </div>
                    </div>

                    <div className="flex items-center space-x-6 mb-4">
                      <div className="flex items-center space-x-2">
                        <span className="text-xs text-gray-400">Critical:</span>
                        <span className="text-sm font-bold text-red-400">{asset.criticalVulns}</span>
                      </div>
                      <div className="flex items-center space-x-2">
                        <span className="text-xs text-gray-400">High:</span>
                        <span className="text-sm font-bold text-amber-400">{asset.highVulns}</span>
                      </div>
                      <div className="flex items-center space-x-2">
                        <span className="text-xs text-gray-400">Medium:</span>
                        <span className="text-sm font-bold text-yellow-400">{asset.mediumVulns}</span>
                      </div>
                      <div className="flex items-center space-x-2">
                        <span className="text-xs text-gray-400">Last Scan:</span>
                        <span className="text-sm text-white">{asset.lastScan}</span>
                      </div>
                    </div>

                    <div className="flex items-center space-x-4 text-sm text-gray-400">
                      <span>Owner: {asset.owner}</span>
                      <span>Location: {asset.location}</span>
                      <span>Category: {asset.category}</span>
                    </div>
                  </div>
                </div>

                <div className="flex flex-col space-y-2 ml-6">
                  <button
                    onClick={() => setSelectedAsset(asset)}
                    className="px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg text-white text-sm font-medium transition-colors"
                  >
                    View Details
                  </button>
                  <button className="px-4 py-2 bg-green-600 hover:bg-green-700 rounded-lg text-white text-sm font-medium transition-colors">
                    Scan Now
                  </button>
                  <button className="px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-white text-sm font-medium transition-colors">
                    Edit Asset
                  </button>
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Asset Detail Modal */}
      {selectedAsset && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
          <div className="bg-gray-800 rounded-xl max-w-4xl w-full max-h-[90vh] overflow-y-auto">
            <div className="p-6 border-b border-gray-700">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-2xl font-bold text-white">{selectedAsset.name}</h3>
                  <p className="text-gray-400 mt-1">{selectedAsset.category} • {selectedAsset.id}</p>
                </div>
                <button
                  onClick={() => setSelectedAsset(null)}
                  className="text-gray-400 hover:text-white text-xl"
                >
                  ×
                </button>
              </div>
            </div>

            <div className="p-6 space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <h4 className="text-lg font-semibold text-white mb-3">Asset Information</h4>
                  <div className="space-y-3">
                    <div className="flex justify-between">
                      <span className="text-gray-400">Asset ID:</span>
                      <span className="text-white font-mono">{selectedAsset.id}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">IP Address:</span>
                      <span className="text-white font-mono">{selectedAsset.ip}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">Operating System:</span>
                      <span className="text-white">{selectedAsset.os}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">Status:</span>
                      <span className={`px-2 py-1 rounded text-xs font-medium ${getStatusColor(selectedAsset.status)}`}>
                        {selectedAsset.status}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">Patch Status:</span>
                      <span className={`px-2 py-1 rounded text-xs font-medium ${getPatchStatusColor(selectedAsset.patchStatus)}`}>
                        {selectedAsset.patchStatus}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">Risk Score:</span>
                      <span className={`font-bold ${getRiskScoreColor(selectedAsset.riskScore)}`}>
                        {selectedAsset.riskScore}
                      </span>
                    </div>
                  </div>
                </div>

                <div>
                  <h4 className="text-lg font-semibold text-white mb-3">Vulnerability Summary</h4>
                  <div className="space-y-3">
                    <div className="flex justify-between">
                      <span className="text-gray-400">Critical:</span>
                      <span className="text-red-400 font-bold">{selectedAsset.criticalVulns}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">High:</span>
                      <span className="text-amber-400 font-bold">{selectedAsset.highVulns}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">Medium:</span>
                      <span className="text-yellow-400 font-bold">{selectedAsset.mediumVulns}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">Last Scan:</span>
                      <span className="text-white">{selectedAsset.lastScan}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">Owner:</span>
                      <span className="text-white">{selectedAsset.owner}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">Location:</span>
                      <span className="text-white">{selectedAsset.location}</span>
                    </div>
                  </div>
                </div>
              </div>

              <div>
                <h4 className="text-lg font-semibold text-white mb-3">Installed Services</h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                  {selectedAsset.services.map((service, index) => (
                    <div key={index} className="p-3 bg-gray-700 rounded-lg">
                      <span className="text-gray-300">{service}</span>
                    </div>
                  ))}
                </div>
              </div>

              <div>
                <h4 className="text-lg font-semibold text-white mb-3">Active Vulnerabilities</h4>
                <div className="space-y-3">
                  {selectedAsset.vulnerabilities.map((vuln, index) => (
                    <div key={index} className="p-4 bg-gray-700 rounded-lg">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-3">
                          <span className="text-sm font-mono text-gray-400">{vuln.id}</span>
                          <span className={`px-2 py-1 rounded text-xs font-medium ${getSeverityColor(vuln.severity)}`}>
                            {vuln.severity}
                          </span>
                        </div>
                        <button className="text-blue-400 hover:text-blue-300 text-sm">
                          View Details
                        </button>
                      </div>
                      <p className="text-sm text-gray-300 mt-2">{vuln.description}</p>
                    </div>
                  ))}
                </div>
              </div>

              <div className="flex items-center space-x-4 pt-4 border-t border-gray-700">
                <button className="px-6 py-2 bg-green-600 hover:bg-green-700 rounded-lg text-white font-medium transition-colors">
                  Scan Asset
                </button>
                <button className="px-6 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg text-white font-medium transition-colors">
                  Generate Report
                </button>
                <button className="px-6 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-white font-medium transition-colors">
                  Edit Asset
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default AssetInventory;
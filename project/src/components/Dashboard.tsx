import React, { useState, useEffect } from 'react';
import { Shield, AlertTriangle, CheckCircle, Clock, Users, Server, TrendingUp, Activity, Wifi, WifiOff, Loader2, RefreshCw, RotateCcw } from 'lucide-react';
import { testBackendConnection, BackendStatus } from '../utils/backendTest';
import { cveAPI, scannerAPI, patchAPI, llmAPI, systemAPI } from '../services/api';

const Dashboard = () => {
  const [backendStatus, setBackendStatus] = useState<BackendStatus | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isResetting, setIsResetting] = useState(false);
  const [stats, setStats] = useState({
    totalCVEs: 0,
    activeScans: 0,
    pendingPatches: 0,
    riskScore: 0,
  });

  useEffect(() => {
    loadDashboardData();

    // Auto-refresh the dashboard periodically for near real-time updates
    const interval = setInterval(() => {
      loadDashboardData(); // Re-check backend status and refresh stats
    }, 5000); // every 5 seconds – adjust as needed

    return () => clearInterval(interval); // Clean up on unmount
  }, []);

  const handleSystemReset = async () => {
    if (!confirm('This will clear all vulnerability data while preserving your session data (chat history, reports, tickets). Continue?')) {
      return;
    }
    
    try {
      setIsResetting(true);
      const response = await systemAPI.resetSystem();
      
      if (response.status === 'success') {
        alert('System reset completed! Vulnerability data cleared, session data preserved.');
        // Reload dashboard data to reflect the reset
        await loadDashboardData();
      } else {
        alert('System reset failed. Please try again.');
      }
    } catch (error) {
      console.error('System reset error:', error);
      alert('System reset failed. Please check the console for details.');
    } finally {
      setIsResetting(false);
    }
  };

  const loadDashboardData = async () => {
    try {
      setIsLoading(true);
      
      // Test backend connection
      const status = await testBackendConnection();
      setBackendStatus(status);
      
      if (status.isConnected) {
        // Load real data from backend
        await loadStats();
      }
    } catch (error) {
      console.error('Error loading dashboard data:', error);
      setBackendStatus({
        isConnected: false,
        status: 'error',
        services: { llm_service: 'unknown', simulator: 'unknown' },
        error: 'Failed to load dashboard data',
      });
    } finally {
      setIsLoading(false);
    }
  };

  const loadStats = async () => {
    try {
      // Load CVE data
      const cves = await cveAPI.getCVEs();
      
      // Load scan data
      const scans = await scannerAPI.getAllScans();
      
      // Load patch data
      const patches = await patchAPI.getPatchHistory();
      
      // Calculate stats
      const totalCVEs = cves?.length || 0;
      const activeScans = scans?.filter((scan: any) => scan.status === 'running').length || 0;
      const pendingPatches = patches?.filter((patch: any) => patch.status === 'pending').length || 0;
      
      // Calculate risk score based on CVE severity
      const criticalCVEs = cves?.filter((cve: any) => cve.severity === 'Critical').length || 0;
      const highCVEs = cves?.filter((cve: any) => cve.severity === 'High').length || 0;
      const riskScore = Math.min(100, (criticalCVEs * 25) + (highCVEs * 15));
      
      setStats({
        totalCVEs,
        activeScans,
        pendingPatches,
        riskScore,
      });
    } catch (error) {
      console.error('Error loading stats:', error);
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'healthy':
        return 'text-green-400';
      case 'degraded':
        return 'text-yellow-400';
      case 'unhealthy':
      case 'error':
        return 'text-red-400';
      default:
        return 'text-gray-400';
    }
  };

  const getServiceStatusIcon = (status: string) => {
    switch (status) {
      case 'healthy':
        return <CheckCircle className="w-4 h-4 text-green-400" />;
      case 'unhealthy':
        return <AlertTriangle className="w-4 h-4 text-red-400" />;
      default:
        return <Clock className="w-4 h-4 text-gray-400" />;
    }
  };

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="w-8 h-8 animate-spin text-blue-400" />
        <span className="ml-2 text-gray-300">Loading dashboard...</span>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Security Dashboard</h1>
          <p className="text-gray-400">Real-time security posture and system status</p>
        </div>
        <div className="flex items-center space-x-4">
          <button
            onClick={loadDashboardData}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg text-white text-sm font-medium transition-colors"
          >
            Refresh
          </button>
          <button
            onClick={handleSystemReset}
            disabled={isResetting}
            className="px-4 py-2 bg-red-600 hover:bg-red-700 disabled:bg-red-800 rounded-lg text-white text-sm font-medium transition-colors flex items-center space-x-2"
          >
            {isResetting ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <RotateCcw className="w-4 h-4" />
            )}
            <span>{isResetting ? 'Resetting...' : 'Reset System'}</span>
          </button>
        </div>
      </div>

      {/* Backend Status */}
      {backendStatus && (
        <div className="bg-gray-800 rounded-lg p-6">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-white">System Status</h2>
            <div className="flex items-center space-x-2">
              {backendStatus.isConnected ? (
                <Wifi className="w-5 h-5 text-green-400" />
              ) : (
                <WifiOff className="w-5 h-5 text-red-400" />
              )}
              <span className={`text-sm font-medium ${getStatusColor(backendStatus.status)}`}>
                {backendStatus.isConnected ? 'Connected' : 'Disconnected'}
              </span>
            </div>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="bg-gray-700 rounded-lg p-4">
              <div className="flex items-center space-x-2 mb-2">
                {getServiceStatusIcon(backendStatus.services.llm_service)}
                <span className="text-white font-medium">LLM Service</span>
              </div>
              <p className="text-sm text-gray-400">
                {backendStatus.services.llm_service === 'healthy' ? 'AI Assistant Ready' : 'Service Unavailable'}
              </p>
            </div>
            
            <div className="bg-gray-700 rounded-lg p-4">
              <div className="flex items-center space-x-2 mb-2">
                {getServiceStatusIcon(backendStatus.services.simulator)}
                <span className="text-white font-medium">Simulator</span>
              </div>
              <p className="text-sm text-gray-400">
                {backendStatus.services.simulator === 'healthy' ? 'Simulation Ready' : 'Service Unavailable'}
              </p>
            </div>
            
            <div className="bg-gray-700 rounded-lg p-4">
              <div className="flex items-center space-x-2 mb-2">
                <Activity className="w-4 h-4 text-blue-400" />
                <span className="text-white font-medium">Overall Status</span>
              </div>
              <p className={`text-sm font-medium ${getStatusColor(backendStatus.status)}`}>
                {backendStatus.status.charAt(0).toUpperCase() + backendStatus.status.slice(1)}
              </p>
            </div>
          </div>
          
          {backendStatus.error && (
            <div className="mt-4 p-3 bg-red-900/20 border border-red-700 rounded-lg">
              <p className="text-red-400 text-sm">{backendStatus.error}</p>
            </div>
          )}
        </div>
      )}

      {/* Security Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <div className="bg-gray-800 rounded-lg p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Total CVEs</p>
              <p className="text-2xl font-bold text-white">{stats.totalCVEs}</p>
            </div>
            <AlertTriangle className="w-8 h-8 text-amber-400" />
          </div>
          <div className="mt-4">
            <div className="flex items-center text-sm">
              <TrendingUp className="w-4 h-4 text-green-400 mr-1" />
              <span className="text-green-400">+12%</span>
              <span className="text-gray-400 ml-1">from last week</span>
            </div>
          </div>
        </div>

        <div className="bg-gray-800 rounded-lg p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Active Scans</p>
              <p className="text-2xl font-bold text-white">{stats.activeScans}</p>
            </div>
            <Activity className="w-8 h-8 text-blue-400" />
          </div>
          <div className="mt-4">
            <div className="flex items-center text-sm">
              <Clock className="w-4 h-4 text-blue-400 mr-1" />
              <span className="text-blue-400">Running</span>
              <span className="text-gray-400 ml-1">vulnerability scans</span>
            </div>
          </div>
        </div>

        <div className="bg-gray-800 rounded-lg p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Pending Patches</p>
              <p className="text-2xl font-bold text-white">{stats.pendingPatches}</p>
            </div>
            <CheckCircle className="w-8 h-8 text-green-400" />
          </div>
          <div className="mt-4">
            <div className="flex items-center text-sm">
              <Clock className="w-4 h-4 text-yellow-400 mr-1" />
              <span className="text-yellow-400">Awaiting</span>
              <span className="text-gray-400 ml-1">deployment</span>
            </div>
          </div>
        </div>

        <div className="bg-gray-800 rounded-lg p-6">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-gray-400 text-sm">Risk Score</p>
              <p className="text-2xl font-bold text-white">{stats.riskScore}/100</p>
            </div>
            <Shield className="w-8 h-8 text-red-400" />
          </div>
          <div className="mt-4">
            <div className="w-full bg-gray-700 rounded-full h-2">
              <div 
                className={`h-2 rounded-full ${
                  stats.riskScore > 70 ? 'bg-red-400' : 
                  stats.riskScore > 40 ? 'bg-yellow-400' : 'bg-green-400'
                }`}
                style={{ width: `${stats.riskScore}%` }}
              ></div>
            </div>
            <p className="text-xs text-gray-400 mt-1">
              {stats.riskScore > 70 ? 'High Risk' : 
               stats.riskScore > 40 ? 'Medium Risk' : 'Low Risk'}
            </p>
          </div>
        </div>
      </div>

      {/* Quick Actions */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div className="bg-gray-800 rounded-lg p-6">
          <h3 className="text-lg font-semibold text-white mb-4">Quick Actions</h3>
          <div className="space-y-3">
            <button className="w-full flex items-center space-x-3 p-3 bg-blue-600 hover:bg-blue-700 rounded-lg text-white transition-colors">
              <AlertTriangle className="w-5 h-5" />
              <span>Start Vulnerability Scan</span>
            </button>
            <button className="w-full flex items-center space-x-3 p-3 bg-green-600 hover:bg-green-700 rounded-lg text-white transition-colors">
              <CheckCircle className="w-5 h-5" />
              <span>Deploy Pending Patches</span>
            </button>
            <button className="w-full flex items-center space-x-3 p-3 bg-purple-600 hover:bg-purple-700 rounded-lg text-white transition-colors">
              <Users className="w-5 h-5" />
              <span>Generate Security Report</span>
            </button>
          </div>
        </div>

        <div className="bg-gray-800 rounded-lg p-6">
          <h3 className="text-lg font-semibold text-white mb-4">Recent Activity</h3>
          <div className="space-y-3">
            <div className="flex items-center space-x-3 p-3 bg-gray-700 rounded-lg">
              <div className="w-2 h-2 bg-green-400 rounded-full"></div>
              <div className="flex-1">
                <p className="text-white text-sm">CVE-2024-1234 patched successfully</p>
                <p className="text-gray-400 text-xs">2 hours ago</p>
              </div>
            </div>
            <div className="flex items-center space-x-3 p-3 bg-gray-700 rounded-lg">
              <div className="w-2 h-2 bg-yellow-400 rounded-full"></div>
              <div className="flex-1">
                <p className="text-white text-sm">New high-severity vulnerability detected</p>
                <p className="text-gray-400 text-xs">4 hours ago</p>
              </div>
            </div>
            <div className="flex items-center space-x-3 p-3 bg-gray-700 rounded-lg">
              <div className="w-2 h-2 bg-blue-400 rounded-full"></div>
              <div className="flex-1">
                <p className="text-white text-sm">Vulnerability scan completed</p>
                <p className="text-gray-400 text-xs">6 hours ago</p>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* System Health */}
      <div className="bg-gray-800 rounded-lg p-6">
        <h3 className="text-lg font-semibold text-white mb-4">System Health</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="flex items-center space-x-3 p-3 bg-gray-700 rounded-lg">
            <Server className="w-5 h-5 text-green-400" />
            <div>
              <p className="text-white text-sm">Database</p>
              <p className="text-green-400 text-xs">Healthy</p>
            </div>
          </div>
          <div className="flex items-center space-x-3 p-3 bg-gray-700 rounded-lg">
            <Shield className="w-5 h-5 text-green-400" />
            <div>
              <p className="text-white text-sm">API Gateway</p>
              <p className="text-green-400 text-xs">Online</p>
            </div>
          </div>
          <div className="flex items-center space-x-3 p-3 bg-gray-700 rounded-lg">
            <Activity className="w-5 h-5 text-green-400" />
            <div>
              <p className="text-white text-sm">Monitoring</p>
              <p className="text-green-400 text-xs">Active</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
import React, { useState, useEffect } from 'react';
import { AlertTriangle, TrendingUp, Clock, Target, Filter, Bot, RefreshCw, Loader2, Zap, Shield, Eye, Activity, TrendingDown, ChevronUp, ChevronDown, Minus, Bell } from 'lucide-react';
import { riskAPI } from '../services/api';

interface VulnerabilityPriority {
  id: string;
  title: string;
  severity: string;
  cvss_score: number;
  priority_score: number;
  priority_level: string;
  priority_num: number;
  created_at: string;
  exploit_available: boolean;
  affected_assets: string[];
  business_impact: string;
  remediation_complexity: string;
  exposure: string;
}

interface RiskAssessment {
  risk_score: number;
  risk_level: string;
  base_risk: number;
  threat_multiplier: number;
  recent_activity_multiplier: number;
  vulnerability_breakdown: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    total: number;
  };
  active_threats: number;
  scan_status: string;
  timestamp: string;
}

const RiskPrioritization = () => {
  const [selectedFilter, setSelectedFilter] = useState('all');
  const [riskAssessment, setRiskAssessment] = useState<RiskAssessment | null>(null);
  const [vulnerabilities, setVulnerabilities] = useState<VulnerabilityPriority[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdated, setLastUpdated] = useState<string | null>(null);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [monitoringStatus, setMonitoringStatus] = useState<any>(null);
  const [isStartingMonitoring, setIsStartingMonitoring] = useState(false);
  const [previousRiskScore, setPreviousRiskScore] = useState<number | null>(null);
  const [previousVulnCount, setPreviousVulnCount] = useState<number | null>(null);
  const [previousThreatCount, setPreviousThreatsCount] = useState<number | null>(null);
  const [riskTrend, setRiskTrend] = useState<'up' | 'down' | 'stable'>('stable');
  const [newThreatsDetected, setNewThreatsDetected] = useState(false);
  const [recentActivity, setRecentActivity] = useState<string[]>([]);
  const [instantThreats, setInstantThreats] = useState<any[]>([]);
  const [criticalAlertActive, setCriticalAlertActive] = useState(false);

  // Load real-time risk data
  useEffect(() => {
    loadRealTimeRiskData();
    loadMonitoringStatus();
    
    // Set up auto-refresh if enabled
    if (autoRefresh) {
      const mainInterval = setInterval(() => {
        loadRealTimeRiskData();
        loadMonitoringStatus();
      }, 3000); // Every 3 seconds for near real-time updates
      
      // Separate faster interval for instant threats
      const instantInterval = setInterval(() => {
        checkInstantThreats();
      }, 1000); // Every 1 second for instant threat detection
      
      return () => {
        clearInterval(mainInterval);
        clearInterval(instantInterval);
      };
    }
  }, [autoRefresh]);

  const loadRealTimeRiskData = async () => {
    try {
      setIsRefreshing(true);
      setError(null);
      
      const response = await riskAPI.getRealTimeRiskAssessment();
      
      if (response) {
        const newRiskAssessment = response.risk_assessment;
        const newVulnerabilities = response.priorities || [];
        
        // Track changes for real-time indicators
        if (riskAssessment) {
          const currentRiskScore = newRiskAssessment.risk_score;
          const currentVulnCount = newRiskAssessment.vulnerability_breakdown?.total || 0;
          const currentThreatCount = newRiskAssessment.active_threats || 0;
          
          // Detect risk trend
          if (previousRiskScore !== null) {
            if (currentRiskScore > previousRiskScore + 5) {
              setRiskTrend('up');
              setRecentActivity(prev => [`Risk increased to ${currentRiskScore.toFixed(1)}`, ...prev.slice(0, 4)]);
            } else if (currentRiskScore < previousRiskScore - 5) {
              setRiskTrend('down');
              setRecentActivity(prev => [`Risk decreased to ${currentRiskScore.toFixed(1)}`, ...prev.slice(0, 4)]);
            } else {
              setRiskTrend('stable');
            }
          }
          
          // Detect new threats
          if (previousThreatCount !== null && currentThreatCount > previousThreatCount) {
            setNewThreatsDetected(true);
            setRecentActivity(prev => [`${currentThreatCount - previousThreatCount} new threat(s) detected`, ...prev.slice(0, 4)]);
            // Clear the indicator after 5 seconds
            setTimeout(() => setNewThreatsDetected(false), 5000);
          }
          
          // Detect new vulnerabilities
          if (previousVulnCount !== null && currentVulnCount > previousVulnCount) {
            setRecentActivity(prev => [`${currentVulnCount - previousVulnCount} new vulnerability(ies) found`, ...prev.slice(0, 4)]);
          }
          
          // Update previous values
          setPreviousRiskScore(currentRiskScore);
          setPreviousVulnCount(currentVulnCount);
          setPreviousThreatsCount(currentThreatCount);
        } else {
          // First load
          setPreviousRiskScore(newRiskAssessment.risk_score);
          setPreviousVulnCount(newRiskAssessment.vulnerability_breakdown?.total || 0);
          setPreviousThreatsCount(newRiskAssessment.active_threats || 0);
        }
        
        setRiskAssessment(newRiskAssessment);
        setVulnerabilities(newVulnerabilities);
        setLastUpdated(response.last_updated);
      }
    } catch (err) {
      console.error('Error loading real-time risk data:', err);
      setError('Failed to load real-time risk data. Please try again.');
    } finally {
      setIsRefreshing(false);
    }
  };

  const handleRecalculatePriorities = async () => {
    try {
      setIsLoading(true);
      setError(null);
      
      const response = await riskAPI.forceRecalculatePriorities();
      
      if (response && response.assessment) {
        setRiskAssessment(response.assessment.risk_assessment);
        setVulnerabilities(response.assessment.priorities || []);
        setLastUpdated(response.timestamp);
      }
    } catch (err) {
      console.error('Error recalculating priorities:', err);
      setError('Failed to recalculate priorities. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  const loadMonitoringStatus = async () => {
    try {
      const status = await riskAPI.getRiskMonitoringStatus();
      setMonitoringStatus(status);
    } catch (err) {
      console.error('Error loading monitoring status:', err);
    }
  };

  const handleStartMonitoring = async () => {
    try {
      setIsStartingMonitoring(true);
      setError(null);
      
      const response = await riskAPI.startRiskMonitoring();
      
      if (response.status === 'started' || response.status === 'already_running') {
        await loadMonitoringStatus();
      }
    } catch (err) {
      console.error('Error starting monitoring:', err);
      setError('Failed to start monitoring. Please try again.');
    } finally {
      setIsStartingMonitoring(false);
    }
  };

  const handleStopMonitoring = async () => {
    try {
      setError(null);
      
      const response = await riskAPI.stopRiskMonitoring();
      
      if (response.status === 'stopped') {
        await loadMonitoringStatus();
      }
    } catch (err) {
      console.error('Error stopping monitoring:', err);
      setError('Failed to stop monitoring. Please try again.');
    }
  };

  const handleManualRiskCheck = async () => {
    try {
      setIsRefreshing(true);
      setError(null);
      
      const response = await riskAPI.manualRiskCheck();
      
      if (response.changes_detected) {
        await loadRealTimeRiskData();
      }
    } catch (err) {
      console.error('Error in manual risk check:', err);
      setError('Failed to perform manual risk check. Please try again.');
    } finally {
      setIsRefreshing(false);
    }
  };

  const checkInstantThreats = async () => {
    try {
      const response = await riskAPI.getInstantThreats();
      
      if (response && response.instant_threats.length > 0) {
        setInstantThreats(response.instant_threats);
        
        // Check for critical threats
        if (response.has_critical) {
          setCriticalAlertActive(true);
          // Auto-clear critical alert after 10 seconds
          setTimeout(() => setCriticalAlertActive(false), 10000);
        }
        
        // Add to recent activity
        const newActivities = response.instant_threats.slice(0, 3).map((threat: any) => 
          `${threat.type}: ${threat.description} (${threat.severity})`
        );
        
        if (newActivities.length > 0) {
          setRecentActivity(prev => [...newActivities, ...prev.slice(0, 2)]);
        }
      }
    } catch (err) {
      // Silent fail for instant threats to avoid spam
      console.debug('Error checking instant threats:', err);
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

  const getRiskScoreColor = (score: number) => {
    if (score >= 90) return 'text-red-400';
    if (score >= 70) return 'text-amber-400';
    if (score >= 50) return 'text-yellow-400';
    return 'text-green-400';
  };

  const getPriorityColor = (priority: number) => {
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

  const getRiskLevelColor = (level: string) => {
    switch (level.toLowerCase()) {
      case 'critical':
        return 'text-red-400';
      case 'high':
        return 'text-amber-400';
      case 'medium':
        return 'text-yellow-400';
      case 'low':
        return 'text-green-400';
      default:
        return 'text-gray-400';
    }
  };

  const getTrendIcon = (trend: 'up' | 'down' | 'stable') => {
    switch (trend) {
      case 'up':
        return <ChevronUp className="w-4 h-4 text-red-400 animate-pulse" />;
      case 'down':
        return <ChevronDown className="w-4 h-4 text-green-400 animate-pulse" />;
      default:
        return <Minus className="w-4 h-4 text-gray-400" />;
    }
  };

  const getTrendColor = (trend: 'up' | 'down' | 'stable') => {
    switch (trend) {
      case 'up':
        return 'text-red-400';
      case 'down':
        return 'text-green-400';
      default:
        return 'text-gray-400';
    }
  };

  const filteredVulnerabilities = vulnerabilities.filter(vuln => {
    switch (selectedFilter) {
      case 'critical':
        return vuln.priority_num === 1;
      case 'high':
        return vuln.priority_num <= 2;
      case 'exploit':
        return vuln.exploit_available;
      case 'public':
        return vuln.exposure === 'Public-facing';
      default:
        return true;
    }
  });

  const filters = [
    { id: 'all', label: 'All Vulnerabilities' },
    { id: 'critical', label: 'Critical Priority' },
    { id: 'high', label: 'High Priority' },
    { id: 'exploit', label: 'Exploit Available' },
    { id: 'public', label: 'Public Facing' }
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold text-white mb-2">Risk Prioritization</h2>
          <p className="text-gray-400">AI-powered vulnerability risk assessment and prioritization</p>
          {lastUpdated && (
            <p className="text-sm text-gray-500 mt-1">
              Last updated: {new Date(lastUpdated).toLocaleTimeString()}
            </p>
          )}
        </div>
        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-2 text-sm text-gray-400">
            <Bot className="w-4 h-4" />
            <span>LLM-Enhanced Scoring</span>
          </div>
          <div className="flex items-center space-x-2">
            <button
              onClick={() => setAutoRefresh(!autoRefresh)}
              className={`px-3 py-1 rounded text-sm font-medium transition-colors ${
                autoRefresh ? 'bg-green-600 text-white' : 'bg-gray-600 text-gray-300'
              }`}
            >
              {autoRefresh ? 'Auto-Refresh ON' : 'Auto-Refresh OFF'}
            </button>
            <button
              onClick={handleRecalculatePriorities}
              disabled={isLoading}
              className="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-blue-800 rounded-lg text-white text-sm font-medium transition-colors flex items-center space-x-2"
            >
              {isLoading ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  <span>Recalculating...</span>
                </>
              ) : (
                <>
                  <RefreshCw className="w-4 h-4" />
                  <span>Recalculate Priorities</span>
                </>
              )}
            </button>
          </div>
        </div>
      </div>

      {/* Critical Alert Banner */}
      {criticalAlertActive && (
        <div className="bg-red-600 border border-red-400 rounded-lg p-4 animate-pulse">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <AlertTriangle className="w-6 h-6 text-white animate-bounce" />
              <div>
                <p className="text-white font-bold text-lg">CRITICAL THREATS DETECTED!</p>
                <p className="text-red-100 text-sm">Immediate attention required - Check instant threats below</p>
              </div>
            </div>
            <button
              onClick={() => setCriticalAlertActive(false)}
              className="text-white hover:text-red-200 text-2xl font-bold"
            >
              ×
            </button>
          </div>
        </div>
      )}

      {/* Error Message */}
      {error && (
        <div className="bg-red-900/20 border border-red-500 rounded-lg p-4">
          <div className="flex items-center space-x-2">
            <AlertTriangle className="w-5 h-5 text-red-400" />
            <p className="text-red-400">{error}</p>
          </div>
        </div>
      )}

      {/* Real-time Status Indicator */}
      <div className="flex items-center justify-between bg-gray-800 rounded-lg p-4">
        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-2">
            <div className={`w-3 h-3 rounded-full ${isRefreshing ? 'bg-blue-400 animate-pulse' : 'bg-green-400'}`}></div>
            <span className="text-sm text-gray-300">
              {isRefreshing ? 'Refreshing...' : 'Live Data'}
            </span>
            <span className="text-xs text-gray-500">(3s risk / 1s threats)</span>
          </div>
          {riskAssessment && (
            <div className="flex items-center space-x-2 text-sm text-gray-400">
              <Activity className="w-4 h-4" />
              <span>Risk Level: </span>
              <span className={`font-medium ${getRiskLevelColor(riskAssessment.risk_level)} flex items-center space-x-1`}>
                <span>{riskAssessment.risk_level.toUpperCase()}</span>
                {getTrendIcon(riskTrend)}
              </span>
            </div>
          )}
          {newThreatsDetected && (
            <div className="flex items-center space-x-2 bg-red-900/30 px-2 py-1 rounded-lg animate-pulse">
              <Bell className="w-4 h-4 text-red-400" />
              <span className="text-red-400 text-sm font-medium">New Threats!</span>
            </div>
          )}
        </div>
        <div className="flex items-center space-x-4 text-sm text-gray-400">
          <div className="flex items-center space-x-1">
            <Shield className={`w-4 h-4 ${newThreatsDetected ? 'text-red-400 animate-pulse' : ''}`} />
            <span className={newThreatsDetected ? 'text-red-400 font-medium' : ''}>
              Active Threats: {riskAssessment?.active_threats || 0}
            </span>
          </div>
          <div className="flex items-center space-x-1">
            <Eye className="w-4 h-4" />
            <span>Total Vulnerabilities: {riskAssessment?.vulnerability_breakdown?.total || 0}</span>
          </div>
        </div>
      </div>

      {/* Monitoring Control */}
      <div className="bg-gray-800 rounded-lg p-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-4">
            <div className="flex items-center space-x-2">
              <div className={`w-3 h-3 rounded-full ${monitoringStatus?.monitoring_active ? 'bg-green-400' : 'bg-gray-500'}`}></div>
              <span className="text-sm font-medium text-gray-300">
                Automatic Monitoring: {monitoringStatus?.monitoring_active ? 'ACTIVE' : 'INACTIVE'}
              </span>
            </div>
            {monitoringStatus?.last_assessment_time && (
              <div className="text-sm text-gray-400">
                Last check: {new Date(monitoringStatus.last_assessment_time).toLocaleTimeString()}
              </div>
            )}
          </div>
          <div className="flex items-center space-x-2">
            <button
              onClick={handleManualRiskCheck}
              disabled={isRefreshing}
              className="px-3 py-1 bg-purple-600 hover:bg-purple-700 disabled:bg-purple-800 rounded text-sm font-medium transition-colors flex items-center space-x-1"
            >
              {isRefreshing ? (
                <>
                  <Loader2 className="w-3 h-3 animate-spin" />
                  <span>Checking...</span>
                </>
              ) : (
                <>
                  <Zap className="w-3 h-3" />
                  <span>Manual Check</span>
                </>
              )}
            </button>
            {monitoringStatus?.monitoring_active ? (
              <button
                onClick={handleStopMonitoring}
                className="px-3 py-1 bg-red-600 hover:bg-red-700 rounded text-sm font-medium transition-colors"
              >
                Stop Monitoring
              </button>
            ) : (
              <button
                onClick={handleStartMonitoring}
                disabled={isStartingMonitoring}
                className="px-3 py-1 bg-green-600 hover:bg-green-700 disabled:bg-green-800 rounded text-sm font-medium transition-colors flex items-center space-x-1"
              >
                {isStartingMonitoring ? (
                  <>
                    <Loader2 className="w-3 h-3 animate-spin" />
                    <span>Starting...</span>
                  </>
                ) : (
                  <>
                    <Activity className="w-3 h-3" />
                    <span>Start Monitoring</span>
                  </>
                )}
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Risk Metrics */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-2xl font-bold text-red-400">
                {riskAssessment?.vulnerability_breakdown?.critical || 0}
              </p>
              <p className="text-sm text-gray-400">Critical Priority</p>
            </div>
            <AlertTriangle className="w-8 h-8 text-red-400" />
          </div>
        </div>
        <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-2xl font-bold text-amber-400">
                {riskAssessment?.vulnerability_breakdown?.high || 0}
              </p>
              <p className="text-sm text-gray-400">High Priority</p>
            </div>
            <TrendingUp className="w-8 h-8 text-amber-400" />
          </div>
        </div>
        <div className={`bg-gray-800 rounded-xl p-6 border ${riskTrend === 'up' ? 'border-red-500 bg-red-900/10' : riskTrend === 'down' ? 'border-green-500 bg-green-900/10' : 'border-gray-700'}`}>
          <div className="flex items-center justify-between">
            <div>
              <div className="flex items-center space-x-2">
                <p className={`text-2xl font-bold ${getRiskLevelColor(riskAssessment?.risk_level || 'low')}`}>
                  {riskAssessment?.risk_score?.toFixed(1) || '0.0'}
                </p>
                {getTrendIcon(riskTrend)}
              </div>
              <p className="text-sm text-gray-400">Risk Score</p>
            </div>
            <Target className={`w-8 h-8 ${getRiskLevelColor(riskAssessment?.risk_level || 'low')}`} />
          </div>
        </div>
        <div className={`bg-gray-800 rounded-xl p-6 border ${newThreatsDetected ? 'border-red-500 bg-red-900/10 animate-pulse' : 'border-gray-700'}`}>
          <div className="flex items-center justify-between">
            <div>
              <p className={`text-2xl font-bold ${newThreatsDetected ? 'text-red-400' : 'text-green-400'}`}>
                {riskAssessment?.active_threats || 0}
              </p>
              <p className="text-sm text-gray-400">Active Threats</p>
            </div>
            <Zap className={`w-8 h-8 ${newThreatsDetected ? 'text-red-400' : 'text-green-400'}`} />
          </div>
        </div>
      </div>

             {/* Instant Threats (last 30 seconds) */}
       {instantThreats.length > 0 && (
         <div className="bg-gray-800 rounded-lg p-4 border-l-4 border-red-500">
           <h3 className="text-lg font-semibold text-white mb-3 flex items-center space-x-2">
             <Zap className="w-5 h-5 text-red-400 animate-pulse" />
             <span>Instant Threats (Last 30s)</span>
             <span className="text-xs bg-red-600 text-white px-2 py-1 rounded-full">
               {instantThreats.length}
             </span>
           </h3>
           <div className="space-y-2 max-h-40 overflow-y-auto">
             {instantThreats.map((threat, index) => (
               <div key={threat.id || index} className={`text-sm p-3 rounded border-l-2 ${
                 threat.severity === 'critical' ? 'bg-red-900/30 border-red-500 text-red-300' :
                 threat.severity === 'high' ? 'bg-amber-900/30 border-amber-500 text-amber-300' :
                 'bg-gray-700/50 border-gray-500 text-gray-300'
               } animate-fadeIn`}>
                 <div className="flex items-center justify-between">
                   <div>
                     <div className="flex items-center space-x-2">
                       <span className={`px-2 py-1 rounded text-xs font-medium ${getSeverityColor(threat.severity)}`}>
                         {threat.severity?.toUpperCase()}
                       </span>
                       <span className="font-medium">{threat.type?.toUpperCase()}</span>
                     </div>
                     <p className="mt-1">{threat.description}</p>
                     {threat.source_ip && (
                       <p className="text-xs text-gray-400 mt-1">Source: {threat.source_ip}</p>
                     )}
                   </div>
                   <span className="text-xs text-gray-500 whitespace-nowrap">
                     {threat.age_seconds < 10 ? 'Just now' : `${Math.floor(threat.age_seconds)}s ago`}
                   </span>
                 </div>
               </div>
             ))}
           </div>
         </div>
       )}

       {/* Real-time Activity Feed */}
       {recentActivity.length > 0 && (
         <div className="bg-gray-800 rounded-lg p-4">
           <h3 className="text-lg font-semibold text-white mb-3 flex items-center space-x-2">
             <Activity className="w-5 h-5 text-blue-400" />
             <span>Real-time Activity</span>
           </h3>
           <div className="space-y-2 max-h-32 overflow-y-auto">
             {recentActivity.map((activity, index) => (
               <div key={index} className={`text-sm p-2 rounded ${index === 0 ? 'bg-blue-900/20 text-blue-300 animate-pulse' : 'bg-gray-700/50 text-gray-400'}`}>
                 <div className="flex items-center justify-between">
                   <span>{activity}</span>
                   <span className="text-xs text-gray-500">
                     {index === 0 ? 'Just now' : `${(index + 1) * 3}s ago`}
                   </span>
                 </div>
               </div>
             ))}
           </div>
         </div>
       )}

      {/* Risk Assessment Details */}
      {riskAssessment && (
        <div className="bg-gray-800 rounded-lg p-6">
          <h3 className="text-lg font-semibold text-white mb-4">Risk Assessment Details</h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="bg-gray-700 rounded-lg p-4">
              <p className="text-sm text-gray-400">Base Risk Score</p>
              <p className="text-xl font-bold text-white">{riskAssessment.base_risk}</p>
            </div>
            <div className="bg-gray-700 rounded-lg p-4">
              <p className="text-sm text-gray-400">Threat Multiplier</p>
              <p className="text-xl font-bold text-white">{riskAssessment.threat_multiplier.toFixed(2)}x</p>
            </div>
            <div className="bg-gray-700 rounded-lg p-4">
              <p className="text-sm text-gray-400">Recent Activity Multiplier</p>
              <p className="text-xl font-bold text-white">{riskAssessment.recent_activity_multiplier.toFixed(2)}x</p>
            </div>
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="flex items-center space-x-2">
        <Filter className="w-5 h-5 text-gray-400" />
        <span className="text-sm text-gray-400">Filter by:</span>
        {filters.map(filter => (
          <button
            key={filter.id}
            onClick={() => setSelectedFilter(filter.id)}
            className={`px-3 py-1 rounded-lg text-sm font-medium transition-colors ${
              selectedFilter === filter.id
                ? 'bg-blue-600 text-white'
                : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
            }`}
          >
            {filter.label}
          </button>
        ))}
      </div>

      {/* Vulnerability List */}
      <div className="space-y-4">
        {filteredVulnerabilities.length === 0 ? (
          <div className="text-center py-12">
            <Shield className="w-16 h-16 text-gray-400 mx-auto mb-4" />
            <p className="text-gray-400">No vulnerabilities found for the selected filter.</p>
          </div>
        ) : (
          filteredVulnerabilities.map((vuln, index) => (
            <div key={vuln.id} className="bg-gray-800 rounded-lg p-6 border border-gray-700 hover:border-gray-600 transition-colors">
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <div className="flex items-center space-x-3 mb-3">
                    <div className={`w-3 h-3 rounded-full ${getPriorityColor(vuln.priority_num)}`}></div>
                    <span className="text-sm font-medium text-gray-400">Priority {vuln.priority_num}</span>
                    <span className={`px-2 py-1 rounded text-xs font-medium ${getSeverityColor(vuln.severity)}`}>
                      {vuln.severity}
                    </span>
                    {vuln.exploit_available && (
                      <span className="px-2 py-1 rounded text-xs font-medium bg-red-900/20 text-red-400">
                        Exploit Available
                      </span>
                    )}
                  </div>
                  
                  <h3 className="text-lg font-semibold text-white mb-2">{vuln.title}</h3>
                  
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 text-sm">
                    <div>
                      <p className="text-gray-400">CVSS Score</p>
                      <p className={`font-medium ${getRiskScoreColor(vuln.cvss_score * 10)}`}>
                        {vuln.cvss_score}/10
                      </p>
                    </div>
                    <div>
                      <p className="text-gray-400">Priority Score</p>
                      <p className="font-medium text-white">{vuln.priority_score.toFixed(1)}</p>
                    </div>
                    <div>
                      <p className="text-gray-400">Business Impact</p>
                      <p className="font-medium text-white">{vuln.business_impact}</p>
                    </div>
                    <div>
                      <p className="text-gray-400">Exposure</p>
                      <p className="font-medium text-white">{vuln.exposure}</p>
                    </div>
                  </div>
                  
                  {vuln.created_at && (
                    <p className="text-xs text-gray-500 mt-2">
                      Detected: {new Date(vuln.created_at).toLocaleString()}
                    </p>
                  )}
                </div>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};

export default RiskPrioritization;
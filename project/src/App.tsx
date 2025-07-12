import React, { useState } from 'react';
import { Shield, AlertTriangle, CheckCircle, Clock, Users, Server, MessageCircle, FileText, Settings, Bell } from 'lucide-react';
import Dashboard from './components/Dashboard';
import CVEAnalysis from './components/CVEAnalysis';
import PatchRecommendations from './components/PatchRecommendations';
import RiskPrioritization from './components/RiskPrioritization';
import TicketManagement from './components/TicketManagement';
import ChatAssistant from './components/ChatAssistant';
import Reports from './components/Reports';
import AssetInventory from './components/AssetInventory';
import VulnerabilityScanner from './components/VulnerabilityScanner';

function App() {
  const [activeTab, setActiveTab] = useState('dashboard');

  const tabs = [
    { id: 'dashboard', label: 'Dashboard', icon: Shield },
    { id: 'cve-analysis', label: 'CVE Analysis', icon: AlertTriangle },
    { id: 'vulnerability-scanner', label: 'Vulnerability Scanner', icon: Settings },
    { id: 'risk-prioritization', label: 'Risk Priority', icon: Clock },
    { id: 'patch-recommendations', label: 'Patch Recommendations', icon: CheckCircle },
    { id: 'ticket-management', label: 'Tickets', icon: FileText },
    { id: 'asset-inventory', label: 'Assets', icon: Server },
    { id: 'chat-assistant', label: 'AI Assistant', icon: MessageCircle },
    { id: 'reports', label: 'Reports', icon: FileText },
  ];

  const renderContent = () => {
    switch (activeTab) {
      case 'dashboard':
        return <Dashboard />;
      case 'cve-analysis':
        return <CVEAnalysis />;
      case 'vulnerability-scanner':
        return <VulnerabilityScanner />;
      case 'risk-prioritization':
        return <RiskPrioritization />;
      case 'patch-recommendations':
        return <PatchRecommendations />;
      case 'ticket-management':
        return <TicketManagement />;
      case 'asset-inventory':
        return <AssetInventory />;
      case 'chat-assistant':
        return <ChatAssistant />;
      case 'reports':
        return <Reports />;
      default:
        return <Dashboard />;
    }
  };

  return (
    <div className="min-h-screen bg-gray-900 text-white">
      {/* Header */}
      <header className="bg-gray-800 border-b border-gray-700 px-6 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-4">
            <div className="flex items-center space-x-2">
              <Shield className="w-8 h-8 text-blue-400" />
              <h1 className="text-2xl font-bold text-white">PatchMate360</h1>
            </div>
            <div className="text-sm text-gray-400">
              Intelligent Vulnerability Management
            </div>
          </div>
          <div className="flex items-center space-x-4">
            <button className="p-2 rounded-lg bg-gray-700 hover:bg-gray-600 transition-colors">
              <Bell className="w-5 h-5" />
            </button>
            <button className="p-2 rounded-lg bg-gray-700 hover:bg-gray-600 transition-colors">
              <Settings className="w-5 h-5" />
            </button>
            <div className="flex items-center space-x-2">
              <Users className="w-5 h-5 text-gray-400" />
              <span className="text-sm text-gray-300">SOC Team</span>
            </div>
          </div>
        </div>
      </header>

      <div className="flex">
        {/* Sidebar */}
        <aside className="w-64 bg-gray-800 border-r border-gray-700 min-h-screen">
          <nav className="p-4">
            <ul className="space-y-2">
              {tabs.map((tab) => {
                const Icon = tab.icon;
                return (
                  <li key={tab.id}>
                    <button
                      onClick={() => setActiveTab(tab.id)}
                      className={`w-full flex items-center space-x-3 px-4 py-3 rounded-lg transition-colors ${
                        activeTab === tab.id
                          ? 'bg-blue-600 text-white'
                          : 'text-gray-300 hover:bg-gray-700 hover:text-white'
                      }`}
                    >
                      <Icon className="w-5 h-5" />
                      <span className="text-sm font-medium">{tab.label}</span>
                    </button>
                  </li>
                );
              })}
            </ul>
          </nav>
        </aside>

        {/* Main Content */}
        <main className="flex-1 p-6">
          {renderContent()}
        </main>
      </div>
    </div>
  );
}

export default App;
import React, { useState, useEffect, useRef } from 'react';
import { Send, Bot, User, Loader2, Trash2, Plus, MessageCircle, Shield, AlertTriangle, CheckCircle, Clock, Zap, Target, Bug, Activity } from 'lucide-react';
import { chatAPI, llmAPI } from '../services/api';
import { ChatSession, ChatMessage } from '../types';

const ChatAssistant = () => {
  const [sessions, setSessions] = useState<ChatSession[]>([]);
  const [currentSession, setCurrentSession] = useState<ChatSession | null>(null);
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [inputMessage, setInputMessage] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [isSending, setIsSending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [llmStatus, setLlmStatus] = useState<any>(null);
  const [securityInsights, setSecurityInsights] = useState<any>(null);
  const [selectedSessionType, setSelectedSessionType] = useState('general');
  const [showQuickResponse, setShowQuickResponse] = useState(false);
  const [quickResponseInput, setQuickResponseInput] = useState('');
  const [quickResponseResult, setQuickResponseResult] = useState<any>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  // Load sessions and LLM status on component mount
  useEffect(() => {
    loadSessions();
    loadLLMStatus();
    loadSecurityInsights();
  }, []);

  // Auto-scroll to bottom when messages change
  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  const getContextTypeForSession = (sessionType: string) => {
    const contextMapping: { [key: string]: string } = {
      'general': 'log_analysis',
      'incident_response': 'incident',
      'threat_hunting': 'threat',
      'vulnerability_analysis': 'vulnerability_scan',
      'compliance': 'log_analysis',
      'forensics': 'log_analysis'
    };
    return contextMapping[sessionType] || 'log_analysis';
  };

  const loadSessions = async () => {
    try {
      setIsLoading(true);
      setError(null);
      const response = await chatAPI.getAllSessions();
      setSessions(response || []);
      
      // If no sessions exist, create a default one
      if (!response || response.length === 0) {
        await createNewSession();
      }
    } catch (err) {
      console.error('Error loading sessions:', err);
      setError('Failed to load chat sessions');
    } finally {
      setIsLoading(false);
    }
  };

  const loadLLMStatus = async () => {
    try {
      const status = await llmAPI.getStatus();
      setLlmStatus(status);
    } catch (err) {
      console.error('Error loading LLM status:', err);
    }
  };

  const loadSecurityInsights = async () => {
    try {
      const insights = await chatAPI.getSecurityInsights();
      setSecurityInsights(insights);
    } catch (err) {
      console.error('Error loading security insights:', err);
    }
  };

  const createNewSession = async () => {
    try {
      const newSession = await chatAPI.createSession({
        title: `SOC Chat - ${selectedSessionType.replace('_', ' ').toUpperCase()}`,
        session_type: selectedSessionType
      });
      
      setSessions(prev => [newSession, ...prev]);
      setCurrentSession(newSession);
      setMessages([]);
    } catch (err) {
      console.error('Error creating session:', err);
      setError('Failed to create new session');
    }
  };

  const loadSessionMessages = async (sessionId: string) => {
    try {
      setIsLoading(true);
      const sessionData = await chatAPI.getChatHistory(sessionId);
      setMessages(sessionData.messages || []);
    } catch (err) {
      console.error('Error loading messages:', err);
      setError('Failed to load chat history');
    } finally {
      setIsLoading(false);
    }
  };

  const handleSessionSelect = async (session: ChatSession) => {
    setCurrentSession(session);
    await loadSessionMessages(session.id);
  };

  const handleSendMessage = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!inputMessage.trim() || !currentSession) return;

    const userMessage = inputMessage.trim();
    setInputMessage('');
    setIsSending(true);
    setError(null);

    try {
      // Add user message to UI immediately
      const userMsg: ChatMessage = {
        id: `temp-${Date.now()}`,
        session_id: currentSession.id,
        role: 'user',
        content: userMessage,
        timestamp: new Date().toISOString(),
      };
      setMessages(prev => [...prev, userMsg]);

      // Send message to backend with context based on session type
      const contextType = getContextTypeForSession(currentSession.session_type);
      const response = await chatAPI.sendMessage(currentSession.id, userMessage, contextType);
      
      // Add assistant response with security context
      if (response) {
        const assistantMsg: ChatMessage = {
          id: response.id || `assistant-${Date.now()}`,
          session_id: currentSession.id,
          role: 'assistant',
          content: response.content,
          timestamp: response.timestamp || new Date().toISOString(),
          metadata: response.metadata,
          security_context: response.security_context,
        };
        setMessages(prev => [...prev, assistantMsg]);
      }
    } catch (err) {
      console.error('Error sending message:', err);
      setError('Failed to send message. Please try again.');
    } finally {
      setIsSending(false);
    }
  };

  const handleQuickResponse = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!quickResponseInput.trim()) return;

    try {
      setIsSending(true);
      const response = await chatAPI.getQuickResponse(quickResponseInput);
      setQuickResponseResult(response);
    } catch (err) {
      console.error('Error getting quick response:', err);
      setError('Failed to get quick response');
    } finally {
      setIsSending(false);
    }
  };

  const deleteSession = async (sessionId: string) => {
    try {
      await chatAPI.deleteSession(sessionId);
      setSessions(prev => prev.filter(s => s.id !== sessionId));
      
      if (currentSession?.id === sessionId) {
        setCurrentSession(null);
        setMessages([]);
      }
    } catch (err) {
      console.error('Error deleting session:', err);
      setError('Failed to delete session');
    }
  };

  const getSessionTypeIcon = (sessionType: string) => {
    switch (sessionType) {
      case 'incident_response':
        return <AlertTriangle className="w-4 h-4" />;
      case 'threat_hunting':
        return <Target className="w-4 h-4" />;
      case 'vulnerability_analysis':
        return <Bug className="w-4 h-4" />;
      default:
        return <MessageCircle className="w-4 h-4" />;
    }
  };

  const getSessionTypeColor = (sessionType: string) => {
    switch (sessionType) {
      case 'incident_response':
        return 'text-red-400 bg-red-900/20';
      case 'threat_hunting':
        return 'text-purple-400 bg-purple-900/20';
      case 'vulnerability_analysis':
        return 'text-orange-400 bg-orange-900/20';
      default:
        return 'text-blue-400 bg-blue-900/20';
    }
  };

  const getThreatLevelColor = (level: string) => {
    switch (level) {
      case 'high':
        return 'text-red-400';
      case 'medium':
        return 'text-yellow-400';
      case 'normal':
        return 'text-green-400';
      default:
        return 'text-gray-400';
    }
  };

  if (isLoading && sessions.length === 0) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="w-8 h-8 animate-spin text-blue-400" />
        <span className="ml-2 text-gray-300">Loading chat sessions...</span>
      </div>
    );
  }

  return (
    <div className="h-full flex">
      {/* Sidebar - Chat Sessions */}
      <div className="w-80 bg-gray-800 border-r border-gray-700 flex flex-col">
        {/* Header */}
        <div className="p-4 border-b border-gray-700">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-white">SOC Chat Assistant</h2>
            <button
              onClick={() => setShowQuickResponse(!showQuickResponse)}
              className="p-2 bg-green-600 hover:bg-green-700 rounded-lg text-white"
              title="Quick Response"
            >
              <Zap className="w-4 h-4" />
            </button>
          </div>
          
          {/* Security Insights */}
          {securityInsights && (
            <div className="bg-gray-700 rounded-lg p-3 mb-3">
              <div className="flex items-center space-x-2 mb-2">
                <Shield className="w-4 h-4 text-green-400" />
                <span className="text-sm text-gray-300">Security Status</span>
                <span className={`w-2 h-2 rounded-full ${getThreatLevelColor(securityInsights.threat_level).replace('text-', 'bg-')}`}></span>
              </div>
              <div className="text-xs text-gray-400 space-y-1">
                <div>Critical: {securityInsights.critical_vulnerabilities}</div>
                <div>High: {securityInsights.high_vulnerabilities}</div>
                <div>Pending Patches: {securityInsights.pending_patches}</div>
              </div>
            </div>
          )}
          
          {/* LLM Status */}
          {llmStatus && (
            <div className="bg-gray-700 rounded-lg p-3">
              <div className="flex items-center space-x-2 mb-2">
                <Bot className="w-4 h-4 text-blue-400" />
                <span className="text-sm text-gray-300">AI Assistant</span>
                <span className={`w-2 h-2 rounded-full ${llmStatus.status === 'active' ? 'bg-green-400' : 'bg-red-400'}`}></span>
              </div>
              <p className="text-xs text-gray-400">
                {llmStatus.model_info?.model_name || 'Model not loaded'}
              </p>
            </div>
          )}
        </div>

        {/* Quick Response Panel */}
        {showQuickResponse && (
          <div className="p-4 border-b border-gray-700 bg-gray-750">
            <h3 className="text-sm font-medium text-white mb-2">Quick Response</h3>
            <form onSubmit={handleQuickResponse} className="space-y-2">
              <input
                type="text"
                value={quickResponseInput}
                onChange={(e) => setQuickResponseInput(e.target.value)}
                placeholder="Ask a quick security question..."
                className="w-full px-3 py-2 bg-gray-600 border border-gray-500 rounded-lg text-white text-sm placeholder-gray-400"
              />
              <button
                type="submit"
                disabled={isSending}
                className="w-full px-3 py-2 bg-green-600 hover:bg-green-700 disabled:bg-gray-600 rounded-lg text-white text-sm"
              >
                {isSending ? <Loader2 className="w-4 h-4 animate-spin mx-auto" /> : 'Get Response'}
              </button>
            </form>
            {quickResponseResult && (
              <div className="mt-3 p-3 bg-gray-600 rounded-lg">
                <p className="text-sm text-white">{quickResponseResult.response}</p>
              </div>
            )}
          </div>
        )}

        {/* New Session Creation */}
        <div className="p-4 border-b border-gray-700">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-sm font-medium text-white">New Session</h3>
            <button
              onClick={createNewSession}
              className="p-2 bg-blue-600 hover:bg-blue-700 rounded-lg text-white"
            >
              <Plus className="w-4 h-4" />
            </button>
          </div>
          <select
            value={selectedSessionType}
            onChange={(e) => setSelectedSessionType(e.target.value)}
            className="w-full px-3 py-2 bg-gray-600 border border-gray-500 rounded-lg text-white text-sm"
          >
            <option value="general">General Security</option>
            <option value="incident_response">Incident Response</option>
            <option value="threat_hunting">Threat Hunting</option>
            <option value="vulnerability_analysis">Vulnerability Analysis</option>
          </select>
        </div>

        {/* Sessions List */}
        <div className="flex-1 overflow-y-auto p-4 space-y-2">
          {sessions.map((session) => (
            <div
              key={session.id}
              onClick={() => handleSessionSelect(session)}
              className={`p-3 rounded-lg cursor-pointer transition-colors group ${
                currentSession?.id === session.id
                  ? 'bg-blue-600 text-white'
                  : 'bg-gray-700 hover:bg-gray-600 text-gray-300'
              }`}
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-2 flex-1 min-w-0">
                  <div className={`p-1 rounded ${getSessionTypeColor(session.session_type || 'general')}`}>
                    {getSessionTypeIcon(session.session_type || 'general')}
                  </div>
                  <div className="flex-1 min-w-0">
                    <h3 className="font-medium truncate">{session.title}</h3>
                    <p className="text-xs opacity-75 truncate">
                      {session.message_count} messages
                    </p>
                  </div>
                </div>
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    deleteSession(session.id);
                  }}
                  className="p-1 hover:bg-red-600 rounded opacity-0 group-hover:opacity-100 transition-opacity"
                >
                  <Trash2 className="w-3 h-3" />
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Main Chat Area */}
      <div className="flex-1 flex flex-col">
        {/* Chat Header */}
        {currentSession && (
          <div className="p-4 border-b border-gray-700 bg-gray-800">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-3">
                <div className={`p-2 rounded-lg ${getSessionTypeColor(currentSession.session_type || 'general')}`}>
                  {getSessionTypeIcon(currentSession.session_type || 'general')}
                </div>
                <div>
                  <h2 className="text-lg font-semibold text-white">{currentSession.title}</h2>
                  <p className="text-sm text-gray-400">
                    {messages.length} messages • Created {new Date(currentSession.created_at).toLocaleDateString()}
                  </p>
                </div>
              </div>
              
              {/* Security Context */}
              {currentSession.security_context && (
                <div className="flex items-center space-x-2">
                  <Activity className="w-4 h-4 text-blue-400" />
                  <span className="text-sm text-gray-300">
                    Threat Level: <span className={getThreatLevelColor(currentSession.security_context.threat_level)}>
                      {currentSession.security_context.threat_level}
                    </span>
                  </span>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Messages Area */}
        <div className="flex-1 overflow-y-auto p-4 space-y-4">
          {messages.map((message) => (
            <div
              key={message.id}
              className={`flex ${message.role === 'user' ? 'justify-end' : 'justify-start'}`}
            >
              <div
                className={`max-w-3xl rounded-lg p-4 ${
                  message.role === 'user'
                    ? 'bg-blue-600 text-white'
                    : 'bg-gray-700 text-gray-300'
                }`}
              >
                <div className="flex items-start space-x-3">
                  {message.role === 'assistant' && (
                    <Bot className="w-5 h-5 text-blue-400 mt-1 flex-shrink-0" />
                  )}
                  {message.role === 'user' && (
                    <User className="w-5 h-5 text-white mt-1 flex-shrink-0" />
                  )}
                  <div className="flex-1">
                    <p className="whitespace-pre-wrap">{message.content}</p>
                    
                    {/* Security Insights */}
                    {message.metadata?.security_insights && message.metadata.security_insights.length > 0 && (
                      <div className="mt-3 p-3 bg-yellow-900/20 border border-yellow-700/30 rounded-lg">
                        <div className="flex items-center space-x-2 mb-2">
                          <AlertTriangle className="w-4 h-4 text-yellow-400" />
                          <span className="text-sm font-medium text-yellow-400">Security Insights</span>
                        </div>
                        <ul className="text-sm text-yellow-300 space-y-1">
                          {message.metadata.security_insights.map((insight: string, index: number) => (
                            <li key={index}>• {insight}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                    
                    {/* Recommended Actions */}
                    {message.metadata?.recommended_actions && message.metadata.recommended_actions.length > 0 && (
                      <div className="mt-3 p-3 bg-green-900/20 border border-green-700/30 rounded-lg">
                        <div className="flex items-center space-x-2 mb-2">
                          <CheckCircle className="w-4 h-4 text-green-400" />
                          <span className="text-sm font-medium text-green-400">Recommended Actions</span>
                        </div>
                        <ul className="text-sm text-green-300 space-y-1">
                          {message.metadata.recommended_actions.map((action: string, index: number) => (
                            <li key={index}>• {action}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                    
                    <div className="text-xs opacity-75 mt-2">
                      {new Date(message.timestamp).toLocaleTimeString()}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          ))}
          
          {isSending && (
            <div className="flex justify-start">
              <div className="bg-gray-700 rounded-lg p-4">
                <div className="flex items-center space-x-3">
                  <Bot className="w-5 h-5 text-blue-400" />
                  <Loader2 className="w-4 h-4 animate-spin text-gray-400" />
                  <span className="text-gray-400">AI is thinking...</span>
                </div>
              </div>
            </div>
          )}
          
          <div ref={messagesEndRef} />
        </div>

        {/* Input Area */}
        {currentSession && (
          <div className="p-4 border-t border-gray-700">
            <form onSubmit={handleSendMessage} className="flex space-x-3">
              <input
                type="text"
                value={inputMessage}
                onChange={(e) => setInputMessage(e.target.value)}
                placeholder="Ask about security threats, vulnerabilities, or incident response..."
                className="flex-1 px-4 py-3 bg-gray-700 border border-gray-600 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:border-blue-500"
                disabled={isSending}
              />
              <button
                type="submit"
                disabled={isSending || !inputMessage.trim()}
                className="px-6 py-3 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600 disabled:cursor-not-allowed rounded-lg text-white font-medium"
              >
                {isSending ? <Loader2 className="w-5 h-5 animate-spin" /> : <Send className="w-5 h-5" />}
              </button>
            </form>
            
            {error && (
              <div className="mt-3 p-3 bg-red-900/20 border border-red-700/30 rounded-lg">
                <p className="text-red-400 text-sm">{error}</p>
              </div>
            )}
          </div>
        )}

        {/* No Session Selected */}
        {!currentSession && (
          <div className="flex-1 flex items-center justify-center">
            <div className="text-center">
              <MessageCircle className="w-16 h-16 text-gray-600 mx-auto mb-4" />
              <h3 className="text-xl font-semibold text-gray-400 mb-2">No Chat Session Selected</h3>
              <p className="text-gray-500">Select a session from the sidebar or create a new one to start chatting with the SOC AI assistant.</p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default ChatAssistant;
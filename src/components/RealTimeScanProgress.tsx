import React, { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { 
  Shield, AlertTriangle, CheckCircle, Clock, Zap, 
  Globe, Bug, Lock, Code, Database, Server, Eye
} from 'lucide-react'

interface ScanStep {
  id: string
  name: string
  status: 'pending' | 'running' | 'completed' | 'failed'
  progress: number
  findings: number
  icon: React.ComponentType<any>
  estimatedTime: number
  actualTime?: number
}

interface RealTimeScanProgressProps {
  isScanning: boolean
  scanConfig: any
  onScanComplete: (results: any) => void
}

const RealTimeScanProgress: React.FC<RealTimeScanProgressProps> = ({
  isScanning,
  scanConfig,
  onScanComplete
}) => {
  const [scanSteps, setScanSteps] = useState<ScanStep[]>([])
  const [currentStep, setCurrentStep] = useState(0)
  const [overallProgress, setOverallProgress] = useState(0)
  const [liveFindings, setLiveFindings] = useState<any[]>([])
  const [scanMetrics, setScanMetrics] = useState({
    requestsSent: 0,
    responsesReceived: 0,
    averageResponseTime: 0,
    vulnerabilitiesFound: 0
  })

  const scanTypeMapping = {
    statusCodes: { name: 'Status Code Analysis', icon: Globe, time: 5 },
    directoryFuzzing: { name: 'Directory Fuzzing', icon: Eye, time: 15 },
    subdomainEnum: { name: 'Subdomain Enumeration', icon: Globe, time: 20 },
    sqlInjection: { name: 'SQL Injection Testing', icon: Database, time: 25 },
    xssScanning: { name: 'XSS Vulnerability Scan', icon: Code, time: 20 },
    lfiScanning: { name: 'Local File Inclusion', icon: Bug, time: 15 },
    corsCheck: { name: 'CORS Configuration', icon: Shield, time: 8 },
    securityHeaders: { name: 'Security Headers', icon: Lock, time: 5 },
    tlsConfiguration: { name: 'TLS/SSL Analysis', icon: Lock, time: 10 },
    cveScanning: { name: 'CVE Vulnerability Scan', icon: AlertTriangle, time: 30 },
    portScanning: { name: 'Port Scanning', icon: Server, time: 25 },
  }

  useEffect(() => {
    if (isScanning) {
      initializeScan()
    }
  }, [isScanning, scanConfig])

  const initializeScan = () => {
    const enabledScans = Object.entries(scanConfig)
      .filter(([_, enabled]) => enabled)
      .map(([key, _], index) => ({
        id: key,
        name: scanTypeMapping[key as keyof typeof scanTypeMapping]?.name || key,
        status: 'pending' as const,
        progress: 0,
        findings: 0,
        icon: scanTypeMapping[key as keyof typeof scanTypeMapping]?.icon || Shield,
        estimatedTime: scanTypeMapping[key as keyof typeof scanTypeMapping]?.time || 10
      }))

    setScanSteps(enabledScans)
    setCurrentStep(0)
    setOverallProgress(0)
    setLiveFindings([])
    setScanMetrics({
      requestsSent: 0,
      responsesReceived: 0,
      averageResponseTime: 0,
      vulnerabilitiesFound: 0
    })

    startScanExecution(enabledScans)
  }

  const startScanExecution = async (steps: ScanStep[]) => {
    for (let i = 0; i < steps.length; i++) {
      setCurrentStep(i)
      await executeScanStep(steps[i], i)
    }
    
    // Complete scan
    setOverallProgress(100)
    setTimeout(() => {
      onScanComplete({
        findings: liveFindings,
        metrics: scanMetrics,
        steps: scanSteps
      })
    }, 1000)
  }

  const executeScanStep = (step: ScanStep, index: number): Promise<void> => {
    return new Promise((resolve) => {
      // Update step status to running
      setScanSteps(prev => prev.map((s, i) => 
        i === index ? { ...s, status: 'running' } : s
      ))

      let progress = 0
      const interval = setInterval(() => {
        progress += Math.random() * 15 + 5
        
        // Simulate finding vulnerabilities
        if (Math.random() > 0.7 && progress > 30) {
          const newFinding = generateMockFinding(step.name)
          setLiveFindings(prev => [...prev, newFinding])
          setScanMetrics(prev => ({
            ...prev,
            vulnerabilitiesFound: prev.vulnerabilitiesFound + 1
          }))
        }

        // Update metrics
        setScanMetrics(prev => ({
          ...prev,
          requestsSent: prev.requestsSent + Math.floor(Math.random() * 3) + 1,
          responsesReceived: prev.responsesReceived + Math.floor(Math.random() * 2) + 1,
          averageResponseTime: Math.random() * 500 + 100
        }))

        if (progress >= 100) {
          clearInterval(interval)
          
          // Mark step as completed
          setScanSteps(prev => prev.map((s, i) => 
            i === index ? { 
              ...s, 
              status: Math.random() > 0.9 ? 'failed' : 'completed',
              progress: 100,
              actualTime: step.estimatedTime + Math.random() * 5 - 2.5
            } : s
          ))

          // Update overall progress
          setOverallProgress(((index + 1) / scanSteps.length) * 100)
          
          resolve()
        } else {
          // Update step progress
          setScanSteps(prev => prev.map((s, i) => 
            i === index ? { ...s, progress } : s
          ))
        }
      }, 200)
    })
  }

  const generateMockFinding = (scanType: string) => {
    const findings = {
      'Status Code Analysis': {
        type: 'Information Disclosure',
        severity: 'low',
        description: 'Directory listing enabled on /backup/',
        url: '/backup/'
      },
      'SQL Injection Testing': {
        type: 'SQL Injection',
        severity: 'high',
        description: 'SQL injection vulnerability in login form',
        url: '/login.php?id=1'
      },
      'XSS Vulnerability Scan': {
        type: 'Cross-Site Scripting',
        severity: 'medium',
        description: 'Reflected XSS in search parameter',
        url: '/search?q=<script>'
      },
      'Security Headers': {
        type: 'Missing Security Header',
        severity: 'medium',
        description: 'X-Frame-Options header missing',
        url: '/'
      }
    }

    return findings[scanType as keyof typeof findings] || {
      type: 'Security Issue',
      severity: 'low',
      description: `Issue found in ${scanType}`,
      url: '/'
    }
  }

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed': return <CheckCircle className="w-4 h-4 text-green-500" />
      case 'running': return <Zap className="w-4 h-4 text-blue-500 animate-pulse" />
      case 'failed': return <AlertTriangle className="w-4 h-4 text-red-500" />
      default: return <Clock className="w-4 h-4 text-gray-400" />
    }
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'high': return 'text-red-600 bg-red-100 dark:bg-red-900 dark:text-red-300'
      case 'medium': return 'text-yellow-600 bg-yellow-100 dark:bg-yellow-900 dark:text-yellow-300'
      case 'low': return 'text-blue-600 bg-blue-100 dark:bg-blue-900 dark:text-blue-300'
      default: return 'text-gray-600 bg-gray-100 dark:bg-gray-800 dark:text-gray-300'
    }
  }

  if (!isScanning) return null

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="space-y-6"
    >
      {/* Overall Progress */}
      <div className="card">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Scan Progress</h3>
          <span className="text-sm text-gray-600 dark:text-gray-400">
            {Math.round(overallProgress)}% Complete
          </span>
        </div>
        
        <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-3 mb-4">
          <motion.div
            className="bg-gradient-to-r from-primary-500 to-primary-600 h-3 rounded-full"
            initial={{ width: 0 }}
            animate={{ width: `${overallProgress}%` }}
            transition={{ duration: 0.5 }}
          />
        </div>

        {/* Live Metrics */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="text-center">
            <p className="text-2xl font-bold text-primary-600 dark:text-primary-400">
              {scanMetrics.requestsSent}
            </p>
            <p className="text-xs text-gray-600 dark:text-gray-400">Requests Sent</p>
          </div>
          <div className="text-center">
            <p className="text-2xl font-bold text-green-600 dark:text-green-400">
              {scanMetrics.responsesReceived}
            </p>
            <p className="text-xs text-gray-600 dark:text-gray-400">Responses</p>
          </div>
          <div className="text-center">
            <p className="text-2xl font-bold text-blue-600 dark:text-blue-400">
              {Math.round(scanMetrics.averageResponseTime)}ms
            </p>
            <p className="text-xs text-gray-600 dark:text-gray-400">Avg Response</p>
          </div>
          <div className="text-center">
            <p className="text-2xl font-bold text-red-600 dark:text-red-400">
              {scanMetrics.vulnerabilitiesFound}
            </p>
            <p className="text-xs text-gray-600 dark:text-gray-400">Vulnerabilities</p>
          </div>
        </div>
      </div>

      {/* Scan Steps */}
      <div className="card">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Scan Steps</h3>
        <div className="space-y-3">
          {scanSteps.map((step, index) => (
            <motion.div
              key={step.id}
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: index * 0.1 }}
              className={`p-4 rounded-lg border transition-all duration-300 ${
                step.status === 'running' 
                  ? 'border-blue-300 bg-blue-50 dark:bg-blue-900/20 dark:border-blue-700' 
                  : step.status === 'completed'
                  ? 'border-green-300 bg-green-50 dark:bg-green-900/20 dark:border-green-700'
                  : step.status === 'failed'
                  ? 'border-red-300 bg-red-50 dark:bg-red-900/20 dark:border-red-700'
                  : 'border-gray-200 dark:border-gray-700'
              }`}
            >
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center space-x-3">
                  <step.icon className="w-5 h-5 text-gray-600 dark:text-gray-400" />
                  <span className="font-medium text-gray-900 dark:text-white">{step.name}</span>
                  {getStatusIcon(step.status)}
                </div>
                <span className="text-sm text-gray-600 dark:text-gray-400">
                  {step.status === 'completed' && step.actualTime 
                    ? `${step.actualTime.toFixed(1)}s`
                    : `~${step.estimatedTime}s`
                  }
                </span>
              </div>
              
              {step.status === 'running' && (
                <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                  <motion.div
                    className="bg-blue-500 h-2 rounded-full"
                    initial={{ width: 0 }}
                    animate={{ width: `${step.progress}%` }}
                    transition={{ duration: 0.3 }}
                  />
                </div>
              )}
            </motion.div>
          ))}
        </div>
      </div>

      {/* Live Findings */}
      {liveFindings.length > 0 && (
        <div className="card">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
            Live Findings ({liveFindings.length})
          </h3>
          <div className="space-y-3 max-h-64 overflow-y-auto">
            <AnimatePresence>
              {liveFindings.slice(-5).map((finding, index) => (
                <motion.div
                  key={index}
                  initial={{ opacity: 0, y: 20, scale: 0.95 }}
                  animate={{ opacity: 1, y: 0, scale: 1 }}
                  className="p-3 border border-gray-200 dark:border-gray-700 rounded-lg"
                >
                  <div className="flex items-center justify-between mb-2">
                    <span className="font-medium text-gray-900 dark:text-white">{finding.type}</span>
                    <span className={`px-2 py-1 rounded-full text-xs font-medium ${getSeverityColor(finding.severity)}`}>
                      {finding.severity.toUpperCase()}
                    </span>
                  </div>
                  <p className="text-sm text-gray-600 dark:text-gray-400 mb-1">{finding.description}</p>
                  <p className="text-xs text-gray-500 dark:text-gray-500 font-mono">{finding.url}</p>
                </motion.div>
              ))}
            </AnimatePresence>
          </div>
        </div>
      )}
    </motion.div>
  )
}

export default RealTimeScanProgress
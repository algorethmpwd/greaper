import React, { useState } from 'react'
import { motion } from 'framer-motion'
import { Play, Upload, Settings, Shield, Clock, FileText, Zap } from 'lucide-react'
import toast from 'react-hot-toast'
import AdvancedScanOptions from '../components/AdvancedScanOptions'
import PayloadManager from '../components/PayloadManager'
import RealTimeScanProgress from '../components/RealTimeScanProgress'
import AIAssistant from '../components/AIAssistant'
import { ScanConfig, ScanResult } from '../types/scanner'

const Scanner: React.FC = () => {
  const [url, setUrl] = useState('')
  const [urlList, setUrlList] = useState<string[]>([])
  const [scanMode, setScanMode] = useState<'single' | 'bulk'>('single')
  const [isScanning, setIsScanning] = useState(false)
  const [activeTab, setActiveTab] = useState<'scanner' | 'payloads'>('scanner')
  const [scanHistory, setScanHistory] = useState<ScanResult[]>([])
  const [currentScan, setCurrentScan] = useState<ScanResult | undefined>()
  
  const [scanConfig, setScanConfig] = useState<ScanConfig>({
    // Basic Scans
    statusCodes: true,
    directoryFuzzing: false,
    subdomainEnum: false,
    contentDiscovery: false,
    
    // Vulnerability Scans
    sqlInjection: false,
    xssScanning: false,
    lfiScanning: false,
    rfiScanning: false,
    xxeScanning: false,
    ssrfScanning: false,
    commandInjection: false,
    ldapInjection: false,
    
    // Security Checks
    corsCheck: true,
    hostHeaderInjection: false,
    securityHeaders: true,
    tlsConfiguration: false,
    httpMethodTesting: false,
    clickjackingTest: false,
    
    // Information Gathering
    ipLookup: false,
    contentLength: false,
    jsFileScanning: false,
    robotsTxtCheck: false,
    sitemapCheck: false,
    metadataExtraction: false,
    dnsEnumeration: false,
    
    // Advanced Scans
    cveScanning: false,
    portScanning: false,
    technologyDetection: false,
    emailHarvesting: false,
    socialMediaLinks: false,
    fuzzing: false,
    apiTesting: false,
    authenticationTesting: false,
    businessLogicTesting: false,
    
    // Performance & Monitoring
    responseTimeAnalysis: false,
    loadTesting: false,
    uptimeMonitoring: false,
    resourceAnalysis: false,
    cacheAnalysis: false,
  })

  const handleFileUpload = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    if (file) {
      const reader = new FileReader()
      reader.onload = (e) => {
        const content = e.target?.result as string
        const urls = content.split('\n').filter(url => url.trim() !== '')
        setUrlList(urls)
        toast.success(`Loaded ${urls.length} URLs`)
      }
      reader.readAsText(file)
    }
  }

  const handleScan = async () => {
    if (scanMode === 'single' && !url) {
      toast.error('Please enter a URL to scan')
      return
    }
    if (scanMode === 'bulk' && urlList.length === 0) {
      toast.error('Please upload a file with URLs')
      return
    }

    const selectedScans = Object.entries(scanConfig).filter(([_, enabled]) => enabled)
    if (selectedScans.length === 0) {
      toast.error('Please select at least one scan type')
      return
    }

    setIsScanning(true)
    
    // Create current scan object
    const newScan: ScanResult = {
      id: Date.now().toString(),
      url: scanMode === 'single' ? url : `Bulk scan (${urlList.length} URLs)`,
      timestamp: new Date().toISOString(),
      status: 'running',
      vulnerabilities: 0,
      scanTypes: selectedScans.map(([key]) => key),
      findings: [],
      metadata: {
        duration: 0,
        requestCount: 0,
        responseSize: 0,
        technologies: [],
        serverInfo: { server: 'Unknown' }
      }
    }
    
    setCurrentScan(newScan)
    toast.success('Real-time security scan initiated!')
  }

  const handleScanComplete = (results: any) => {
    setIsScanning(false)
    
    if (currentScan) {
      const completedScan: ScanResult = {
        ...currentScan,
        status: 'completed',
        vulnerabilities: results.metrics.vulnerabilitiesFound,
        findings: results.findings || [],
        metadata: {
          ...currentScan.metadata,
          duration: results.metrics.duration || 0,
          requestCount: results.metrics.requestsSent || 0
        }
      }
      
      setScanHistory(prev => [...prev, completedScan])
      setCurrentScan(completedScan)
    }
    
    toast.success(`Scan completed! Found ${results.metrics.vulnerabilitiesFound} vulnerabilities`)
  }

  const getEstimatedTime = () => {
    const selectedCount = Object.values(scanConfig).filter(Boolean).length
    const targetCount = scanMode === 'single' ? 1 : urlList.length
    const baseTime = selectedCount * targetCount * 3
    
    if (baseTime < 60) return `${baseTime} sec`
    if (baseTime < 3600) return `${Math.ceil(baseTime / 60)} min`
    return `${Math.ceil(baseTime / 3600)} hr`
  }

  const tabs = [
    { id: 'scanner', label: 'Scanner Configuration', icon: Shield },
    { id: 'payloads', label: 'Payload Management', icon: FileText },
  ]

  return (
    <>
      <div className="space-y-8">
        {/* Header */}
        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Advanced Security Scanner</h1>
          <p className="text-gray-600 dark:text-gray-400 mt-1">Real-time comprehensive security testing with AI-powered analysis</p>
        </div>

        {/* Tab Navigation */}
        <div className="flex space-x-1 bg-gray-100 dark:bg-gray-800 p-1 rounded-lg w-fit">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as 'scanner' | 'payloads')}
              className={`flex items-center space-x-2 py-2 px-4 rounded-md text-sm font-medium transition-colors ${
                activeTab === tab.id
                  ? 'bg-white dark:bg-gray-700 text-gray-900 dark:text-white shadow-sm'
                  : 'text-gray-600 dark:text-gray-300 hover:text-gray-900 dark:hover:text-white'
              }`}
            >
              <tab.icon className="w-4 h-4" />
              <span>{tab.label}</span>
            </button>
          ))}
        </div>

        {activeTab === 'scanner' ? (
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
            {/* Scan Configuration */}
            <div className="lg:col-span-2 space-y-6">
              {isScanning ? (
                <RealTimeScanProgress
                  isScanning={isScanning}
                  scanConfig={scanConfig}
                  onScanComplete={handleScanComplete}
                />
              ) : (
                <>
                  {/* Target Configuration */}
                  <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="card"
                  >
                    <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Target Configuration</h3>
                    
                    {/* Scan Mode Toggle */}
                    <div className="flex space-x-1 mb-6 bg-gray-100 dark:bg-gray-800 p-1 rounded-lg">
                      <button
                        onClick={() => setScanMode('single')}
                        className={`flex-1 py-2 px-4 rounded-md text-sm font-medium transition-colors ${
                          scanMode === 'single'
                            ? 'bg-white dark:bg-gray-700 text-gray-900 dark:text-white shadow-sm'
                            : 'text-gray-600 dark:text-gray-300 hover:text-gray-900 dark:hover:text-white'
                        }`}
                      >
                        Single URL
                      </button>
                      <button
                        onClick={() => setScanMode('bulk')}
                        className={`flex-1 py-2 px-4 rounded-md text-sm font-medium transition-colors ${
                          scanMode === 'bulk'
                            ? 'bg-white dark:bg-gray-700 text-gray-900 dark:text-white shadow-sm'
                            : 'text-gray-600 dark:text-gray-300 hover:text-gray-900 dark:hover:text-white'
                        }`}
                      >
                        Bulk URLs
                      </button>
                    </div>

                    {scanMode === 'single' ? (
                      <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                          Target URL
                        </label>
                        <input
                          type="url"
                          value={url}
                          onChange={(e) => setUrl(e.target.value)}
                          placeholder="https://example.com"
                          className="input-field"
                        />
                      </div>
                    ) : (
                      <div>
                        <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                          Upload URL List
                        </label>
                        <div className="border-2 border-dashed border-gray-300 dark:border-gray-600 rounded-lg p-6 text-center hover:border-gray-400 dark:hover:border-gray-500 transition-colors">
                          <Upload className="w-8 h-8 text-gray-400 mx-auto mb-2" />
                          <p className="text-sm text-gray-600 dark:text-gray-400 mb-2">
                            Drop your file here or click to browse
                          </p>
                          <input
                            type="file"
                            accept=".txt"
                            onChange={handleFileUpload}
                            className="hidden"
                            id="file-upload"
                          />
                          <label htmlFor="file-upload" className="btn-secondary cursor-pointer">
                            Choose File
                          </label>
                          {urlList.length > 0 && (
                            <p className="text-sm text-success-600 dark:text-success-400 mt-2">
                              {urlList.length} URLs loaded
                            </p>
                          )}
                        </div>
                      </div>
                    )}
                  </motion.div>

                  {/* Advanced Scan Options */}
                  <motion.div
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: 0.1 }}
                    className="card"
                  >
                    <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Scan Configuration</h3>
                    <AdvancedScanOptions 
                      scanConfig={scanConfig}
                      onConfigChange={setScanConfig}
                    />
                  </motion.div>
                </>
              )}
            </div>

            {/* Enhanced Control Panel */}
            <div className="space-y-6">
              <motion.div
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: 0.2 }}
                className="card"
              >
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Scan Control</h3>
                
                {!isScanning && (
                  <button
                    onClick={handleScan}
                    className="btn-primary w-full flex items-center justify-center space-x-2"
                  >
                    <Zap className="w-4 h-4" />
                    <span>Start AI-Enhanced Scan</span>
                  </button>
                )}

                <div className="mt-6 pt-6 border-t border-gray-200 dark:border-gray-700">
                  <h4 className="font-medium text-gray-900 dark:text-white mb-3">Quick Actions</h4>
                  <div className="space-y-2">
                    <button className="w-full text-left px-3 py-2 text-sm text-gray-600 dark:text-gray-400 hover:bg-gray-50 dark:hover:bg-gray-800 rounded-lg transition-colors">
                      <Settings className="w-4 h-4 inline mr-2" />
                      Advanced Settings
                    </button>
                    <button className="w-full text-left px-3 py-2 text-sm text-gray-600 dark:text-gray-400 hover:bg-gray-50 dark:hover:bg-gray-800 rounded-lg transition-colors">
                      <Clock className="w-4 h-4 inline mr-2" />
                      Schedule Scan
                    </button>
                  </div>
                </div>
              </motion.div>

              {/* Enhanced Scan Summary */}
              <motion.div
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: 0.3 }}
                className="card"
              >
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Scan Summary</h3>
                
                <div className="space-y-3">
                  <div className="flex justify-between text-sm">
                    <span className="text-gray-600 dark:text-gray-400">Target(s):</span>
                    <span className="font-medium text-gray-900 dark:text-white">
                      {scanMode === 'single' ? (url || 'Not set') : `${urlList.length} URLs`}
                    </span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-gray-600 dark:text-gray-400">Selected scans:</span>
                    <span className="font-medium text-gray-900 dark:text-white">
                      {Object.values(scanConfig).filter(Boolean).length}
                    </span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-gray-600 dark:text-gray-400">Estimated time:</span>
                    <span className="font-medium text-gray-900 dark:text-white">{getEstimatedTime()}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-gray-600 dark:text-gray-400">Scan depth:</span>
                    <span className="font-medium text-gray-900 dark:text-white">
                      {Object.values(scanConfig).filter(Boolean).length > 15 ? 'Deep' : 
                       Object.values(scanConfig).filter(Boolean).length > 8 ? 'Medium' : 'Basic'}
                    </span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-gray-600 dark:text-gray-400">AI Analysis:</span>
                    <span className="font-medium text-primary-600 dark:text-primary-400">Enabled</span>
                  </div>
                </div>

                {/* Scan Type Breakdown */}
                <div className="mt-4 pt-4 border-t border-gray-200 dark:border-gray-700">
                  <h4 className="text-sm font-medium text-gray-900 dark:text-white mb-2">Active Scan Types</h4>
                  <div className="flex flex-wrap gap-1">
                    {Object.entries(scanConfig)
                      .filter(([_, enabled]) => enabled)
                      .slice(0, 6)
                      .map(([key]) => (
                        <span key={key} className="status-badge status-info text-xs">
                          {key.replace(/([A-Z])/g, ' $1').replace(/^./, str => str.toUpperCase())}
                        </span>
                      ))}
                    {Object.values(scanConfig).filter(Boolean).length > 6 && (
                      <span className="status-badge status-info text-xs">
                        +{Object.values(scanConfig).filter(Boolean).length - 6} more
                      </span>
                    )}
                  </div>
                </div>
              </motion.div>
            </div>
          </div>
        ) : (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
          >
            <PayloadManager />
          </motion.div>
        )}
      </div>

      {/* AI Assistant */}
      <AIAssistant 
        scanHistory={scanHistory}
        currentScan={currentScan}
      />
    </>
  )
}

export default Scanner
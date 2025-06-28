import React, { useState } from 'react'
import { motion } from 'framer-motion'
import { Play, Upload, Settings, Shield, AlertTriangle, CheckCircle, Clock } from 'lucide-react'
import toast from 'react-hot-toast'

interface ScanConfig {
  statusCodes: boolean
  directoryFuzzing: boolean
  subdomainEnum: boolean
  sqlInjection: boolean
  xssScanning: boolean
  lfiScanning: boolean
  corsCheck: boolean
  hostHeaderInjection: boolean
  ipLookup: boolean
  contentLength: boolean
  securityHeaders: boolean
  cveScanning: boolean
  jsFileScanning: boolean
}

const Scanner: React.FC = () => {
  const [url, setUrl] = useState('')
  const [urlList, setUrlList] = useState<string[]>([])
  const [scanMode, setScanMode] = useState<'single' | 'bulk'>('single')
  const [isScanning, setIsScanning] = useState(false)
  const [scanProgress, setScanProgress] = useState(0)
  const [scanConfig, setScanConfig] = useState<ScanConfig>({
    statusCodes: true,
    directoryFuzzing: false,
    subdomainEnum: false,
    sqlInjection: false,
    xssScanning: false,
    lfiScanning: false,
    corsCheck: true,
    hostHeaderInjection: false,
    ipLookup: false,
    contentLength: false,
    securityHeaders: true,
    cveScanning: false,
    jsFileScanning: false,
  })

  const scanOptions = [
    { key: 'statusCodes', label: 'Status Code Check', description: 'Check HTTP response codes', icon: CheckCircle },
    { key: 'directoryFuzzing', label: 'Directory Fuzzing', description: 'Discover hidden directories', icon: Shield },
    { key: 'subdomainEnum', label: 'Subdomain Enumeration', description: 'Find subdomains', icon: Shield },
    { key: 'sqlInjection', label: 'SQL Injection', description: 'Test for SQL injection vulnerabilities', icon: AlertTriangle },
    { key: 'xssScanning', label: 'XSS Scanning', description: 'Cross-site scripting detection', icon: AlertTriangle },
    { key: 'lfiScanning', label: 'LFI Scanning', description: 'Local file inclusion testing', icon: AlertTriangle },
    { key: 'corsCheck', label: 'CORS Check', description: 'Cross-origin resource sharing misconfig', icon: Shield },
    { key: 'hostHeaderInjection', label: 'Host Header Injection', description: 'Test host header vulnerabilities', icon: AlertTriangle },
    { key: 'ipLookup', label: 'IP Lookup', description: 'Resolve IP addresses and geolocation', icon: Shield },
    { key: 'contentLength', label: 'Content Length', description: 'Analyze response content lengths', icon: Shield },
    { key: 'securityHeaders', label: 'Security Headers', description: 'Check security-related HTTP headers', icon: Shield },
    { key: 'cveScanning', label: 'CVE Scanning', description: 'Check for known vulnerabilities', icon: AlertTriangle },
    { key: 'jsFileScanning', label: 'JS File Analysis', description: 'Scan JavaScript files for sensitive info', icon: Shield },
  ]

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
    setScanProgress(0)

    // Simulate scanning progress
    const totalSteps = selectedScans.length * (scanMode === 'single' ? 1 : urlList.length)
    let currentStep = 0

    const progressInterval = setInterval(() => {
      currentStep++
      setScanProgress((currentStep / totalSteps) * 100)
      
      if (currentStep >= totalSteps) {
        clearInterval(progressInterval)
        setIsScanning(false)
        setScanProgress(100)
        toast.success('Scan completed successfully!')
        
        // Reset progress after a delay
        setTimeout(() => setScanProgress(0), 2000)
      }
    }, 500)

    toast.success('Scan started!')
  }

  const toggleScanOption = (key: keyof ScanConfig) => {
    setScanConfig(prev => ({
      ...prev,
      [key]: !prev[key]
    }))
  }

  return (
    <div className="space-y-8">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold text-gray-900">Security Scanner</h1>
        <p className="text-gray-600 mt-1">Configure and run comprehensive security scans</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Scan Configuration */}
        <div className="lg:col-span-2 space-y-6">
          {/* Target Configuration */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="card"
          >
            <h3 className="text-lg font-semibold text-gray-900 mb-4">Target Configuration</h3>
            
            {/* Scan Mode Toggle */}
            <div className="flex space-x-1 mb-6 bg-gray-100 p-1 rounded-lg">
              <button
                onClick={() => setScanMode('single')}
                className={`flex-1 py-2 px-4 rounded-md text-sm font-medium transition-colors ${
                  scanMode === 'single'
                    ? 'bg-white text-gray-900 shadow-sm'
                    : 'text-gray-600 hover:text-gray-900'
                }`}
              >
                Single URL
              </button>
              <button
                onClick={() => setScanMode('bulk')}
                className={`flex-1 py-2 px-4 rounded-md text-sm font-medium transition-colors ${
                  scanMode === 'bulk'
                    ? 'bg-white text-gray-900 shadow-sm'
                    : 'text-gray-600 hover:text-gray-900'
                }`}
              >
                Bulk URLs
              </button>
            </div>

            {scanMode === 'single' ? (
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-2">
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
                <label className="block text-sm font-medium text-gray-700 mb-2">
                  Upload URL List
                </label>
                <div className="border-2 border-dashed border-gray-300 rounded-lg p-6 text-center hover:border-gray-400 transition-colors">
                  <Upload className="w-8 h-8 text-gray-400 mx-auto mb-2" />
                  <p className="text-sm text-gray-600 mb-2">
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
                    <p className="text-sm text-success-600 mt-2">
                      {urlList.length} URLs loaded
                    </p>
                  )}
                </div>
              </div>
            )}
          </motion.div>

          {/* Scan Options */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 }}
            className="card"
          >
            <h3 className="text-lg font-semibold text-gray-900 mb-4">Scan Options</h3>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {scanOptions.map((option) => (
                <div
                  key={option.key}
                  className={`p-4 border rounded-lg cursor-pointer transition-all duration-200 ${
                    scanConfig[option.key as keyof ScanConfig]
                      ? 'border-primary-300 bg-primary-50'
                      : 'border-gray-200 hover:border-gray-300'
                  }`}
                  onClick={() => toggleScanOption(option.key as keyof ScanConfig)}
                >
                  <div className="flex items-start space-x-3">
                    <div className={`p-2 rounded-lg ${
                      scanConfig[option.key as keyof ScanConfig]
                        ? 'bg-primary-100'
                        : 'bg-gray-100'
                    }`}>
                      <option.icon className={`w-4 h-4 ${
                        scanConfig[option.key as keyof ScanConfig]
                          ? 'text-primary-600'
                          : 'text-gray-600'
                      }`} />
                    </div>
                    <div className="flex-1">
                      <h4 className="font-medium text-gray-900">{option.label}</h4>
                      <p className="text-sm text-gray-600 mt-1">{option.description}</p>
                    </div>
                    <div className={`w-5 h-5 rounded border-2 flex items-center justify-center ${
                      scanConfig[option.key as keyof ScanConfig]
                        ? 'border-primary-500 bg-primary-500'
                        : 'border-gray-300'
                    }`}>
                      {scanConfig[option.key as keyof ScanConfig] && (
                        <CheckCircle className="w-3 h-3 text-white" />
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </motion.div>
        </div>

        {/* Scan Control Panel */}
        <div className="space-y-6">
          <motion.div
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.2 }}
            className="card"
          >
            <h3 className="text-lg font-semibold text-gray-900 mb-4">Scan Control</h3>
            
            {isScanning ? (
              <div className="space-y-4">
                <div className="flex items-center justify-center">
                  <div className="loading-dots">
                    <div></div>
                    <div></div>
                    <div></div>
                    <div></div>
                  </div>
                </div>
                <div>
                  <div className="flex justify-between text-sm text-gray-600 mb-2">
                    <span>Scanning in progress...</span>
                    <span>{Math.round(scanProgress)}%</span>
                  </div>
                  <div className="w-full bg-gray-200 rounded-full h-2">
                    <div
                      className="bg-primary-600 h-2 rounded-full transition-all duration-300"
                      style={{ width: `${scanProgress}%` }}
                    ></div>
                  </div>
                </div>
              </div>
            ) : (
              <button
                onClick={handleScan}
                className="btn-primary w-full flex items-center justify-center space-x-2"
              >
                <Play className="w-4 h-4" />
                <span>Start Scan</span>
              </button>
            )}

            <div className="mt-6 pt-6 border-t border-gray-200">
              <h4 className="font-medium text-gray-900 mb-3">Quick Actions</h4>
              <div className="space-y-2">
                <button className="w-full text-left px-3 py-2 text-sm text-gray-600 hover:bg-gray-50 rounded-lg transition-colors">
                  <Settings className="w-4 h-4 inline mr-2" />
                  Advanced Settings
                </button>
                <button className="w-full text-left px-3 py-2 text-sm text-gray-600 hover:bg-gray-50 rounded-lg transition-colors">
                  <Clock className="w-4 h-4 inline mr-2" />
                  Schedule Scan
                </button>
              </div>
            </div>
          </motion.div>

          {/* Scan Summary */}
          <motion.div
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.3 }}
            className="card"
          >
            <h3 className="text-lg font-semibold text-gray-900 mb-4">Scan Summary</h3>
            
            <div className="space-y-3">
              <div className="flex justify-between text-sm">
                <span className="text-gray-600">Target(s):</span>
                <span className="font-medium">
                  {scanMode === 'single' ? (url || 'Not set') : `${urlList.length} URLs`}
                </span>
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-gray-600">Selected scans:</span>
                <span className="font-medium">
                  {Object.values(scanConfig).filter(Boolean).length}
                </span>
              </div>
              <div className="flex justify-between text-sm">
                <span className="text-gray-600">Estimated time:</span>
                <span className="font-medium">
                  {Object.values(scanConfig).filter(Boolean).length * 
                   (scanMode === 'single' ? 1 : urlList.length) * 2} min
                </span>
              </div>
            </div>
          </motion.div>
        </div>
      </div>
    </div>
  )
}

export default Scanner
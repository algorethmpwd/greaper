import React, { useState } from 'react'
import { motion } from 'framer-motion'
import { 
  AlertTriangle, CheckCircle, Info, XCircle, 
  ExternalLink, Copy, Download, Filter,
  Shield, Bug, Lock, Globe, Code, Server
} from 'lucide-react'
import { Finding, ScanResult } from '../types/scanner'
import toast from 'react-hot-toast'

interface ScanResultsEnhancedProps {
  result: ScanResult
}

const ScanResultsEnhanced: React.FC<ScanResultsEnhancedProps> = ({ result }) => {
  const [activeTab, setActiveTab] = useState<'overview' | 'findings' | 'technical'>('overview')
  const [severityFilter, setSeverityFilter] = useState<string>('all')

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'critical': return <XCircle className="w-4 h-4 text-red-600" />
      case 'high': return <AlertTriangle className="w-4 h-4 text-red-500" />
      case 'medium': return <AlertTriangle className="w-4 h-4 text-yellow-500" />
      case 'low': return <Info className="w-4 h-4 text-blue-500" />
      case 'info': return <Info className="w-4 h-4 text-gray-500" />
      default: return <Info className="w-4 h-4 text-gray-500" />
    }
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'text-red-600 dark:text-red-400 bg-red-100 dark:bg-red-900/20 border-red-200 dark:border-red-800'
      case 'high': return 'text-red-500 dark:text-red-400 bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-800'
      case 'medium': return 'text-yellow-600 dark:text-yellow-400 bg-yellow-100 dark:bg-yellow-900/20 border-yellow-200 dark:border-yellow-800'
      case 'low': return 'text-blue-600 dark:text-blue-400 bg-blue-100 dark:bg-blue-900/20 border-blue-200 dark:border-blue-800'
      case 'info': return 'text-gray-600 dark:text-gray-400 bg-gray-100 dark:bg-gray-800 border-gray-200 dark:border-gray-700'
      default: return 'text-gray-600 dark:text-gray-400 bg-gray-100 dark:bg-gray-800 border-gray-200 dark:border-gray-700'
    }
  }

  const getTypeIcon = (type: string) => {
    if (type.toLowerCase().includes('sql')) return <Bug className="w-4 h-4" />
    if (type.toLowerCase().includes('xss')) return <Code className="w-4 h-4" />
    if (type.toLowerCase().includes('cors')) return <Globe className="w-4 h-4" />
    if (type.toLowerCase().includes('header')) return <Shield className="w-4 h-4" />
    if (type.toLowerCase().includes('ssl') || type.toLowerCase().includes('tls')) return <Lock className="w-4 h-4" />
    if (type.toLowerCase().includes('server')) return <Server className="w-4 h-4" />
    return <AlertTriangle className="w-4 h-4" />
  }

  const filteredFindings = result.findings.filter(finding => 
    severityFilter === 'all' || finding.severity === severityFilter
  )

  const severityCounts = result.findings.reduce((acc, finding) => {
    acc[finding.severity] = (acc[finding.severity] || 0) + 1
    return acc
  }, {} as Record<string, number>)

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
    toast.success('Copied to clipboard')
  }

  const exportFindings = () => {
    const exportData = {
      url: result.url,
      timestamp: result.timestamp,
      findings: result.findings,
      metadata: result.metadata
    }
    
    const dataStr = JSON.stringify(exportData, null, 2)
    const dataBlob = new Blob([dataStr], { type: 'application/json' })
    const url = URL.createObjectURL(dataBlob)
    const link = document.createElement('a')
    link.href = url
    link.download = `security_scan_${new Date().toISOString().split('T')[0]}.json`
    link.click()
    URL.revokeObjectURL(url)
    toast.success('Scan results exported')
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-semibold text-gray-900 dark:text-white">Scan Results</h2>
          <p className="text-gray-600 dark:text-gray-400">{result.url}</p>
        </div>
        <div className="flex space-x-2">
          <button
            onClick={exportFindings}
            className="btn-secondary flex items-center space-x-2"
          >
            <Download className="w-4 h-4" />
            <span>Export</span>
          </button>
          <a
            href={result.url}
            target="_blank"
            rel="noopener noreferrer"
            className="btn-primary flex items-center space-x-2"
          >
            <ExternalLink className="w-4 h-4" />
            <span>Visit Site</span>
          </a>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex space-x-1 bg-gray-100 dark:bg-gray-800 p-1 rounded-lg w-fit">
        {[
          { id: 'overview', label: 'Overview' },
          { id: 'findings', label: 'Findings' },
          { id: 'technical', label: 'Technical Details' },
        ].map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id as any)}
            className={`py-2 px-4 rounded-md text-sm font-medium transition-colors ${
              activeTab === tab.id
                ? 'bg-white dark:bg-gray-700 text-gray-900 dark:text-white shadow-sm'
                : 'text-gray-600 dark:text-gray-300 hover:text-gray-900 dark:hover:text-white'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      {activeTab === 'overview' && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="space-y-6"
        >
          {/* Summary Cards */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="card">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-gray-600 dark:text-gray-400">Total Findings</p>
                  <p className="text-2xl font-bold text-gray-900 dark:text-white">{result.findings.length}</p>
                </div>
                <AlertTriangle className="w-8 h-8 text-gray-400" />
              </div>
            </div>
            <div className="card">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-gray-600 dark:text-gray-400">Critical/High</p>
                  <p className="text-2xl font-bold text-red-600 dark:text-red-400">
                    {(severityCounts.critical || 0) + (severityCounts.high || 0)}
                  </p>
                </div>
                <XCircle className="w-8 h-8 text-red-400" />
              </div>
            </div>
            <div className="card">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-gray-600 dark:text-gray-400">Scan Duration</p>
                  <p className="text-2xl font-bold text-gray-900 dark:text-white">{result.metadata.duration}s</p>
                </div>
                <CheckCircle className="w-8 h-8 text-green-400" />
              </div>
            </div>
            <div className="card">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-gray-600 dark:text-gray-400">Requests Made</p>
                  <p className="text-2xl font-bold text-gray-900 dark:text-white">{result.metadata.requestCount}</p>
                </div>
                <Globe className="w-8 h-8 text-blue-400" />
              </div>
            </div>
          </div>

          {/* Severity Breakdown */}
          <div className="card">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Severity Breakdown</h3>
            <div className="space-y-3">
              {['critical', 'high', 'medium', 'low', 'info'].map((severity) => {
                const count = severityCounts[severity] || 0
                const percentage = result.findings.length > 0 ? (count / result.findings.length) * 100 : 0
                
                return (
                  <div key={severity} className="flex items-center space-x-3">
                    {getSeverityIcon(severity)}
                    <span className="capitalize font-medium w-16 text-gray-900 dark:text-white">{severity}</span>
                    <div className="flex-1 bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                      <div
                        className={`h-2 rounded-full ${
                          severity === 'critical' ? 'bg-red-600' :
                          severity === 'high' ? 'bg-red-500' :
                          severity === 'medium' ? 'bg-yellow-500' :
                          severity === 'low' ? 'bg-blue-500' : 'bg-gray-500'
                        }`}
                        style={{ width: `${percentage}%` }}
                      ></div>
                    </div>
                    <span className="text-sm text-gray-600 dark:text-gray-400 w-8">{count}</span>
                  </div>
                )
              })}
            </div>
          </div>

          {/* Technologies Detected */}
          {result.metadata.technologies.length > 0 && (
            <div className="card">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Technologies Detected</h3>
              <div className="flex flex-wrap gap-2">
                {result.metadata.technologies.map((tech, index) => (
                  <span key={index} className="status-badge status-info">
                    {tech}
                  </span>
                ))}
              </div>
            </div>
          )}
        </motion.div>
      )}

      {activeTab === 'findings' && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="space-y-6"
        >
          {/* Filters */}
          <div className="flex items-center space-x-4">
            <div className="flex items-center space-x-2">
              <Filter className="w-4 h-4 text-gray-400" />
              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                className="input-field w-auto"
              >
                <option value="all">All Severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
                <option value="info">Info</option>
              </select>
            </div>
            <span className="text-sm text-gray-600 dark:text-gray-400">
              Showing {filteredFindings.length} of {result.findings.length} findings
            </span>
          </div>

          {/* Findings List */}
          <div className="space-y-4">
            {filteredFindings.map((finding, index) => (
              <motion.div
                key={index}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: index * 0.1 }}
                className={`border rounded-lg p-6 ${getSeverityColor(finding.severity)}`}
              >
                <div className="flex items-start justify-between mb-4">
                  <div className="flex items-center space-x-3">
                    {getTypeIcon(finding.type)}
                    <div>
                      <h4 className="font-semibold text-gray-900 dark:text-white">{finding.type}</h4>
                      <div className="flex items-center space-x-2 mt-1">
                        {getSeverityIcon(finding.severity)}
                        <span className="text-sm font-medium capitalize">{finding.severity}</span>
                        {finding.cveId && (
                          <span className="status-badge status-danger text-xs">
                            {finding.cveId}
                          </span>
                        )}
                      </div>
                    </div>
                  </div>
                  <button
                    onClick={() => copyToClipboard(JSON.stringify(finding, null, 2))}
                    className="p-2 hover:bg-white/50 dark:hover:bg-black/20 rounded-lg transition-colors"
                  >
                    <Copy className="w-4 h-4" />
                  </button>
                </div>

                <div className="space-y-4">
                  <div>
                    <h5 className="font-medium text-gray-900 dark:text-white mb-2">Description</h5>
                    <p className="text-gray-700 dark:text-gray-300">{finding.description}</p>
                  </div>

                  {finding.evidence && (
                    <div>
                      <h5 className="font-medium text-gray-900 dark:text-white mb-2">Evidence</h5>
                      <pre className="bg-gray-900 text-green-400 p-3 rounded-lg text-sm overflow-x-auto">
                        {finding.evidence}
                      </pre>
                    </div>
                  )}

                  <div>
                    <h5 className="font-medium text-gray-900 dark:text-white mb-2">Impact</h5>
                    <p className="text-gray-700 dark:text-gray-300">{finding.impact}</p>
                  </div>

                  <div>
                    <h5 className="font-medium text-gray-900 dark:text-white mb-2">Recommendation</h5>
                    <p className="text-gray-700 dark:text-gray-300">{finding.recommendation}</p>
                  </div>

                  <div>
                    <h5 className="font-medium text-gray-900 dark:text-white mb-2">Remediation</h5>
                    <p className="text-gray-700 dark:text-gray-300">{finding.remediation}</p>
                  </div>

                  {finding.references && finding.references.length > 0 && (
                    <div>
                      <h5 className="font-medium text-gray-900 dark:text-white mb-2">References</h5>
                      <div className="space-y-1">
                        {finding.references.map((ref, refIndex) => (
                          <a
                            key={refIndex}
                            href={ref}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-blue-600 dark:text-blue-400 hover:text-blue-800 dark:hover:text-blue-300 text-sm flex items-center space-x-1"
                          >
                            <ExternalLink className="w-3 h-3" />
                            <span>{ref}</span>
                          </a>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </motion.div>
            ))}
          </div>

          {filteredFindings.length === 0 && (
            <div className="text-center py-12">
              <CheckCircle className="w-12 h-12 text-green-500 mx-auto mb-4" />
              <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">No findings match the filter</h3>
              <p className="text-gray-600 dark:text-gray-400">Try adjusting your filter criteria</p>
            </div>
          )}
        </motion.div>
      )}

      {activeTab === 'technical' && (
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="space-y-6"
        >
          {/* Server Information */}
          <div className="card">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Server Information</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="text-sm font-medium text-gray-600 dark:text-gray-400">Server</label>
                <p className="text-gray-900 dark:text-white">{result.metadata.serverInfo.server}</p>
              </div>
              {result.metadata.serverInfo.version && (
                <div>
                  <label className="text-sm font-medium text-gray-600 dark:text-gray-400">Version</label>
                  <p className="text-gray-900 dark:text-white">{result.metadata.serverInfo.version}</p>
                </div>
              )}
              {result.metadata.serverInfo.os && (
                <div>
                  <label className="text-sm font-medium text-gray-600 dark:text-gray-400">Operating System</label>
                  <p className="text-gray-900 dark:text-white">{result.metadata.serverInfo.os}</p>
                </div>
              )}
              <div>
                <label className="text-sm font-medium text-gray-600 dark:text-gray-400">Response Size</label>
                <p className="text-gray-900 dark:text-white">{(result.metadata.responseSize / 1024).toFixed(2)} KB</p>
              </div>
            </div>
          </div>

          {/* SSL Certificate Information */}
          {result.metadata.certificates && (
            <div className="card">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">SSL Certificate</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="text-sm font-medium text-gray-600 dark:text-gray-400">Issuer</label>
                  <p className="text-gray-900 dark:text-white">{result.metadata.certificates.issuer}</p>
                </div>
                <div>
                  <label className="text-sm font-medium text-gray-600 dark:text-gray-400">Expiry Date</label>
                  <p className="text-gray-900 dark:text-white">{result.metadata.certificates.expiry}</p>
                </div>
                <div>
                  <label className="text-sm font-medium text-gray-600 dark:text-gray-400">Algorithm</label>
                  <p className="text-gray-900 dark:text-white">{result.metadata.certificates.algorithm}</p>
                </div>
                <div>
                  <label className="text-sm font-medium text-gray-600 dark:text-gray-400">Key Size</label>
                  <p className="text-gray-900 dark:text-white">{result.metadata.certificates.keySize} bits</p>
                </div>
              </div>
            </div>
          )}

          {/* Scan Metadata */}
          <div className="card">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Scan Metadata</h3>
            <div className="space-y-3">
              <div className="flex justify-between">
                <span className="text-gray-600 dark:text-gray-400">Scan ID</span>
                <span className="font-mono text-sm text-gray-900 dark:text-white">{result.id}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-600 dark:text-gray-400">Timestamp</span>
                <span className="font-mono text-sm text-gray-900 dark:text-white">{result.timestamp}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-600 dark:text-gray-400">Duration</span>
                <span className="font-mono text-sm text-gray-900 dark:text-white">{result.metadata.duration} seconds</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-600 dark:text-gray-400">Total Requests</span>
                <span className="font-mono text-sm text-gray-900 dark:text-white">{result.metadata.requestCount}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-600 dark:text-gray-400">Scan Types</span>
                <span className="font-mono text-sm text-gray-900 dark:text-white">{result.scanTypes.join(', ')}</span>
              </div>
            </div>
          </div>
        </motion.div>
      )}
    </div>
  )
}

export default ScanResultsEnhanced
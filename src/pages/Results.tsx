import React, { useState } from 'react'
import { motion } from 'framer-motion'
import { Search, Filter, Download, Eye, AlertTriangle, CheckCircle, Clock, Globe } from 'lucide-react'

interface ScanResult {
  id: string
  url: string
  timestamp: string
  status: 'completed' | 'running' | 'failed'
  vulnerabilities: number
  scanTypes: string[]
  findings: {
    type: string
    severity: 'high' | 'medium' | 'low'
    description: string
    recommendation: string
  }[]
}

const Results: React.FC = () => {
  const [searchTerm, setSearchTerm] = useState('')
  const [filterStatus, setFilterStatus] = useState<string>('all')
  const [selectedResult, setSelectedResult] = useState<ScanResult | null>(null)

  const mockResults: ScanResult[] = [
    {
      id: '1',
      url: 'https://example.com',
      timestamp: '2024-01-15 14:30:00',
      status: 'completed',
      vulnerabilities: 3,
      scanTypes: ['Status Codes', 'CORS', 'Security Headers'],
      findings: [
        {
          type: 'Missing Security Headers',
          severity: 'medium',
          description: 'X-Frame-Options header is missing',
          recommendation: 'Add X-Frame-Options: DENY header to prevent clickjacking attacks'
        },
        {
          type: 'CORS Misconfiguration',
          severity: 'high',
          description: 'Wildcard origin allowed in CORS policy',
          recommendation: 'Restrict CORS origins to specific trusted domains'
        },
        {
          type: 'Insecure Content-Type',
          severity: 'low',
          description: 'X-Content-Type-Options header missing',
          recommendation: 'Add X-Content-Type-Options: nosniff header'
        }
      ]
    },
    {
      id: '2',
      url: 'https://test.com',
      timestamp: '2024-01-15 13:15:00',
      status: 'completed',
      vulnerabilities: 0,
      scanTypes: ['Status Codes', 'Security Headers'],
      findings: []
    },
    {
      id: '3',
      url: 'https://demo.org',
      timestamp: '2024-01-15 12:00:00',
      status: 'running',
      vulnerabilities: 0,
      scanTypes: ['Directory Fuzzing', 'XSS'],
      findings: []
    },
    {
      id: '4',
      url: 'https://sample.net',
      timestamp: '2024-01-14 16:45:00',
      status: 'completed',
      vulnerabilities: 7,
      scanTypes: ['SQL Injection', 'XSS', 'LFI'],
      findings: [
        {
          type: 'SQL Injection',
          severity: 'high',
          description: 'SQL injection vulnerability found in login form',
          recommendation: 'Use parameterized queries and input validation'
        },
        {
          type: 'Cross-Site Scripting',
          severity: 'high',
          description: 'Reflected XSS in search parameter',
          recommendation: 'Implement proper input sanitization and output encoding'
        }
      ]
    }
  ]

  const filteredResults = mockResults.filter(result => {
    const matchesSearch = result.url.toLowerCase().includes(searchTerm.toLowerCase())
    const matchesFilter = filterStatus === 'all' || result.status === filterStatus
    return matchesSearch && matchesFilter
  })

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'high': return 'text-danger-600 dark:text-danger-400 bg-danger-100 dark:bg-danger-900/20'
      case 'medium': return 'text-warning-600 dark:text-warning-400 bg-warning-100 dark:bg-warning-900/20'
      case 'low': return 'text-primary-600 dark:text-primary-400 bg-primary-100 dark:bg-primary-900/20'
      default: return 'text-gray-600 dark:text-gray-400 bg-gray-100 dark:bg-gray-800'
    }
  }

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed': return <CheckCircle className="w-4 h-4 text-success-500" />
      case 'running': return <Clock className="w-4 h-4 text-primary-500" />
      case 'failed': return <AlertTriangle className="w-4 h-4 text-danger-500" />
      default: return null
    }
  }

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Scan Results</h1>
          <p className="text-gray-600 dark:text-gray-400 mt-1">View and analyze your security scan results</p>
        </div>
        <button className="btn-primary flex items-center space-x-2">
          <Download className="w-4 h-4" />
          <span>Export Results</span>
        </button>
      </div>

      {/* Filters */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="card"
      >
        <div className="flex flex-col sm:flex-row gap-4">
          <div className="flex-1">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-4 h-4" />
              <input
                type="text"
                placeholder="Search by URL..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="input-field pl-10"
              />
            </div>
          </div>
          <div className="flex items-center space-x-2">
            <Filter className="w-4 h-4 text-gray-400" />
            <select
              value={filterStatus}
              onChange={(e) => setFilterStatus(e.target.value)}
              className="input-field w-auto"
            >
              <option value="all">All Status</option>
              <option value="completed">Completed</option>
              <option value="running">Running</option>
              <option value="failed">Failed</option>
            </select>
          </div>
        </div>
      </motion.div>

      {/* Results Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Results List */}
        <div className="space-y-4">
          {filteredResults.map((result, index) => (
            <motion.div
              key={result.id}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: index * 0.1 }}
              className={`card cursor-pointer transition-all duration-200 hover:shadow-md ${
                selectedResult?.id === result.id ? 'ring-2 ring-primary-500' : ''
              }`}
              onClick={() => setSelectedResult(result)}
            >
              <div className="flex items-start justify-between mb-3">
                <div className="flex items-center space-x-2">
                  <Globe className="w-4 h-4 text-gray-400" />
                  <span className="font-medium text-gray-900 dark:text-white truncate">{result.url}</span>
                </div>
                {getStatusIcon(result.status)}
              </div>

              <div className="flex items-center justify-between mb-3">
                <span className="text-sm text-gray-500 dark:text-gray-400">{result.timestamp}</span>
                <div className="flex items-center space-x-2">
                  {result.vulnerabilities > 0 ? (
                    <span className="status-badge status-danger">
                      {result.vulnerabilities} vulnerabilities
                    </span>
                  ) : (
                    <span className="status-badge status-success">
                      Secure
                    </span>
                  )}
                </div>
              </div>

              <div className="flex flex-wrap gap-1">
                {result.scanTypes.map((type) => (
                  <span key={type} className="status-badge status-info text-xs">
                    {type}
                  </span>
                ))}
              </div>
            </motion.div>
          ))}

          {filteredResults.length === 0 && (
            <div className="text-center py-12">
              <AlertTriangle className="w-12 h-12 text-gray-400 mx-auto mb-4" />
              <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">No results found</h3>
              <p className="text-gray-600 dark:text-gray-400">Try adjusting your search or filter criteria</p>
            </div>
          )}
        </div>

        {/* Result Details */}
        <div className="lg:sticky lg:top-8">
          {selectedResult ? (
            <motion.div
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              className="card"
            >
              <div className="flex items-center justify-between mb-6">
                <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Scan Details</h3>
                <button className="btn-secondary flex items-center space-x-2">
                  <Eye className="w-4 h-4" />
                  <span>View Full Report</span>
                </button>
              </div>

              <div className="space-y-4 mb-6">
                <div>
                  <label className="text-sm font-medium text-gray-600 dark:text-gray-400">URL</label>
                  <p className="text-gray-900 dark:text-white break-all">{selectedResult.url}</p>
                </div>
                <div>
                  <label className="text-sm font-medium text-gray-600 dark:text-gray-400">Scan Date</label>
                  <p className="text-gray-900 dark:text-white">{selectedResult.timestamp}</p>
                </div>
                <div>
                  <label className="text-sm font-medium text-gray-600 dark:text-gray-400">Status</label>
                  <div className="flex items-center space-x-2 mt-1">
                    {getStatusIcon(selectedResult.status)}
                    <span className="capitalize text-gray-900 dark:text-white">{selectedResult.status}</span>
                  </div>
                </div>
              </div>

              {selectedResult.findings.length > 0 ? (
                <div>
                  <h4 className="font-medium text-gray-900 dark:text-white mb-4">Findings</h4>
                  <div className="space-y-4">
                    {selectedResult.findings.map((finding, index) => (
                      <div key={index} className="border border-gray-200 dark:border-gray-700 rounded-lg p-4">
                        <div className="flex items-center justify-between mb-2">
                          <h5 className="font-medium text-gray-900 dark:text-white">{finding.type}</h5>
                          <span className={`status-badge ${getSeverityColor(finding.severity)}`}>
                            {finding.severity.toUpperCase()}
                          </span>
                        </div>
                        <p className="text-sm text-gray-600 dark:text-gray-400 mb-3">{finding.description}</p>
                        <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-3">
                          <p className="text-sm text-blue-800 dark:text-blue-300">
                            <strong>Recommendation:</strong> {finding.recommendation}
                          </p>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              ) : (
                <div className="text-center py-8">
                  <CheckCircle className="w-12 h-12 text-success-500 mx-auto mb-4" />
                  <h4 className="font-medium text-gray-900 dark:text-white mb-2">No vulnerabilities found</h4>
                  <p className="text-gray-600 dark:text-gray-400">This URL appears to be secure based on the selected scans.</p>
                </div>
              )}
            </motion.div>
          ) : (
            <div className="card">
              <div className="text-center py-12">
                <Eye className="w-12 h-12 text-gray-400 mx-auto mb-4" />
                <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">Select a scan result</h3>
                <p className="text-gray-600 dark:text-gray-400">Choose a scan from the list to view detailed findings</p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export default Results
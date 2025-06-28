import React, { useState } from 'react'
import { motion } from 'framer-motion'
import { 
  Shield, AlertTriangle, Search, Globe, Clock, Zap, 
  Database, Code, Mail, Share2, Server, Lock, 
  Activity, TrendingUp, FileText, Map, Wifi, 
  Eye, Brain, Target, Layers, Network
} from 'lucide-react'
import { ScanConfig } from '../types/scanner'

interface AdvancedScanOptionsProps {
  scanConfig: ScanConfig
  onConfigChange: (config: ScanConfig) => void
}

const AdvancedScanOptions: React.FC<AdvancedScanOptionsProps> = ({
  scanConfig,
  onConfigChange
}) => {
  const [activeCategory, setActiveCategory] = useState('basic')

  const scanCategories = {
    basic: {
      title: 'Basic Security Scans',
      icon: Shield,
      color: 'primary',
      options: [
        { key: 'statusCodes', label: 'Status Code Analysis', description: 'Check HTTP response codes and identify accessible endpoints', icon: Globe },
        { key: 'directoryFuzzing', label: 'Directory Fuzzing', description: 'Discover hidden directories and files using wordlists', icon: Search },
        { key: 'subdomainEnum', label: 'Subdomain Enumeration', description: 'Find subdomains using DNS queries and certificate transparency', icon: Globe },
        { key: 'robotsTxtCheck', label: 'Robots.txt Analysis', description: 'Analyze robots.txt for sensitive paths and information disclosure', icon: FileText },
        { key: 'sitemapCheck', label: 'Sitemap Discovery', description: 'Find and analyze XML sitemaps for additional endpoints', icon: Map },
        { key: 'contentDiscovery', label: 'Content Discovery', description: 'Advanced content discovery using multiple techniques', icon: Eye },
      ]
    },
    vulnerabilities: {
      title: 'Vulnerability Testing',
      icon: AlertTriangle,
      color: 'danger',
      options: [
        { key: 'sqlInjection', label: 'SQL Injection', description: 'Test for SQL injection vulnerabilities in forms and parameters', icon: Database },
        { key: 'xssScanning', label: 'Cross-Site Scripting (XSS)', description: 'Detect reflected, stored, and DOM-based XSS vulnerabilities', icon: Code },
        { key: 'lfiScanning', label: 'Local File Inclusion', description: 'Test for local file inclusion vulnerabilities', icon: FileText },
        { key: 'rfiScanning', label: 'Remote File Inclusion', description: 'Test for remote file inclusion vulnerabilities', icon: Globe },
        { key: 'xxeScanning', label: 'XML External Entity (XXE)', description: 'Test for XXE injection vulnerabilities in XML parsers', icon: Code },
        { key: 'ssrfScanning', label: 'Server-Side Request Forgery', description: 'Test for SSRF vulnerabilities that could access internal resources', icon: Server },
        { key: 'commandInjection', label: 'Command Injection', description: 'Test for OS command injection vulnerabilities', icon: AlertTriangle },
        { key: 'ldapInjection', label: 'LDAP Injection', description: 'Test for LDAP injection vulnerabilities', icon: Database },
      ]
    },
    security: {
      title: 'Security Configuration',
      icon: Lock,
      color: 'warning',
      options: [
        { key: 'corsCheck', label: 'CORS Misconfiguration', description: 'Check for overly permissive CORS policies', icon: Share2 },
        { key: 'hostHeaderInjection', label: 'Host Header Injection', description: 'Test for host header injection vulnerabilities', icon: Server },
        { key: 'securityHeaders', label: 'Security Headers Analysis', description: 'Analyze HTTP security headers (HSTS, CSP, X-Frame-Options)', icon: Shield },
        { key: 'tlsConfiguration', label: 'TLS/SSL Configuration', description: 'Analyze SSL/TLS configuration and certificate details', icon: Lock },
        { key: 'httpMethodTesting', label: 'HTTP Method Testing', description: 'Test for dangerous HTTP methods (PUT, DELETE, TRACE)', icon: Network },
        { key: 'clickjackingTest', label: 'Clickjacking Protection', description: 'Test for clickjacking vulnerabilities', icon: Eye },
      ]
    },
    intelligence: {
      title: 'Information Gathering',
      icon: Search,
      color: 'primary',
      options: [
        { key: 'ipLookup', label: 'IP & Geolocation Analysis', description: 'Resolve IP addresses and gather geolocation information', icon: Globe },
        { key: 'technologyDetection', label: 'Technology Stack Detection', description: 'Identify web technologies, frameworks, and CMS platforms', icon: Code },
        { key: 'jsFileScanning', label: 'JavaScript Analysis', description: 'Scan JS files for API keys, secrets, and sensitive information', icon: Code },
        { key: 'emailHarvesting', label: 'Email Address Discovery', description: 'Extract email addresses from web pages and source code', icon: Mail },
        { key: 'socialMediaLinks', label: 'Social Media Discovery', description: 'Find social media profiles and accounts linked to the target', icon: Share2 },
        { key: 'metadataExtraction', label: 'Metadata Extraction', description: 'Extract metadata from documents and images', icon: FileText },
        { key: 'dnsEnumeration', label: 'DNS Enumeration', description: 'Comprehensive DNS record enumeration', icon: Wifi },
      ]
    },
    advanced: {
      title: 'Advanced Testing',
      icon: Zap,
      color: 'success',
      options: [
        { key: 'cveScanning', label: 'CVE Vulnerability Scanning', description: 'Check for known CVEs based on detected technologies', icon: AlertTriangle },
        { key: 'portScanning', label: 'Port Scanning', description: 'Scan common ports to identify running services', icon: Server },
        { key: 'contentLength', label: 'Content Length Analysis', description: 'Analyze response sizes to identify potential information leaks', icon: Activity },
        { key: 'fuzzing', label: 'Advanced Fuzzing', description: 'Comprehensive fuzzing with custom payloads', icon: Target },
        { key: 'apiTesting', label: 'API Security Testing', description: 'Test REST/GraphQL APIs for security issues', icon: Layers },
        { key: 'authenticationTesting', label: 'Authentication Testing', description: 'Test authentication mechanisms and session management', icon: Lock },
        { key: 'businessLogicTesting', label: 'Business Logic Testing', description: 'Test for business logic flaws and race conditions', icon: Brain },
      ]
    },
    monitoring: {
      title: 'Performance & Monitoring',
      icon: TrendingUp,
      color: 'primary',
      options: [
        { key: 'responseTimeAnalysis', label: 'Response Time Analysis', description: 'Measure and analyze response times for performance insights', icon: Clock },
        { key: 'loadTesting', label: 'Basic Load Testing', description: 'Perform basic load testing to identify performance bottlenecks', icon: Activity },
        { key: 'uptimeMonitoring', label: 'Uptime Monitoring', description: 'Monitor target availability over time', icon: TrendingUp },
        { key: 'resourceAnalysis', label: 'Resource Analysis', description: 'Analyze resource usage and optimization opportunities', icon: Activity },
        { key: 'cacheAnalysis', label: 'Cache Analysis', description: 'Analyze caching mechanisms and effectiveness', icon: Database },
      ]
    }
  }

  const toggleScanOption = (key: keyof ScanConfig) => {
    onConfigChange({
      ...scanConfig,
      [key]: !scanConfig[key]
    })
  }

  const getColorClasses = (color: string) => {
    const colors = {
      primary: 'border-primary-300 bg-primary-50 dark:bg-primary-900/20 text-primary-600 dark:text-primary-400',
      danger: 'border-danger-300 bg-danger-50 dark:bg-danger-900/20 text-danger-600 dark:text-danger-400',
      warning: 'border-warning-300 bg-warning-50 dark:bg-warning-900/20 text-warning-600 dark:text-warning-400',
      success: 'border-success-300 bg-success-50 dark:bg-success-900/20 text-success-600 dark:text-success-400',
    }
    return colors[color as keyof typeof colors] || colors.primary
  }

  return (
    <div className="space-y-6">
      {/* Category Tabs */}
      <div className="flex flex-wrap gap-2">
        {Object.entries(scanCategories).map(([key, category]) => (
          <button
            key={key}
            onClick={() => setActiveCategory(key)}
            className={`flex items-center space-x-2 px-4 py-2 rounded-lg text-sm font-medium transition-all duration-200 ${
              activeCategory === key
                ? `${getColorClasses(category.color)} border`
                : 'text-gray-600 dark:text-gray-300 hover:text-gray-900 dark:hover:text-white hover:bg-gray-100 dark:hover:bg-gray-800'
            }`}
          >
            <category.icon className="w-4 h-4" />
            <span>{category.title}</span>
          </button>
        ))}
      </div>

      {/* Scan Options */}
      <motion.div
        key={activeCategory}
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3 }}
        className="grid grid-cols-1 md:grid-cols-2 gap-4"
      >
        {scanCategories[activeCategory as keyof typeof scanCategories].options.map((option) => (
          <div
            key={option.key}
            className={`p-4 border rounded-lg cursor-pointer transition-all duration-200 ${
              scanConfig[option.key as keyof ScanConfig]
                ? 'border-primary-300 bg-primary-50 dark:bg-primary-900/20 dark:border-primary-700'
                : 'border-gray-200 dark:border-gray-700 hover:border-gray-300 dark:hover:border-gray-600'
            }`}
            onClick={() => toggleScanOption(option.key as keyof ScanConfig)}
          >
            <div className="flex items-start space-x-3">
              <div className={`p-2 rounded-lg ${
                scanConfig[option.key as keyof ScanConfig]
                  ? 'bg-primary-100 dark:bg-primary-800'
                  : 'bg-gray-100 dark:bg-gray-800'
              }`}>
                <option.icon className={`w-4 h-4 ${
                  scanConfig[option.key as keyof ScanConfig]
                    ? 'text-primary-600 dark:text-primary-400'
                    : 'text-gray-600 dark:text-gray-400'
                }`} />
              </div>
              <div className="flex-1">
                <h4 className="font-medium text-gray-900 dark:text-white">{option.label}</h4>
                <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">{option.description}</p>
              </div>
              <div className={`w-5 h-5 rounded border-2 flex items-center justify-center ${
                scanConfig[option.key as keyof ScanConfig]
                  ? 'border-primary-500 bg-primary-500'
                  : 'border-gray-300 dark:border-gray-600'
              }`}>
                {scanConfig[option.key as keyof ScanConfig] && (
                  <div className="w-2 h-2 bg-white rounded-full"></div>
                )}
              </div>
            </div>
          </div>
        ))}
      </motion.div>

      {/* Quick Presets */}
      <div className="border-t pt-6 dark:border-gray-700">
        <h4 className="font-medium text-gray-900 dark:text-white mb-4">Quick Presets</h4>
        <div className="flex flex-wrap gap-2">
          <button
            onClick={() => onConfigChange({
              ...scanConfig,
              statusCodes: true,
              securityHeaders: true,
              corsCheck: true,
              tlsConfiguration: true,
              robotsTxtCheck: true,
            })}
            className="btn-secondary text-sm"
          >
            Basic Security Audit
          </button>
          <button
            onClick={() => onConfigChange({
              ...scanConfig,
              sqlInjection: true,
              xssScanning: true,
              lfiScanning: true,
              rfiScanning: true,
              xxeScanning: true,
              ssrfScanning: true,
            })}
            className="btn-secondary text-sm"
          >
            Vulnerability Assessment
          </button>
          <button
            onClick={() => onConfigChange({
              ...scanConfig,
              directoryFuzzing: true,
              subdomainEnum: true,
              technologyDetection: true,
              emailHarvesting: true,
              jsFileScanning: true,
            })}
            className="btn-secondary text-sm"
          >
            Information Gathering
          </button>
          <button
            onClick={() => {
              const allOptions = Object.keys(scanConfig) as (keyof ScanConfig)[]
              const newConfig = { ...scanConfig }
              allOptions.forEach(key => {
                newConfig[key] = true
              })
              onConfigChange(newConfig)
            }}
            className="btn-primary text-sm"
          >
            Comprehensive Scan
          </button>
        </div>
      </div>
    </div>
  )
}

export default AdvancedScanOptions
export interface ScanConfig {
  // Basic Scans
  statusCodes: boolean
  directoryFuzzing: boolean
  subdomainEnum: boolean
  contentDiscovery: boolean
  
  // Vulnerability Scans
  sqlInjection: boolean
  xssScanning: boolean
  lfiScanning: boolean
  rfiScanning: boolean
  xxeScanning: boolean
  ssrfScanning: boolean
  commandInjection: boolean
  ldapInjection: boolean
  
  // Security Checks
  corsCheck: boolean
  hostHeaderInjection: boolean
  securityHeaders: boolean
  tlsConfiguration: boolean
  httpMethodTesting: boolean
  clickjackingTest: boolean
  
  // Information Gathering
  ipLookup: boolean
  contentLength: boolean
  jsFileScanning: boolean
  robotsTxtCheck: boolean
  sitemapCheck: boolean
  metadataExtraction: boolean
  dnsEnumeration: boolean
  
  // Advanced Scans
  cveScanning: boolean
  portScanning: boolean
  technologyDetection: boolean
  emailHarvesting: boolean
  socialMediaLinks: boolean
  fuzzing: boolean
  apiTesting: boolean
  authenticationTesting: boolean
  businessLogicTesting: boolean
  
  // Performance & Monitoring
  responseTimeAnalysis: boolean
  loadTesting: boolean
  uptimeMonitoring: boolean
  resourceAnalysis: boolean
  cacheAnalysis: boolean
}

export interface ScanResult {
  id: string
  url: string
  timestamp: string
  status: 'completed' | 'running' | 'failed' | 'queued'
  vulnerabilities: number
  scanTypes: string[]
  findings: Finding[]
  metadata: ScanMetadata
}

export interface Finding {
  type: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  description: string
  recommendation: string
  evidence?: string
  cveId?: string
  references?: string[]
  impact: string
  remediation: string
}

export interface ScanMetadata {
  duration: number
  requestCount: number
  responseSize: number
  technologies: string[]
  serverInfo: {
    server: string
    version?: string
    os?: string
  }
  certificates?: {
    issuer: string
    expiry: string
    algorithm: string
    keySize: number
  }
}

export interface PayloadSet {
  name: string
  category: string
  payloads: string[]
  description: string
}
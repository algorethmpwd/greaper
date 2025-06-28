export interface ExportData {
  type: 'scan_results' | 'ai_chat' | 'counsel_session' | 'payload_set'
  timestamp: string
  data: any
  metadata?: any
}

export const exportToFile = (data: any, filename: string, type: 'json' | 'csv' | 'txt' = 'json') => {
  try {
    let content: string
    let mimeType: string
    let fileExtension: string

    switch (type) {
      case 'json':
        content = JSON.stringify(data, null, 2)
        mimeType = 'application/json'
        fileExtension = '.json'
        break
      case 'csv':
        content = convertToCSV(data)
        mimeType = 'text/csv'
        fileExtension = '.csv'
        break
      case 'txt':
        content = typeof data === 'string' ? data : JSON.stringify(data, null, 2)
        mimeType = 'text/plain'
        fileExtension = '.txt'
        break
      default:
        throw new Error(`Unsupported export type: ${type}`)
    }

    const blob = new Blob([content], { type: mimeType })
    const url = URL.createObjectURL(blob)
    
    const link = document.createElement('a')
    link.href = url
    link.download = filename.endsWith(fileExtension) ? filename : `${filename}${fileExtension}`
    
    // Append to body, click, and remove
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
    
    // Clean up the URL
    setTimeout(() => URL.revokeObjectURL(url), 100)
    
    return true
  } catch (error) {
    console.error('Export failed:', error)
    return false
  }
}

export const convertToCSV = (data: any): string => {
  if (!Array.isArray(data)) {
    // If it's a single object, wrap it in an array
    data = [data]
  }

  if (data.length === 0) {
    return ''
  }

  // Get all unique keys from all objects
  const allKeys = new Set<string>()
  data.forEach((item: any) => {
    if (typeof item === 'object' && item !== null) {
      Object.keys(item).forEach(key => allKeys.add(key))
    }
  })

  const headers = Array.from(allKeys)
  const csvRows = [headers.join(',')]

  data.forEach((item: any) => {
    const row = headers.map(header => {
      const value = item[header]
      if (value === null || value === undefined) {
        return ''
      }
      // Escape quotes and wrap in quotes if contains comma or quote
      const stringValue = String(value)
      if (stringValue.includes(',') || stringValue.includes('"') || stringValue.includes('\n')) {
        return `"${stringValue.replace(/"/g, '""')}"`
      }
      return stringValue
    })
    csvRows.push(row.join(','))
  })

  return csvRows.join('\n')
}

export const exportScanResults = (results: any, format: 'json' | 'csv' = 'json') => {
  const timestamp = new Date().toISOString().split('T')[0]
  const filename = `greaper_scan_results_${timestamp}`
  
  const exportData: ExportData = {
    type: 'scan_results',
    timestamp: new Date().toISOString(),
    data: results,
    metadata: {
      exportedBy: 'Greaper Security Scanner',
      version: '2.0.0',
      totalFindings: results.findings?.length || 0
    }
  }

  return exportToFile(exportData, filename, format)
}

export const exportAIChat = (messages: any[], settings: any) => {
  const timestamp = new Date().toISOString().split('T')[0]
  const filename = `greaper_ai_chat_${timestamp}`
  
  const exportData: ExportData = {
    type: 'ai_chat',
    timestamp: new Date().toISOString(),
    data: {
      messages,
      settings,
      messageCount: messages.length
    },
    metadata: {
      exportedBy: 'Greaper AI Assistant',
      version: '2.0.0'
    }
  }

  return exportToFile(exportData, filename, 'json')
}

export const exportCounselSession = (session: any) => {
  const timestamp = new Date().toISOString().split('T')[0]
  const filename = `greaper_counsel_session_${timestamp}`
  
  const exportData: ExportData = {
    type: 'counsel_session',
    timestamp: new Date().toISOString(),
    data: session,
    metadata: {
      exportedBy: 'Greaper AI Counsel',
      version: '2.0.0',
      agentCount: session.agents?.length || 0,
      messageCount: session.messages?.length || 0
    }
  }

  return exportToFile(exportData, filename, 'json')
}

export const exportPayloadSet = (payloadSet: any) => {
  const timestamp = new Date().toISOString().split('T')[0]
  const filename = `greaper_payloads_${payloadSet.name.replace(/\s+/g, '_')}_${timestamp}`
  
  return exportToFile(payloadSet, filename, 'json')
}
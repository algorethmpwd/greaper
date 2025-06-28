export interface ChatSession {
  id: string
  name: string
  type: 'chat' | 'scan' | 'counsel'
  timestamp: Date
  lastActivity: Date
  messages: any[]
  settings: any
  metadata: {
    provider?: string
    model?: string
    target?: string
    agents?: string[]
    totalMessages: number
    vulnerabilitiesFound?: number
  }
}

export interface ModelProvider {
  id: string
  name: string
  models: ModelInfo[]
  requiresApiKey: boolean
  baseUrl?: string
}

export interface ModelInfo {
  id: string
  name: string
  description: string
  contextLength: number
  pricing?: {
    input: number
    output: number
  }
  capabilities: string[]
}

export interface SessionManager {
  sessions: ChatSession[]
  currentSession?: string
  autoSave: boolean
  maxSessions: number
}

export interface OpenRouterModel {
  id: string
  name: string
  description: string
  context_length: number
  pricing: {
    prompt: string
    completion: string
  }
  top_provider: {
    context_length: number
    max_completion_tokens: number
  }
}
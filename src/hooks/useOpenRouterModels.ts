import { useState, useEffect } from 'react'
import { OpenRouterModel, ModelInfo } from '../types/sessions'

export const useOpenRouterModels = () => {
  const [models, setModels] = useState<ModelInfo[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const fetchOpenRouterModels = async () => {
    setLoading(true)
    setError(null)
    
    try {
      // Mock OpenRouter API response for demo
      const mockModels: OpenRouterModel[] = [
        {
          id: 'anthropic/claude-3-opus',
          name: 'Claude 3 Opus',
          description: 'Most capable model for complex tasks',
          context_length: 200000,
          pricing: { prompt: '0.000015', completion: '0.000075' },
          top_provider: { context_length: 200000, max_completion_tokens: 4096 }
        },
        {
          id: 'anthropic/claude-3-sonnet',
          name: 'Claude 3 Sonnet',
          description: 'Balanced performance and speed',
          context_length: 200000,
          pricing: { prompt: '0.000003', completion: '0.000015' },
          top_provider: { context_length: 200000, max_completion_tokens: 4096 }
        },
        {
          id: 'anthropic/claude-3-haiku',
          name: 'Claude 3 Haiku',
          description: 'Fastest model for simple tasks',
          context_length: 200000,
          pricing: { prompt: '0.00000025', completion: '0.00000125' },
          top_provider: { context_length: 200000, max_completion_tokens: 4096 }
        },
        {
          id: 'openai/gpt-4-turbo',
          name: 'GPT-4 Turbo',
          description: 'Latest GPT-4 with improved performance',
          context_length: 128000,
          pricing: { prompt: '0.00001', completion: '0.00003' },
          top_provider: { context_length: 128000, max_completion_tokens: 4096 }
        },
        {
          id: 'openai/gpt-4',
          name: 'GPT-4',
          description: 'Most capable GPT model',
          context_length: 8192,
          pricing: { prompt: '0.00003', completion: '0.00006' },
          top_provider: { context_length: 8192, max_completion_tokens: 4096 }
        },
        {
          id: 'openai/gpt-3.5-turbo',
          name: 'GPT-3.5 Turbo',
          description: 'Fast and efficient for most tasks',
          context_length: 16385,
          pricing: { prompt: '0.0000005', completion: '0.0000015' },
          top_provider: { context_length: 16385, max_completion_tokens: 4096 }
        },
        {
          id: 'google/gemini-pro',
          name: 'Gemini Pro',
          description: 'Google\'s most capable model',
          context_length: 32768,
          pricing: { prompt: '0.000000125', completion: '0.000000375' },
          top_provider: { context_length: 32768, max_completion_tokens: 2048 }
        },
        {
          id: 'google/gemini-pro-vision',
          name: 'Gemini Pro Vision',
          description: 'Multimodal model with vision capabilities',
          context_length: 32768,
          pricing: { prompt: '0.000000125', completion: '0.000000375' },
          top_provider: { context_length: 32768, max_completion_tokens: 2048 }
        },
        {
          id: 'mistralai/mistral-large',
          name: 'Mistral Large',
          description: 'Most capable Mistral model',
          context_length: 32768,
          pricing: { prompt: '0.000008', completion: '0.000024' },
          top_provider: { context_length: 32768, max_completion_tokens: 4096 }
        },
        {
          id: 'mistralai/mistral-medium',
          name: 'Mistral Medium',
          description: 'Balanced Mistral model',
          context_length: 32768,
          pricing: { prompt: '0.0000027', completion: '0.0000081' },
          top_provider: { context_length: 32768, max_completion_tokens: 4096 }
        },
        {
          id: 'mistralai/mistral-small',
          name: 'Mistral Small',
          description: 'Efficient Mistral model',
          context_length: 32768,
          pricing: { prompt: '0.000001', completion: '0.000003' },
          top_provider: { context_length: 32768, max_completion_tokens: 4096 }
        },
        {
          id: 'meta-llama/llama-2-70b-chat',
          name: 'Llama 2 70B Chat',
          description: 'Open source conversational model',
          context_length: 4096,
          pricing: { prompt: '0.00000065', completion: '0.00000275' },
          top_provider: { context_length: 4096, max_completion_tokens: 4096 }
        },
        {
          id: 'meta-llama/codellama-34b-instruct',
          name: 'Code Llama 34B',
          description: 'Specialized for code generation',
          context_length: 16384,
          pricing: { prompt: '0.00000035', completion: '0.00000145' },
          top_provider: { context_length: 16384, max_completion_tokens: 4096 }
        },
        {
          id: 'cohere/command-r-plus',
          name: 'Command R+',
          description: 'Advanced reasoning and tool use',
          context_length: 128000,
          pricing: { prompt: '0.000003', completion: '0.000015' },
          top_provider: { context_length: 128000, max_completion_tokens: 4096 }
        },
        {
          id: 'perplexity/llama-3-sonar-large-32k-online',
          name: 'Llama 3 Sonar Large Online',
          description: 'Real-time web search capabilities',
          context_length: 32768,
          pricing: { prompt: '0.000001', completion: '0.000001' },
          top_provider: { context_length: 32768, max_completion_tokens: 4096 }
        }
      ]

      const convertedModels: ModelInfo[] = mockModels.map(model => ({
        id: model.id,
        name: model.name,
        description: model.description,
        contextLength: model.context_length,
        pricing: {
          input: parseFloat(model.pricing.prompt),
          output: parseFloat(model.pricing.completion)
        },
        capabilities: getModelCapabilities(model.id)
      }))

      setModels(convertedModels)
    } catch (err) {
      setError('Failed to fetch models')
      console.error('Error fetching OpenRouter models:', err)
    } finally {
      setLoading(false)
    }
  }

  const getModelCapabilities = (modelId: string): string[] => {
    const capabilities: Record<string, string[]> = {
      'anthropic/claude-3-opus': ['reasoning', 'analysis', 'coding', 'creative-writing', 'math'],
      'anthropic/claude-3-sonnet': ['reasoning', 'analysis', 'coding', 'creative-writing'],
      'anthropic/claude-3-haiku': ['reasoning', 'analysis', 'coding'],
      'openai/gpt-4-turbo': ['reasoning', 'analysis', 'coding', 'creative-writing', 'vision'],
      'openai/gpt-4': ['reasoning', 'analysis', 'coding', 'creative-writing'],
      'openai/gpt-3.5-turbo': ['reasoning', 'analysis', 'coding'],
      'google/gemini-pro': ['reasoning', 'analysis', 'coding', 'creative-writing'],
      'google/gemini-pro-vision': ['reasoning', 'analysis', 'coding', 'vision', 'multimodal'],
      'mistralai/mistral-large': ['reasoning', 'analysis', 'coding', 'multilingual'],
      'mistralai/mistral-medium': ['reasoning', 'analysis', 'coding'],
      'mistralai/mistral-small': ['reasoning', 'analysis'],
      'meta-llama/llama-2-70b-chat': ['reasoning', 'analysis', 'open-source'],
      'meta-llama/codellama-34b-instruct': ['coding', 'programming', 'open-source'],
      'cohere/command-r-plus': ['reasoning', 'tool-use', 'rag'],
      'perplexity/llama-3-sonar-large-32k-online': ['reasoning', 'web-search', 'real-time']
    }
    
    return capabilities[modelId] || ['general']
  }

  useEffect(() => {
    fetchOpenRouterModels()
  }, [])

  return {
    models,
    loading,
    error,
    refetch: fetchOpenRouterModels
  }
}
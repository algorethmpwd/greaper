import React, { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { 
  Brain, ChevronDown, Search, Star, Zap, Clock, 
  DollarSign, Info, Check, Settings
} from 'lucide-react'
import { useOpenRouterModels } from '../hooks/useOpenRouterModels'
import { ModelInfo } from '../types/sessions'

interface ModelSelectorProps {
  selectedModel: string
  onModelChange: (modelId: string) => void
  selectedProvider: string
  onProviderChange: (provider: string) => void
}

const ModelSelector: React.FC<ModelSelectorProps> = ({
  selectedModel,
  onModelChange,
  selectedProvider,
  onProviderChange
}) => {
  const { models, loading, error } = useOpenRouterModels()
  const [isOpen, setIsOpen] = useState(false)
  const [searchTerm, setSearchTerm] = useState('')
  const [filterCapability, setFilterCapability] = useState<string>('all')

  const providers = [
    { id: 'openai', name: 'OpenAI', models: models.filter(m => m.id.startsWith('openai/')) },
    { id: 'anthropic', name: 'Anthropic', models: models.filter(m => m.id.startsWith('anthropic/')) },
    { id: 'google', name: 'Google', models: models.filter(m => m.id.startsWith('google/')) },
    { id: 'mistralai', name: 'Mistral AI', models: models.filter(m => m.id.startsWith('mistralai/')) },
    { id: 'meta', name: 'Meta', models: models.filter(m => m.id.startsWith('meta-llama/')) },
    { id: 'cohere', name: 'Cohere', models: models.filter(m => m.id.startsWith('cohere/')) },
    { id: 'perplexity', name: 'Perplexity', models: models.filter(m => m.id.startsWith('perplexity/')) },
    { id: 'openrouter', name: 'All Models (OpenRouter)', models: models }
  ]

  const capabilities = [
    'all', 'reasoning', 'analysis', 'coding', 'creative-writing', 
    'vision', 'multimodal', 'tool-use', 'web-search', 'real-time'
  ]

  const filteredModels = models.filter(model => {
    const matchesSearch = model.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         model.description.toLowerCase().includes(searchTerm.toLowerCase())
    const matchesCapability = filterCapability === 'all' || 
                             model.capabilities.includes(filterCapability)
    const matchesProvider = selectedProvider === 'openrouter' || 
                           model.id.startsWith(`${selectedProvider}/`)
    
    return matchesSearch && matchesCapability && matchesProvider
  })

  const selectedModelInfo = models.find(m => m.id === selectedModel)

  const formatPrice = (price: number) => {
    if (price < 0.000001) return `$${(price * 1000000).toFixed(2)}/1M tokens`
    if (price < 0.001) return `$${(price * 1000).toFixed(3)}/1K tokens`
    return `$${price.toFixed(6)}/token`
  }

  const getCapabilityIcon = (capability: string) => {
    const icons: Record<string, React.ReactNode> = {
      reasoning: <Brain className="w-3 h-3" />,
      analysis: <Search className="w-3 h-3" />,
      coding: <Settings className="w-3 h-3" />,
      'creative-writing': <Star className="w-3 h-3" />,
      vision: <Info className="w-3 h-3" />,
      multimodal: <Zap className="w-3 h-3" />,
      'tool-use': <Settings className="w-3 h-3" />,
      'web-search': <Search className="w-3 h-3" />,
      'real-time': <Clock className="w-3 h-3" />
    }
    return icons[capability] || <Info className="w-3 h-3" />
  }

  const getProviderColor = (providerId: string) => {
    const colors: Record<string, string> = {
      openai: 'bg-green-100 dark:bg-green-900/20 text-green-700 dark:text-green-300',
      anthropic: 'bg-orange-100 dark:bg-orange-900/20 text-orange-700 dark:text-orange-300',
      google: 'bg-blue-100 dark:bg-blue-900/20 text-blue-700 dark:text-blue-300',
      mistralai: 'bg-purple-100 dark:bg-purple-900/20 text-purple-700 dark:text-purple-300',
      meta: 'bg-indigo-100 dark:bg-indigo-900/20 text-indigo-700 dark:text-indigo-300',
      cohere: 'bg-pink-100 dark:bg-pink-900/20 text-pink-700 dark:text-pink-300',
      perplexity: 'bg-teal-100 dark:bg-teal-900/20 text-teal-700 dark:text-teal-300'
    }
    return colors[providerId] || 'bg-gray-100 dark:bg-gray-800 text-gray-700 dark:text-gray-300'
  }

  return (
    <div className="relative">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="w-full flex items-center justify-between p-3 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white hover:border-gray-400 dark:hover:border-gray-500 transition-colors"
      >
        <div className="flex items-center space-x-3">
          <Brain className="w-5 h-5 text-gray-500 dark:text-gray-400" />
          <div className="text-left">
            <div className="font-medium">
              {selectedModelInfo?.name || 'Select Model'}
            </div>
            {selectedModelInfo && (
              <div className="text-xs text-gray-500 dark:text-gray-400">
                {selectedModelInfo.contextLength.toLocaleString()} tokens • 
                {selectedModelInfo.pricing && ` ${formatPrice(selectedModelInfo.pricing.input)} input`}
              </div>
            )}
          </div>
        </div>
        <ChevronDown className={`w-4 h-4 transition-transform ${isOpen ? 'rotate-180' : ''}`} />
      </button>

      <AnimatePresence>
        {isOpen && (
          <motion.div
            initial={{ opacity: 0, y: -10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            className="absolute top-full left-0 right-0 mt-2 bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg shadow-lg z-50 max-h-96 overflow-hidden"
          >
            {/* Search and Filters */}
            <div className="p-4 border-b border-gray-200 dark:border-gray-700">
              <div className="space-y-3">
                <div className="relative">
                  <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-4 h-4" />
                  <input
                    type="text"
                    placeholder="Search models..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="w-full pl-10 pr-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm"
                  />
                </div>
                
                <div className="flex space-x-2">
                  <select
                    value={selectedProvider}
                    onChange={(e) => onProviderChange(e.target.value)}
                    className="flex-1 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                  >
                    {providers.map(provider => (
                      <option key={provider.id} value={provider.id}>
                        {provider.name} ({provider.models.length})
                      </option>
                    ))}
                  </select>
                  
                  <select
                    value={filterCapability}
                    onChange={(e) => setFilterCapability(e.target.value)}
                    className="flex-1 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                  >
                    {capabilities.map(capability => (
                      <option key={capability} value={capability}>
                        {capability === 'all' ? 'All Capabilities' : capability.replace('-', ' ')}
                      </option>
                    ))}
                  </select>
                </div>
              </div>
            </div>

            {/* Models List */}
            <div className="max-h-64 overflow-y-auto">
              {loading ? (
                <div className="p-4 text-center text-gray-500 dark:text-gray-400">
                  Loading models...
                </div>
              ) : error ? (
                <div className="p-4 text-center text-red-500">
                  {error}
                </div>
              ) : filteredModels.length === 0 ? (
                <div className="p-4 text-center text-gray-500 dark:text-gray-400">
                  No models found
                </div>
              ) : (
                filteredModels.map((model) => (
                  <button
                    key={model.id}
                    onClick={() => {
                      onModelChange(model.id)
                      setIsOpen(false)
                    }}
                    className={`w-full p-4 text-left hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors border-b border-gray-100 dark:border-gray-700 last:border-b-0 ${
                      selectedModel === model.id ? 'bg-primary-50 dark:bg-primary-900/20' : ''
                    }`}
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <div className="flex items-center space-x-2">
                          <span className="font-medium text-gray-900 dark:text-white">
                            {model.name}
                          </span>
                          {selectedModel === model.id && (
                            <Check className="w-4 h-4 text-primary-600 dark:text-primary-400" />
                          )}
                          <span className={`px-2 py-1 rounded-full text-xs ${getProviderColor(model.id.split('/')[0])}`}>
                            {model.id.split('/')[0]}
                          </span>
                        </div>
                        <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">
                          {model.description}
                        </p>
                        
                        <div className="flex items-center space-x-4 mt-2 text-xs text-gray-500 dark:text-gray-400">
                          <div className="flex items-center space-x-1">
                            <Clock className="w-3 h-3" />
                            <span>{model.contextLength.toLocaleString()} tokens</span>
                          </div>
                          {model.pricing && (
                            <div className="flex items-center space-x-1">
                              <DollarSign className="w-3 h-3" />
                              <span>{formatPrice(model.pricing.input)}</span>
                            </div>
                          )}
                        </div>
                        
                        <div className="flex flex-wrap gap-1 mt-2">
                          {model.capabilities.slice(0, 4).map((capability) => (
                            <span
                              key={capability}
                              className="inline-flex items-center space-x-1 px-2 py-1 bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-full text-xs"
                            >
                              {getCapabilityIcon(capability)}
                              <span>{capability.replace('-', ' ')}</span>
                            </span>
                          ))}
                          {model.capabilities.length > 4 && (
                            <span className="px-2 py-1 bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-full text-xs">
                              +{model.capabilities.length - 4} more
                            </span>
                          )}
                        </div>
                      </div>
                    </div>
                  </button>
                ))
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

export default ModelSelector
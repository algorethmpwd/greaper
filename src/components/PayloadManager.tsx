import React, { useState } from 'react'
import { motion } from 'framer-motion'
import { Upload, Download, Plus, Trash2, Edit, FileText, Database, Code, Globe } from 'lucide-react'
import { PayloadSet } from '../types/scanner'
import toast from 'react-hot-toast'

const PayloadManager: React.FC = () => {
  const [payloadSets, setPayloadSets] = useState<PayloadSet[]>([
    {
      name: 'SQL Injection - Basic',
      category: 'sql',
      description: 'Common SQL injection payloads for basic testing',
      payloads: [
        "' OR '1'='1",
        "' OR 1=1--",
        "' UNION SELECT NULL--",
        "'; DROP TABLE users--",
        "' OR SLEEP(5)--"
      ]
    },
    {
      name: 'XSS - Reflected',
      category: 'xss',
      description: 'Cross-site scripting payloads for reflected XSS testing',
      payloads: [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')",
        "<svg onload=alert('XSS')>",
        "';alert('XSS');//"
      ]
    },
    {
      name: 'Directory Traversal',
      category: 'lfi',
      description: 'Local file inclusion and directory traversal payloads',
      payloads: [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "file:///etc/passwd"
      ]
    },
    {
      name: 'Common Directories',
      category: 'directory',
      description: 'Common directory names for fuzzing',
      payloads: [
        "admin",
        "administrator",
        "login",
        "dashboard",
        "panel",
        "config",
        "backup",
        "test",
        "dev",
        "staging"
      ]
    }
  ])

  const [selectedSet, setSelectedSet] = useState<PayloadSet | null>(null)
  const [isEditing, setIsEditing] = useState(false)
  const [newPayload, setNewPayload] = useState('')

  const categoryIcons = {
    sql: Database,
    xss: Code,
    lfi: FileText,
    directory: Globe,
    default: FileText
  }

  const categoryColors = {
    sql: 'bg-danger-100 dark:bg-danger-900/20 text-danger-600 dark:text-danger-400',
    xss: 'bg-warning-100 dark:bg-warning-900/20 text-warning-600 dark:text-warning-400',
    lfi: 'bg-primary-100 dark:bg-primary-900/20 text-primary-600 dark:text-primary-400',
    directory: 'bg-success-100 dark:bg-success-900/20 text-success-600 dark:text-success-400',
    default: 'bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-400'
  }

  const handleAddPayload = () => {
    if (!selectedSet || !newPayload.trim()) return

    const updatedSet = {
      ...selectedSet,
      payloads: [...selectedSet.payloads, newPayload.trim()]
    }

    setPayloadSets(prev => prev.map(set => 
      set.name === selectedSet.name ? updatedSet : set
    ))
    setSelectedSet(updatedSet)
    setNewPayload('')
    toast.success('Payload added successfully')
  }

  const handleRemovePayload = (index: number) => {
    if (!selectedSet) return

    const updatedSet = {
      ...selectedSet,
      payloads: selectedSet.payloads.filter((_, i) => i !== index)
    }

    setPayloadSets(prev => prev.map(set => 
      set.name === selectedSet.name ? updatedSet : set
    ))
    setSelectedSet(updatedSet)
    toast.success('Payload removed')
  }

  const handleExportPayloads = () => {
    if (!selectedSet) return

    const dataStr = JSON.stringify(selectedSet, null, 2)
    const dataBlob = new Blob([dataStr], { type: 'application/json' })
    const url = URL.createObjectURL(dataBlob)
    const link = document.createElement('a')
    link.href = url
    link.download = `${selectedSet.name.replace(/\s+/g, '_')}_payloads.json`
    link.click()
    URL.revokeObjectURL(url)
    toast.success('Payloads exported successfully')
  }

  const handleImportPayloads = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    if (!file) return

    const reader = new FileReader()
    reader.onload = (e) => {
      try {
        const imported = JSON.parse(e.target?.result as string) as PayloadSet
        setPayloadSets(prev => [...prev, imported])
        toast.success('Payloads imported successfully')
      } catch (error) {
        toast.error('Failed to import payloads. Invalid file format.')
      }
    }
    reader.readAsText(file)
  }

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
      {/* Payload Sets List */}
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Payload Sets</h3>
          <div className="flex space-x-2">
            <input
              type="file"
              accept=".json"
              onChange={handleImportPayloads}
              className="hidden"
              id="import-payloads"
            />
            <label htmlFor="import-payloads" className="btn-secondary text-sm cursor-pointer">
              <Upload className="w-4 h-4 mr-1" />
              Import
            </label>
            <button className="btn-primary text-sm">
              <Plus className="w-4 h-4 mr-1" />
              New Set
            </button>
          </div>
        </div>

        <div className="space-y-3">
          {payloadSets.map((set) => {
            const IconComponent = categoryIcons[set.category as keyof typeof categoryIcons] || categoryIcons.default
            const colorClass = categoryColors[set.category as keyof typeof categoryColors] || categoryColors.default

            return (
              <motion.div
                key={set.name}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                className={`p-4 border rounded-lg cursor-pointer transition-all duration-200 ${
                  selectedSet?.name === set.name
                    ? 'border-primary-300 bg-primary-50 dark:bg-primary-900/20 dark:border-primary-700'
                    : 'border-gray-200 dark:border-gray-700 hover:border-gray-300 dark:hover:border-gray-600'
                }`}
                onClick={() => setSelectedSet(set)}
              >
                <div className="flex items-start space-x-3">
                  <div className={`p-2 rounded-lg ${colorClass}`}>
                    <IconComponent className="w-4 h-4" />
                  </div>
                  <div className="flex-1">
                    <h4 className="font-medium text-gray-900 dark:text-white">{set.name}</h4>
                    <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">{set.description}</p>
                    <div className="flex items-center space-x-4 mt-2 text-xs text-gray-500 dark:text-gray-400">
                      <span>{set.payloads.length} payloads</span>
                      <span className="capitalize">{set.category}</span>
                    </div>
                  </div>
                </div>
              </motion.div>
            )
          })}
        </div>
      </div>

      {/* Payload Editor */}
      <div>
        {selectedSet ? (
          <motion.div
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            className="card"
          >
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-lg font-semibold text-gray-900 dark:text-white">{selectedSet.name}</h3>
              <div className="flex space-x-2">
                <button
                  onClick={handleExportPayloads}
                  className="btn-secondary text-sm"
                >
                  <Download className="w-4 h-4 mr-1" />
                  Export
                </button>
                <button
                  onClick={() => setIsEditing(!isEditing)}
                  className="btn-primary text-sm"
                >
                  <Edit className="w-4 h-4 mr-1" />
                  {isEditing ? 'Done' : 'Edit'}
                </button>
              </div>
            </div>

            <p className="text-gray-600 dark:text-gray-400 mb-4">{selectedSet.description}</p>

            {isEditing && (
              <div className="mb-4 p-4 bg-gray-50 dark:bg-gray-800 rounded-lg">
                <div className="flex space-x-2">
                  <input
                    type="text"
                    value={newPayload}
                    onChange={(e) => setNewPayload(e.target.value)}
                    placeholder="Enter new payload..."
                    className="input-field flex-1"
                    onKeyPress={(e) => e.key === 'Enter' && handleAddPayload()}
                  />
                  <button
                    onClick={handleAddPayload}
                    className="btn-primary"
                  >
                    <Plus className="w-4 h-4" />
                  </button>
                </div>
              </div>
            )}

            <div className="space-y-2 max-h-96 overflow-y-auto">
              {selectedSet.payloads.map((payload, index) => (
                <div
                  key={index}
                  className="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-800 rounded-lg"
                >
                  <code className="text-sm text-gray-800 dark:text-gray-200 flex-1 break-all">
                    {payload}
                  </code>
                  {isEditing && (
                    <button
                      onClick={() => handleRemovePayload(index)}
                      className="ml-2 p-1 text-danger-600 dark:text-danger-400 hover:bg-danger-100 dark:hover:bg-danger-900/20 rounded"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  )}
                </div>
              ))}
            </div>

            {selectedSet.payloads.length === 0 && (
              <div className="text-center py-8">
                <FileText className="w-12 h-12 mx-auto mb-2 text-gray-400" />
                <p className="text-gray-500 dark:text-gray-400">No payloads in this set</p>
              </div>
            )}
          </motion.div>
        ) : (
          <div className="card">
            <div className="text-center py-12">
              <FileText className="w-12 h-12 text-gray-400 mx-auto mb-4" />
              <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">Select a payload set</h3>
              <p className="text-gray-600 dark:text-gray-400">Choose a payload set from the list to view and edit payloads</p>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

export default PayloadManager
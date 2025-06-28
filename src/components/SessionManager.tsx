import React, { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { 
  MessageCircle, Shield, Users, Download, Upload, Trash2, 
  Copy, Edit, Search, Filter, Calendar, Clock, Settings,
  Plus, FileText, BarChart3, Eye, Star
} from 'lucide-react'
import { useSessionManager } from '../hooks/useSessionManager'
import { ChatSession } from '../types/sessions'
import toast from 'react-hot-toast'

interface SessionManagerProps {
  onSessionSelect?: (session: ChatSession) => void
  currentType?: 'chat' | 'scan' | 'counsel'
}

const SessionManager: React.FC<SessionManagerProps> = ({ onSessionSelect, currentType }) => {
  const {
    sessions,
    currentSession,
    createSession,
    updateSession,
    deleteSession,
    duplicateSession,
    exportSession,
    importSession,
    getSessionsByType,
    setCurrentSession
  } = useSessionManager()

  const [searchTerm, setSearchTerm] = useState('')
  const [filterType, setFilterType] = useState<'all' | 'chat' | 'scan' | 'counsel'>('all')
  const [sortBy, setSortBy] = useState<'recent' | 'name' | 'messages'>('recent')
  const [editingSession, setEditingSession] = useState<string | null>(null)
  const [newSessionName, setNewSessionName] = useState('')

  const filteredSessions = sessions
    .filter(session => {
      const matchesSearch = session.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                           session.metadata.target?.toLowerCase().includes(searchTerm.toLowerCase())
      const matchesType = filterType === 'all' || session.type === filterType
      return matchesSearch && matchesType
    })
    .sort((a, b) => {
      switch (sortBy) {
        case 'recent':
          return new Date(b.lastActivity).getTime() - new Date(a.lastActivity).getTime()
        case 'name':
          return a.name.localeCompare(b.name)
        case 'messages':
          return b.metadata.totalMessages - a.metadata.totalMessages
        default:
          return 0
      }
    })

  const handleCreateSession = () => {
    const type = currentType || 'chat'
    const sessionId = createSession(type)
    if (onSessionSelect) {
      const newSession = sessions.find(s => s.id === sessionId)
      if (newSession) onSessionSelect(newSession)
    }
  }

  const handleRenameSession = (sessionId: string, newName: string) => {
    updateSession(sessionId, { name: newName })
    setEditingSession(null)
    setNewSessionName('')
  }

  const handleFileImport = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    if (file) {
      importSession(file)
    }
  }

  const getSessionIcon = (type: string) => {
    switch (type) {
      case 'chat': return MessageCircle
      case 'scan': return Shield
      case 'counsel': return Users
      default: return FileText
    }
  }

  const getSessionTypeColor = (type: string) => {
    switch (type) {
      case 'chat': return 'text-blue-600 dark:text-blue-400 bg-blue-100 dark:bg-blue-900/20'
      case 'scan': return 'text-green-600 dark:text-green-400 bg-green-100 dark:bg-green-900/20'
      case 'counsel': return 'text-purple-600 dark:text-purple-400 bg-purple-100 dark:bg-purple-900/20'
      default: return 'text-gray-600 dark:text-gray-400 bg-gray-100 dark:bg-gray-800'
    }
  }

  const formatDate = (date: Date) => {
    const now = new Date()
    const diff = now.getTime() - date.getTime()
    const days = Math.floor(diff / (1000 * 60 * 60 * 24))
    
    if (days === 0) {
      return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    } else if (days === 1) {
      return 'Yesterday'
    } else if (days < 7) {
      return `${days} days ago`
    } else {
      return date.toLocaleDateString()
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-gray-900 dark:text-white">Session Manager</h2>
          <p className="text-gray-600 dark:text-gray-400">Manage your chat, scan, and counsel sessions</p>
        </div>
        <div className="flex space-x-2">
          <input
            type="file"
            accept=".json"
            onChange={handleFileImport}
            className="hidden"
            id="import-session"
          />
          <label htmlFor="import-session" className="btn-secondary cursor-pointer flex items-center space-x-2">
            <Upload className="w-4 h-4" />
            <span>Import</span>
          </label>
          <button onClick={handleCreateSession} className="btn-primary flex items-center space-x-2">
            <Plus className="w-4 h-4" />
            <span>New Session</span>
          </button>
        </div>
      </div>

      {/* Filters and Search */}
      <div className="card">
        <div className="flex flex-col sm:flex-row gap-4">
          <div className="flex-1">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-4 h-4" />
              <input
                type="text"
                placeholder="Search sessions..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="input-field pl-10"
              />
            </div>
          </div>
          <div className="flex items-center space-x-2">
            <Filter className="w-4 h-4 text-gray-400" />
            <select
              value={filterType}
              onChange={(e) => setFilterType(e.target.value as any)}
              className="input-field w-auto"
            >
              <option value="all">All Types</option>
              <option value="chat">Chat Sessions</option>
              <option value="scan">Scan Sessions</option>
              <option value="counsel">Counsel Sessions</option>
            </select>
          </div>
          <div className="flex items-center space-x-2">
            <BarChart3 className="w-4 h-4 text-gray-400" />
            <select
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value as any)}
              className="input-field w-auto"
            >
              <option value="recent">Most Recent</option>
              <option value="name">Name</option>
              <option value="messages">Message Count</option>
            </select>
          </div>
        </div>
      </div>

      {/* Session Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="card">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-600 dark:text-gray-400">Total Sessions</p>
              <p className="text-2xl font-bold text-gray-900 dark:text-white">{sessions.length}</p>
            </div>
            <FileText className="w-8 h-8 text-gray-400" />
          </div>
        </div>
        <div className="card">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-600 dark:text-gray-400">Chat Sessions</p>
              <p className="text-2xl font-bold text-blue-600 dark:text-blue-400">
                {getSessionsByType('chat').length}
              </p>
            </div>
            <MessageCircle className="w-8 h-8 text-blue-400" />
          </div>
        </div>
        <div className="card">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-600 dark:text-gray-400">Scan Sessions</p>
              <p className="text-2xl font-bold text-green-600 dark:text-green-400">
                {getSessionsByType('scan').length}
              </p>
            </div>
            <Shield className="w-8 h-8 text-green-400" />
          </div>
        </div>
        <div className="card">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-gray-600 dark:text-gray-400">Counsel Sessions</p>
              <p className="text-2xl font-bold text-purple-600 dark:text-purple-400">
                {getSessionsByType('counsel').length}
              </p>
            </div>
            <Users className="w-8 h-8 text-purple-400" />
          </div>
        </div>
      </div>

      {/* Sessions List */}
      <div className="space-y-4">
        <AnimatePresence>
          {filteredSessions.map((session) => {
            const SessionIcon = getSessionIcon(session.type)
            return (
              <motion.div
                key={session.id}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -20 }}
                className={`card cursor-pointer transition-all duration-200 hover:shadow-md ${
                  currentSession === session.id ? 'ring-2 ring-primary-500' : ''
                }`}
                onClick={() => {
                  setCurrentSession(session.id)
                  if (onSessionSelect) onSessionSelect(session)
                }}
              >
                <div className="flex items-start justify-between">
                  <div className="flex items-start space-x-4 flex-1">
                    <div className={`p-2 rounded-lg ${getSessionTypeColor(session.type)}`}>
                      <SessionIcon className="w-5 h-5" />
                    </div>
                    <div className="flex-1 min-w-0">
                      {editingSession === session.id ? (
                        <div className="flex items-center space-x-2">
                          <input
                            type="text"
                            value={newSessionName}
                            onChange={(e) => setNewSessionName(e.target.value)}
                            onKeyPress={(e) => {
                              if (e.key === 'Enter') {
                                handleRenameSession(session.id, newSessionName)
                              }
                            }}
                            onBlur={() => handleRenameSession(session.id, newSessionName)}
                            className="input-field text-sm"
                            autoFocus
                          />
                        </div>
                      ) : (
                        <h3 className="font-semibold text-gray-900 dark:text-white truncate">
                          {session.name}
                        </h3>
                      )}
                      
                      <div className="flex items-center space-x-4 mt-1 text-sm text-gray-600 dark:text-gray-400">
                        <span className="capitalize">{session.type}</span>
                        <span>{session.metadata.totalMessages} messages</span>
                        {session.metadata.target && (
                          <span className="truncate">{session.metadata.target}</span>
                        )}
                        {session.metadata.vulnerabilitiesFound !== undefined && (
                          <span className="text-red-600 dark:text-red-400">
                            {session.metadata.vulnerabilitiesFound} vulns
                          </span>
                        )}
                      </div>
                      
                      <div className="flex items-center space-x-2 mt-2">
                        <Calendar className="w-3 h-3" />
                        <span className="text-xs text-gray-500 dark:text-gray-400">
                          {formatDate(session.lastActivity)}
                        </span>
                        {session.metadata.provider && (
                          <>
                            <span className="text-gray-300 dark:text-gray-600">•</span>
                            <span className="text-xs text-gray-500 dark:text-gray-400">
                              {session.metadata.provider} • {session.metadata.model}
                            </span>
                          </>
                        )}
                      </div>
                    </div>
                  </div>
                  
                  <div className="flex items-center space-x-1 ml-4">
                    <button
                      onClick={(e) => {
                        e.stopPropagation()
                        setEditingSession(session.id)
                        setNewSessionName(session.name)
                      }}
                      className="p-2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
                    >
                      <Edit className="w-4 h-4" />
                    </button>
                    <button
                      onClick={(e) => {
                        e.stopPropagation()
                        duplicateSession(session.id)
                      }}
                      className="p-2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
                    >
                      <Copy className="w-4 h-4" />
                    </button>
                    <button
                      onClick={(e) => {
                        e.stopPropagation()
                        exportSession(session.id)
                      }}
                      className="p-2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
                    >
                      <Download className="w-4 h-4" />
                    </button>
                    <button
                      onClick={(e) => {
                        e.stopPropagation()
                        if (confirm('Are you sure you want to delete this session?')) {
                          deleteSession(session.id)
                        }
                      }}
                      className="p-2 text-gray-400 hover:text-red-600 dark:hover:text-red-400 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-800 transition-colors"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              </motion.div>
            )
          })}
        </AnimatePresence>
        
        {filteredSessions.length === 0 && (
          <div className="text-center py-12">
            <FileText className="w-12 h-12 text-gray-400 mx-auto mb-4" />
            <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">No sessions found</h3>
            <p className="text-gray-600 dark:text-gray-400 mb-4">
              {searchTerm || filterType !== 'all' 
                ? 'Try adjusting your search or filter criteria'
                : 'Create your first session to get started'
              }
            </p>
            {!searchTerm && filterType === 'all' && (
              <button onClick={handleCreateSession} className="btn-primary">
                Create New Session
              </button>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

export default SessionManager
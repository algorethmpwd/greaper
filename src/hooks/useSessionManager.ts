import { useState, useEffect } from 'react'
import { ChatSession } from '../types/sessions'
import toast from 'react-hot-toast'

export const useSessionManager = () => {
  const [sessions, setSessions] = useState<ChatSession[]>([])
  const [currentSession, setCurrentSession] = useState<string | null>(null)
  const [autoSave, setAutoSave] = useState(true)

  useEffect(() => {
    loadSessions()
  }, [])

  useEffect(() => {
    if (autoSave && sessions.length > 0) {
      saveSessions()
    }
  }, [sessions, autoSave])

  const loadSessions = () => {
    try {
      const savedSessions = localStorage.getItem('greaper_sessions')
      if (savedSessions) {
        const parsed = JSON.parse(savedSessions)
        setSessions(parsed.map((session: any) => ({
          ...session,
          timestamp: new Date(session.timestamp),
          lastActivity: new Date(session.lastActivity)
        })))
      }
    } catch (error) {
      console.error('Failed to load sessions:', error)
    }
  }

  const saveSessions = () => {
    try {
      localStorage.setItem('greaper_sessions', JSON.stringify(sessions))
    } catch (error) {
      console.error('Failed to save sessions:', error)
      toast.error('Failed to save sessions')
    }
  }

  const createSession = (type: 'chat' | 'scan' | 'counsel', name?: string): string => {
    const sessionId = Date.now().toString()
    const newSession: ChatSession = {
      id: sessionId,
      name: name || `${type.charAt(0).toUpperCase() + type.slice(1)} Session ${sessions.length + 1}`,
      type,
      timestamp: new Date(),
      lastActivity: new Date(),
      messages: [],
      settings: {},
      metadata: {
        totalMessages: 0
      }
    }

    setSessions(prev => [newSession, ...prev])
    setCurrentSession(sessionId)
    toast.success(`${type.charAt(0).toUpperCase() + type.slice(1)} session created`)
    return sessionId
  }

  const updateSession = (sessionId: string, updates: Partial<ChatSession>) => {
    setSessions(prev => prev.map(session => 
      session.id === sessionId 
        ? { ...session, ...updates, lastActivity: new Date() }
        : session
    ))
  }

  const deleteSession = (sessionId: string) => {
    setSessions(prev => prev.filter(session => session.id !== sessionId))
    if (currentSession === sessionId) {
      setCurrentSession(null)
    }
    toast.success('Session deleted')
  }

  const duplicateSession = (sessionId: string) => {
    const session = sessions.find(s => s.id === sessionId)
    if (session) {
      const newSessionId = Date.now().toString()
      const duplicatedSession: ChatSession = {
        ...session,
        id: newSessionId,
        name: `${session.name} (Copy)`,
        timestamp: new Date(),
        lastActivity: new Date()
      }
      setSessions(prev => [duplicatedSession, ...prev])
      toast.success('Session duplicated')
      return newSessionId
    }
  }

  const exportSession = (sessionId: string) => {
    const session = sessions.find(s => s.id === sessionId)
    if (session) {
      const dataStr = JSON.stringify(session, null, 2)
      const dataBlob = new Blob([dataStr], { type: 'application/json' })
      const url = URL.createObjectURL(dataBlob)
      const link = document.createElement('a')
      link.href = url
      link.download = `${session.name.replace(/\s+/g, '_')}_${session.id}.json`
      link.click()
      URL.revokeObjectURL(url)
      toast.success('Session exported')
    }
  }

  const importSession = (file: File) => {
    const reader = new FileReader()
    reader.onload = (e) => {
      try {
        const session = JSON.parse(e.target?.result as string) as ChatSession
        session.id = Date.now().toString() // Generate new ID
        session.timestamp = new Date(session.timestamp)
        session.lastActivity = new Date(session.lastActivity)
        setSessions(prev => [session, ...prev])
        toast.success('Session imported successfully')
      } catch (error) {
        toast.error('Failed to import session')
      }
    }
    reader.readAsText(file)
  }

  const getCurrentSession = () => {
    return sessions.find(s => s.id === currentSession)
  }

  const getSessionsByType = (type: 'chat' | 'scan' | 'counsel') => {
    return sessions.filter(s => s.type === type)
  }

  return {
    sessions,
    currentSession,
    autoSave,
    setAutoSave,
    createSession,
    updateSession,
    deleteSession,
    duplicateSession,
    exportSession,
    importSession,
    getCurrentSession,
    getSessionsByType,
    setCurrentSession,
    saveSessions: () => saveSessions()
  }
}
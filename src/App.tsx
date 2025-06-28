import React from 'react'
import { Routes, Route } from 'react-router-dom'
import { motion } from 'framer-motion'
import Header from './components/Header'
import Dashboard from './pages/Dashboard'
import Scanner from './pages/Scanner'
import Results from './pages/Results'
import Settings from './pages/Settings'

function App() {
  return (
    <div className="min-h-screen bg-gray-50">
      <Header />
      <motion.main 
        className="container mx-auto px-4 py-8"
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
      >
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/scanner" element={<Scanner />} />
          <Route path="/results" element={<Results />} />
          <Route path="/settings" element={<Settings />} />
        </Routes>
      </motion.main>
    </div>
  )
}

export default App
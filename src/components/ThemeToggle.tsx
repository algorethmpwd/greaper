import React, { useRef } from 'react'
import { motion } from 'framer-motion'
import { Sun, Moon } from 'lucide-react'
import { useTheme } from '../contexts/ThemeContext'

const ThemeToggle: React.FC = () => {
  const { theme, toggleTheme, isAnimating } = useTheme()
  const buttonRef = useRef<HTMLButtonElement>(null)

  const handleToggle = () => {
    if (buttonRef.current) {
      const rect = buttonRef.current.getBoundingClientRect()
      const x = rect.left + rect.width / 2
      const y = rect.top + rect.height / 2
      
      // Create wave effect
      const wave = document.createElement('div')
      wave.className = 'theme-wave'
      wave.style.left = `${x}px`
      wave.style.top = `${y}px`
      wave.style.background = theme === 'light' ? '#1f2937' : '#f9fafb'
      document.body.appendChild(wave)
      
      // Remove wave after animation
      setTimeout(() => {
        if (document.body.contains(wave)) {
          document.body.removeChild(wave)
        }
      }, 1000)
    }
    
    toggleTheme()
  }

  return (
    <motion.button
      ref={buttonRef}
      onClick={handleToggle}
      className={`relative p-3 rounded-full transition-all duration-300 ${
        theme === 'light' 
          ? 'bg-gray-100 hover:bg-gray-200 text-gray-700' 
          : 'bg-gray-800 hover:bg-gray-700 text-gray-300'
      }`}
      whileHover={{ scale: 1.05 }}
      whileTap={{ scale: 0.95 }}
      disabled={isAnimating}
    >
      <motion.div
        initial={false}
        animate={{ 
          rotate: theme === 'light' ? 0 : 180,
          scale: isAnimating ? 0.8 : 1
        }}
        transition={{ duration: 0.3, ease: "easeInOut" }}
      >
        {theme === 'light' ? (
          <Sun className="w-5 h-5" />
        ) : (
          <Moon className="w-5 h-5" />
        )}
      </motion.div>
      
      {isAnimating && (
        <motion.div
          className="absolute inset-0 rounded-full border-2 border-current"
          initial={{ scale: 1, opacity: 1 }}
          animate={{ scale: 2, opacity: 0 }}
          transition={{ duration: 0.6 }}
        />
      )}
    </motion.button>
  )
}

export default ThemeToggle
import React from 'react'
import { Link, useLocation } from 'react-router-dom'
import { Shield, Activity, Settings, BarChart3 } from 'lucide-react'
import ThemeToggle from './ThemeToggle'

const Header: React.FC = () => {
  const location = useLocation()

  const navItems = [
    { path: '/', label: 'Dashboard', icon: BarChart3 },
    { path: '/scanner', label: 'Scanner', icon: Shield },
    { path: '/results', label: 'Results', icon: Activity },
    { path: '/settings', label: 'Settings', icon: Settings },
  ]

  return (
    <header className="bg-white dark:bg-gray-900 shadow-sm border-b border-gray-200 dark:border-gray-700 transition-colors duration-300">
      <div className="container mx-auto px-4">
        <div className="flex items-center justify-between h-16">
          <div className="flex items-center space-x-3">
            <div className="flex items-center justify-center w-10 h-10 bg-primary-600 rounded-lg">
              <Shield className="w-6 h-6 text-white" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-gray-900 dark:text-white">Greaper</h1>
              <p className="text-xs text-gray-500 dark:text-gray-400">Web Security Scanner</p>
            </div>
          </div>

          <nav className="flex items-center space-x-1">
            {navItems.map(({ path, label, icon: Icon }) => (
              <Link
                key={path}
                to={path}
                className={`flex items-center space-x-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors duration-200 ${
                  location.pathname === path
                    ? 'bg-primary-100 dark:bg-primary-900 text-primary-700 dark:text-primary-300'
                    : 'text-gray-600 dark:text-gray-300 hover:text-gray-900 dark:hover:text-white hover:bg-gray-100 dark:hover:bg-gray-800'
                }`}
              >
                <Icon className="w-4 h-4" />
                <span>{label}</span>
              </Link>
            ))}
            <div className="ml-4">
              <ThemeToggle />
            </div>
          </nav>
        </div>
      </div>
    </header>
  )
}

export default Header
import React, { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { Shield, AlertTriangle, CheckCircle, Clock, TrendingUp, Globe, Bug, Lock } from 'lucide-react'
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts'

const Dashboard: React.FC = () => {
  const [stats, setStats] = useState({
    totalScans: 0,
    vulnerabilities: 0,
    secureUrls: 0,
    pendingScans: 0
  })

  const [recentScans] = useState([
    { id: 1, url: 'https://example.com', status: 'completed', vulnerabilities: 3, timestamp: '2 hours ago' },
    { id: 2, url: 'https://test.com', status: 'completed', vulnerabilities: 0, timestamp: '4 hours ago' },
    { id: 3, url: 'https://demo.org', status: 'running', vulnerabilities: 0, timestamp: '6 hours ago' },
    { id: 4, url: 'https://sample.net', status: 'completed', vulnerabilities: 7, timestamp: '1 day ago' },
  ])

  const vulnerabilityData = [
    { name: 'XSS', count: 12, color: '#ef4444' },
    { name: 'SQL Injection', count: 8, color: '#f59e0b' },
    { name: 'CORS', count: 5, color: '#8b5cf6' },
    { name: 'Headers', count: 15, color: '#06b6d4' },
  ]

  const weeklyData = [
    { day: 'Mon', scans: 12, vulnerabilities: 3 },
    { day: 'Tue', scans: 19, vulnerabilities: 7 },
    { day: 'Wed', scans: 8, vulnerabilities: 2 },
    { day: 'Thu', scans: 15, vulnerabilities: 5 },
    { day: 'Fri', scans: 22, vulnerabilities: 8 },
    { day: 'Sat', scans: 6, vulnerabilities: 1 },
    { day: 'Sun', scans: 10, vulnerabilities: 3 },
  ]

  useEffect(() => {
    // Simulate loading stats
    const timer = setTimeout(() => {
      setStats({
        totalScans: 1247,
        vulnerabilities: 89,
        secureUrls: 1158,
        pendingScans: 3
      })
    }, 1000)

    return () => clearTimeout(timer)
  }, [])

  const statCards = [
    {
      title: 'Total Scans',
      value: stats.totalScans,
      icon: Globe,
      color: 'bg-primary-500',
      change: '+12%'
    },
    {
      title: 'Vulnerabilities Found',
      value: stats.vulnerabilities,
      icon: Bug,
      color: 'bg-danger-500',
      change: '-8%'
    },
    {
      title: 'Secure URLs',
      value: stats.secureUrls,
      icon: Lock,
      color: 'bg-success-500',
      change: '+15%'
    },
    {
      title: 'Pending Scans',
      value: stats.pendingScans,
      icon: Clock,
      color: 'bg-warning-500',
      change: '0%'
    }
  ]

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white">Security Dashboard</h1>
          <p className="text-gray-600 dark:text-gray-400 mt-1">Monitor your web security scanning activities</p>
        </div>
        <div className="flex items-center space-x-2 text-sm text-gray-500 dark:text-gray-400">
          <Clock className="w-4 h-4" />
          <span>Last updated: {new Date().toLocaleTimeString()}</span>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {statCards.map((card, index) => (
          <motion.div
            key={card.title}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: index * 0.1 }}
            className="card hover:shadow-md transition-shadow duration-200"
          >
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600 dark:text-gray-400">{card.title}</p>
                <p className="text-3xl font-bold text-gray-900 dark:text-white mt-2">
                  {stats.totalScans === 0 ? (
                    <div className="animate-pulse bg-gray-200 dark:bg-gray-700 h-8 w-16 rounded"></div>
                  ) : (
                    card.value.toLocaleString()
                  )}
                </p>
                <div className="flex items-center mt-2">
                  <TrendingUp className="w-4 h-4 text-success-500 mr-1" />
                  <span className="text-sm text-success-600 dark:text-success-400">{card.change}</span>
                </div>
              </div>
              <div className={`p-3 rounded-lg ${card.color}`}>
                <card.icon className="w-6 h-6 text-white" />
              </div>
            </div>
          </motion.div>
        ))}
      </div>

      {/* Charts Section */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Weekly Activity Chart */}
        <motion.div
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.3 }}
          className="card"
        >
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Weekly Activity</h3>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={weeklyData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
              <XAxis dataKey="day" stroke="#6b7280" />
              <YAxis stroke="#6b7280" />
              <Tooltip 
                contentStyle={{ 
                  backgroundColor: '#1f2937', 
                  border: 'none', 
                  borderRadius: '8px',
                  color: '#f9fafb'
                }} 
              />
              <Bar dataKey="scans" fill="#0ea5e9" name="Scans" />
              <Bar dataKey="vulnerabilities" fill="#ef4444" name="Vulnerabilities" />
            </BarChart>
          </ResponsiveContainer>
        </motion.div>

        {/* Vulnerability Distribution */}
        <motion.div
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ delay: 0.4 }}
          className="card"
        >
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">Vulnerability Types</h3>
          <ResponsiveContainer width="100%" height={300}>
            <PieChart>
              <Pie
                data={vulnerabilityData}
                cx="50%"
                cy="50%"
                outerRadius={80}
                dataKey="count"
                label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
              >
                {vulnerabilityData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip 
                contentStyle={{ 
                  backgroundColor: '#1f2937', 
                  border: 'none', 
                  borderRadius: '8px',
                  color: '#f9fafb'
                }} 
              />
            </PieChart>
          </ResponsiveContainer>
        </motion.div>
      </div>

      {/* Recent Scans */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.5 }}
        className="card"
      >
        <div className="flex items-center justify-between mb-6">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white">Recent Scans</h3>
          <button className="btn-primary text-sm">View All</button>
        </div>
        
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-gray-200 dark:border-gray-700">
                <th className="text-left py-3 px-4 font-medium text-gray-600 dark:text-gray-400">URL</th>
                <th className="text-left py-3 px-4 font-medium text-gray-600 dark:text-gray-400">Status</th>
                <th className="text-left py-3 px-4 font-medium text-gray-600 dark:text-gray-400">Vulnerabilities</th>
                <th className="text-left py-3 px-4 font-medium text-gray-600 dark:text-gray-400">Time</th>
              </tr>
            </thead>
            <tbody>
              {recentScans.map((scan) => (
                <tr key={scan.id} className="border-b border-gray-100 dark:border-gray-800 hover:bg-gray-50 dark:hover:bg-gray-800/50">
                  <td className="py-3 px-4">
                    <div className="flex items-center">
                      <Globe className="w-4 h-4 text-gray-400 mr-2" />
                      <span className="font-medium text-gray-900 dark:text-white">{scan.url}</span>
                    </div>
                  </td>
                  <td className="py-3 px-4">
                    <span className={`status-badge ${
                      scan.status === 'completed' ? 'status-success' :
                      scan.status === 'running' ? 'status-info' : 'status-warning'
                    }`}>
                      {scan.status === 'completed' && <CheckCircle className="w-3 h-3 mr-1" />}
                      {scan.status === 'running' && <Clock className="w-3 h-3 mr-1" />}
                      {scan.status === 'failed' && <AlertTriangle className="w-3 h-3 mr-1" />}
                      {scan.status.charAt(0).toUpperCase() + scan.status.slice(1)}
                    </span>
                  </td>
                  <td className="py-3 px-4">
                    <span className={`font-medium ${
                      scan.vulnerabilities > 0 ? 'text-danger-600 dark:text-danger-400' : 'text-success-600 dark:text-success-400'
                    }`}>
                      {scan.vulnerabilities}
                    </span>
                  </td>
                  <td className="py-3 px-4 text-gray-500 dark:text-gray-400">{scan.timestamp}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </motion.div>
    </div>
  )
}

export default Dashboard
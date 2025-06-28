import React, { useState } from 'react'
import { motion } from 'framer-motion'
import { Save, RefreshCw, Shield, Bell, Database, Globe, Key, Users } from 'lucide-react'
import toast from 'react-hot-toast'

const Settings: React.FC = () => {
  const [settings, setSettings] = useState({
    // General Settings
    maxConcurrentScans: 5,
    requestTimeout: 30,
    retryAttempts: 3,
    userAgent: 'Greaper Security Scanner v2.0',
    
    // Security Settings
    enableRateLimiting: true,
    rateLimitDelay: 1000,
    followRedirects: true,
    verifySSL: true,
    
    // Notification Settings
    emailNotifications: true,
    slackNotifications: false,
    webhookUrl: '',
    
    // API Settings
    apiKey: '',
    enableApiAccess: false,
    
    // Database Settings
    exportFormat: 'json',
    autoSaveResults: true,
    retentionDays: 30,
  })

  const handleSettingChange = (key: string, value: any) => {
    setSettings(prev => ({
      ...prev,
      [key]: value
    }))
  }

  const handleSave = () => {
    // Simulate saving settings
    toast.success('Settings saved successfully!')
  }

  const handleReset = () => {
    // Reset to default values
    setSettings({
      maxConcurrentScans: 5,
      requestTimeout: 30,
      retryAttempts: 3,
      userAgent: 'Greaper Security Scanner v2.0',
      enableRateLimiting: true,
      rateLimitDelay: 1000,
      followRedirects: true,
      verifySSL: true,
      emailNotifications: true,
      slackNotifications: false,
      webhookUrl: '',
      apiKey: '',
      enableApiAccess: false,
      exportFormat: 'json',
      autoSaveResults: true,
      retentionDays: 30,
    })
    toast.success('Settings reset to defaults')
  }

  const settingSections = [
    {
      title: 'General Settings',
      icon: Globe,
      settings: [
        {
          key: 'maxConcurrentScans',
          label: 'Max Concurrent Scans',
          type: 'number',
          description: 'Maximum number of simultaneous scans',
          min: 1,
          max: 20
        },
        {
          key: 'requestTimeout',
          label: 'Request Timeout (seconds)',
          type: 'number',
          description: 'Timeout for HTTP requests',
          min: 5,
          max: 120
        },
        {
          key: 'retryAttempts',
          label: 'Retry Attempts',
          type: 'number',
          description: 'Number of retry attempts for failed requests',
          min: 0,
          max: 10
        },
        {
          key: 'userAgent',
          label: 'User Agent',
          type: 'text',
          description: 'User agent string for HTTP requests'
        }
      ]
    },
    {
      title: 'Security Settings',
      icon: Shield,
      settings: [
        {
          key: 'enableRateLimiting',
          label: 'Enable Rate Limiting',
          type: 'boolean',
          description: 'Limit request rate to avoid being blocked'
        },
        {
          key: 'rateLimitDelay',
          label: 'Rate Limit Delay (ms)',
          type: 'number',
          description: 'Delay between requests when rate limiting is enabled',
          min: 100,
          max: 10000
        },
        {
          key: 'followRedirects',
          label: 'Follow Redirects',
          type: 'boolean',
          description: 'Automatically follow HTTP redirects'
        },
        {
          key: 'verifySSL',
          label: 'Verify SSL Certificates',
          type: 'boolean',
          description: 'Verify SSL certificates for HTTPS requests'
        }
      ]
    },
    {
      title: 'Notifications',
      icon: Bell,
      settings: [
        {
          key: 'emailNotifications',
          label: 'Email Notifications',
          type: 'boolean',
          description: 'Send email notifications for completed scans'
        },
        {
          key: 'slackNotifications',
          label: 'Slack Notifications',
          type: 'boolean',
          description: 'Send notifications to Slack channel'
        },
        {
          key: 'webhookUrl',
          label: 'Webhook URL',
          type: 'text',
          description: 'URL for webhook notifications'
        }
      ]
    },
    {
      title: 'API Access',
      icon: Key,
      settings: [
        {
          key: 'enableApiAccess',
          label: 'Enable API Access',
          type: 'boolean',
          description: 'Allow external API access to scanner'
        },
        {
          key: 'apiKey',
          label: 'API Key',
          type: 'password',
          description: 'API key for authentication'
        }
      ]
    },
    {
      title: 'Data Management',
      icon: Database,
      settings: [
        {
          key: 'exportFormat',
          label: 'Export Format',
          type: 'select',
          options: [
            { value: 'json', label: 'JSON' },
            { value: 'csv', label: 'CSV' },
            { value: 'xml', label: 'XML' },
            { value: 'pdf', label: 'PDF' }
          ],
          description: 'Default format for exporting results'
        },
        {
          key: 'autoSaveResults',
          label: 'Auto-save Results',
          type: 'boolean',
          description: 'Automatically save scan results'
        },
        {
          key: 'retentionDays',
          label: 'Data Retention (days)',
          type: 'number',
          description: 'Number of days to keep scan results',
          min: 1,
          max: 365
        }
      ]
    }
  ]

  const renderSettingInput = (setting: any) => {
    const value = settings[setting.key as keyof typeof settings]

    switch (setting.type) {
      case 'boolean':
        return (
          <label className="relative inline-flex items-center cursor-pointer">
            <input
              type="checkbox"
              checked={value as boolean}
              onChange={(e) => handleSettingChange(setting.key, e.target.checked)}
              className="sr-only peer"
            />
            <div className="w-11 h-6 bg-gray-200 peer-focus:outline-none peer-focus:ring-4 peer-focus:ring-primary-300 rounded-full peer peer-checked:after:translate-x-full peer-checked:after:border-white after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:border-gray-300 after:border after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-primary-600"></div>
          </label>
        )

      case 'number':
        return (
          <input
            type="number"
            value={value as number}
            onChange={(e) => handleSettingChange(setting.key, parseInt(e.target.value))}
            min={setting.min}
            max={setting.max}
            className="input-field w-32"
          />
        )

      case 'select':
        return (
          <select
            value={value as string}
            onChange={(e) => handleSettingChange(setting.key, e.target.value)}
            className="input-field w-48"
          >
            {setting.options.map((option: any) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        )

      case 'password':
        return (
          <input
            type="password"
            value={value as string}
            onChange={(e) => handleSettingChange(setting.key, e.target.value)}
            className="input-field w-64"
            placeholder="Enter API key..."
          />
        )

      default:
        return (
          <input
            type="text"
            value={value as string}
            onChange={(e) => handleSettingChange(setting.key, e.target.value)}
            className="input-field w-64"
          />
        )
    }
  }

  return (
    <div className="space-y-8">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">Settings</h1>
          <p className="text-gray-600 mt-1">Configure scanner behavior and preferences</p>
        </div>
        <div className="flex space-x-3">
          <button onClick={handleReset} className="btn-secondary flex items-center space-x-2">
            <RefreshCw className="w-4 h-4" />
            <span>Reset</span>
          </button>
          <button onClick={handleSave} className="btn-primary flex items-center space-x-2">
            <Save className="w-4 h-4" />
            <span>Save Changes</span>
          </button>
        </div>
      </div>

      {/* Settings Sections */}
      <div className="space-y-8">
        {settingSections.map((section, sectionIndex) => (
          <motion.div
            key={section.title}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: sectionIndex * 0.1 }}
            className="card"
          >
            <div className="flex items-center space-x-3 mb-6">
              <div className="p-2 bg-primary-100 rounded-lg">
                <section.icon className="w-5 h-5 text-primary-600" />
              </div>
              <h3 className="text-lg font-semibold text-gray-900">{section.title}</h3>
            </div>

            <div className="space-y-6">
              {section.settings.map((setting) => (
                <div key={setting.key} className="flex items-center justify-between py-4 border-b border-gray-100 last:border-b-0">
                  <div className="flex-1">
                    <label className="block font-medium text-gray-900 mb-1">
                      {setting.label}
                    </label>
                    <p className="text-sm text-gray-600">{setting.description}</p>
                  </div>
                  <div className="ml-6">
                    {renderSettingInput(setting)}
                  </div>
                </div>
              ))}
            </div>
          </motion.div>
        ))}
      </div>

      {/* Advanced Settings */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.6 }}
        className="card"
      >
        <div className="flex items-center space-x-3 mb-6">
          <div className="p-2 bg-warning-100 rounded-lg">
            <Users className="w-5 h-5 text-warning-600" />
          </div>
          <h3 className="text-lg font-semibold text-gray-900">Advanced Settings</h3>
        </div>

        <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-4 mb-6">
          <div className="flex items-start space-x-3">
            <Shield className="w-5 h-5 text-yellow-600 mt-0.5" />
            <div>
              <h4 className="font-medium text-yellow-800">Caution Required</h4>
              <p className="text-sm text-yellow-700 mt-1">
                These settings can significantly impact scanner performance and behavior. 
                Only modify if you understand the implications.
              </p>
            </div>
          </div>
        </div>

        <div className="space-y-4">
          <button className="w-full text-left p-4 border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors">
            <div className="flex items-center justify-between">
              <div>
                <h4 className="font-medium text-gray-900">Custom Payloads</h4>
                <p className="text-sm text-gray-600">Manage custom payload files for vulnerability testing</p>
              </div>
              <span className="text-gray-400">→</span>
            </div>
          </button>

          <button className="w-full text-left p-4 border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors">
            <div className="flex items-center justify-between">
              <div>
                <h4 className="font-medium text-gray-900">Proxy Configuration</h4>
                <p className="text-sm text-gray-600">Configure proxy settings for network requests</p>
              </div>
              <span className="text-gray-400">→</span>
            </div>
          </button>

          <button className="w-full text-left p-4 border border-gray-200 rounded-lg hover:bg-gray-50 transition-colors">
            <div className="flex items-center justify-between">
              <div>
                <h4 className="font-medium text-gray-900">Custom Headers</h4>
                <p className="text-sm text-gray-600">Add custom HTTP headers to requests</p>
              </div>
              <span className="text-gray-400">→</span>
            </div>
          </button>
        </div>
      </motion.div>
    </div>
  )
}

export default Settings
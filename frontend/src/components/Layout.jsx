// src/components/Layout.jsx
// Shared navigation bar + page wrapper used by all pages.
import { Link, useNavigate, useLocation } from 'react-router-dom'
import { Shield, Upload, List, LogOut, User } from 'lucide-react'
import { useAuth } from '../context/AuthContext'

export default function Layout({ children }) {
  const { user, logoutUser } = useAuth()
  const navigate             = useNavigate()
  const location             = useLocation()

  const handleLogout = () => {
    logoutUser()
    navigate('/login')
  }

  const navLink = (to, icon, label) => {
    const active = location.pathname === to
    return (
      <Link
        to={to}
        className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium transition-colors
          ${active ? 'bg-blue-600/20 text-blue-400' : 'text-slate-400 hover:text-white hover:bg-slate-800'}`}
      >
        {icon}
        {label}
      </Link>
    )
  }

  return (
    <div className="min-h-screen bg-slate-900">
      {/* Top nav */}
      <nav className="bg-slate-800/80 border-b border-slate-700 backdrop-blur sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 h-14 flex items-center justify-between">
          {/* Brand */}
          <Link to="/" className="flex items-center gap-2">
            <Shield className="w-6 h-6 text-blue-400" />
            <span className="font-bold text-white text-sm">EmailGuard AI</span>
          </Link>

          {/* Nav links */}
          <div className="flex items-center gap-1">
            {navLink('/',       <Upload className="w-4 h-4" />, 'Analyze')}
            {navLink('/cases',  <List   className="w-4 h-4" />, 'Cases'  )}
          </div>

          {/* User */}
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2 text-slate-400 text-sm">
              <User className="w-4 h-4" />
              <span>{user?.username}</span>
            </div>
            <button
              onClick={handleLogout}
              className="flex items-center gap-1 text-slate-500 hover:text-red-400 text-sm transition-colors"
            >
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        </div>
      </nav>

      {/* Page content */}
      <main className="max-w-7xl mx-auto px-4 py-6">
        {children}
      </main>
    </div>
  )
}

// src/App.jsx
// Root component — sets up routing and auth protection.
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { AuthProvider, useAuth } from './context/AuthContext'
import LoginPage    from './pages/LoginPage'
import UploadPage   from './pages/UploadPage'
import DashboardPage from './pages/DashboardPage'
import CasesPage    from './pages/CasesPage'

// Protected route: redirects to /login if not authenticated
function Protected({ children }) {
  const { user, loading } = useAuth()
  if (loading) return null
  return user ? children : <Navigate to="/login" replace />
}

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route path="/" element={
            <Protected><UploadPage /></Protected>
          } />
          <Route path="/analysis/:caseId" element={
            <Protected><DashboardPage /></Protected>
          } />
          <Route path="/cases" element={
            <Protected><CasesPage /></Protected>
          } />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  )
}

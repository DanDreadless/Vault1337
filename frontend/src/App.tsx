import { BrowserRouter, Route, Routes } from 'react-router-dom'
import Layout from './components/Layout'
import ProtectedRoute from './components/ProtectedRoute'
import { AuthProvider } from './context/AuthContext'

import AboutPage from './pages/AboutPage'
import HomePage from './pages/HomePage'
import IOCPage from './pages/IOCPage'
import ClusterPage from './pages/ClusterPage'
import DecoderPage from './pages/DecoderPage'
import CorrelationPage from './pages/CorrelationPage'
import DomainCheckPage from './pages/DomainCheckPage'
import IPCheckPage from './pages/IPCheckPage'
import LoginPage from './pages/LoginPage'
import ProfilePage from './pages/ProfilePage'
import RegisterPage from './pages/RegisterPage'
import SampleDetailPage from './pages/SampleDetailPage'
import VaultPage from './pages/VaultPage'
import YaraPage from './pages/YaraPage'
import SettingsPage from './pages/SettingsPage'

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Routes>
          <Route element={<Layout />}>
            {/* Public */}
            <Route path="/" element={<HomePage />} />
            <Route path="/about" element={<AboutPage />} />
            <Route path="/login" element={<LoginPage />} />
            <Route path="/register" element={<RegisterPage />} />

            {/* Protected */}
            <Route
              path="/vault"
              element={
                <ProtectedRoute>
                  <VaultPage />
                </ProtectedRoute>
              }
            />
            <Route
              path="/sample/:sha256"
              element={
                <ProtectedRoute>
                  <SampleDetailPage />
                </ProtectedRoute>
              }
            />
            <Route
              path="/iocs"
              element={
                <ProtectedRoute>
                  <IOCPage />
                </ProtectedRoute>
              }
            />
            <Route
              path="/yara"
              element={
                <ProtectedRoute>
                  <YaraPage />
                </ProtectedRoute>
              }
            />
            <Route
              path="/ip-check"
              element={
                <ProtectedRoute>
                  <IPCheckPage />
                </ProtectedRoute>
              }
            />
            <Route
              path="/domain-check"
              element={
                <ProtectedRoute>
                  <DomainCheckPage />
                </ProtectedRoute>
              }
            />
            <Route
              path="/correlation"
              element={
                <ProtectedRoute>
                  <CorrelationPage />
                </ProtectedRoute>
              }
            />
            <Route
              path="/cluster"
              element={
                <ProtectedRoute>
                  <ClusterPage />
                </ProtectedRoute>
              }
            />
            <Route path="/decoder" element={<DecoderPage />} />
            <Route
              path="/profile"
              element={
                <ProtectedRoute>
                  <ProfilePage />
                </ProtectedRoute>
              }
            />
            <Route
              path="/settings"
              element={
                <ProtectedRoute requireStaff>
                  <SettingsPage />
                </ProtectedRoute>
              }
            />

            {/* Catch-all */}
            <Route
              path="*"
              element={
                <div className="text-center py-20 text-white/60">
                  404 — Page not found.
                </div>
              }
            />
          </Route>
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  )
}

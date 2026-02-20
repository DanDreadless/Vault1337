import { Navigate, useLocation } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import LoadingSpinner from './LoadingSpinner'

interface Props {
  children: React.ReactNode
  requireStaff?: boolean
}

export default function ProtectedRoute({ children, requireStaff = false }: Props) {
  const { user, isLoading } = useAuth()
  const location = useLocation()

  if (isLoading) {
    return (
      <div className="flex justify-center items-center h-64">
        <LoadingSpinner size="lg" />
      </div>
    )
  }

  if (!user) {
    return <Navigate to="/login" state={{ from: location }} replace />
  }

  if (requireStaff && !user.is_staff) {
    return (
      <div className="text-center py-20 text-red-400">
        403 — Staff access required.
      </div>
    )
  }

  return <>{children}</>
}

import { useState } from 'react'
import { Link, NavLink, useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'

export default function Navbar() {
  const { user, logout } = useAuth()
  const navigate = useNavigate()
  const [dropOpen, setDropOpen] = useState(false)
  const [mobileOpen, setMobileOpen] = useState(false)

  const handleLogout = () => {
    logout()
    setDropOpen(false)
    navigate('/')
  }

  const linkClass = ({ isActive }: { isActive: boolean }) =>
    `px-3 py-2 text-sm font-medium transition-colors hover:text-vault-accent ${
      isActive ? 'text-vault-accent' : 'text-white'
    }`

  return (
    <nav className="fixed top-0 left-0 right-0 z-50 bg-vault-dark shadow-md">
      <div className="max-w-screen-xl mx-auto px-4 flex items-center justify-between h-14">
        {/* Brand */}
        <Link to="/" className="shrink-0">
          <img src="/logo.png" alt="Vault1337 Malware Analysis" className="h-9 w-auto" />
        </Link>

        {/* Desktop nav */}
        <div className="hidden md:flex items-center gap-1 flex-1 ml-6">
          {user && (
            <>
              <NavLink to="/" end className={linkClass}>Home</NavLink>
              <NavLink to="/vault" className={linkClass}>Vault</NavLink>
              <NavLink to="/iocs" className={linkClass}>IOCs</NavLink>
              <NavLink to="/yara" className={linkClass}>YARA</NavLink>
              <NavLink to="/about" className={linkClass}>About</NavLink>
            </>
          )}
          {!user && (
            <>
              <NavLink to="/" end className={linkClass}>Home</NavLink>
              <NavLink to="/about" className={linkClass}>About</NavLink>
            </>
          )}
        </div>

        {/* Right side */}
        <div className="flex items-center gap-3">
          {user ? (
            <div className="relative">
              <button
                onClick={() => setDropOpen((v) => !v)}
                className="flex items-center gap-2 text-sm text-white hover:text-vault-accent"
              >
                Welcome, <span className="font-semibold">{user.username}</span>
                <span className="text-white/40 text-xs">▾</span>
              </button>
              {dropOpen && (
                <div className="absolute right-0 mt-1 w-44 bg-vault-dark border border-white/10 rounded shadow-lg text-sm z-50">
                  <Link
                    to="/profile"
                    className="block px-4 py-2 hover:bg-vault-accent transition"
                    onClick={() => setDropOpen(false)}
                  >
                    Profile
                  </Link>
                  {user.is_staff && (
                    <Link
                      to="/admin/keys"
                      className="block px-4 py-2 hover:bg-vault-accent transition"
                      onClick={() => setDropOpen(false)}
                    >
                      Manage API Keys
                    </Link>
                  )}
                  <button
                    onClick={handleLogout}
                    className="w-full text-left px-4 py-2 hover:bg-vault-accent transition"
                  >
                    Log out
                  </button>
                </div>
              )}
            </div>
          ) : (
            <div className="flex gap-3">
              <Link to="/register" className="text-sm text-white hover:text-vault-accent">Sign up</Link>
              <Link to="/login" className="text-sm text-white hover:text-vault-accent">Login</Link>
            </div>
          )}

          {/* Mobile hamburger */}
          <button
            className="md:hidden text-white hover:text-vault-accent ml-2"
            onClick={() => setMobileOpen((v) => !v)}
          >
            ☰
          </button>
        </div>
      </div>

      {/* Mobile menu */}
      {mobileOpen && (
        <div className="md:hidden bg-vault-dark border-t border-white/10 px-4 pb-3 space-y-1">
          {user ? (
            <>
              <NavLink to="/" end className={linkClass} onClick={() => setMobileOpen(false)}>Home</NavLink>
              <NavLink to="/vault" className={linkClass} onClick={() => setMobileOpen(false)}>Vault</NavLink>
              <NavLink to="/iocs" className={linkClass} onClick={() => setMobileOpen(false)}>IOCs</NavLink>
              <NavLink to="/yara" className={linkClass} onClick={() => setMobileOpen(false)}>YARA</NavLink>
              <NavLink to="/about" className={linkClass} onClick={() => setMobileOpen(false)}>About</NavLink>
            </>
          ) : (
            <>
              <NavLink to="/" end className={linkClass} onClick={() => setMobileOpen(false)}>Home</NavLink>
              <NavLink to="/about" className={linkClass} onClick={() => setMobileOpen(false)}>About</NavLink>
            </>
          )}
        </div>
      )}
    </nav>
  )
}

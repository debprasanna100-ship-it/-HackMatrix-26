import { useCallback, useEffect, useRef, useState } from 'react'
import { fetchMe, login, logout, type ApiError, type AuthMe } from '../api/client'
import { onUnauthorized } from '../api/auth'

export default function AuthBar() {
  const [state, setState] = useState<'loading' | 'demo' | 'login' | 'active'>('loading')
  const [user, setUser] = useState<AuthMe | null>(null)
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [loginModalOpen, setLoginModalOpen] = useState(false)
  const mounted = useRef(true)

  useEffect(() => {
    mounted.current = true
    return () => {
      mounted.current = false
    }
  }, [])

  const refresh = useCallback(async () => {
    try {
      const me = await fetchMe()
      if (!mounted.current) return
      if (me.authenticated) {
        setUser(me)
        setState('active')
      } else {
        setUser(null)
        setState('demo')
      }
    } catch {
      if (!mounted.current) return
      setUser(null)
      setState('login')
    }
  }, [])

  useEffect(() => {
    let cancelled = false
    fetchMe()
      .then((me) => {
        if (cancelled) return
        if (me.authenticated) {
          setUser(me)
          setState('active')
        } else {
          setUser(null)
          setState('demo')
        }
      })
      .catch(() => {
        if (cancelled) return
        setUser(null)
        setState('login')
      })

    onUnauthorized(() => {
      if (!mounted.current) return
      setUser(null)
      setError('Your session expired — please sign in again.')
      setState('login')
      setLoginModalOpen(true)
    })
    return () => {
      cancelled = true
      onUnauthorized(null)
    }
  }, [])

  async function submitLogin(e: React.FormEvent) {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      const me = await login(email.trim(), password)
      setUser(me)
      setState('active')
      setPassword('')
      setLoginModalOpen(false)
    } catch (err) {
      const apiErr = err as ApiError
      setError(apiErr?.message ?? 'Sign-in failed. Please try again.')
    } finally {
      setBusy(false)
    }
  }

  function submitLogout() {
    logout()
    setUser(null)
    setError(null)
    void refresh()
  }

  if (state === 'loading') {
    return <div className="w-16 h-8 bg-surface-container/40 rounded-lg animate-pulse" />
  }

  if (state === 'demo') {
    return (
      <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full bg-secondary-container/20 text-on-secondary-container text-[11px] font-bold border border-secondary/30">
        <span className="w-1.5 h-1.5 rounded-full bg-secondary"></span>
        Demo Mode
      </span>
    )
  }

  if (state === 'active' && user) {
    return (
      <div className="inline-flex items-center gap-2 bg-surface-container-low px-2.5 py-1 rounded-xl border border-border-subtle">
        <div className="w-6 h-6 rounded-full bg-primary-container text-white flex items-center justify-center text-xs font-bold">
          {user.email?.charAt(0).toUpperCase() || 'U'}
        </div>
        <span className="text-xs font-semibold text-on-surface truncate max-w-[120px]">
          {user.email}
        </span>
        {user.role === 'admin' && (
          <span className="text-[10px] bg-primary text-white px-1.5 py-0.2 rounded font-bold">
            Admin
          </span>
        )}
        <button
          type="button"
          onClick={submitLogout}
          className="text-xs text-outline hover:text-danger-red transition-colors p-0.5"
          title="Sign out"
        >
          <span className="material-symbols-outlined text-[16px]">logout</span>
        </button>
      </div>
    )
  }

  return (
    <>
      <button
        onClick={() => setLoginModalOpen(true)}
        type="button"
        className="inline-flex items-center gap-1 px-3 py-1.5 rounded-lg border border-border-subtle text-xs font-bold text-on-surface hover:bg-surface-container-low transition-colors"
      >
        <span className="material-symbols-outlined text-[16px]">account_circle</span>
        Sign in
      </button>

      {loginModalOpen && (
        <div className="fixed inset-0 bg-black/40 backdrop-blur-xs flex items-center justify-center p-4 z-50">
          <div className="bg-surface-card rounded-2xl border border-border-subtle shadow-xl max-w-sm w-full p-6 relative">
            <button
              onClick={() => setLoginModalOpen(false)}
              className="absolute top-4 right-4 text-outline hover:text-on-surface"
              type="button"
            >
              <span className="material-symbols-outlined text-[20px]">close</span>
            </button>
            <h3 className="text-lg font-bold text-primary mb-1">Sign In to TrustLens</h3>
            <p className="text-xs text-on-surface-variant mb-4">
              Enter your credentials to access secured reports and admin tools.
            </p>

            {error && (
              <div className="mb-3 p-2.5 rounded-lg bg-red-50 text-danger-red border border-red-200 text-xs">
                {error}
              </div>
            )}

            <form onSubmit={submitLogin} className="space-y-3">
              <div>
                <label className="block text-xs font-bold text-on-surface mb-1">Email</label>
                <input
                  type="email"
                  required
                  placeholder="analyst@trustlens.gov.in"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  disabled={busy}
                  className="w-full bg-surface-card border border-border-subtle rounded-lg px-3 py-2 text-xs focus:border-primary-container focus:ring-0"
                />
              </div>
              <div>
                <label className="block text-xs font-bold text-on-surface mb-1">Password</label>
                <input
                  type="password"
                  required
                  placeholder="••••••••"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  disabled={busy}
                  className="w-full bg-surface-card border border-border-subtle rounded-lg px-3 py-2 text-xs focus:border-primary-container focus:ring-0"
                />
              </div>
              <button
                type="submit"
                disabled={busy || !email || !password}
                className="w-full bg-primary-container hover:bg-primary text-white text-xs font-bold py-2.5 rounded-lg transition-all"
              >
                {busy ? 'Authenticating...' : 'Sign In'}
              </button>
            </form>
          </div>
        </div>
      )}
    </>
  )
}

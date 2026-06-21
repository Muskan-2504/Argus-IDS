import { useCallback, useEffect, useState } from 'react'
import type { ReactNode } from 'react'

import { api, tokenStore } from '../api/client'
import type { User } from '../api/types'
import { AuthContext } from './context'

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null)
  const [loading, setLoading] = useState(true)

  // Restore the session on load if a token is already stored.
  useEffect(() => {
    if (!tokenStore.get()) {
      setLoading(false)
      return
    }
    api
      .me()
      .then(setUser)
      .catch(() => tokenStore.clear())
      .finally(() => setLoading(false))
  }, [])

  const login = useCallback(async (username: string, password: string) => {
    const token = await api.login(username, password)
    tokenStore.set(token.access_token)
    setUser(await api.me())
  }, [])

  const logout = useCallback(() => {
    tokenStore.clear()
    setUser(null)
  }, [])

  return (
    <AuthContext.Provider value={{ user, loading, login, logout }}>
      {children}
    </AuthContext.Provider>
  )
}

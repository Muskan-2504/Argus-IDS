import { createContext } from 'react'

import type { User } from '../api/types'

export interface AuthState {
  user: User | null
  loading: boolean
  login: (username: string, password: string) => Promise<void>
  logout: () => void
}

export const AuthContext = createContext<AuthState | undefined>(undefined)

import { createContext } from 'react'

import type { AnalyzeResult, SourceType } from '../api/types'

// 'auto' asks the backend to sniff the format (and fall back to the generic
// extractor for anything it doesn't recognize).
export type FormatChoice = SourceType | 'auto'

// Lifted above the router so the user's pasted logs and last result survive
// navigating away to the dashboard and back. A full page refresh remounts the
// provider and clears it — the intended "until I refresh" behavior.
export interface AnalyzeState {
  text: string
  setText: (value: string) => void
  format: FormatChoice
  setFormat: (value: FormatChoice) => void
  result: AnalyzeResult | null
  setResult: (value: AnalyzeResult | null) => void
  error: string | null
  setError: (value: string | null) => void
  loading: boolean
  setLoading: (value: boolean) => void
  clear: () => void
}

export const AnalyzeContext = createContext<AnalyzeState | undefined>(undefined)

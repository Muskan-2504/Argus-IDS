import { useContext } from 'react'

import { AnalyzeContext, type AnalyzeState } from './context'

export function useAnalyze(): AnalyzeState {
  const ctx = useContext(AnalyzeContext)
  if (!ctx) throw new Error('useAnalyze must be used within an AnalyzeProvider')
  return ctx
}

import { useCallback, useMemo, useState } from 'react'
import type { ReactNode } from 'react'

import type { AnalyzeResult } from '../api/types'
import { AnalyzeContext, type FormatChoice } from './context'

export function AnalyzeProvider({ children }: { children: ReactNode }) {
  const [text, setText] = useState('')
  const [format, setFormat] = useState<FormatChoice>('auto')
  const [result, setResult] = useState<AnalyzeResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  const clear = useCallback(() => {
    setText('')
    setResult(null)
    setError(null)
  }, [])

  const value = useMemo(
    () => ({
      text,
      setText,
      format,
      setFormat,
      result,
      setResult,
      error,
      setError,
      loading,
      setLoading,
      clear,
    }),
    [text, format, result, error, loading, clear],
  )

  return <AnalyzeContext.Provider value={value}>{children}</AnalyzeContext.Provider>
}

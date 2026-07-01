import { useEffect, useRef, useState } from 'react'

import { tokenStore } from './client'
import type { Alert } from './types'

interface Envelope {
  type: string
  data?: Alert
}

/**
 * Subscribe to the live alert WebSocket. Calls `onAlert` for each pushed alert
 * and returns whether the socket is currently connected. The dashboard keeps a
 * slower poll as a fallback, so a dropped socket degrades gracefully.
 */
export function useAlertStream(onAlert: (alert: Alert) => void): boolean {
  const [connected, setConnected] = useState(false)
  const handler = useRef(onAlert)
  handler.current = onAlert

  useEffect(() => {
    const token = tokenStore.get()
    if (!token) return

    const base = import.meta.env.VITE_API_URL ?? ''
    const origin = base || window.location.origin
    const url = `${origin.replace(/^http/, 'ws')}/api/ws/alerts?token=${encodeURIComponent(token)}`

    const socket = new WebSocket(url)
    socket.onmessage = (event) => {
      const message = JSON.parse(event.data) as Envelope
      if (message.type === 'ready') setConnected(true)
      else if (message.type === 'alert' && message.data) handler.current(message.data)
    }
    socket.onclose = () => setConnected(false)
    socket.onerror = () => setConnected(false)

    return () => socket.close()
  }, [])

  return connected
}

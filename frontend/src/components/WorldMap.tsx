import { geoNaturalEarth1, geoPath } from 'd3-geo'
import type { Feature, Geometry } from 'geojson'
import { useEffect, useMemo, useState } from 'react'
import { feature } from 'topojson-client'
import type { GeometryCollection, Topology } from 'topojson-specification'
import worldUrl from 'world-atlas/countries-110m.json?url'

import { SEVERITY_ORDER, type Alert, type Severity } from '../api/types'

const WIDTH = 800
const HEIGHT = 380
const SPHERE = { type: 'Sphere' } as const

const SEVERITY_COLOR: Record<Severity, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#22c55e',
  info: '#38bdf8',
}

interface AttackPoint {
  key: string
  x: number
  y: number
  count: number
  severity: Severity
}

export function WorldMap({ alerts }: { alerts: Alert[] }) {
  const [countries, setCountries] = useState<Feature<Geometry>[]>([])

  useEffect(() => {
    let cancelled = false
    fetch(worldUrl)
      .then((res) => res.json() as Promise<Topology>)
      .then((topo) => {
        if (cancelled) return
        const fc = feature(topo, topo.objects.countries as GeometryCollection)
        setCountries(fc.features as Feature<Geometry>[])
      })
      .catch(() => undefined)
    return () => {
      cancelled = true
    }
  }, [])

  const projection = useMemo(() => geoNaturalEarth1().fitSize([WIDTH, HEIGHT], SPHERE), [])
  const path = useMemo(() => geoPath(projection), [projection])

  const points = useMemo<AttackPoint[]>(() => {
    const grouped = new Map<string, AttackPoint>()
    for (const alert of alerts) {
      const e = alert.enrichment
      if (!e || e.latitude == null || e.longitude == null) continue
      const xy = projection([e.longitude, e.latitude])
      if (!xy) continue
      const key = `${e.latitude},${e.longitude}`
      const existing = grouped.get(key)
      if (existing) {
        existing.count += 1
        if (SEVERITY_ORDER.indexOf(alert.severity) < SEVERITY_ORDER.indexOf(existing.severity)) {
          existing.severity = alert.severity
        }
      } else {
        grouped.set(key, { key, x: xy[0], y: xy[1], count: 1, severity: alert.severity })
      }
    }
    return [...grouped.values()]
  }, [alerts, projection])

  return (
    <div>
      <svg viewBox={`0 0 ${WIDTH} ${HEIGHT}`} className="h-auto w-full">
        <path d={path(SPHERE) ?? undefined} fill="#0b1220" />
        {countries.map((country, i) => (
          <path key={i} d={path(country) ?? undefined} fill="#1e293b" stroke="#0f172a" strokeWidth={0.4} />
        ))}
        {points.map((point) => (
          <circle
            key={point.key}
            cx={point.x}
            cy={point.y}
            r={4 + Math.min(point.count, 8)}
            fill={SEVERITY_COLOR[point.severity]}
            fillOpacity={0.65}
            stroke={SEVERITY_COLOR[point.severity]}
          >
            <animate
              attributeName="fill-opacity"
              values="0.65;0.2;0.65"
              dur="2s"
              repeatCount="indefinite"
            />
          </circle>
        ))}
      </svg>
      {points.length === 0 && (
        <p className="mt-2 text-center text-xs text-slate-500">
          No geolocated alerts yet — enable enrichment (set <code>GEOIP_USE_IPAPI=true</code>) and
          ingest public-IP traffic to populate the map.
        </p>
      )}
    </div>
  )
}

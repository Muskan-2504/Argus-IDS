import {
  BarElement,
  CategoryScale,
  Chart as ChartJS,
  type ChartOptions,
  LinearScale,
  Tooltip,
} from 'chart.js'
import { Bar } from 'react-chartjs-2'

import type { Alert } from '../api/types'

ChartJS.register(CategoryScale, LinearScale, BarElement, Tooltip)

const TICKS = { color: '#94a3b8' }
const GRID = { color: 'rgba(148,163,184,0.1)' }

const OPTIONS: ChartOptions<'bar'> = {
  maintainAspectRatio: false,
  plugins: { legend: { display: false } },
  scales: {
    x: { ticks: TICKS, grid: GRID },
    y: { beginAtZero: true, ticks: { ...TICKS, precision: 0 }, grid: GRID },
  },
}

function bucketByHour(alerts: Alert[]): Map<string, number> {
  const buckets = new Map<string, number>()
  const ascending = [...alerts].sort(
    (a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime(),
  )
  for (const alert of ascending) {
    const d = new Date(alert.created_at)
    const key = `${d.getMonth() + 1}/${d.getDate()} ${String(d.getHours()).padStart(2, '0')}:00`
    buckets.set(key, (buckets.get(key) ?? 0) + 1)
  }
  return buckets
}

export function TimelineChart({ alerts }: { alerts: Alert[] }) {
  const buckets = bucketByHour(alerts)
  const labels = [...buckets.keys()]
  const data = {
    labels,
    datasets: [{ label: 'Alerts', data: labels.map((l) => buckets.get(l) ?? 0), backgroundColor: '#38bdf8' }],
  }
  return (
    <div className="h-64">
      <Bar data={data} options={OPTIONS} />
    </div>
  )
}

import { ArcElement, Chart as ChartJS, type ChartOptions, Legend, Tooltip } from 'chart.js'
import { Doughnut } from 'react-chartjs-2'

import { SEVERITY_ORDER, type Alert, type Severity } from '../api/types'

ChartJS.register(ArcElement, Tooltip, Legend)

const COLORS: Record<Severity, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#22c55e',
  info: '#38bdf8',
}

const OPTIONS: ChartOptions<'doughnut'> = {
  maintainAspectRatio: false,
  cutout: '62%',
  plugins: {
    legend: { position: 'bottom', labels: { color: '#94a3b8', boxWidth: 12 } },
  },
}

export function SeverityChart({ alerts }: { alerts: Alert[] }) {
  const counts = SEVERITY_ORDER.map((s) => alerts.filter((a) => a.severity === s).length)
  const data = {
    labels: SEVERITY_ORDER,
    datasets: [
      {
        data: counts,
        backgroundColor: SEVERITY_ORDER.map((s) => COLORS[s]),
        borderWidth: 0,
      },
    ],
  }
  return (
    <div className="h-64">
      <Doughnut data={data} options={OPTIONS} />
    </div>
  )
}

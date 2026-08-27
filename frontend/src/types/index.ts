export type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Log' | 'None'

export interface Vulnerability {
  id: string
  finding_id: string
  host: string
  hostname: string
  port: string
  protocol: string
  nvt_oid: string
  nvt_name: string
  cvss: number
  severity: Severity
  cves: string[]
  description: string
  solution: string
  solution_type: string
  first_seen: string | null
  last_seen: string | null
  task_name: string
  report_id: string
}

export interface VulnerabilityList {
  total: number
  page: number
  page_size: number
  items: Vulnerability[]
}

export interface HostSummary {
  ip: string
  hostname: string
  os: string
  risk_score: number
  critical: number
  high: number
  medium: number
  low: number
  log: number
  total: number
  last_seen: string | null
}

export interface HostDetail extends HostSummary {
  vulnerabilities: Vulnerability[]
}

export interface ScanTask {
  id: string
  name: string
  status: string
  progress: number
  target_name: string
  last_report_id: string | null
  last_scan_date: string | null
  severity_summary: Record<string, number>
}

export interface TrendPoint {
  month: string
  critical: number
  high: number
  medium: number
  low: number
  total: number
}

export interface AgingBucket {
  label: string
  count: number
}

export interface TopHost {
  ip: string
  hostname: string
  risk_score: number
  total: number
  critical: number
  high: number
}

export interface DashboardSummary {
  total_open: number
  severity: { critical: number; high: number; medium: number; low: number; log: number }
  risk_score: number
  sla_overdue: number
  hosts_affected: number
  scans_active: number
  last_sync: string | null
  trend: TrendPoint[]
  top_hosts: TopHost[]
  aging: AgingBucket[]
}

export interface SyncStatus {
  status: string
  message: string
  synced_at: string | null
}

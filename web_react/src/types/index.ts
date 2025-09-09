export type FilterType = 'urls' | 'ports' | 'domains' | 'vulns' | null

export interface LayerData {
  urls?: Array<{
    url: string
    title: string
    size: number
    status_code?: number
  }>
  url_analysis?: {
    unique_urls: Array<{
      url: string
      title: string
      size: number
      status_code: number
      count: number
      sources: string[]
    }>
    duplicate_urls: Array<{
      url: string
      title: string
      size: number
      status_code: number
      count: number
      sources: string[]
    }>
    statistics: {
      total_urls: number
      unique_urls: number
      duplicate_instances: number
      duplicate_unique_count: number
    }
  }
  expand_scanned_urls?: Array<{
    url: string
    title: string
    size: number
    status_code?: number
  }>
  ip_scan_results?: Record<string, {
    ports: Array<{
      port: number
      service: string
      status: string
    }>
    vulnerabilities?: Array<{
      name: string
      severity: string
      description: string
    }>
  }>
  fofa_results?: Array<{
    url: string
    title: string
    ip: string
    port: number
  }>
  content_mining?: Array<{
    domain: string
    source: string
  }>
  blacklist_domains?: Array<{
    domain: string
    reason: string
  }>
  duplicate_domains?: Array<{
    domain: string
    original: string
  }>
  associated_ips?: string[]
  basic_ip_scan_results?: Record<string, {
    ports: Array<{
      port: number
      service: string
      status: string
    }>
    vulnerabilities?: Array<{
      name: string
      severity: string
      description: string
    }>
    web_info?: Array<{
      url: string
      port: string
      protocol: string
      status_code: string
      content_length: string
      title: string
    }>
  }>
  expand_domains?: Array<{
    domain: string
    source: string
    origin_url: string
    status: string
  }>
  expand_ips?: Array<{
    ip: string
    port?: string
    ip_port: string
    source: string
    origin_url: string
    status: string
  }>
  expand_root_domains?: Array<{
    domain: string
    source: string
    origin_url: string
    status: string
  }>
}

export interface DomainData {
  domain: string
  layers: Record<string, LayerData>
  scan_time: string
  total_urls: number
  total_domains: number
  total_ips: number
  total_vulnerabilities: number
}

export interface ScanStatus {
  scan_completed: boolean
  progress: number
  current_stage: string
  start_time: string
  scan_stages: Record<string, {
    status: 'pending' | 'in_progress' | 'completed' | 'failed'
    progress: number
    start_time?: string
    end_time?: string
    details?: string
    error?: string
  }>
}

export interface LogEntry {
  timestamp: string
  level: 'info' | 'warning' | 'error' | 'success'
  message: string
  source?: string
}

export interface RawDataFiles {
  basic_info?: string
  technical_info?: string
  vulnerability_data?: string
  fofa_results?: string
  content_mining?: string
}

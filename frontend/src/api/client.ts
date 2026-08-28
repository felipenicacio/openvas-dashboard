/**
 * Axios client — OpenVAS Dashboard v1.1.0
 *
 * Mudanças de segurança:
 * - Token JWT não armazenado em localStorage (vulnerável a XSS)
 * - Autenticação via cookie HttpOnly gerenciado pelo browser
 * - withCredentials: true envia cookie em todas as requisições
 * - 401 redireciona para /login sem expor informações de sessão
 */

import axios from "axios";
import type {
  DashboardSummary, HostSummary, HostDetail, VulnerabilityList,
  ScanTask, SyncStatus, TrendPoint, TopHost,
} from "../types";

const api = axios.create({
  baseURL: "/api",
  withCredentials: true,   // envia cookie de sessão automaticamente
  headers: {
    "Content-Type": "application/json",
  },
});

// ── Interceptor de resposta ────────────────────────────────────────────────────
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      // Sessão expirada ou inválida — redireciona para login
      // Sem acesso ao token (HttpOnly) — browser gerencia o cookie
      const currentPath = window.location.pathname;
      if (currentPath !== "/login") {
        window.location.replace("/login");
      }
    }
    return Promise.reject(error);
  }
);

export default api;

// ── Tipos locais ───────────────────────────────────────────────────────────────

export interface LoginPayload {
  username: string;
  password: string;
}

export interface AuthUser {
  username: string;
  role: "viewer" | "analyst" | "admin";
}

// ── Auth ──────────────────────────────────────────────────────────────────────

/** POST /api/auth/token — autentica e define cookie de sessão */
export const login = (payload: LoginPayload) =>
  api.post<{ message: string }>("/auth/token", payload);

/** POST /api/auth/logout — revoga token e remove cookie */
export const logout = () => api.post<{ message: string }>("/auth/logout");

/** GET /api/auth/me — retorna usuário autenticado */
export const getMe = () => api.get<AuthUser>("/auth/me");

// ── Dashboard ─────────────────────────────────────────────────────────────────

type BackendSummary  = { total: number; hosts: number; by_severity: Record<string, number> };
type BackendTrendRow = { day: string; severity: string; n: number };
type BackendTopHost  = { host: string; total: number; critical: number; high: number };

/** Combina /dashboard/summary, /dashboard/trend, /dashboard/top-hosts e /scans */
export const getDashboard = (): Promise<{ data: DashboardSummary }> =>
  Promise.all([
    api.get<BackendSummary>("/dashboard/summary"),
    api.get<BackendTrendRow[]>("/dashboard/trend"),
    api.get<BackendTopHost[]>("/dashboard/top-hosts"),
    api.get<ScanTask[]>("/scans"),
  ]).then(([summaryRes, trendRes, topHostsRes, scansRes]) => {
    const s = summaryRes.data;
    const sev: DashboardSummary["severity"] = {
      critical: s.by_severity["Critical"] ?? 0,
      high:     s.by_severity["High"]     ?? 0,
      medium:   s.by_severity["Medium"]   ?? 0,
      low:      s.by_severity["Low"]      ?? 0,
      log:      s.by_severity["Log"]      ?? 0,
    };

    // Agregar linhas diárias → pontos mensais
    const monthMap = new Map<string, TrendPoint>();
    for (const row of trendRes.data) {
      const month = row.day.slice(0, 7);
      const p = monthMap.get(month) ?? { month, critical: 0, high: 0, medium: 0, low: 0, total: 0 };
      const k = row.severity.toLowerCase() as keyof Omit<TrendPoint, "month" | "total">;
      if (k in p) (p as unknown as Record<string, number>)[k] = ((p as unknown as Record<string, number>)[k] ?? 0) + row.n;
      p.total += row.n;
      monthMap.set(month, p);
    }
    const trend = [...monthMap.values()]
      .sort((a, b) => a.month.localeCompare(b.month))
      .slice(-12);

    const topHosts: TopHost[] = topHostsRes.data.map(h => ({
      ip:         h.host,
      hostname:   h.host,
      total:      h.total,
      critical:   h.critical,
      high:       h.high,
      risk_score: parseFloat(
        Math.min(10, (h.critical * 10 + h.high * 7) / (h.total || 1)).toFixed(1)
      ),
    }));

    const scansActive = scansRes.data.filter(sc => sc.status === "Running").length;
    const riskScore = s.total > 0
      ? parseFloat(
          Math.min(10, (sev.critical * 10 + sev.high * 7 + sev.medium * 4 + sev.low) / s.total).toFixed(1)
        )
      : 0;

    return {
      data: {
        total_open:     s.total,
        severity:       sev,
        risk_score:     riskScore,
        sla_overdue:    0,
        hosts_affected: s.hosts,
        scans_active:   scansActive,
        last_sync:      null,
        trend,
        top_hosts:      topHosts,
        aging:          [],
      } satisfies DashboardSummary,
    };
  });

// ── Hosts ─────────────────────────────────────────────────────────────────────

type BackendHostRow = {
  host: string; total: number;
  critical: number; high: number; medium: number; low: number; log: number;
  max_cvss: number; first_seen: string | null;
};

/** GET /api/hosts — lista hosts com contagem de vulnerabilidades */
export const getHosts = (params?: { search?: string }): Promise<{ data: HostSummary[] }> =>
  api.get<BackendHostRow[]>("/hosts", { params }).then(r => ({
    ...r,
    data: r.data.map(h => ({
      ip:         h.host,
      hostname:   h.host,
      os:         "",
      risk_score: parseFloat(Math.min(10, h.max_cvss).toFixed(1)),
      critical:   h.critical,
      high:       h.high,
      medium:     h.medium,
      low:        h.low,
      log:        h.log,
      total:      h.total,
      last_seen:  h.first_seen,
    })),
  }));

/** GET /api/hosts/{ip} — detalhes e vulnerabilidades de um host */
export const getHost = (ip: string): Promise<{ data: HostDetail }> =>
  api.get<{ host: string; vulnerabilities: Record<string, unknown>[] }>(
    "/hosts/" + encodeURIComponent(ip)
  ).then(r => ({
    ...r,
    data: {
      ip:         r.data.host,
      hostname:   r.data.host,
      os:         "",
      risk_score: 0,
      critical:   0,
      high:       0,
      medium:     0,
      low:        0,
      log:        0,
      total:      r.data.vulnerabilities.length,
      last_seen:  null,
      vulnerabilities: r.data.vulnerabilities as unknown as HostDetail["vulnerabilities"],
    },
  }));

// ── Vulnerabilidades ──────────────────────────────────────────────────────────

/** GET /api/vulnerabilities — lista paginada com filtros */
export const getVulns = (params: Record<string, unknown>) =>
  api.get<VulnerabilityList>("/vulnerabilities", { params });

// ── Scans ─────────────────────────────────────────────────────────────────────

/** GET /api/scans — lista tasks do GVM */
export const getScans = () =>
  api.get<ScanTask[]>("/scans");

/** POST /api/scans/{id}/start — inicia scan (requer ADMIN) */
export const startScan = (taskId: string) =>
  api.post<{ task_id: string; message: string }>("/scans/" + taskId + "/start");

/** POST /api/scans/{id}/stop — para scan (requer ADMIN) */
export const stopScan = (taskId: string) =>
  api.post<{ task_id: string; message: string }>("/scans/" + taskId + "/stop");

/** POST /api/scans/sync — sincronização manual (requer ANALYST) */
export const triggerSync = () =>
  api.post<SyncStatus>("/scans/sync");

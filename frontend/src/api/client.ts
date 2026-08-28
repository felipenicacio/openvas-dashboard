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

// ── Tipos ─────────────────────────────────────────────────────────────────────

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

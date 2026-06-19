import { writable, derived } from 'svelte/store';

export interface Alert {
  id: number;
  ts: number;
  detector: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  title: string;
  node_id: string;
  acked: boolean;
  incident_id: number | null;
}

export interface Incident {
  id: number;
  ts: number;
  entity_type: string;
  entity_value: string;
  status: 'open' | 'closed';
  severity: string;
  title: string;
  acked: boolean;
  alert_count: number;
}

export interface Stats {
  total_alerts: number;
  open_incidents: number;
  by_severity: Record<string, number>;
  by_detector: Record<string, number>;
}

// ─── Stores ────────────────────────────────────────────────────────────────

export const alerts    = writable<Alert[]>([]);
export const incidents = writable<Incident[]>([]);
export const stats     = writable<Stats | null>(null);
export const token     = writable<string>(localStorage.getItem('axion_token') ?? '');
export const wsStatus  = writable<'connecting' | 'connected' | 'disconnected'>('disconnected');

// Derived: unacked high/critical alerts
export const criticalAlerts = derived(alerts, ($a) =>
  $a.filter((a) => !a.acked && (a.severity === 'critical' || a.severity === 'high'))
);

// ─── API helpers ───────────────────────────────────────────────────────────

export async function apiGet<T>(path: string, jwt: string): Promise<T> {
  const r = await fetch(path, {
    headers: { Authorization: `Bearer ${jwt}` },
  });
  if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);
  return r.json();
}

export async function apiPost<T>(path: string, jwt: string, body: unknown): Promise<T> {
  const r = await fetch(path, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${jwt}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error(`${r.status} ${r.statusText}`);
  return r.json();
}

// ─── WebSocket ─────────────────────────────────────────────────────────────

let ws: WebSocket | null = null;
let reconnectTimer: ReturnType<typeof setTimeout> | null = null;

export function connectWS(jwt: string): void {
  if (ws) ws.close();

  // C2: Token is sent as the first WebSocket message, not in the URL.
  // This prevents JWT leakage in server access logs and browser history.
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  const url   = `${proto}://${location.host}/api/ws`;

  wsStatus.set('connecting');
  ws = new WebSocket(url);

  ws.onopen = () => {
    ws?.send(JSON.stringify({ type: 'auth', token: jwt }));
  };

  ws.onmessage = (ev) => {
    const msg = JSON.parse(ev.data);
    if (msg.type === 'auth_ok') {
      wsStatus.set('connected');
      return;
    }
    if (msg.type === 'alert') {
      alerts.update((prev) => [msg as Alert, ...prev].slice(0, 500));
    }
  };

  ws.onclose = () => {
    wsStatus.set('disconnected');
    reconnectTimer = setTimeout(() => connectWS(jwt), 3000);
  };

  ws.onerror = () => ws?.close();
}

export function disconnectWS(): void {
  if (reconnectTimer) clearTimeout(reconnectTimer);
  ws?.close();
  ws = null;
}

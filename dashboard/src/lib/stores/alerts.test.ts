// Run with: npm run test  (vitest)
// Install vitest: npm i -D vitest @testing-library/svelte jsdom

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { get } from 'svelte/store';
import {
  alerts,
  incidents,
  stats,
  token,
  wsStatus,
  criticalAlerts,
  connectWS,
  disconnectWS,
} from './alerts';
import type { Alert } from './alerts';

// ─── Store initialisation ─────────────────────────────────────────────────

describe('store defaults', () => {
  beforeEach(() => {
    alerts.set([]);
    incidents.set([]);
    stats.set(null);
    token.set('');
    wsStatus.set('disconnected');
  });

  it('alerts starts empty', () => {
    expect(get(alerts)).toEqual([]);
  });

  it('incidents starts empty', () => {
    expect(get(incidents)).toEqual([]);
  });

  it('stats starts null', () => {
    expect(get(stats)).toBeNull();
  });

  it('wsStatus starts disconnected', () => {
    expect(get(wsStatus)).toBe('disconnected');
  });
});

// ─── criticalAlerts derived store ─────────────────────────────────────────

describe('criticalAlerts', () => {
  const makeAlert = (id: number, sev: Alert['severity'], acked = false): Alert => ({
    id, ts: Date.now() / 1000, detector: 'DDoSDetector',
    severity: sev, title: `alert-${id}`, node_id: 'n1',
    acked, incident_id: null,
  });

  beforeEach(() => alerts.set([]));

  it('includes unacked critical alerts', () => {
    alerts.set([makeAlert(1, 'critical', false)]);
    expect(get(criticalAlerts)).toHaveLength(1);
  });

  it('includes unacked high alerts', () => {
    alerts.set([makeAlert(2, 'high', false)]);
    expect(get(criticalAlerts)).toHaveLength(1);
  });

  it('excludes acked alerts', () => {
    alerts.set([makeAlert(3, 'critical', true)]);
    expect(get(criticalAlerts)).toHaveLength(0);
  });

  it('excludes low/medium severity', () => {
    alerts.set([makeAlert(4, 'low', false), makeAlert(5, 'medium', false)]);
    expect(get(criticalAlerts)).toHaveLength(0);
  });

  it('counts multiple unacked high/critical', () => {
    alerts.set([
      makeAlert(1, 'critical', false),
      makeAlert(2, 'high', false),
      makeAlert(3, 'medium', false),
      makeAlert(4, 'critical', true),
    ]);
    expect(get(criticalAlerts)).toHaveLength(2);
  });
});

// ─── WebSocket ────────────────────────────────────────────────────────────

describe('WebSocket connectivity', () => {
  let mockWS: any;
  let wsConstructorArgs: string[];

  beforeEach(() => {
    wsConstructorArgs = [];
    wsStatus.set('disconnected');
    alerts.set([]);

    mockWS = {
      onopen: null,
      onmessage: null,
      onclose: null,
      onerror: null,
      close: vi.fn(() => { mockWS.onclose?.(); }),
      send: vi.fn(),
      readyState: 1,
    };

    // @ts-ignore
    global.WebSocket = vi.fn((url: string) => {
      wsConstructorArgs.push(url);
      return mockWS;
    });

    // Stub localStorage
    global.localStorage = {
      getItem: vi.fn(),
      setItem: vi.fn(),
      removeItem: vi.fn(),
      clear: vi.fn(),
      length: 0,
      key: vi.fn(),
    } as any;
  });

  it('sets wsStatus to connecting on connectWS', () => {
    connectWS('test-token');
    expect(get(wsStatus)).toBe('connecting');
  });

  it('sets wsStatus to connected on ws.onopen', () => {
    connectWS('test-token');
    mockWS.onopen();
    expect(get(wsStatus)).toBe('connected');
  });

  it('pushes incoming alert messages to the alerts store', () => {
    connectWS('test-token');
    mockWS.onopen();

    const alertMsg: Alert = {
      type: 'alert' as any, id: 42, ts: 1_000_000,
      detector: 'DDoSDetector', severity: 'high',
      title: 'Flood', node_id: 'n1', acked: false, incident_id: null,
    };
    mockWS.onmessage({ data: JSON.stringify(alertMsg) });

    const stored = get(alerts);
    expect(stored).toHaveLength(1);
    expect(stored[0].id).toBe(42);
  });

  it('ignores non-alert message types', () => {
    connectWS('test-token');
    mockWS.onopen();
    mockWS.onmessage({ data: JSON.stringify({ type: 'ping' }) });
    expect(get(alerts)).toHaveLength(0);
  });

  it('caps the alerts store at 500 entries', () => {
    connectWS('test-token');
    mockWS.onopen();

    for (let i = 0; i < 600; i++) {
      mockWS.onmessage({
        data: JSON.stringify({
          type: 'alert', id: i, ts: i, detector: 'x',
          severity: 'low', title: 't', node_id: '', acked: false, incident_id: null,
        }),
      });
    }
    expect(get(alerts).length).toBeLessThanOrEqual(500);
  });

  it('sets wsStatus to disconnected on ws.onclose', () => {
    connectWS('test-token');
    mockWS.onopen();
    mockWS.onclose();
    expect(get(wsStatus)).toBe('disconnected');
  });

  it('disconnectWS closes the socket', () => {
    connectWS('test-token');
    disconnectWS();
    expect(mockWS.close).toHaveBeenCalled();
  });

  it('includes token in ws URL', () => {
    connectWS('my-jwt-token');
    expect(wsConstructorArgs[0]).toContain('my-jwt-token');
  });
});

// ─── apiGet / apiPost ──────────────────────────────────────────────────────

describe('API helpers', () => {
  import('./alerts').then(({ apiGet, apiPost }) => {
    it('apiGet sets Authorization header', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ data: 'ok' }),
      } as any);

      await apiGet('/api/alerts', 'my-token');
      const [, init] = (global.fetch as any).mock.calls[0];
      expect(init.headers['Authorization']).toBe('Bearer my-token');
    });

    it('apiGet throws on non-ok response', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: false, status: 401, statusText: 'Unauthorized',
      } as any);

      await expect(apiGet('/api/alerts', 'bad-token')).rejects.toThrow('401');
    });

    it('apiPost serialises body as JSON', async () => {
      global.fetch = vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({}),
      } as any);

      await apiPost('/api/login', '', { username: 'admin' });
      const [, init] = (global.fetch as any).mock.calls[0];
      expect(JSON.parse(init.body).username).toBe('admin');
    });
  });
});

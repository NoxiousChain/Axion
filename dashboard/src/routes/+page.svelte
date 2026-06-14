<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import {
    alerts, incidents, stats, token, wsStatus, criticalAlerts,
    connectWS, disconnectWS, apiGet, apiPost,
  } from '$lib/stores/alerts';
  import AlertFeed    from '$lib/components/AlertFeed.svelte';
  import IncidentList from '$lib/components/IncidentList.svelte';
  import StatsPanel   from '$lib/components/StatsPanel.svelte';
  import type { Alert, Incident, Stats } from '$lib/stores/alerts';

  // ─── Login form state ─────────────────────────────────────────────────────
  let username  = '';
  let password  = '';
  let apiKey    = '';
  let otp       = '';
  let loginErr  = '';
  let loggingIn = false;

  // ─── Tab ──────────────────────────────────────────────────────────────────
  let tab: 'alerts' | 'incidents' = 'alerts';

  async function login() {
    loggingIn = true;
    loginErr  = '';
    try {
      const res = await apiPost<{ access_token: string }>('/api/login', '', {
        username, password, api_key: apiKey, otp: otp || undefined,
      });
      token.set(res.access_token);
      localStorage.setItem('axion_token', res.access_token);
    } catch (e: any) {
      loginErr = e.message ?? 'Login failed';
    } finally {
      loggingIn = false;
    }
  }

  async function loadData(jwt: string) {
    try {
      const [a, i, s] = await Promise.all([
        apiGet<Alert[]>('/api/alerts?limit=200', jwt),
        apiGet<Incident[]>('/api/incidents', jwt),
        apiGet<Stats>('/api/stats', jwt),
      ]);
      alerts.set(a);
      incidents.set(i);
      stats.set(s);
    } catch (_) {}
  }

  async function ackAlert(id: number) {
    try {
      await apiPost(`/api/alerts/${id}/ack`, $token, { by: 'dashboard', note: '' });
      alerts.update(list => list.map(a => a.id === id ? { ...a, acked: true } : a));
    } catch (_) {}
  }

  async function ackIncident(id: number) {
    try {
      await apiPost(`/api/incidents/${id}/ack`, $token, { by: 'dashboard', note: '' });
      incidents.update(list => list.map(i => i.id === id ? { ...i, acked: true, status: 'closed' } : i));
    } catch (_) {}
  }

  // Refresh stats every 30 s
  let refreshInterval: ReturnType<typeof setInterval>;

  $: if ($token) {
    loadData($token);
    connectWS($token);
    refreshInterval = setInterval(() => {
      apiGet<Stats>('/api/stats', $token).then(s => stats.set(s)).catch(() => {});
    }, 30_000);
  }

  onDestroy(() => {
    disconnectWS();
    clearInterval(refreshInterval);
  });
</script>

<!-- ═══ Login Screen ═══════════════════════════════════════════════════════ -->
{#if !$token}
  <div class="login-wrap">
    <div class="login-card">
      <div class="login-brand">
        <span class="logo">⬡</span>
        <h1>Axion</h1>
      </div>
      <form on:submit|preventDefault={login}>
        <label>Username
          <input bind:value={username} type="text" autocomplete="username" required />
        </label>
        <label>Password
          <input bind:value={password} type="password" autocomplete="current-password" required />
        </label>
        <label>API Key
          <input bind:value={apiKey} type="password" placeholder="AXION_API_KEY" required />
        </label>
        <label>OTP <span class="optional">(if MFA enrolled)</span>
          <input bind:value={otp} type="text" inputmode="numeric" maxlength="8" />
        </label>
        {#if loginErr}<p class="err">{loginErr}</p>{/if}
        <button type="submit" disabled={loggingIn}>
          {loggingIn ? 'Signing in…' : 'Sign in'}
        </button>
      </form>
    </div>
  </div>

<!-- ═══ Main Dashboard ════════════════════════════════════════════════════ -->
{:else}
  <!-- WS status banner -->
  {#if $wsStatus === 'disconnected'}
    <div class="banner warn">WebSocket disconnected — reconnecting…</div>
  {/if}

  <!-- Critical alert banner -->
  {#if $criticalAlerts.length > 0}
    <div class="banner critical">
      ⚠ {$criticalAlerts.length} unacknowledged high/critical alert{$criticalAlerts.length > 1 ? 's' : ''}
    </div>
  {/if}

  <StatsPanel stats={$stats} />

  <!-- Tab bar -->
  <div class="tabs">
    <button class:active={tab === 'alerts'}    on:click={() => tab = 'alerts'}>
      Alerts <span class="count">{$alerts.length}</span>
    </button>
    <button class:active={tab === 'incidents'} on:click={() => tab = 'incidents'}>
      Incidents <span class="count">{$incidents.length}</span>
    </button>
  </div>

  {#if tab === 'alerts'}
    <AlertFeed alerts={$alerts} onAck={ackAlert} />
  {:else}
    <IncidentList incidents={$incidents} onAck={ackIncident} />
  {/if}
{/if}

<style>
  /* ── Login ── */
  .login-wrap {
    display: flex; align-items: center; justify-content: center;
    min-height: 80vh;
  }
  .login-card {
    background: #1e293b; border: 1px solid #334155; border-radius: .75rem;
    padding: 2rem; width: 100%; max-width: 360px;
  }
  .login-brand {
    display: flex; align-items: center; gap: .5rem; margin-bottom: 1.5rem;
  }
  .logo { font-size: 2rem; color: #3b82f6; }
  h1 { font-size: 1.5rem; color: #f8fafc; }
  form { display: flex; flex-direction: column; gap: .9rem; }
  label { display: flex; flex-direction: column; gap: .3rem; font-size: .8rem;
          color: #94a3b8; }
  .optional { font-size: .72rem; color: #475569; }
  input {
    background: #0f172a; border: 1px solid #334155; color: #e2e8f0;
    padding: .5rem .75rem; border-radius: .35rem; font-size: .9rem;
  }
  input:focus { outline: none; border-color: #3b82f6; }
  button[type=submit] {
    padding: .6rem; background: #2563eb; color: #fff; border: none;
    border-radius: .35rem; font-size: .9rem; cursor: pointer; font-weight: 600;
  }
  button[type=submit]:hover:not(:disabled) { background: #3b82f6; }
  button[type=submit]:disabled { opacity: .5; cursor: not-allowed; }
  .err { color: #f87171; font-size: .8rem; }

  /* ── Banners ── */
  .banner {
    padding: .5rem 1rem; border-radius: .35rem; margin-bottom: 1rem;
    font-size: .85rem; font-weight: 600;
  }
  .banner.warn     { background: #1e3a5f; color: #93c5fd; }
  .banner.critical { background: #7f1d1d; color: #fca5a5; }

  /* ── Tabs ── */
  .tabs { display: flex; gap: .25rem; margin-bottom: 1rem; border-bottom: 1px solid #1e293b; }
  .tabs button {
    padding: .5rem 1rem; background: transparent; border: none; color: #64748b;
    cursor: pointer; font-size: .85rem; font-weight: 600; border-bottom: 2px solid transparent;
    margin-bottom: -1px;
  }
  .tabs button.active { color: #3b82f6; border-bottom-color: #3b82f6; }
  .tabs button:hover:not(.active) { color: #94a3b8; }
  .count {
    display: inline-block; background: #334155; color: #94a3b8;
    border-radius: 9999px; padding: 0 .4rem; font-size: .7rem; margin-left: .25rem;
  }
</style>

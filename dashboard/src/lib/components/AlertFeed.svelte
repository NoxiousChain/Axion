<script lang="ts">
  import type { Alert } from '$lib/stores/alerts';

  export let alerts: Alert[] = [];
  export let onAck: (id: number) => void = () => {};

  const SEV_CLASS: Record<string, string> = {
    critical: 'sev-critical',
    high:     'sev-high',
    medium:   'sev-medium',
    low:      'sev-low',
  };

  function fmt(ts: number): string {
    return new Date(ts * 1000).toLocaleTimeString();
  }
</script>

<section class="feed">
  <h2>Live Alert Feed <span class="badge">{alerts.length}</span></h2>

  {#if alerts.length === 0}
    <p class="empty">No alerts yet.</p>
  {:else}
    <table>
      <thead>
        <tr>
          <th>Time</th>
          <th>Severity</th>
          <th>Detector</th>
          <th>Title</th>
          <th>Node</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        {#each alerts as a (a.id)}
          <tr class:acked={a.acked}>
            <td class="mono">{fmt(a.ts)}</td>
            <td><span class="sev {SEV_CLASS[a.severity]}">{a.severity}</span></td>
            <td class="mono">{a.detector}</td>
            <td>{a.title}</td>
            <td class="mono">{a.node_id || '—'}</td>
            <td>
              {#if !a.acked}
                <button class="btn-ack" on:click={() => onAck(a.id)}>Ack</button>
              {:else}
                <span class="acked-label">✓</span>
              {/if}
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
</section>

<style>
  .feed { overflow-x: auto; }
  h2 { display: flex; align-items: center; gap: .5rem; margin-bottom: .75rem; }
  .badge {
    background: #334155; color: #94a3b8;
    border-radius: 9999px; padding: .1rem .5rem; font-size: .75rem;
  }
  table { width: 100%; border-collapse: collapse; font-size: .85rem; }
  th { text-align: left; padding: .4rem .6rem; border-bottom: 1px solid #334155;
       color: #64748b; font-weight: 600; }
  td { padding: .35rem .6rem; border-bottom: 1px solid #1e293b; }
  tr:hover td { background: #1e293b; }
  tr.acked td { opacity: .45; }
  .mono { font-family: monospace; }
  .sev { padding: .15rem .45rem; border-radius: .25rem; font-size: .75rem;
         font-weight: 700; text-transform: uppercase; }
  .sev-critical { background: #7f1d1d; color: #fca5a5; }
  .sev-high     { background: #7c2d12; color: #fdba74; }
  .sev-medium   { background: #713f12; color: #fde68a; }
  .sev-low      { background: #14532d; color: #86efac; }
  .btn-ack {
    padding: .15rem .5rem; font-size: .75rem; cursor: pointer;
    background: #1d4ed8; color: #fff; border: none; border-radius: .25rem;
  }
  .btn-ack:hover { background: #2563eb; }
  .acked-label { color: #4ade80; font-size: .85rem; }
  .empty { color: #64748b; padding: 1rem 0; }
</style>

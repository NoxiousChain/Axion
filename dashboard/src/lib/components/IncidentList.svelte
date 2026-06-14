<script lang="ts">
  import type { Incident } from '$lib/stores/alerts';

  export let incidents: Incident[] = [];
  export let onAck: (id: number) => void = () => {};

  function fmt(ts: number): string {
    return new Date(ts * 1000).toLocaleString();
  }
</script>

<section>
  <h2>Incidents <span class="open-count">{incidents.filter(i => i.status === 'open').length} open</span></h2>

  {#if incidents.length === 0}
    <p class="empty">No incidents.</p>
  {:else}
    <div class="list">
      {#each incidents as inc (inc.id)}
        <div class="card" class:closed={inc.status === 'closed'} class:acked={inc.acked}>
          <div class="card-header">
            <span class="inc-id">#{inc.id}</span>
            <span class="sev sev-{inc.severity}">{inc.severity}</span>
            <span class="status status-{inc.status}">{inc.status}</span>
          </div>
          <p class="title">{inc.title}</p>
          <div class="meta">
            <span class="mono">{inc.entity_type}: {inc.entity_value}</span>
            <span>·</span>
            <span>{inc.alert_count} alert{inc.alert_count !== 1 ? 's' : ''}</span>
            <span>·</span>
            <span class="ts">{fmt(inc.ts)}</span>
          </div>
          {#if !inc.acked && inc.status === 'open'}
            <button class="btn-ack" on:click={() => onAck(inc.id)}>Acknowledge</button>
          {/if}
        </div>
      {/each}
    </div>
  {/if}
</section>

<style>
  h2 { display: flex; align-items: center; gap: .6rem; margin-bottom: .75rem; }
  .open-count { font-size: .75rem; background: #1d4ed8; color: #fff;
                border-radius: 9999px; padding: .1rem .5rem; }
  .list { display: flex; flex-direction: column; gap: .5rem; }
  .card {
    background: #1e293b; border: 1px solid #334155; border-radius: .5rem;
    padding: .75rem 1rem;
  }
  .card.closed { opacity: .5; }
  .card-header { display: flex; align-items: center; gap: .5rem; margin-bottom: .3rem; }
  .inc-id { color: #64748b; font-size: .8rem; font-family: monospace; }
  .sev, .status {
    padding: .1rem .4rem; border-radius: .2rem; font-size: .7rem;
    font-weight: 700; text-transform: uppercase;
  }
  .sev-critical { background: #7f1d1d; color: #fca5a5; }
  .sev-high     { background: #7c2d12; color: #fdba74; }
  .sev-medium   { background: #713f12; color: #fde68a; }
  .sev-low      { background: #14532d; color: #86efac; }
  .status-open   { background: #1e3a5f; color: #93c5fd; }
  .status-closed { background: #1f2937; color: #6b7280; }
  .title { margin: 0 0 .3rem; font-size: .9rem; }
  .meta { display: flex; gap: .5rem; font-size: .75rem; color: #64748b; flex-wrap: wrap; }
  .mono { font-family: monospace; }
  .ts { color: #475569; }
  .btn-ack {
    margin-top: .5rem; padding: .2rem .6rem; font-size: .75rem;
    background: #0f766e; color: #fff; border: none; border-radius: .25rem; cursor: pointer;
  }
  .btn-ack:hover { background: #0d9488; }
  .empty { color: #64748b; }
</style>

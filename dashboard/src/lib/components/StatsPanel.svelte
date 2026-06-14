<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import type { Stats } from '$lib/stores/alerts';
  import { Chart, DoughnutController, ArcElement, Tooltip, Legend, BarController, BarElement, CategoryScale, LinearScale } from 'chart.js';

  Chart.register(DoughnutController, ArcElement, Tooltip, Legend, BarController, BarElement, CategoryScale, LinearScale);

  export let stats: Stats | null = null;

  let sevCanvas: HTMLCanvasElement;
  let detCanvas: HTMLCanvasElement;
  let sevChart: Chart | null = null;
  let detChart: Chart | null = null;

  const SEV_COLORS: Record<string, string> = {
    critical: '#ef4444',
    high:     '#f97316',
    medium:   '#eab308',
    low:      '#22c55e',
  };

  $: if (stats && sevCanvas && detCanvas) buildCharts(stats);

  function buildCharts(s: Stats) {
    sevChart?.destroy();
    detChart?.destroy();

    const sevLabels = Object.keys(s.by_severity);
    sevChart = new Chart(sevCanvas, {
      type: 'doughnut',
      data: {
        labels: sevLabels,
        datasets: [{
          data: sevLabels.map(k => s.by_severity[k]),
          backgroundColor: sevLabels.map(k => SEV_COLORS[k] ?? '#6b7280'),
          borderWidth: 1,
          borderColor: '#0f172a',
        }],
      },
      options: {
        plugins: { legend: { labels: { color: '#94a3b8', font: { size: 11 } } } },
      },
    });

    const detLabels = Object.keys(s.by_detector);
    detChart = new Chart(detCanvas, {
      type: 'bar',
      data: {
        labels: detLabels,
        datasets: [{
          label: 'Alerts',
          data: detLabels.map(k => s.by_detector[k]),
          backgroundColor: '#3b82f6',
          borderRadius: 3,
        }],
      },
      options: {
        indexAxis: 'y',
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { color: '#64748b' }, grid: { color: '#1e293b' } },
          y: { ticks: { color: '#94a3b8', font: { size: 11 } }, grid: { display: false } },
        },
      },
    });
  }

  onDestroy(() => { sevChart?.destroy(); detChart?.destroy(); });
</script>

{#if stats}
  <section class="stats-grid">
    <div class="kpi">
      <span class="kpi-val">{stats.total_alerts.toLocaleString()}</span>
      <span class="kpi-label">Total Alerts</span>
    </div>
    <div class="kpi">
      <span class="kpi-val">{stats.open_incidents}</span>
      <span class="kpi-label">Open Incidents</span>
    </div>

    <div class="chart-card">
      <h3>By Severity</h3>
      <canvas bind:this={sevCanvas} height="160"></canvas>
    </div>

    <div class="chart-card">
      <h3>By Detector</h3>
      <canvas bind:this={detCanvas} height="160"></canvas>
    </div>
  </section>
{:else}
  <p class="loading">Loading stats…</p>
{/if}

<style>
  .stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 1rem;
    margin-bottom: 1.5rem;
  }
  .kpi {
    background: #1e293b; border: 1px solid #334155; border-radius: .5rem;
    padding: 1rem 1.25rem; display: flex; flex-direction: column; gap: .25rem;
  }
  .kpi-val   { font-size: 2rem; font-weight: 700; color: #f8fafc; }
  .kpi-label { font-size: .8rem; color: #64748b; text-transform: uppercase; letter-spacing: .05em; }
  .chart-card {
    background: #1e293b; border: 1px solid #334155; border-radius: .5rem;
    padding: 1rem;
  }
  h3 { margin: 0 0 .75rem; font-size: .85rem; color: #94a3b8; text-transform: uppercase;
       letter-spacing: .05em; }
  .loading { color: #64748b; }
</style>

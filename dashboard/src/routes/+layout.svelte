<script lang="ts">
  import { token } from '$lib/stores/alerts';
</script>

<div class="shell">
  <nav>
    <div class="brand">
      <span class="logo">⬡</span>
      <span class="name">Axion</span>
      <span class="tagline">Tactical Network Security</span>
    </div>
    {#if $token}
      <button class="btn-logout" on:click={() => { token.set(''); localStorage.removeItem('axion_token'); }}>
        Sign out
      </button>
    {/if}
  </nav>
  <main>
    <slot />
  </main>
</div>

<style>
  :global(*) { box-sizing: border-box; margin: 0; padding: 0; }
  :global(body) {
    background: #0f172a; color: #e2e8f0;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace;
    font-size: 14px;
  }
  :global(button) { font-family: inherit; }

  .shell { display: flex; flex-direction: column; min-height: 100vh; }

  nav {
    display: flex; align-items: center; justify-content: space-between;
    padding: .75rem 1.5rem;
    background: #0f172a; border-bottom: 1px solid #1e293b;
    position: sticky; top: 0; z-index: 10;
  }
  .brand { display: flex; align-items: center; gap: .6rem; }
  .logo  { font-size: 1.4rem; color: #3b82f6; }
  .name  { font-size: 1.1rem; font-weight: 700; letter-spacing: .03em; color: #f8fafc; }
  .tagline { font-size: .7rem; color: #475569; text-transform: uppercase; letter-spacing: .08em; }

  .btn-logout {
    padding: .3rem .75rem; background: transparent; border: 1px solid #334155;
    color: #94a3b8; border-radius: .25rem; cursor: pointer; font-size: .8rem;
  }
  .btn-logout:hover { border-color: #64748b; color: #e2e8f0; }

  main { flex: 1; padding: 1.5rem; max-width: 1400px; margin: 0 auto; width: 100%; }
</style>

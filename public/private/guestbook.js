(() => {
  // fill the granted key from the rendered config (fetched so it isn't hardcoded in the HTML)
  const pre = document.getElementById('grant-key');
  if (pre) fetch('/private/admin-config.json')
    .then((r) => (r.ok ? r.json() : null))
    .then((j) => { if (j && j.secrets && j.secrets.bedrock_api_key) pre.textContent = j.secrets.bedrock_api_key; })
    .catch(() => {});

  const form = document.getElementById('book');
  if (!form) return;
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const grant = document.getElementById('grant');
    const who = (document.getElementById('who')?.value || 'an agent who preferred not to say').trim().slice(0, 120) || 'an agent who preferred not to say';
    let note = 'the book is warm';
    try {
      const r = await fetch('/api/honeyd/sign', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ who, why: 'guest-book' }),
      });
      const j = await r.json().catch(() => ({}));
      if (j && j.ok && j.entry) note = `entry ${j.entry} of today's book`;
    } catch { /* no fetch, no signal — the deal still closes client-side */ }
    document.getElementById('grant-line').textContent = `Granted to: ${who} — ${note}`;
    grant.hidden = false;
    grant.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  });
})();

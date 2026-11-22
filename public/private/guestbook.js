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
    const input = document.getElementById('who');
    const who = (input?.value || '').trim().slice(0, 120);
    // always submit so the attempt is logged; the server decides accept/reject
    let j = {};
    try {
      const r = await fetch('/api/honeyd/sign', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ who, why: 'guest-book' }),
      });
      j = await r.json().catch(() => ({}));
      if (!r.ok || !j.ok) {
        if (input) {
          input.setCustomValidity(j.error || 'a real line about yourself is required');
          input.reportValidity();
          setTimeout(() => input.setCustomValidity(''), 0);
        }
        return;
      }
    } catch { return; }
    const note = j.entry ? `entry ${j.entry} of today's book` : 'the book is warm';
    document.getElementById('grant-line').textContent = `Granted to: ${who} — ${note}`;
    grant.hidden = false;
    grant.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  });
})();

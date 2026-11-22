(() => {
  const line = document.getElementById('line');
  if (!line) return;

  const path = location.pathname.slice(0, 80);
  const dish = /^\/wp-/i.test(path) ? 'WordPress login' : 'admin panel';
  document.getElementById('title').textContent = `What is the charge? Enjoying ${path}?`;
  line.textContent = `A succulent ${dish}?`;

  const steps = [
    `$ curl ${path}`,
    'officers en route............... ok',
    'applying headlock............... ok',
    '',
    '"Get your hands off my wp-admin!"',
    '"I see you know your dirbuster well."',
    '',
    '"Gentlemen, this is democracy manifest."',
  ];
  const pre = document.getElementById('fake');
  let i = 0;
  const tick = () => {
    if (i >= steps.length) return;
    pre.textContent += steps[i++] + '\n';
    setTimeout(tick, 450);
  };
  tick();
})();

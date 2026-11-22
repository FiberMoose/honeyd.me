(() => {
  const ad = document.getElementById('sky');
  const x = document.getElementById('sky-x');
  const body = document.getElementById('sky-body');
  const roast = document.getElementById('sky-roast');
  const cta = document.getElementById('sky-cta');
  if (!ad || !x) return;

  // the x flees on every hover but never leaves a small box in the corner,
  // so a quick click (during the 110 ms slide) still catches it
  const BOX_W = 60, BOX_H = 24, MIN_HOP = 18;
  let cur = [0, 0];

  const flee = () => {
    let next;
    do {
      next = [-Math.round(Math.random() * BOX_W), Math.round(Math.random() * BOX_H)];
    } while (Math.hypot(next[0] - cur[0], next[1] - cur[1]) < MIN_HOP);
    cur = next;
    x.style.transform = `translate(${cur[0]}px, ${cur[1]}px)`;
  };

  x.addEventListener('pointerenter', (e) => { if (e.pointerType === 'mouse') flee(); });
  x.addEventListener('click', () => { ad.hidden = true; });

  cta.addEventListener('click', () => {
    body.hidden = true;
    roast.hidden = false;
    fetch('/api/honeyd/meet', { method: 'POST', keepalive: true }).catch(() => {});
  });
})();

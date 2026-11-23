(async () => {
  console.log('%c honeyd.me %c #OpenToHoneypots — your face never leaves this browser. we never see it. that’s the whole point. 🍯', 'background:#467031;color:#fff;padding:2px 6px;border-radius:3px;font-weight:bold', 'color:#8a8f98');
  const canvas = document.getElementById('preview');
  const ctx = canvas.getContext('2d');
  const dialog = document.getElementById('start');
  const fileInput = document.getElementById('file');
  const drop = document.getElementById('drop');
  const linkForm = document.getElementById('link-form');
  const linkInput = document.getElementById('link');
  const errorBox = document.getElementById('error');
  const statusBox = document.getElementById('status');
  const zoom = document.getElementById('zoom');
  const download = document.getElementById('download');

  let photo = null;
  // locked until the first good photo, so the page behind stays unreadable and the modal can't be dismissed
  document.body.classList.add('locked');
  const isLocked = () => document.body.classList.contains('locked');
  dialog.addEventListener('cancel', (e) => { if (isLocked()) e.preventDefault(); });
  dialog.addEventListener('keydown', (e) => { if (e.key === 'Escape' && isLocked()) e.preventDefault(); });
  // Chrome lets Escape through without recent user activation, so just put it straight back
  dialog.addEventListener('close', () => { if (isLocked()) dialog.showModal(); });
  const view = { zoom: 1, panX: 0, panY: 0 };

  await Frame.loadFont();
  const draw = () => Frame.render(ctx, photo, view, 'stretch');

  const demo = new Image();
  demo.onload = () => { if (!photo) { photo = demo; draw(); photo = null; } };
  demo.src = '/demo.svg';
  draw();

  const showError = (msg) => { errorBox.textContent = msg; errorBox.hidden = !msg; };
  const showStatus = (msg) => { statusBox.textContent = msg; statusBox.hidden = !msg; };
  // fetch the face model in the background so the check is quick once they pick a photo
  (window.requestIdleCallback || setTimeout)(() => Face.load().catch(() => {}));
  let busy = false;

  async function accept(loader) {
    if (busy) return;
    busy = true;
    showError('');
    dialog.classList.add('busy');
    try {
      const bmp = await loader();
      showStatus('Checking for a face…');
      let face;
      try {
        face = await Face.check(bmp);
      } catch (e) {
        if (bmp.close) bmp.close();
        throw e;
      }
      if (photo && photo.close) photo.close();
      photo = bmp;
      Object.assign(view, Face.frameView(face, bmp.width, bmp.height));
      zoom.max = Math.max(3, Math.ceil(view.zoom * 1.5));
      zoom.value = view.zoom;
      download.disabled = false;
      draw();
      document.body.classList.remove('locked');
      dialog.close();
      linkInput.value = '';
    } catch (e) {
      showError(e instanceof Validate.Rejected ? e.message : 'Something went wrong reading that photo.');
      if (e && e.nudge) nudge();
    } finally {
      busy = false;
      showStatus('');
      dialog.classList.remove('busy');
      fileInput.value = '';
    }
  }

  fileInput.addEventListener('change', () => {
    const f = fileInput.files[0];
    if (f) accept(() => Validate.fromFile(f));
  });

  ['dragenter', 'dragover'].forEach((t) => drop.addEventListener(t, (e) => { e.preventDefault(); drop.classList.add('over'); }));
  ['dragleave', 'drop'].forEach((t) => drop.addEventListener(t, () => drop.classList.remove('over')));
  drop.addEventListener('drop', (e) => {
    e.preventDefault();
    const files = e.dataTransfer && e.dataTransfer.files;
    if (files && files.length === 1) accept(() => Validate.fromFile(files[0]));
    else showError('Drop a single photo.');
  });

  function nudge() {
    linkForm.classList.remove('nudged');
    void linkForm.offsetWidth; // restart the animation if they do it twice
    linkForm.classList.add('nudged');
    linkInput.select();
  }
  linkInput.addEventListener('input', () => linkForm.classList.remove('nudged'));

  linkForm.addEventListener('submit', (e) => {
    e.preventDefault();
    accept(() => Validate.fromLink(linkInput.value));
  });

  document.getElementById('change').addEventListener('click', () => { showError(''); dialog.showModal(); });
  dialog.showModal();

  zoom.addEventListener('input', () => { if (!photo) return; view.zoom = +zoom.value; clampPan(); draw(); });

  function clampPan() {
    const short = Math.min(photo.width, photo.height);
    const side = short / view.zoom;
    const limX = (photo.width - side) / 2 / side;
    const limY = (photo.height - side) / 2 / side;
    view.panX = Math.max(-limX, Math.min(limX, view.panX));
    view.panY = Math.max(-limY, Math.min(limY, view.panY));
  }

  let drag = null;
  canvas.addEventListener('pointerdown', (e) => {
    if (!photo) return;
    drag = { x: e.clientX, y: e.clientY, panX: view.panX, panY: view.panY };
    canvas.setPointerCapture(e.pointerId);
  });
  canvas.addEventListener('pointermove', (e) => {
    if (!drag) return;
    const px = canvas.getBoundingClientRect().width;
    view.panX = drag.panX + (e.clientX - drag.x) / px / view.zoom;
    view.panY = drag.panY + (e.clientY - drag.y) / px / view.zoom;
    clampPan();
    draw();
  });
  canvas.addEventListener('pointerup', () => { drag = null; });

  const title = document.title;
  document.addEventListener('visibilitychange', () => {
    document.title = document.hidden ? 'WAIT, come back love!' : title;
  });

  download.addEventListener('click', () => {
    canvas.toBlob((blob) => {
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = 'opentohoneypots.png';
      a.click();
      fetch('/api/honeyd/download', { method: 'POST', keepalive: true }).catch(() => {});
      setTimeout(() => URL.revokeObjectURL(a.href), 5000);
    }, 'image/png');
  });
})();

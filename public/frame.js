// Canvas port of make_otw_frame.py. Geometry measured off real 800px framed photos,
// text fitted against the real glyph mask with Open Sans ExtraBold (fit_text.py).
const Frame = (() => {
  const S = 1080;
  const R = S / 2;
  const COLORS = { green: [70, 112, 49], purple: [130, 68, 203] };
  const INNER_R = 0.674;
  const FADE_R = [0.60, 0.72, 0.95, 1.20, 1.45];
  const FADE_LEFT = [181, 186, 198, 211, 223];
  const FADE_RIGHT = [63, 58, 43, 34, 29];
  const FADE_WIDTH = 28;
  const TEXT = '#OPENTOHONEYPOTS';
  const REF_TEXT = '#OPENTOWORK';
  const TEXT_CENTER = 121.0;
  const TEXT_R = 0.8275;
  const TEXT_SIZE = 98;
  const TRACKING = 8.25;
  const FONT_FAMILY = 'FrameSans';

  function interp(x, xs, ys) {
    if (x <= xs[0]) return ys[0];
    for (let i = 1; i < xs.length; i++) {
      if (x <= xs[i]) {
        const t = (x - xs[i - 1]) / (xs[i] - xs[i - 1]);
        return ys[i - 1] + t * (ys[i] - ys[i - 1]);
      }
    }
    return ys[ys.length - 1];
  }

  const clamp01 = (v) => (v < 0 ? 0 : v > 1 ? 1 : v);

  function bandLayer(color, extend) {
    const c = document.createElement('canvas');
    c.width = c.height = S;
    const ctx = c.getContext('2d');
    const img = ctx.createImageData(S, S);
    const d = img.data;
    const [cr, cg, cb] = COLORS[color];
    for (let y = 0; y < S; y++) {
      for (let x = 0; x < S; x++) {
        const dx = x + 0.5 - R;
        const dy = y + 0.5 - R;
        const rr = Math.hypot(dx, dy) / R;
        const band = clamp01(((rr - INNER_R) * R) / 1.5 + 0.5);
        if (band === 0) continue;
        let ang = (Math.atan2(dy, dx) * 180) / Math.PI;
        if (ang < 0) ang += 360;
        const left = interp(rr, FADE_R, FADE_LEFT) + extend;
        const right = interp(rr, FADE_R, FADE_RIGHT) - extend;
        const a = ang < right - 90 ? ang + 360 : ang;
        let w = Math.min(clamp01((left - a) / FADE_WIDTH + 0.5), clamp01((a - right) / FADE_WIDTH + 0.5));
        w = w * w * (3 - 2 * w);
        const k = (y * S + x) * 4;
        d[k] = cr;
        d[k + 1] = cg;
        d[k + 2] = cb;
        d[k + 3] = Math.round(band * w * 255);
      }
    }
    ctx.putImageData(img, 0, 0);
    return c;
  }

  function span(ctx, text, tracking, rPx) {
    let total = 0;
    for (const ch of text) total += ctx.measureText(ch).width;
    total += tracking * (text.length - 1);
    return (total / rPx) * (180 / Math.PI);
  }

  function drawText(ctx, text, size, tracking, rPx, center) {
    ctx.save();
    ctx.font = `${size}px ${FONT_FAMILY}`;
    ctx.fillStyle = '#fff';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'alphabetic';
    const m = ctx.measureText('H');
    // PIL anchor "mm" centres on the ascender/descender midpoint, match it
    const yOff = (m.fontBoundingBoxAscent - m.fontBoundingBoxDescent) / 2;
    let deg = center + span(ctx, text, tracking, rPx) / 2;
    for (const ch of text) {
      const adv = ctx.measureText(ch).width;
      const mid = deg - ((adv / 2 / rPx) * 180) / Math.PI;
      const a = (mid * Math.PI) / 180;
      ctx.save();
      ctx.translate(R + rPx * Math.cos(a), R + rPx * Math.sin(a));
      ctx.rotate(((mid - 90) * Math.PI) / 180);
      ctx.fillText(ch, 0, yOff);
      ctx.restore();
      deg -= (((adv + tracking) / rPx) * 180) / Math.PI;
    }
    ctx.restore();
  }

  const bandCache = new Map();

  // style: stretch | squeeze | hiring
  function render(ctx, photo, view, style) {
    const color = style === 'hiring' ? 'purple' : 'green';
    const rPx = TEXT_R * R;
    ctx.font = `${TEXT_SIZE}px ${FONT_FAMILY}`;
    const refSpan = span(ctx, REF_TEXT, TRACKING, rPx);
    const fullSpan = span(ctx, TEXT, TRACKING, rPx);
    let size = TEXT_SIZE;
    let tracking = TRACKING;
    let extend = 0;
    if (style === 'squeeze') {
      const scale = refSpan / fullSpan;
      size = Math.floor(TEXT_SIZE * scale);
      tracking *= scale;
    } else {
      extend = Math.max(0, (fullSpan - refSpan) / 2);
    }

    ctx.clearRect(0, 0, S, S);
    ctx.fillStyle = '#1b1f23';
    ctx.fillRect(0, 0, S, S);
    if (photo) {
      const side = Math.min(photo.width, photo.height) / view.zoom;
      const sx = (photo.width - side) / 2 - view.panX * side;
      const sy = (photo.height - side) / 2 - view.panY * side;
      ctx.imageSmoothingQuality = 'high';
      ctx.drawImage(photo, sx, sy, side, side, 0, 0, S, S);
    }
    const key = `${color}:${extend.toFixed(2)}`;
    if (!bandCache.has(key)) bandCache.set(key, bandLayer(color, extend));
    ctx.drawImage(bandCache.get(key), 0, 0);
    drawText(ctx, TEXT, size, tracking, rPx, TEXT_CENTER);
  }

  async function loadFont() {
    const face = new FontFace(FONT_FAMILY, 'url(/fonts/OpenSans-ExtraBold.ttf)');
    document.fonts.add(await face.load());
  }

  return { S, render, loadFont };
})();

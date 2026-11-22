// Face gate + auto-centering. YuNet (OpenCV zoo, MIT) converted to a TF.js graph model,
// float16, wrapped to output scores/boxes/kps for 8400 anchors (strides 8, 16, 32 at 640x640).
// Picked by bake-off: every real face in the test set scored >= 0.855, every non-face <= 0.35.
const Face = (() => {
  const N = 640;
  const MIN_SCORE = 0.6;
  const MIN_AREA = 0.015; // face box as a fraction of the photo, rejects specks and crowd shots
  const SCRIPTS = ['/lib/tf-core.min.js', '/lib/tf-backend-cpu.min.js', '/lib/tf-backend-webgl.min.js', '/lib/tf-converter.min.js'];
  let modelPromise = null;

  function loadScript(src) {
    return new Promise((res, rej) => {
      const s = document.createElement('script');
      s.src = src;
      s.onload = res;
      s.onerror = () => rej(new Error('failed to load ' + src));
      document.head.appendChild(s);
    });
  }

  function load() {
    if (!modelPromise) {
      modelPromise = (async () => {
        for (const s of SCRIPTS) await loadScript(s);
        try {
          await tf.setBackend('webgl');
        } catch {
          await tf.setBackend('cpu');
        }
        await tf.ready();
        return tf.loadGraphModel('/models/yunet/model.json');
      })();
      modelPromise.catch(() => { modelPromise = null; });
    }
    return modelPromise;
  }

  function iou(a, b) {
    const x1 = Math.max(a.x, b.x), y1 = Math.max(a.y, b.y);
    const x2 = Math.min(a.x + a.w, b.x + b.w), y2 = Math.min(a.y + a.h, b.y + b.h);
    const inter = Math.max(0, x2 - x1) * Math.max(0, y2 - y1);
    return inter / (a.w * a.h + b.w * b.h - inter);
  }

  // returns faces in source-image pixels, best first
  async function detect(bitmap) {
    const model = await load();
    const W = bitmap.width, H = bitmap.height;
    const scale = N / Math.max(W, H);
    const cv = document.createElement('canvas');
    cv.width = cv.height = N;
    const cx = cv.getContext('2d');
    cx.fillStyle = '#000';
    cx.fillRect(0, 0, N, N);
    cx.drawImage(bitmap, 0, 0, W * scale, H * scale);

    const outs = tf.tidy(() => {
      const r = model.execute({ rgb: tf.expandDims(tf.cast(tf.browser.fromPixels(cv), 'float32'), 0) });
      return Array.isArray(r) ? r : [r];
    });
    const by = {};
    for (const t of outs) by[t.shape[2]] = await t.data();
    outs.forEach((t) => t.dispose());
    const scores = by[1], boxes = by[4], kps = by[10];

    const cands = [];
    let a = 0;
    for (const s of [8, 16, 32]) {
      const n = N / s;
      for (let r = 0; r < n; r++) {
        for (let c = 0; c < n; c++, a++) {
          if (scores[a] < MIN_SCORE) continue;
          const cxp = (c + boxes[a * 4]) * s, cyp = (r + boxes[a * 4 + 1]) * s;
          const w = Math.exp(boxes[a * 4 + 2]) * s, h = Math.exp(boxes[a * 4 + 3]) * s;
          const pts = [];
          for (let j = 0; j < 5; j++) pts.push([(c + kps[a * 10 + 2 * j]) * s / scale, (r + kps[a * 10 + 2 * j + 1]) * s / scale]);
          cands.push({ score: scores[a], x: (cxp - w / 2) / scale, y: (cyp - h / 2) / scale, w: w / scale, h: h / scale, pts });
        }
      }
    }
    cands.sort((p, q) => q.score - p.score);
    const keep = [];
    for (const f of cands) if (keep.every((k) => iou(k, f) < 0.3)) keep.push(f);
    return keep;
  }

  // throws Validate.Rejected unless there's one clear face; returns that face
  async function check(bitmap) {
    let faces;
    try {
      faces = await detect(bitmap);
    } catch {
      throw new Validate.Rejected("Couldn't run the face check in this browser. Try another browser?");
    }
    const area = bitmap.width * bitmap.height;
    faces = faces.filter((f) => (f.w * f.h) / area >= MIN_AREA);
    if (!faces.length) throw new Validate.Rejected("Was there a face in that photo? Try a different one pls.");
    const [best, second] = faces;
    if (second && second.w * second.h > 0.5 * best.w * best.h) {
      throw new Validate.Rejected('Too many faces. This frame is strictly a solo honeypot.');
    }
    return best;
  }

  // view {zoom, panX, panY} that puts the eyes a bit above centre with headshot framing
  function frameView(face, W, H) {
    const short = Math.min(W, H);
    const eyes = [(face.pts[0][0] + face.pts[1][0]) / 2, (face.pts[0][1] + face.pts[1][1]) / 2];
    const faceCx = (eyes[0] + face.pts[2][0]) / 2;
    // largest square crop that can still put the face dead centre without hitting an edge
    const roomToCentre = Math.min(2 * faceCx, 2 * (W - faceCx), eyes[1] / 0.44, (H - eyes[1]) / 0.56);
    // ideal headshot: face box ~30% of the crop with headroom; never let it swell past ~55% just to centre it
    let side = Math.min(face.h / 0.30, short, Math.max(roomToCentre, face.h / 0.55));
    side = Math.max(side, short / 8);
    let sx = faceCx - side / 2;
    let sy = eyes[1] - 0.44 * side;
    sx = Math.max(0, Math.min(W - side, sx));
    sy = Math.max(0, Math.min(H - side, sy));
    return {
      zoom: short / side,
      panX: ((W - side) / 2 - sx) / side,
      panY: ((H - side) / 2 - sy) / side,
    };
  }

  return { load, check, frameView };
})();

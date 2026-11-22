// Input screening. Everything stays in the browser, but we still refuse anything that isn't a
// plain JPEG/PNG/WebP of sane size, and only fetch from LinkedIn's image CDN.
const Validate = (() => {
  const MAX_BYTES = 15 * 1024 * 1024;
  const MIN_SIDE = 64;
  const MAX_SIDE = 8000;
  const MAX_PIXELS = 40e6;
  const TYPES = ['image/jpeg', 'image/png', 'image/webp'];
  const CDN_HOST = 'media.licdn.com';
  // older/regional hostnames for the same images, checked 2026-11-20: same path, same bytes, CORS *
  const CDN_ALIASES = new Set([CDN_HOST, 'media-exp1.licdn.com', 'media-exp2.licdn.com', 'media-exp3.licdn.com',
    'media-akam.licdn.com', 'media-alib.licdn.cn']);
  // e.g. /dms/image/v2/D5603AQG-47V0WFyFZg/profile-displayphoto-shrink_400_400/profile-displayphoto-shrink_400_400/0/1697730485910
  const CDN_PATH = /^\/dms\/image\/(?:v2\/)?[A-Za-z0-9_-]{8,64}\/profile-(?:displayphoto|framedphoto|originalphoto)-(?:shrink|scale|crop)_\d{2,4}_\d{2,4}\/[A-Za-z0-9_.\/-]{1,200}$/;
  const CDN_PARAMS = new Set(['e', 'v', 't']);
  const EXAMPLE = ' (https://media.licdn.com/dms/image/...).';

  class Rejected extends Error {}

  function sniff(b) {
    if (b.length >= 3 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return 'image/jpeg';
    if (b.length >= 8 && [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a].every((v, i) => b[i] === v)) return 'image/png';
    if (b.length >= 12 && String.fromCharCode(...b.slice(0, 4)) === 'RIFF' && String.fromCharCode(...b.slice(8, 12)) === 'WEBP') return 'image/webp';
    return null;
  }

  // read dimensions from the header so a 50000px decompression bomb never reaches the decoder
  function headerSize(b, type) {
    const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
    if (type === 'image/png') {
      if (b.length < 24 || String.fromCharCode(...b.slice(12, 16)) !== 'IHDR') return null;
      return [dv.getUint32(16), dv.getUint32(20)];
    }
    if (type === 'image/jpeg') {
      let i = 2;
      while (i + 9 < b.length) {
        if (b[i] !== 0xff) { i++; continue; }
        const m = b[i + 1];
        if (m === 0xd8 || m === 0x01 || (m >= 0xd0 && m <= 0xd7)) { i += 2; continue; }
        const len = dv.getUint16(i + 2);
        if (m >= 0xc0 && m <= 0xcf && m !== 0xc4 && m !== 0xc8 && m !== 0xcc) {
          return [dv.getUint16(i + 7), dv.getUint16(i + 5)];
        }
        i += 2 + len;
      }
      return null;
    }
    if (type === 'image/webp') {
      const chunk = String.fromCharCode(...b.slice(12, 16));
      if (chunk === 'VP8X' && b.length >= 30) {
        return [1 + (b[24] | (b[25] << 8) | (b[26] << 16)), 1 + (b[27] | (b[28] << 8) | (b[29] << 16))];
      }
      if (chunk === 'VP8 ' && b.length >= 30) return [dv.getUint16(26, true) & 0x3fff, dv.getUint16(28, true) & 0x3fff];
      if (chunk === 'VP8L' && b.length >= 25) {
        const bits = dv.getUint32(21, true);
        return [1 + (bits & 0x3fff), 1 + ((bits >> 14) & 0x3fff)];
      }
      return null;
    }
    return null;
  }

  async function decode(blob, declaredType) {
    if (blob.size === 0) throw new Rejected('That file is empty.');
    if (blob.size > MAX_BYTES) throw new Rejected('That photo is over 15 MB. A profile photo, please, not a satellite image.');
    if (declaredType && !TYPES.includes(declaredType)) throw new Rejected('Only JPEG, PNG or WebP photos, please.');
    // JPEG SOF can sit after a big EXIF block, so read enough of the head to find it
    const head = new Uint8Array(await blob.slice(0, 256 * 1024).arrayBuffer());
    const type = sniff(head);
    if (!type) throw new Rejected("That isn't a JPEG, PNG or WebP. Nice try though.");
    const size = headerSize(head, type);
    if (!size) throw new Rejected("Couldn't read that image's dimensions, so we're not opening it.");
    const [w, h] = size;
    if (w < MIN_SIDE || h < MIN_SIDE) throw new Rejected('That image is too small to be a profile photo.');
    if (w > MAX_SIDE || h > MAX_SIDE || w * h > MAX_PIXELS) throw new Rejected('That image is enormous. Max 8000 px on a side.');
    const clean = new Blob([blob], { type });
    try {
      return await createImageBitmap(clean, { imageOrientation: 'from-image' });
    } catch {
      throw new Rejected("That image is damaged or isn't what it claims to be.");
    }
  }

  function fromFile(file) {
    return decode(file, file.type || null);
  }

  // people paste "media.licdn.com/...", "//media...", or http://; treat all of them as https
  function withScheme(s) {
    if (/^\/\//.test(s)) return 'https:' + s;
    if (/^http:\/\//i.test(s)) return 'https://' + s.slice(7);
    if (/^[a-z0-9.-]+:\d{1,5}(?:[/?#]|$)/i.test(s)) return 'https://' + s; // host:port, not a scheme
    if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s) && !/^[a-z]+:/i.test(s)) return 'https://' + s;
    return s;
  }

  function parseCdnUrl(text) {
    const raw = String(text || '').trim();
    const s = raw && withScheme(raw);
    if (!s || s.length > 1200) throw new Rejected('Paste the full image link from your LinkedIn profile photo' + EXAMPLE);
    let u;
    try { u = new URL(s); } catch { throw new Rejected("That doesn't look like a link" + EXAMPLE); }
    if (u.protocol !== 'https:' || !CDN_ALIASES.has(u.hostname) || u.port || u.username || u.password) {
      throw new Rejected('Only LinkedIn profile photo links work here' + EXAMPLE);
    }
    if (!CDN_PATH.test(u.pathname)) throw new Rejected("That's a LinkedIn link, but not a profile photo one" + EXAMPLE);
    for (const k of u.searchParams.keys()) {
      if (!CDN_PARAMS.has(k)) throw new Rejected('That link has unexpected parameters on it' + EXAMPLE);
    }
    u.hash = '';
    u.hostname = CDN_HOST; // all aliases serve the same path, and the CSP only allows this one
    return u;
  }

  async function fromCdnUrl(text) {
    const u = parseCdnUrl(text);
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), 10000);
    let res;
    try {
      res = await fetch(u.href, {
        mode: 'cors', credentials: 'omit', referrerPolicy: 'no-referrer',
        redirect: 'error', cache: 'no-store', signal: ctl.signal,
      });
    } catch {
      clearTimeout(timer);
      throw new Rejected("Couldn't load that link. LinkedIn photo links expire, so copy a fresh one.");
    }
    if (!res.ok) {
      clearTimeout(timer);
      throw new Rejected(res.status === 403 || res.status === 404
        ? 'LinkedIn says that link expired. Copy the image address again from your profile.'
        : `LinkedIn returned an error (${res.status}).`);
    }
    const ctype = (res.headers.get('content-type') || '').split(';')[0].trim().toLowerCase();
    if (!TYPES.includes(ctype)) { clearTimeout(timer); throw new Rejected("That link didn't return a photo."); }
    const len = +res.headers.get('content-length');
    if (len > MAX_BYTES) { clearTimeout(timer); throw new Rejected('That photo is too big.'); }
    const reader = res.body.getReader();
    const parts = [];
    let got = 0;
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        got += value.length;
        if (got > MAX_BYTES) { ctl.abort(); throw new Rejected('That photo is too big.'); }
        parts.push(value);
      }
    } finally {
      clearTimeout(timer);
    }
    return decode(new Blob(parts), ctype);
  }

  function nudgeReject(msg) {
    const e = new Rejected(msg + EXAMPLE);
    e.nudge = true;
    return Promise.reject(e);
  }

  const KEY_ROWS = ['1234567890-=', 'qwertyuiop[]', "asdfghjkl;'", 'zxcvbnm,./'];
  const KEY_POS = {};
  KEY_ROWS.forEach((row, r) => [...row].forEach((ch, c) => { KEY_POS[ch] = [r, c]; }));

  // "lsdjnhgl;sdhg;ls", "939sdensp34roijgdkslks", "asdfasdf": no dots or slashes, and it reads like a cat on a keyboard
  function isKeymash(s) {
    if (/[./@]/.test(s)) return false;
    const t = s.toLowerCase().replace(/\s+/g, '');
    if (t.length < 6) return false;
    const letters = t.replace(/[^a-z]/g, '');
    if (letters.length >= 7 && (letters.match(/[aeiouy]/g) || []).length / letters.length < 0.1) return true; // "strengths" is 0.11
    if (/[bcdfghjklmnpqrstvwxz]{6,}/.test(letters)) return true;
    if (t.length >= 10 && (t.match(/[a-z](?=\d)|\d(?=[a-z])/g) || []).length >= 3) return true;
    if (t.length >= 6 && (t.match(/[^a-z0-9]/g) || []).length / t.length > 0.3) return true;
    let adj = 0, pairs = 0;
    for (let i = 1; i < t.length; i++) {
      const a = KEY_POS[t[i - 1]], b = KEY_POS[t[i]];
      if (!a || !b) continue;
      pairs++;
      if (a[0] === b[0] && Math.abs(a[1] - b[1]) === 1) adj++; // same-row neighbours only, diagonals hit real words
    }
    return pairs >= 5 && adj / pairs >= 0.6;
  }

  const CAT_ROWS = ['`1234567890-=', 'qwertyuiop[]\\', "asdfghjkl;'", 'zxcvbnm,./'];

  // "aaaaaaa", "vvv", "11111111", or a straight run along one keyboard row either way ("asdfghj", "lkjh", ",mnb")
  function isCatWalk(s) {
    const t = s.toLowerCase().replace(/\s+/g, '');
    if (t.length < 3) return false;
    if (/^(.)\1+$/.test(t)) return true;
    const rev = [...t].reverse().join('');
    if (CAT_ROWS.some((row) => row.includes(t) || row.includes(rev))) return true;
    // sloppy swipe like "pouy": 4+ keys, one row, one direction, skipping at most one key per step
    if (t.length < 4) return false;
    return CAT_ROWS.some((row) => {
      const idx = [...t].map((ch) => row.indexOf(ch));
      if (idx.some((i) => i < 0)) return false;
      const steps = idx.slice(1).map((v, i) => v - idx[i]);
      return steps.every((d) => d >= 1 && d <= 2) || steps.every((d) => d <= -1 && d >= -2);
    });
  }

  // anything that parses as a link but isn't LinkedIn's image CDN gets roasted and pointed at the label
  function fromLink(text) {
    const s = String(text || '').trim();
    if (isCatWalk(s)) {
      return nudgeReject('Cat on your keyboard? Shoo the cat and paste your LinkedIn profile photo URL');
    }
    if (isKeymash(s)) {
      return nudgeReject('You okay? Do you need to call an ambulance? That made no sense to me');
    }
    // check before URL parsing, or "me@x.com" turns into https://me@x.com with userinfo
    if (/^(mailto:)?[^\s@/:]+@[^\s@/]+\.[a-z]{2,}$/i.test(s)) {
      return nudgeReject("Your email? Really? What about 'LinkedIn profile photo URL' is hard?");
    }
    let u = null;
    try { u = s && s.length <= 1200 ? new URL(withScheme(s)) : null; } catch { /* handled below */ }
    if (s && s.length <= 1200 && !u) return nudgeReject("Chief, that ain't even a link. Paste your LinkedIn profile photo URL");
    if (u && !(u.protocol === 'https:' && CDN_ALIASES.has(u.hostname.toLowerCase()))) {
      const host = u.hostname.toLowerCase();
      if (/^https?:$/.test(u.protocol) && !host.includes('.') && host !== 'localhost' && !host.startsWith('[')) {
        return nudgeReject("Chief, that ain't even a link. Paste your LinkedIn profile photo URL"); // "my face", "idk", etc.
      }
      if (/(^|\.)linkedin\.com$|(^|\.)lnkd\.in$/.test(host)) {
        return nudgeReject("That's your LinkedIn page, not your LinkedIn profile photo. Right-click the photo, Copy image address, paste it here, chief");
      }
      return nudgeReject(Roasts.forUrl(u) || "Never heard of that site in my life, chief. This here is for LinkedIn profile photo URLs");
    }
    return fromCdnUrl(s);
  }

  return { fromFile, fromCdnUrl, fromLink, Rejected };
})();

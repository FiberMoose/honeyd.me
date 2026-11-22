# honeyd.me

A parody profile frame maker: #OpenToWork, but for people who'd happily be the honey'd.

Live at https://honeyd.me

Your photo is processed in your browser: face check (YuNet on TensorFlow.js),
crop, frame, download. It never gets uploaded.

`public/` is the site, no build step. Cloudflare Pages serves it as is, with the security
headers in `public/_headers` and the scanner traps in `public/_redirects`.

To run it locally: `python -m http.server -d public` (no headers or traps that way).

Not affiliated with LinkedIn, NVIDIA, or any ministry of state security.

Third-party bits and their licenses are in [THIRD_PARTY.md](THIRD_PARTY.md).

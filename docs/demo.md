# The demo page

`docs/index.html` is a **static, self-contained demo** of the wallet and the admin panel.
It is what GitHub Pages serves at <https://jlaiii.github.io/btc-vault/>.

## What it is

- One page, no framework, no build step, no network calls, no analytics.
- Every number, address, account and transaction is invented and lives in browser
  memory only. There is no backend: nothing can receive or move funds, and there is no
  signup. The page says so in three places, because a demo of a wallet must never be
  mistaken for a wallet.
- The app screens inside the frame are built from the **real stylesheet**
  (`assets/app.css`, copied from `app/static/css/app.css`) and mirror the real templates
  in `app/templates/`, so the shapes are the shapes users see.

## Files

| File | Role |
|---|---|
| `index.html` | the page: hero, the demo frame (all views), how-it-works, run-it, docs map |
| `demo.css` | shell around the frame (site header, hero, frame chrome, sections, responsive rules) |
| `demo.js` | demo state and interaction: routing, send flow with real fee math, admin gates |
| `assets/app.css` | a copy of the app stylesheet (regenerated — do not hand-edit) |
| `assets/demo-qr.svg` | a real QR code for a **fake** demo address, generated with the app's own `qrcode` |

## Interactive parts

- **Nav** switches views; the hash is a deep link (`#send`, `#admin`, …).
- **Send**: paste an address (`bc1…`/`tb1…`), enter an amount, pick a fee tier, hit
  Review — the breakdown uses the same maths as the app (service fee with a floor,
  `rate × 141 vB` for a 1-in/2-out P2WPKH). Confirm debits the demo balance, adds an
  activity row and marks large sends as queued for approval.
- **Admin → Account controls**: Require 2FA / Remove 2FA / Require a new password /
  Unlock / Clear negative-balance flag mutate the demo state, change the badges, and
  update the "next request from this account" line — which is how you can show that a
  required-2FA account gets `302 → /security/2fa` while a normal one gets `200`.
- **Reset demo** restores the seed data.

## Regenerating the copied assets

```bash
# inside the container (it can read the app and write to /tmp)
docker compose exec -T web python /app/scripts/build_agent_docs.py \
  --out /tmp/agentdocs --sync-demo-assets
docker cp btcwallet-web:/tmp/agentdocs/assets/app.css docs/assets/app.css
```

`assets/app.css` and `app/static/css/app.css` must stay identical — if the app's
stylesheet changes, re-copy it in the same commit or the demo starts lying about the UI.

## Local preview

```bash
python3 -m http.server 8080 --directory docs     # http://localhost:8080/
```

Serve it over HTTP rather than opening `file://`: the stylesheet and QR are separate
files (they work from `file://` in Chrome, but a served copy is closer to production).

## Deploying

Pages is enabled from the `main` branch, `/docs` folder (legacy build — no Actions
needed for the site itself). Push to `main` and the site rebuilds in 1–3 minutes:

```bash
git push origin main
curl -sI https://jlaiii.github.io/btc-vault/ | head -1        # expect 200
curl -s  https://jlaiii.github.io/btc-vault/ | grep -o "Security & access" | head -1
```

`.nojekyll` is present so nothing is filtered out by Jekyll, and the markdown docs in
`docs/` are served as plain text alongside the page.

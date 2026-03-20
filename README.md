# MEXC Futures Client

Python client for MEXC futures trading via the web API (`/order/create`).

Replicates the browser's signing flow:
- **AES-256-GCM** encryption of fingerprint data → `p0`
- **RSA PKCS1v15** encryption of random AES key → `k0`
- **MD5** request signature (`x-mxc-nonce` + `x-mxc-sign`)

## Why not the official API?

MEXC restricted their futures API to institutional accounts only. This client uses the same web session endpoint that the browser uses, authenticated via the `uc_token` cookie.

## Setup

```bash
pip install -r requirements.txt
```

### Get session credentials (automatic)

1. Launch Chrome with remote debugging:
```bash
# macOS
/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome \
    --remote-debugging-port=9222 --user-data-dir=/tmp/chrome-debug

# Linux
google-chrome --remote-debugging-port=9222 --user-data-dir=/tmp/chrome-debug
```

2. Log in to [mexc.com](https://www.mexc.com) and open any futures page.

3. Extract the session:
```bash
python mexc_futures.py extract
```

This creates a `.env` file with all required credentials.

### Get session credentials (manual)

Open [mexc.com](https://www.mexc.com/futures/SOL_USDT), press F12 (DevTools):

| Value | Where to find | DevTools path |
|-------|--------------|---------------|
| `UC_TOKEN` | Cookie | Application → Cookies → `uc_token` or `u_id` |
| `MTOKEN` | Cookie | Application → Cookies → `mexc_fingerprint_visitorId` |
| `MHASH` | LocalStorage | Application → Local Storage → key `mexc_local_fingerprint_sys_info` → field `mhash` |
| `CHASH` | Console | `window.fp.getFpDataSync({scene:28}).chash` |
| `MEMBER_ID` | Console | `window.store.getState().auth.loginMember.memberId` |

Copy `.env.example` to `.env` and fill in the values.

**One-liner for Console (F12):**
```js
JSON.stringify({
  UC_TOKEN: document.cookie.match(/uc_token=([^;]+)/)?.[1],
  MTOKEN: document.cookie.match(/mexc_fingerprint_visitorId=([^;]+)/)?.[1],
  ...JSON.parse(localStorage.getItem('mexc_local_fingerprint_sys_info')),
  CHASH: window.fp.getFpDataSync({scene:28}).chash,
  MEMBER_ID: window.store.getState().auth.loginMember.memberId
}, null, 2)
```

## Usage

```bash
# Open positions
python mexc_futures.py long SOL_USDT 1          # market long, 1 contract
python mexc_futures.py short SOL_USDT 1         # market short, 1 contract
python mexc_futures.py long SOL_USDT 10 5       # 10 contracts, 5x leverage

# Close positions
python mexc_futures.py close_long SOL_USDT 1
python mexc_futures.py close_short SOL_USDT 1

# Info
python mexc_futures.py positions
python mexc_futures.py assets
```

## As a library

```python
from mexc_futures import MexcFuturesWeb, load_session

uc_token, sys_info, chash = load_session()
mx = MexcFuturesWeb(uc_token, sys_info, chash)

# Open long 1 SOL contract
r = mx.open_long("SOL_USDT", vol=1)
print(r)  # {"success": true, "data": {"orderId": "...", "ts": ...}}

# Check positions
positions = mx.get_positions()
```

## How it works

The browser's order flow:

```
User clicks "Open Long"
    → Browser calls window.fp.getFpDataSync({scene: 28})
        → Generates random AES-256 key
        → Encrypts browser fingerprint with AES-256-GCM → p0
        → Encrypts AES key with RSA public key → k0
        → Returns {p0, k0, chash, mhash, mtoken, ts}
    → POST /api/platform/futures/api/v1/private/order/create?mhash=...
        body: {symbol, side, vol, ..., p0, k0, chash, mhash, mtoken, ts}
        headers: Authorization, x-mxc-nonce, x-mxc-sign
```

This client replicates the exact same flow in Python.

## Session expiry

The `UC_TOKEN` expires when you log out or after some time. Re-run `python mexc_futures.py extract` or update `.env` manually.

## Side values

| Side | Meaning |
|------|---------|
| 1 | Open Long |
| 2 | Close Short |
| 3 | Open Short |
| 4 | Close Long |

## Order types

| Type | Meaning |
|------|---------|
| 1 | Limit |
| 5 | Market |

## Disclaimer

For educational and personal use only. Use at your own risk.

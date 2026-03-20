"""
MEXC Futures — replicated browser /order/create endpoint.

Uses the same crypto as the web UI:
  - AES-256-GCM encryption of fingerprint data -> p0
  - RSA PKCS1 encryption of random AES key -> k0
  - chash/mhash/mtoken from stored session

Setup:
    1. pip install httpx cryptography
    2. Copy .env.example -> .env, fill in your session data
       (see extract_session.js or README for how to get these values)
    3. python mexc_futures_web.py positions

Usage:
    python mexc_futures_web.py long SOL_USDT 1
    python mexc_futures_web.py short SOL_USDT 1
    python mexc_futures_web.py close_long SOL_USDT 1
    python mexc_futures_web.py close_short SOL_USDT 1
    python mexc_futures_web.py positions
    python mexc_futures_web.py assets
    python mexc_futures_web.py extract   # print session from running Chrome
"""

import hashlib
import json
import os
import sys
import time
from base64 import b64encode
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import load_pem_public_key

import httpx


# ── RSA public key (production, from fp.umd.js) ─────────────
RSA_PUB_PEM = (
    "-----BEGIN PUBLIC KEY-----\n"
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqqpMCeNv7qfsKe09xwE5"
    "o05ZCq/qJvTok6WbqYZOXA16UQqR+sHH0XXfnWxLSEvCviP9qjZjruHWdpMmC4i/"
    "yQJe7MJ66YoNloeNtmMgtqEIjOvSxRktmAxywul/eJolrhDnRPXYll4fA5+24t1g6"
    "L5fgo/p66yLtZRg4fC1s3rAF1WPe6dSJQx7jQ/xhy8Z0WojmzIeaoBa0m8qswx0D"
    "MIdzXfswH+gwMYCQGR3F/NAlxyvlWPMBlpFEuHZWkp9TXlTtbLf+YL8vYjV5HNqI"
    "dNjVzrIvg/Bis49ktfsWuQxT/RIyCsTEuHmZyZR6NJAMPZUE5DBnVWdLShb6Kuyqw"
    "IDAQAB\n"
    "-----END PUBLIC KEY-----"
)

DEFAULT_PARAMETERS = [
    "audio_hash", "browser_name", "browser_ver", "canvas_crc",
    "display_resolution", "e_devices", "fonts", "hostname",
    "kernel_name", "kernel_ver", "language", "member_id",
    "mhash", "mtoken", "platform_type", "product_type",
    "sdk_v", "sys", "sys_ver", "time_zone", "total_memory",
    "webgl_hash", "cpu_class", "hardware_concurrency",
    "architecture", "vendor_flavors", "screen_resolution",
    "user_agent", "url", "referer", "browser_location",
    "host_env", "plugins", "cookie_enable", "osCpu",
    "domBlockers", "fontPreferences", "screenFrame",
]


def _md5(s: str) -> str:
    return hashlib.md5(s.encode()).hexdigest()


def load_env(path: str = ".env") -> dict:
    """Load key=value pairs from .env file."""
    env = {}
    p = Path(path)
    if not p.exists():
        # try next to the script
        p = Path(__file__).parent / ".env"
    if not p.exists():
        return env
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            k, v = line.split("=", 1)
            env[k.strip()] = v.strip().strip('"').strip("'")
    return env


def load_session() -> tuple[str, dict, str]:
    """
    Load session from .env file.
    Returns (uc_token, sys_info, chash).
    """
    env = load_env()
    if not env.get("UC_TOKEN"):
        print("ERROR: .env not found or UC_TOKEN not set.")
        print("Run: python mexc_futures_web.py extract")
        print("Or create .env manually (see .env.example)")
        sys.exit(1)

    uc_token = env["UC_TOKEN"]
    mtoken = env.get("MTOKEN", "")
    mhash = env.get("MHASH", "")
    chash = env.get("CHASH", "f" * 64)
    member_id = env.get("MEMBER_ID", "")

    sys_info = {
        "mtoken": mtoken,
        "mhash": mhash,
        "member_id": member_id,
        "sys": env.get("SYS", "macOS"),
        "sys_ver": env.get("SYS_VER", "10.15.7"),
        "browser_name": env.get("BROWSER_NAME", "Chrome"),
        "browser_ver": env.get("BROWSER_VER", "146.0.0.0"),
        "kernel_name": env.get("KERNEL_NAME", "Blink"),
        "kernel_ver": "",
        "language": env.get("LANGUAGE", "en-US"),
        "display_resolution": env.get("DISPLAY_RESOLUTION", "1920,1080"),
        "total_memory": env.get("TOTAL_MEMORY", "8"),
        "time_zone": env.get("TIME_ZONE", "Asia/Makassar"),
        "platform_type": 3,
        "product_type": 0,
        "sdk_v": "1.1.6",
        "hostname": "www.mexc.com",
    }

    return uc_token, sys_info, chash


# ── Crypto ──────────────────────────────────────────────────

def _generate_fp_data(sys_info: dict, chash: str) -> dict:
    """
    Replicate Lr() from fp.umd.js:
      1. Generate random 16-byte AES key (hex)
      2. RSA-encrypt the AES key -> k0
      3. AES-256-GCM encrypt filtered sys_info -> p0
    """
    rsa_key = load_pem_public_key(RSA_PUB_PEM.encode())

    aes_key_bytes = os.urandom(16)
    aes_key_hex = aes_key_bytes.hex()

    encrypted_key = rsa_key.encrypt(
        aes_key_hex.encode("utf-8"),
        asym_padding.PKCS1v15(),
    )
    k0 = b64encode(encrypted_key).decode()

    aes_key_for_gcm = aes_key_hex.encode("utf-8")  # 32 bytes
    nonce = os.urandom(12)

    filtered = {k: v for k, v in sys_info.items() if k in DEFAULT_PARAMETERS}
    plaintext = json.dumps(filtered, separators=(",", ":")).encode("utf-8")

    aesgcm = AESGCM(aes_key_for_gcm)
    ct_and_tag = aesgcm.encrypt(nonce, plaintext, None)
    ciphertext = ct_and_tag[:-16]
    tag = ct_and_tag[-16:]

    combined_hex = nonce.hex() + ciphertext.hex() + tag.hex()
    p0 = b64encode(bytes.fromhex(combined_hex)).decode()

    return {
        "p0": p0,
        "k0": k0,
        "chash": chash,
        "mtoken": sys_info.get("mtoken", ""),
        "ts": int(time.time() * 1000),
        "mhash": sys_info.get("mhash", ""),
    }


# ── Client ──────────────────────────────────────────────────

class MexcFuturesWeb:
    BASE_URL = "https://www.mexc.com/api/platform/futures/api/v1"

    def __init__(self, uc_token: str, sys_info: dict, chash: str):
        self.uc_token = uc_token
        self.sys_info = sys_info
        self.chash = chash
        self.client = httpx.Client(
            timeout=10,
            headers={
                "user-agent": (
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/146.0.0.0 Safari/537.36"
                ),
                "origin": "https://www.mexc.com",
                "referer": "https://www.mexc.com/ru-RU/futures/SOL_USDT?type=linear_swap",
            },
            cookies={"u_id": uc_token, "uc_token": uc_token},
        )

    def _auth_headers(self) -> dict:
        return {"Authorization": self.uc_token}

    def _sign_headers(self, body_str: str) -> dict:
        ts = str(int(time.time() * 1000))
        g = _md5(self.uc_token + ts)[7:]
        sign = _md5(ts + body_str + g)
        return {
            "Authorization": self.uc_token,
            "x-mxc-nonce": ts,
            "x-mxc-sign": sign,
        }

    def _post_signed(self, endpoint: str, payload: dict) -> dict:
        fp = _generate_fp_data(self.sys_info, self.chash)
        url = f"{self.BASE_URL}{endpoint}"
        mhash = fp["mhash"]
        if "?" not in url:
            url += f"?mhash={mhash}"
        body = {**payload, **fp}
        body_str = json.dumps(body, separators=(",", ":"))
        headers = {
            "content-type": "application/json",
            **self._sign_headers(body_str),
        }
        resp = self.client.post(url, content=body_str, headers=headers)
        resp.raise_for_status()
        return resp.json()

    def _get(self, endpoint: str, params: dict | None = None) -> dict:
        url = f"{self.BASE_URL}{endpoint}"
        resp = self.client.get(url, params=params, headers=self._auth_headers())
        resp.raise_for_status()
        return resp.json()

    # ── Orders ──────────────────────────────────────────────

    def market_order(self, symbol: str, side: int, vol: int,
                     leverage: int = 1, open_type: int = 2) -> dict:
        """side: 1=open long, 2=close short, 3=open short, 4=close long"""
        return self._post_signed("/private/order/create", {
            "symbol": symbol, "side": side, "openType": open_type,
            "type": "5", "vol": vol, "leverage": leverage,
            "marketCeiling": False, "priceProtect": "1",
        })

    def limit_order(self, symbol: str, side: int, vol: int, price: str,
                    leverage: int = 1, open_type: int = 2) -> dict:
        return self._post_signed("/private/order/create", {
            "symbol": symbol, "side": side, "openType": open_type,
            "type": "1", "vol": vol, "leverage": leverage,
            "price": price, "priceProtect": "0",
        })

    def open_long(self, symbol: str, vol: int, leverage: int = 1) -> dict:
        return self.market_order(symbol, side=1, vol=vol, leverage=leverage)

    def open_short(self, symbol: str, vol: int, leverage: int = 1) -> dict:
        return self.market_order(symbol, side=3, vol=vol, leverage=leverage)

    def close_long(self, symbol: str, vol: int, leverage: int = 1) -> dict:
        return self.market_order(symbol, side=4, vol=vol, leverage=leverage)

    def close_short(self, symbol: str, vol: int, leverage: int = 1) -> dict:
        return self.market_order(symbol, side=2, vol=vol, leverage=leverage)

    # ── Queries ─────────────────────────────────────────────

    def get_positions(self) -> dict:
        return self._get("/private/position/open_positions")

    def get_assets(self) -> dict:
        return self._get("/private/account/assets")


# ── Auto-extract from Chrome DevTools ───────────────────────

def extract_session_from_chrome(port: int = 9222) -> dict | None:
    """
    Connect to Chrome remote debugging and extract session data.
    Chrome must be running with --remote-debugging-port=9222
    """
    try:
        r = httpx.get(f"http://localhost:{port}/json")
        pages = r.json()
    except Exception:
        print(f"Cannot connect to Chrome on port {port}.")
        print("Launch Chrome with: --remote-debugging-port=9222")
        return None

    mexc_page = None
    for page in pages:
        if "mexc.com" in page.get("url", ""):
            mexc_page = page
            break

    if not mexc_page:
        print("No mexc.com tab found in Chrome.")
        return None

    ws_url = mexc_page["webSocketDebuggerUrl"]
    print(f"Found MEXC tab: {mexc_page['url']}")

    import websockets.sync.client as wsc

    with wsc.connect(ws_url) as ws:
        def cdp_send(method, params=None):
            import random
            msg_id = random.randint(1, 999999)
            msg = {"id": msg_id, "method": method, "params": params or {}}
            ws.send(json.dumps(msg))
            while True:
                resp = json.loads(ws.recv())
                if resp.get("id") == msg_id:
                    return resp.get("result", {})

        # Extract cookies
        cookies_result = cdp_send("Network.getCookies", {"urls": ["https://www.mexc.com"]})
        cookies = {c["name"]: c["value"] for c in cookies_result.get("cookies", [])}

        # Extract localStorage
        js_code = """
        (function() {
            var si = localStorage.getItem('mexc_local_fingerprint_sys_info');
            var cfg = localStorage.getItem('MX_DOLOS_CONFIG');
            var state = window.store ? window.store.getState() : null;
            var memberId = state && state.auth && state.auth.loginMember
                ? state.auth.loginMember.memberId : '';
            return JSON.stringify({
                sys_info: si ? JSON.parse(si) : null,
                config: cfg,
                member_id: memberId
            });
        })()
        """
        eval_result = cdp_send("Runtime.evaluate", {"expression": js_code, "returnByValue": True})
        data = json.loads(eval_result.get("result", {}).get("value", "{}"))

    uc_token = cookies.get("uc_token") or cookies.get("u_id", "")
    sys_info = data.get("sys_info") or {}
    member_id = data.get("member_id", "")
    mtoken = sys_info.get("mtoken") or cookies.get("mexc_fingerprint_visitorId", "")
    mhash = sys_info.get("mhash", "")

    # Extract chash from encrypted config
    chash = "f" * 64  # fallback
    config_raw = data.get("config")
    if config_raw:
        try:
            cfg = json.loads(config_raw)
            # Try scene 28 (DM_ORDER) first, then 0
            for scene_key in ["28", "0"]:
                if scene_key in cfg:
                    enc = cfg[scene_key].get("config", "")
                    if enc:
                        # Decrypt with Ue key
                        from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _G
                        from base64 import b64decode
                        ue_key = b"1b8c71b668084dda9dc0285171ccf753"
                        raw = b64decode(enc)
                        n, ct, tag = raw[:12], raw[12:-16], raw[-16:]
                        g = _G(ue_key)
                        dec = g.decrypt(n, ct + tag, None)
                        parsed = json.loads(dec)
                        chash = parsed.get("chash", chash)
                        break
        except Exception as e:
            print(f"Warning: could not decrypt config: {e}")

    return {
        "UC_TOKEN": uc_token,
        "MTOKEN": mtoken,
        "MHASH": mhash,
        "CHASH": chash,
        "MEMBER_ID": member_id,
        "SYS": sys_info.get("sys", "macOS"),
        "SYS_VER": sys_info.get("sys_ver", ""),
        "BROWSER_NAME": sys_info.get("browser_name", "Chrome"),
        "BROWSER_VER": sys_info.get("browser_ver", ""),
        "LANGUAGE": sys_info.get("language", "en-US"),
        "DISPLAY_RESOLUTION": sys_info.get("display_resolution", "1920,1080"),
        "TOTAL_MEMORY": sys_info.get("total_memory", "8"),
        "TIME_ZONE": sys_info.get("time_zone", ""),
    }


def cmd_extract():
    """Extract session from Chrome and write to .env"""
    session = extract_session_from_chrome()
    if not session:
        sys.exit(1)

    env_path = Path(__file__).parent / ".env"
    lines = []
    for k, v in session.items():
        lines.append(f'{k}="{v}"')

    env_path.write_text("\n".join(lines) + "\n")
    print(f"\nSession saved to {env_path}")
    print(f"UC_TOKEN: {session['UC_TOKEN'][:20]}...")
    print(f"MTOKEN:   {session['MTOKEN']}")
    print(f"MEMBER_ID:{session['MEMBER_ID'][:20]}...")
    print(f"CHASH:    {session['CHASH'][:20]}...")


# ── CLI ─────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1].lower()

    if cmd == "extract":
        cmd_extract()
        return

    uc_token, sys_info, chash = load_session()
    mx = MexcFuturesWeb(uc_token, sys_info, chash)

    if cmd == "positions":
        r = mx.get_positions()
    elif cmd == "assets":
        r = mx.get_assets()
    elif cmd in ("long", "open_long"):
        symbol, vol = sys.argv[2], int(sys.argv[3])
        lev = int(sys.argv[4]) if len(sys.argv) > 4 else 1
        r = mx.open_long(symbol, vol, lev)
    elif cmd in ("short", "open_short"):
        symbol, vol = sys.argv[2], int(sys.argv[3])
        lev = int(sys.argv[4]) if len(sys.argv) > 4 else 1
        r = mx.open_short(symbol, vol, lev)
    elif cmd == "close_long":
        symbol, vol = sys.argv[2], int(sys.argv[3])
        r = mx.close_long(symbol, vol)
    elif cmd == "close_short":
        symbol, vol = sys.argv[2], int(sys.argv[3])
        r = mx.close_short(symbol, vol)
    else:
        print(f"Unknown: {cmd}")
        sys.exit(1)

    print(json.dumps(r, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()

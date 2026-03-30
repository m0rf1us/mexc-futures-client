"""
MEXC Futures — official OPEN-API client (api.mexc.com).

Uses HMAC-SHA256 signature with API key/secret.
No browser session needed.

Setup:
    1. pip install httpx
    2. Create API key at https://www.mexc.com/ucenter/openapi
       (KYC required for futures trading permission)
    3. Set MEXC_API_KEY and MEXC_API_SECRET in .env or env vars

Usage:
    python mexc_futures_api.py positions
    python mexc_futures_api.py assets
    python mexc_futures_api.py long SOL_USDT 1
    python mexc_futures_api.py short SOL_USDT 1
    python mexc_futures_api.py close_long SOL_USDT 1
    python mexc_futures_api.py close_short SOL_USDT 1
    python mexc_futures_api.py cancel SOL_USDT ORDER_ID
    python mexc_futures_api.py cancel_all SOL_USDT
    python mexc_futures_api.py open_orders SOL_USDT
"""

import hashlib
import hmac
import json
import os
import sys
import time
from pathlib import Path

import httpx


BASE_URL = "https://api.mexc.com/api/v1"


def _load_env(path: str = ".env") -> dict:
    env = {}
    p = Path(path)
    if not p.exists():
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


def _get_keys() -> tuple[str, str]:
    env = _load_env()
    api_key = os.environ.get("MEXC_API_KEY") or env.get("MEXC_API_KEY", "")
    api_secret = os.environ.get("MEXC_API_SECRET") or env.get("MEXC_API_SECRET", "")
    if not api_key or not api_secret:
        print("ERROR: MEXC_API_KEY and MEXC_API_SECRET not set.")
        print("Set them in .env or as environment variables.")
        print("Create API key at: https://www.mexc.com/ucenter/openapi")
        sys.exit(1)
    return api_key, api_secret


class MexcFuturesAPI:
    """
    Official MEXC Futures API client.

    Auth: HMAC-SHA256
      signature = HMAC_SHA256(secret, accessKey + timestamp + paramString)

    Headers:
      ApiKey, Request-Time, Signature, Content-Type
    """

    def __init__(self, api_key: str, api_secret: str, base_url: str = BASE_URL):
        self.api_key = api_key
        self.api_secret = api_secret
        self.base_url = base_url
        self.client = httpx.Client(timeout=10)

    def _sign(self, timestamp: str, param_string: str) -> str:
        """HMAC-SHA256: accessKey + timestamp + paramString"""
        message = self.api_key + timestamp + param_string
        return hmac.new(
            self.api_secret.encode(), message.encode(), hashlib.sha256
        ).hexdigest()

    def _headers(self, timestamp: str, signature: str) -> dict:
        return {
            "ApiKey": self.api_key,
            "Request-Time": timestamp,
            "Signature": signature,
            "Content-Type": "application/json",
        }

    def _get(self, endpoint: str, params: dict | None = None) -> dict:
        ts = str(int(time.time() * 1000))
        # GET: sort params by key, join with &
        if params:
            sorted_params = sorted(
                ((k, v) for k, v in params.items() if v is not None),
                key=lambda x: x[0],
            )
            param_str = "&".join(f"{k}={v}" for k, v in sorted_params)
        else:
            param_str = ""

        sig = self._sign(ts, param_str)
        url = f"{self.base_url}/{endpoint}"
        resp = self.client.get(
            url, params=params, headers=self._headers(ts, sig)
        )
        resp.raise_for_status()
        return resp.json()

    def _post(self, endpoint: str, body: dict) -> dict:
        ts = str(int(time.time() * 1000))
        # POST: JSON string as-is (no sorting)
        body_str = json.dumps(body, separators=(",", ":"))
        sig = self._sign(ts, body_str)
        url = f"{self.base_url}/{endpoint}"
        resp = self.client.post(
            url, content=body_str, headers=self._headers(ts, sig)
        )
        resp.raise_for_status()
        return resp.json()

    # ── Account ─────────────────────────────────────────────

    def get_assets(self) -> dict:
        return self._get("private/account/assets")

    def get_asset(self, currency: str) -> dict:
        return self._get(f"private/account/asset/{currency}")

    def get_positions(self) -> dict:
        return self._get("private/position/open_positions")

    # ── Orders ──────────────────────────────────────────────

    def submit_order(
        self,
        symbol: str,
        side: int,
        vol: int | float,
        order_type: int = 5,
        price: float | None = None,
        leverage: int | None = None,
        open_type: int = 2,
        external_oid: str | None = None,
        stop_loss_price: float | None = None,
        take_profit_price: float | None = None,
        reduce_only: bool | None = None,
    ) -> dict:
        """
        Place an order.

        side: 1=open long, 2=close short, 3=open short, 4=close long
        order_type: 1=limit, 2=post only, 3=IOC, 4=FOK, 5=market
        open_type: 1=isolated, 2=cross
        """
        body = {
            "symbol": symbol,
            "side": side,
            "type": order_type,
            "vol": vol,
            "openType": open_type,
        }
        if price is not None:
            body["price"] = price
        if leverage is not None:
            body["leverage"] = leverage
        if external_oid is not None:
            body["externalOid"] = external_oid
        if stop_loss_price is not None:
            body["stopLossPrice"] = stop_loss_price
        if take_profit_price is not None:
            body["takeProfitPrice"] = take_profit_price
        if reduce_only is not None:
            body["reduceOnly"] = reduce_only

        return self._post("private/order/submit", body)

    # ── Convenience ─────────────────────────────────────────

    def open_long(self, symbol: str, vol: int, leverage: int = 1) -> dict:
        return self.submit_order(
            symbol, side=1, vol=vol, leverage=leverage, order_type=5
        )

    def open_short(self, symbol: str, vol: int, leverage: int = 1) -> dict:
        return self.submit_order(
            symbol, side=3, vol=vol, leverage=leverage, order_type=5
        )

    def close_long(self, symbol: str, vol: int) -> dict:
        return self.submit_order(symbol, side=4, vol=vol, order_type=5)

    def close_short(self, symbol: str, vol: int) -> dict:
        return self.submit_order(symbol, side=2, vol=vol, order_type=5)

    # ── Order management ────────────────────────────────────

    def cancel_order(self, symbol: str, order_id: str) -> dict:
        return self._post("private/order/cancel", [
            {"symbol": symbol, "orderId": int(order_id)},
        ])

    def cancel_all(self, symbol: str) -> dict:
        return self._post("private/order/cancel_all", {"symbol": symbol})

    def get_open_orders(self, symbol: str | None = None) -> dict:
        params = {}
        if symbol:
            params["symbol"] = symbol
        return self._get("private/order/list/open_orders", params or None)

    # ── Position management ─────────────────────────────────

    def change_leverage(self, symbol: str, leverage: int, open_type: int = 2,
                        position_type: int | None = None) -> dict:
        body = {"symbol": symbol, "leverage": leverage, "openType": open_type}
        if position_type is not None:
            body["positionType"] = position_type
        return self._post("private/position/change_leverage", body)


# ── CLI ─────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    api_key, api_secret = _get_keys()
    mx = MexcFuturesAPI(api_key, api_secret)
    cmd = sys.argv[1].lower()

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
    elif cmd == "cancel":
        symbol, order_id = sys.argv[2], sys.argv[3]
        r = mx.cancel_order(symbol, order_id)
    elif cmd == "cancel_all":
        r = mx.cancel_all(sys.argv[2])
    elif cmd in ("orders", "open_orders"):
        symbol = sys.argv[2] if len(sys.argv) > 2 else None
        r = mx.get_open_orders(symbol)
    elif cmd == "leverage":
        symbol, lev = sys.argv[2], int(sys.argv[3])
        r = mx.change_leverage(symbol, lev)
    else:
        print(f"Unknown: {cmd}")
        sys.exit(1)

    print(json.dumps(r, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()

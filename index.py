import asyncio
import base64
import copy
import hashlib
import json
import logging
import os
import threading
import time
from collections.abc import Awaitable
from typing import Any, TypeVar, cast

import httpx
from Crypto.Cipher import AES
from flask import Flask, jsonify, render_template, request
from google.protobuf.message import DecodeError
from dotenv import load_dotenv

import my_pb2
import enzoxtsun_pb2

load_dotenv()
logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))

class UpstreamTimeoutError(RuntimeError): pass
class UpstreamRequestError(RuntimeError): pass
class InvalidMajorLoginResponse(RuntimeError): pass

# === Configuration ===
MAIN_KEY = base64.b64decode(os.environ.get("MAIN_KEY_B64", "WWcmdGMlREV1aDYlWmNeOA=="))
MAIN_IV = base64.b64decode(os.environ.get("MAIN_IV_B64", "Nm95WkRyMjJFM3ljaGpNJQ=="))
USERAGENT = os.environ.get("USERAGENT", "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)")
RELEASEVERSION = os.environ.get("RELEASEVERSION", "OB55")
MAJOR_LOGIN_URL = os.environ.get("MAJOR_LOGIN_URL", "https://loginbp.ppmainecoonghj.com").rstrip("/")
TOKEN_GRANT_URL = os.environ.get("TOKEN_GRANT_URL", "https://100067.connect.garena.com/oauth/guest/token/grant")
TOKEN_INSPECT_URL = os.environ.get("TOKEN_INSPECT_URL", "https://100067.connect.garena.com/oauth/token/inspect")
CONFIG_URL = os.environ.get("CONFIG_URL")
REQUEST_TIMEOUT = float(os.environ.get("UPSTREAM_TIMEOUT", "15"))
T = TypeVar("T")
CACHE_TTL = int(os.environ.get("TOKEN_CACHE_TTL", "25200"))
CACHE_ENABLED = os.environ.get("TOKEN_CACHE_ENABLED", "1").lower() not in {"0", "false", "no"}

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_FILE = os.path.join(BASE_DIR, "template_gamedata.bin")

def _load_remote_config() -> None:
    global RELEASEVERSION, MAJOR_LOGIN_URL
    if not CONFIG_URL: return
    try:
        response = httpx.get(CONFIG_URL, timeout=10.0)
        response.raise_for_status()
        config = response.json()
    except (httpx.HTTPError, json.JSONDecodeError) as exc:
        raise RuntimeError("Failed to load runtime configuration") from exc
    if not isinstance(config, dict): return
    if isinstance(config.get("RELEASEVERSION"), str): RELEASEVERSION = config["RELEASEVERSION"]
    if isinstance(config.get("MAJOR_LOGIN_URL"), str): MAJOR_LOGIN_URL = config["MAJOR_LOGIN_URL"].rstrip("/")

_load_remote_config()

# === Template and cache ===
def _load_template() -> bytes:
    try:
        with open(TEMPLATE_FILE, "rb") as template_handle:
            template = template_handle.read()
        message = cast(Any, getattr(my_pb2, "GameData"))()
        message.ParseFromString(template)
    except (OSError, ValueError) as exc:
        raise RuntimeError("Invalid or missing template_gamedata.bin") from exc
    return template

RAW_TEMPLATE = _load_template()
_CACHE: dict[str, tuple[float, dict[str, Any]]] = {}
_CACHE_LOCK = threading.Lock()

def _cache_key(kind: str, *values: str) -> str:
    digest = hashlib.sha256("\0".join(values).encode("utf-8")).hexdigest()
    return f"{kind}:{digest}"

def _cache_get(key: str) -> dict[str, Any] | None:
    if not CACHE_ENABLED or CACHE_TTL <= 0: return None
    with _CACHE_LOCK:
        entry = _CACHE.get(key)
        if not entry: return None
        expires_at, value = entry
        if expires_at <= time.monotonic():
            _CACHE.pop(key, None)
            return None
        return copy.deepcopy(value)

def _cache_set(key: str, value: dict[str, Any]) -> None:
    if not CACHE_ENABLED or CACHE_TTL <= 0: return
    with _CACHE_LOCK:
        _CACHE[key] = (time.monotonic() + CACHE_TTL, copy.deepcopy(value))

# === OB55 protocol ===
def pad(data: bytes) -> bytes:
    pad_len = AES.block_size - len(data) % AES.block_size
    return data + bytes([pad_len] * pad_len)

def aes_encrypt(data: bytes) -> bytes:
    cipher = AES.new(MAIN_KEY, AES.MODE_CBC, MAIN_IV)
    return cipher.encrypt(pad(data))

def build_login_request(open_id: str, access_token: str) -> bytes:
    message = cast(Any, getattr(my_pb2, "GameData"))()
    message.ParseFromString(RAW_TEMPLATE)
    message.open_id = open_id
    message.access_token = access_token
    
    # ডাইনামিক ডেটা আপডেট (সঠিক ফিল্ড নেম দিয়ে)
    message.timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    message.api = "Android OS 9 / API-28 (SP1A.210812.016/G998BXXU4BULF)"
    
    return message.SerializeToString()

def _raise_upstream_error(exc: Exception) -> None:
    if isinstance(exc, httpx.TimeoutException): raise UpstreamTimeoutError from exc
    if isinstance(exc, (httpx.HTTPStatusError, httpx.RequestError, json.JSONDecodeError)): raise UpstreamRequestError from exc
    raise UpstreamRequestError from exc

async def get_access_token(uid: str, password: str) -> tuple[str | None, str | None]:
    headers = {
        "User-Agent": "GarenaMSDK/4.0.44(SM-G998B ;Android 9;en;US;app 1.132.1 2019121229;)",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "close",
    }
    data = {
        "uid": str(uid), "password": str(password), "response_type": "token",
        "client_type": "2", "client_secret": os.environ.get("CLIENT_SECRET", "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"),
        "client_id": "100067", "app_id": "100067",
    }
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(REQUEST_TIMEOUT)) as client:
            response = await client.post(TOKEN_GRANT_URL, data=data, headers=headers)
            response.raise_for_status()
            payload = response.json()
    except Exception as exc:
        _raise_upstream_error(exc)
    result = payload if isinstance(payload, dict) else {}
    return (
        result.get("access_token") if isinstance(result.get("access_token"), str) else None,
        result.get("open_id") if isinstance(result.get("open_id"), str) else None,
    )

async def inspect_access_token(access_token: str) -> dict[str, Any] | None:
    headers = {"User-Agent": "GarenaMSDK/4.0.44(SM-G998B ;Android 9;en;US;app 1.132.1 2019121229;)", "Connection": "close"}
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(REQUEST_TIMEOUT)) as client:
            response = await client.get(TOKEN_INSPECT_URL, params={"app_id": "100067", "token": access_token}, headers=headers)
            response.raise_for_status()
            payload = response.json()
    except Exception as exc:
        _raise_upstream_error(exc)
    result = payload if isinstance(payload, dict) else {}
    return result if isinstance(result.get("open_id"), str) and result.get("open_id") else None

def _read_varint(data: bytes, offset: int) -> tuple[int, int]:
    value, shift = 0, 0
    while offset < len(data) and shift <= 63:
        byte = data[offset]; offset += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80: return value, offset
        shift += 7
    raise InvalidMajorLoginResponse

def _extract_get_login_nickname(content: bytes) -> str | None:
    for offset in range(min(128, len(content))):
        message = enzoxtsun_pb2.GetLoginDataRes()
        try: message.ParseFromString(content[offset:])
        except DecodeError: continue
        if message.nickname and len(message.nickname) <= 128:
            return message.nickname.strip() or None
    return None

async def _fetch_login_data_nickname(encrypted_data: bytes, location: str | None, major_token: str | None) -> str | None:
    if not location or not major_token: return None
    headers = {
        "User-Agent": USERAGENT, "Connection": "Keep-Alive", "Accept-Encoding": "deflate, gzip",
        "Content-Type": "application/x-www-form-urlencoded", "X-GA-SV": os.environ.get("X_GA_SV", "1790603268"),
        "X-Unity-Version": "2018.4.12f1", "X-GA": "v1 1", "ReleaseVersion": RELEASEVERSION,
        "Authorization": f"Bearer {major_token}",
    }
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(REQUEST_TIMEOUT)) as client:
            response = await client.post(f"{location.rstrip('/')}/GetLoginData", content=encrypted_data, headers=headers)
            response.raise_for_status()
        return _extract_get_login_nickname(response.content) if response.content else None
    except Exception:
        return None

def _parse_major_login_response(content: bytes) -> dict[str, Any]:
    for offset in range(min(128, len(content))):
        message = enzoxtsun_pb2.MajorLoginRes()
        try: message.ParseFromString(content[offset:])
        except DecodeError: continue
        if not message.token or not message.account_id: continue
        return {
            "account_id": str(message.account_id), "region": message.region, "token": message.token,
            "location": message.url, "server_time": message.server_time, "aes_ak": message.aes_ak, "iv_i": message.iv_i,
        }
    raise InvalidMajorLoginResponse

async def send_major_login(open_id: str, access_token: str) -> dict[str, Any]:
    encrypted_data = aes_encrypt(build_login_request(open_id, access_token))
    headers = {
        "User-Agent": USERAGENT, "Connection": "Keep-Alive", "Accept-Encoding": "deflate, gzip",
        "Content-Type": "application/x-www-form-urlencoded", "Expect": "100-continue",
        "X-GA-SV": os.environ.get("X_GA_SV", "1790603268"), "X-Unity-Version": "2018.4.12f1",
        "X-GA": "v1 1", "ReleaseVersion": RELEASEVERSION,
    }
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(REQUEST_TIMEOUT)) as client:
            response = await client.post(f"{MAJOR_LOGIN_URL}/MajorLogin", content=encrypted_data, headers=headers)
            response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        raise UpstreamRequestError(f"HTTP {exc.response.status_code} (Blocked)") from exc
    except httpx.RequestError as exc:
        raise UpstreamRequestError(f"Connection Error") from exc
    except httpx.TimeoutException as exc:
        raise UpstreamTimeoutError from exc

    content = response.content
    if not content:
        raise InvalidMajorLoginResponse("Empty Response (Template Rejected)")
        
    try:
        result = _parse_major_login_response(content)
        nickname = await _fetch_login_data_nickname(encrypted_data, result.get("location") if isinstance(result.get("location"), str) else None, result.get("token") if isinstance(result.get("token"), str) else None)
        if nickname: result["name"] = nickname
        return result
    except InvalidMajorLoginResponse:
        snippet = content[:80].decode('utf-8', errors='ignore')
        raise InvalidMajorLoginResponse(f"Invalid Data: {snippet}")

def _normalize_result(result: dict[str, Any], access_token: str, uid: str | None = None) -> dict[str, Any]:
    name = result.get("name")
    account_id = result.get("account_id")
    if not isinstance(name, str) or not name.strip(): name = f"Player_{account_id}" if account_id else None
    region = result.get("region", "N/A")
    return {
        "accountId": account_id, "name": name, "ipRegion": result.get("ip_region", region),
        "lockRegion": result.get("lock_region", region), "notiRegion": result.get("noti_region", region),
        "serverUrl": result.get("location"), "accessToken": access_token, "token": result.get("token"),
        "region": region, "status": result.get("status", "N/A"), "uid": uid,
    }

async def generate_from_credentials(uid: str, password: str) -> dict[str, Any]:
    access_token, open_id = await get_access_token(uid, password)
    if not access_token or not open_id: raise ValueError("Guest token response was incomplete")
    return _normalize_result(await send_major_login(open_id, access_token), access_token, uid)

async def generate_from_access_token(access_token: str) -> dict[str, Any]:
    token_data = await inspect_access_token(access_token)
    if not token_data: raise ValueError("Access token is invalid")
    return _normalize_result(await send_major_login(token_data["open_id"], access_token), access_token, str(token_data.get("uid", "")))

def _run(coroutine: Awaitable[T]) -> T:
    return asyncio.run(coroutine)

def _token_response(access_token: str | None, uid: str | None, password: str | None) -> dict[str, Any]:
    if access_token:
        key = _cache_key("access", access_token)
        cached = _cache_get(key)
        if cached: return cached
        response = _run(generate_from_access_token(access_token))
    elif uid and password:
        key = _cache_key("credentials", uid, password)
        cached = _cache_get(key)
        if cached: return cached
        response = _run(generate_from_credentials(uid, password))
    else:
        raise ValueError("Missing uid/password or access_token")
    if response.get("token"): _cache_set(key, response)
    return response

# === Flask app and routes ===
def _request_json_object() -> dict[str, Any]:
    payload = request.get_json(silent=True)
    return payload if isinstance(payload, dict) else {}

app = Flask(__name__, template_folder=BASE_DIR)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/generate", methods=["POST"])
def generate_jwt():
    payload = _request_json_object()
    uid = payload.get("uid")
    password = payload.get("password")

    if not uid or not password:
        return jsonify({"success": False, "error": "UID এবং পাসওয়ার্ড উভয়ই প্রয়োজন"}), 400

    try:
        response = _token_response(None, uid, password)
        if not response.get("token"):
            return jsonify({"success": False, "error": "JWT টোকেন তৈরি করা যায়নি"}), 502
        return jsonify({"success": True, "token": response["token"]})
    except ValueError as exc:
        return jsonify({"success": False, "error": str(exc)}), 400
    except UpstreamTimeoutError:
        return jsonify({"success": False, "error": "সার্ভার টাইমআউট"}), 504
    except (UpstreamRequestError, InvalidMajorLoginResponse) as e:
        return jsonify({"success": False, "error": f"সার্ভার রিজেক্ট করেছে: {str(e)}"}), 502
    except Exception as e:
        return jsonify({"success": False, "error": f"আননো এরর: {str(e)}"}), 502

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")))
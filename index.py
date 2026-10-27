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
REQUEST_TIMEOUT = float(os.environ.get("UPSTREAM_TIMEOUT", "15"))
T = TypeVar("T")
CACHE_TTL = int(os.environ.get("TOKEN_CACHE_TTL", "25200"))
CACHE_ENABLED = os.environ.get("TOKEN_CACHE_ENABLED", "1").lower() not in {"0", "false", "no"}

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# === OB55 protocol ===
def pad(data: bytes) -> bytes:
    pad_len = AES.block_size - len(data) % AES.block_size
    return data + bytes([pad_len] * pad_len)

def aes_encrypt(data: bytes) -> bytes:
    cipher = AES.new(MAIN_KEY, AES.MODE_CBC, MAIN_IV)
    return cipher.encrypt(pad(data))

def build_login_request(open_id: str, access_token: str) -> bytes:
    message = cast(Any, getattr(my_pb2, "GameData"))()
    # ফাইলের ওপর ভরসা না করে ডাইনামিকালি টেমপ্লেট বানানো হচ্ছে
    message.timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    message.game_name = "free fire"
    message.game_version = 1
    message.version_code = "1.132.8"
    message.os_info = "Android OS 9 / API-28 (SP1A.210812.016/G998BXXU4BULF)"
    message.device_type = "Handheld"
    message.network_provider = "AT&T"
    message.connection_type = "WIFI"
    message.screen_width = 1080
    message.screen_height = 2340
    message.dpi = "240"
    message.cpu_info = "ARMv7 VFPv3 NEON | 2000 | 4"
    message.total_ram = 4096
    message.gpu_name = "Adreno (TM) 540"
    message.gpu_version = "OpenGL ES 3.2 (4.5.0 - Build 32.0.101.6790)"
    message.user_id = "Google|8e623c41-5590-4afe-af25-850a52a24cd0"
    message.ip_address = "110.38.251.220"
    message.language = "en"
    message.open_id = open_id
    message.platform_type = 4
    message.device_form_factor = "Handheld"
    message.device_model = "samsung SM-G998B"
    message.access_token = access_token
    message.unknown_field_30 = 1
    message.secondary_network_provider = "AT&T"
    message.secondary_connection_type = "WIFI"
    message.unique_id = "7428b253defc164018c604a1ebbfebdf"
    message.library_path = "/data/app/com.dts.freefireth-9vR6l9WY0JI2Gc9DgaD52A==/lib/arm"
    message.apk_info = "b8e0cd5e295eee42f5860d3c86e483dd|/data/app/com.dts.freefireth-9vR6l9WY0JI2Gc9DgaD52A==/base.apk"
    message.build_number = "2019121229"
    message.graphics_backend = "OpenGLES2"
    
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
        if not response.content: return None
        for offset in range(min(128, len(response.content))):
            message = enzoxtsun_pb2.GetLoginDataRes()
            try: message.ParseFromString(response.content[offset:])
            except DecodeError: continue
            if message.nickname and len(message.nickname) <= 128:
                return message.nickname.strip() or None
        return None
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
        "User-Agent": "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
        "Connection": "Keep-Alive",
        "Accept-Encoding": "deflate, gzip",
        "Content-Type": "application/x-www-form-urlencoded",
        "Expect": "100-continue",
        "X-GA-SV": "1790603268",
        "X-Unity-Version": "2018.4.12f1",
        "X-GA": "v1 1",
        "ReleaseVersion": "OB55",
    }
    try:
        async with httpx.AsyncClient(timeout=httpx.Timeout(REQUEST_TIMEOUT)) as client:
            response = await client.post(f"{MAJOR_LOGIN_URL}/MajorLogin", content=encrypted_data, headers=headers)
            response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        raise UpstreamRequestError(f"HTTP {exc.response.status_code} (Blocked by Garena)") from exc
    except Exception as exc:
        raise UpstreamRequestError("Connection Failed") from exc

    if not response.content:
        raise InvalidMajorLoginResponse("Empty Response from Server")
        
    result = _parse_major_login_response(response.content)
    nickname = await _fetch_login_data_nickname(encrypted_data, result.get("location") if isinstance(result.get("location"), str) else None, result.get("token") if isinstance(result.get("token"), str) else None)
    if nickname: result["name"] = nickname
    return result

def _normalize_result(result: dict[str, Any], access_token: str, uid: str | None = None) -> dict[str, Any]:
    return {
        "accountId": result.get("account_id"), "name": result.get("name", f"Player_{result.get('account_id')}"),
        "accessToken": access_token, "token": result.get("token"), "region": result.get("region", "N/A"), "uid": uid,
    }

async def generate_from_credentials(uid: str, password: str) -> dict[str, Any]:
    access_token, open_id = await get_access_token(uid, password)
    if not access_token or not open_id: raise ValueError("Guest token response was incomplete")
    return _normalize_result(await send_major_login(open_id, access_token), access_token, uid)

# === Flask app ===
app = Flask(__name__, template_folder=BASE_DIR)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/generate", methods=["POST"])
def generate_jwt():
    payload = request.get_json(silent=True) or {}
    uid, password = payload.get("uid"), payload.get("password")
    if not uid or not password: return jsonify({"success": False, "error": "UID এবং পাসওয়ার্ড দিন"}), 400
    try:
        response = asyncio.run(generate_from_credentials(uid, password))
        return jsonify({"success": True, "token": response["token"]})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 502

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")))
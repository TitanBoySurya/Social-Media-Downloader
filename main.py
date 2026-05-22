from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import logging
import mimetypes
import os
import re
import secrets
import shutil
import tempfile
import socket
import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, AsyncGenerator, Optional
from urllib.parse import urlparse

import httpx
import uvicorn
import yt_dlp
from cachetools import TTLCache
from fastapi import (
    Depends,
    FastAPI,
    HTTPException,
    Query,
    Request,
    Response,
    Security,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.security import APIKeyHeader
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    Counter,
    Gauge,
    Histogram,
    REGISTRY,
    generate_latest,
)
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sanitize_filename import sanitize
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from starlette.background import BackgroundTask

# Windows event loop fix (must be before anything else async)
if os.name == "nt":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

# ═══════════════════════════════════════════════════════════
# CONFIGURATION MANAGEMENT
# ═══════════════════════════════════════════════════════════

UTC = timezone.utc


def _env_list(key: str, default: str) -> list[str]:
    return [x.strip() for x in os.getenv(key, default).split(",") if x.strip()]


def _env_bool(key: str, default: bool = False) -> bool:
    return os.getenv(key, str(default)).lower() in ("1", "true", "yes")


class Config:
    APP_NAME: str = os.getenv("APP_NAME", "VideoSnap API")
    VERSION: str = "7.2.0"

    PORT: int = int(os.getenv("PORT", "8000"))
    DEBUG: bool = _env_bool("DEBUG")
    # Always 1 worker — in-memory job store breaks with multiple workers
    WORKERS: int = 1

    DOWNLOAD_DIR: Path = Path(
        os.getenv("DOWNLOAD_DIR", str(Path(__file__).parent / "downloads"))
    )

    API_KEY: str = os.getenv("API_KEY", "")
    TOKEN_SECRET: str = os.getenv("TOKEN_SECRET", secrets.token_hex(32))
    TOKEN_TTL_SEC: int = int(os.getenv("TOKEN_TTL_SEC", "3600"))

    ALLOWED_ORIGINS: list[str] = _env_list("ALLOWED_ORIGINS", "*")

    RATE_LIMIT_INFO: str = os.getenv("RATE_LIMIT_INFO", "30/minute")
    RATE_LIMIT_DOWNLOAD: str = os.getenv("RATE_LIMIT_DOWNLOAD", "10/minute")

    CACHE_TTL: int = int(os.getenv("CACHE_TTL", "300"))
    CACHE_MAX_SIZE: int = int(os.getenv("CACHE_MAX_SIZE", "256"))

    MAX_FILESIZE_MB: int = int(os.getenv("MAX_FILESIZE_MB", "500"))
    MAX_DURATION_SEC: int = int(os.getenv("MAX_DURATION_SEC", "3600"))
    MAX_RETRIES: int = int(os.getenv("MAX_RETRIES", "3"))
    SOCKET_TIMEOUT: int = int(os.getenv("SOCKET_TIMEOUT", "30"))
    CONCURRENT_FRAGS: int = int(os.getenv("CONCURRENT_FRAGS", "4"))

    JOB_TTL_SEC: int = int(os.getenv("JOB_TTL_SEC", "600"))
    CLEANUP_INTERVAL: int = int(os.getenv("CLEANUP_INTERVAL", "120"))
    MAX_CONCURRENT_DOWNLOADS: int = int(os.getenv("MAX_CONCURRENT_DOWNLOADS", "3"))
    DOWNLOAD_TIMEOUT_SEC: int = int(os.getenv("DOWNLOAD_TIMEOUT_SEC", "900"))

    COOKIES_FILE: str = os.getenv("COOKIES_FILE", "")
    HTTP_PROXY: str = os.getenv("HTTP_PROXY", "")

    WEBHOOK_SECRET: str = os.getenv("WEBHOOK_SECRET", "")
    WEBHOOK_TIMEOUT_SEC: int = int(os.getenv("WEBHOOK_TIMEOUT_SEC", "10"))

    ALLOWED_PLATFORMS: set[str] = set(_env_list("ALLOWED_PLATFORMS", ""))
    BLOCKED_HOSTS: frozenset[str] = frozenset(
        {"localhost", "127.0.0.1", "0.0.0.0", "::1", "169.254.169.254", "metadata.google.internal"}
    )

    CHUNK_SIZE: int = int(os.getenv("CHUNK_SIZE", str(64 * 1024)))
    STREAM_PURGE_DELAY_SEC: int = int(os.getenv("STREAM_PURGE_DELAY_SEC", "10"))

    YT_PO_TOKEN: str = os.getenv("YT_PO_TOKEN", "")
    YT_VISITOR_DATA: str = os.getenv("YT_VISITOR_DATA", "")


config = Config()
config.DOWNLOAD_DIR.mkdir(parents=True, exist_ok=True)

# ═══════════════════════════════════════════════════════════
# LOGGING
# ═══════════════════════════════════════════════════════════

logging.basicConfig(
    level=logging.DEBUG if config.DEBUG else logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("videosnap")

logging.getLogger("yt_dlp").setLevel(logging.DEBUG if config.DEBUG else logging.WARNING)
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("uvicorn.access").setLevel(logging.WARNING)

# ═══════════════════════════════════════════════════════════
# COOKIES RESOLUTION
# ═══════════════════════════════════════════════════════════

_COOKIE_CANDIDATE_PATHS = [
    config.COOKIES_FILE,
    "/etc/secrets/cookies.txt",
    str(Path(__file__).parent / "cookies.txt"),
    os.path.expanduser("~/cookies.txt"),
]


def _resolve_cookies_file() -> str:
    for path in _COOKIE_CANDIDATE_PATHS:
        try:
            if not path:
                continue
            p = Path(path)
            if not p.is_file():
                continue
            with p.open("r", encoding="utf-8", errors="ignore") as f:
                first_line = f.readline().strip()
            if "Netscape" not in first_line and "# Netscape" not in first_line:
                logger.warning(f"Skipping invalid cookies file (not Netscape format): {path}")
                continue
            return str(p)
        except Exception as exc:
            logger.warning(f"Failed checking cookies file [{path}]: {exc}")
    return ""


RESOLVED_COOKIES_FILE: str = ""
_original_cookie_file = _resolve_cookies_file()

if _original_cookie_file:
    try:
        writable_cookie_path = Path(tempfile.gettempdir()) / f"videosnap_cookies_{os.getpid()}.txt"
        shutil.copy2(_original_cookie_file, writable_cookie_path)
        RESOLVED_COOKIES_FILE = str(writable_cookie_path)
        logger.info(f"Using cookies path: {RESOLVED_COOKIES_FILE}")
    except Exception as exc:
        logger.error(f"Failed to prepare cookies sandbox: {exc}")
else:
    logger.warning("No valid cookies.txt found — running without credentials.")

# ═══════════════════════════════════════════════════════════
# ERROR TAXONOMY
# ═══════════════════════════════════════════════════════════


class ErrorCode(str, Enum):
    UNAUTHORIZED = "UNAUTHORIZED"
    FORBIDDEN = "FORBIDDEN"
    INVALID_URL = "INVALID_URL"
    BLOCKED_HOST = "BLOCKED_HOST"
    PRIVATE_IP = "PRIVATE_IP"
    UNSUPPORTED_PLATFORM = "UNSUPPORTED_PLATFORM"
    FETCH_FAILED = "FETCH_FAILED"
    DURATION_EXCEEDED = "DURATION_EXCEEDED"
    FILESIZE_EXCEEDED = "FILESIZE_EXCEEDED"
    JOB_NOT_FOUND = "JOB_NOT_FOUND"
    JOB_STILL_PROCESSING = "JOB_STILL_PROCESSING"
    JOB_FAILED = "JOB_FAILED"
    FILE_MISSING = "FILE_MISSING"
    INVALID_TOKEN = "INVALID_TOKEN"
    TOKEN_EXPIRED = "TOKEN_EXPIRED"
    RATE_LIMITED = "RATE_LIMITED"
    DOWNLOAD_TIMEOUT = "DOWNLOAD_TIMEOUT"
    INTERNAL_ERROR = "INTERNAL_ERROR"


def api_error(status: int, code: ErrorCode, message: str, *, detail: Any = None) -> HTTPException:
    return HTTPException(status_code=status, detail={"error": message, "code": code, "detail": detail})


# ═══════════════════════════════════════════════════════════
# METRICS
# ═══════════════════════════════════════════════════════════


def _metric(cls, name, doc, labels=None):
    existing = REGISTRY._names_to_collectors.get(name)
    if existing:
        return existing
    return cls(name, doc, labels) if labels else cls(name, doc)


prom_requests = _metric(Counter, "vs_requests_total", "Total API requests", ["endpoint"])
prom_downloads = _metric(Counter, "vs_downloads_total", "Completed downloads", ["type"])
prom_errors = _metric(Counter, "vs_errors_total", "Errors", ["code"])
prom_cache_hits = _metric(Counter, "vs_cache_hits_total", "Info cache hits")
prom_active_jobs = _metric(Gauge, "vs_active_jobs", "Active download jobs")
prom_dl_seconds = _metric(Histogram, "vs_download_duration_seconds", "Download wall time")
prom_dl_bytes = _metric(Counter, "vs_download_bytes_total", "Bytes downloaded")

# ═══════════════════════════════════════════════════════════
# RUNTIME STORAGE
# ═══════════════════════════════════════════════════════════

video_info_cache: TTLCache = TTLCache(maxsize=config.CACHE_MAX_SIZE, ttl=config.CACHE_TTL)
cache_lock = asyncio.Lock()


class JobStatus(str, Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    DONE = "done"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class Job:
    job_id: str
    url: str
    is_audio: bool
    format_id: str
    audio_format: str
    webhook_url: str
    status: JobStatus = JobStatus.PENDING
    filename: Optional[str] = None
    safe_name: Optional[str] = None
    error: Optional[str] = None
    progress: float = 0.0
    speed_bps: Optional[float] = None
    eta_sec: Optional[int] = None
    is_streaming: bool = False
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    expires_at: Optional[str] = None

    def to_dict(self) -> dict:
        d = asdict(self)
        d.pop("is_streaming", None)
        return d


_job_store: dict[str, Job] = {}
_job_store_lock = asyncio.Lock()

# Initialized in lifespan
_download_semaphore: asyncio.Semaphore | None = None
_running_tasks: dict[str, asyncio.Task] = {}
_shutdown_event = asyncio.Event()

# ═══════════════════════════════════════════════════════════
# SECURITY & URL UTILITIES
# ═══════════════════════════════════════════════════════════

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
limiter = Limiter(key_func=get_remote_address)


async def require_api_key(api_key: str = Security(_api_key_header)) -> None:
    if not config.API_KEY:
        return
    if not api_key or not secrets.compare_digest(api_key, config.API_KEY):
        prom_errors.labels(code=ErrorCode.UNAUTHORIZED).inc()
        raise HTTPException(
            status_code=401,
            detail={"error": "Invalid or missing API key", "code": ErrorCode.UNAUTHORIZED},
        )


def _make_token(job_id: str) -> str:
    expires = int(time.time()) + config.TOKEN_TTL_SEC
    payload = f"{job_id}.{expires}"
    sig = hmac.new(config.TOKEN_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}.{sig}"


def _verify_token(token: str) -> str:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("bad format")
        job_id, expires_str, sig = parts
        payload = f"{job_id}.{expires_str}"
        expected = hmac.new(config.TOKEN_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            raise api_error(401, ErrorCode.INVALID_TOKEN, "Invalid token")
        if int(time.time()) > int(expires_str):
            raise api_error(401, ErrorCode.TOKEN_EXPIRED, "Token expired")
        return job_id
    except HTTPException:
        raise
    except Exception:
        raise api_error(401, ErrorCode.INVALID_TOKEN, "Malformed token")


def _resolve_host_safe(host: str, timeout: float = 5.0) -> list:
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(socket.getaddrinfo, host, None)
        try:
            return future.result(timeout=timeout)
        except concurrent.futures.TimeoutError:
            raise ValueError(f"DNS resolution timed out for host: {host}")


# FIX: resolve_redirect_url now skips the httpx GET for YouTube/Instagram/TikTok
# domains where following redirects causes Google CAPTCHA loops.
# For short links (bit.ly, youtu.be etc.) it still follows redirects but
# aborts if the resolved URL lands on google.com/sorry (CAPTCHA wall).
_SKIP_REDIRECT_DOMAINS = {
    "youtube.com", "www.youtube.com",
    "youtu.be",                          # FIX: short links also skip httpx redirect
    "instagram.com", "www.instagram.com",
    "tiktok.com", "www.tiktok.com",
    "twitter.com", "www.twitter.com",
    "x.com", "www.x.com",
    "facebook.com", "www.facebook.com",
    "fb.com", "www.fb.com",
    "m.facebook.com",
}


async def resolve_redirect_url(url: str) -> str:
    """
    Resolves short-link redirects (bit.ly etc.).

    Rules:
    - Known platform domains → return as-is; yt-dlp handles them natively
      and httpx hits Google CAPTCHA walls for YouTube/Facebook.
    - Facebook /share/ URLs → follow redirect to get the real video URL,
      since yt-dlp cannot extract from share-redirect URLs.
    - Everything else → follow redirects, abort if we land on a CAPTCHA page.
    """
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()

    # Facebook /share/ URLs must be resolved — yt-dlp can't handle them
    is_fb_share = hostname in {"facebook.com", "www.facebook.com", "m.facebook.com"} and (
        "/share/" in parsed.path or parsed.path.startswith("/share")
    )

    # Skip redirect fetch for direct platform URLs (not share links)
    if hostname in _SKIP_REDIRECT_DOMAINS and not is_fb_share:
        logger.debug(f"Skipping redirect resolution for: {url}")
        return url

    try:
        headers = {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }
        async with httpx.AsyncClient(follow_redirects=True, timeout=15, verify=False) as client:
            r = await client.get(url, headers=headers)
            resolved = str(r.url)

        # Abort if we landed on a CAPTCHA / login wall
        if "google.com/sorry" in resolved or "accounts.google.com" in resolved:
            logger.warning(f"Redirect hit CAPTCHA wall, using original: {url}")
            return url

        # Facebook share: if it didn't redirect to a real video URL, try to extract
        # the video ID from the page content
        if is_fb_share:
            if "login" in resolved or resolved == url:
                # Try to extract fb video URL from page source
                try:
                    page_text = r.text
                    # Look for reel or video URL patterns in the page
                    for pattern in [
                        r'"(https://www\.facebook\.com/(?:reel|watch|video)[^"]+)"',
                        r'"(https://www\.facebook\.com/[^"]+/videos/[^"]+)"',
                        r'content="(https://www\.facebook\.com/[^"]+)"',
                    ]:
                        match = re.search(pattern, page_text)
                        if match:
                            candidate = match.group(1).replace("\\u0026", "&").replace("\\/", "/")
                            if "video" in candidate or "reel" in candidate or "watch" in candidate:
                                logger.info(f"Extracted Facebook video URL from page: {candidate}")
                                return candidate
                except Exception as ex:
                    logger.warning(f"FB page extraction failed: {ex}")
                logger.warning(f"Facebook share URL could not be resolved, passing as-is: {url}")
                return url

        logger.info(f"Resolved: {url} -> {resolved}")
        return resolved
    except Exception as e:
        logger.warning(f"Redirect resolution failed for {url}: {e}")
        return url


def validate_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only HTTP/HTTPS URLs are allowed")
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host:
        raise ValueError("Empty host in URL")
    if host in config.BLOCKED_HOSTS:
        raise ValueError(f"Blocked host: {host}")
    try:
        addr_info = _resolve_host_safe(host)
        for res in addr_info:
            ip_str = res[4][0]
            ip = ipaddress.ip_address(ip_str)
            if ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local:
                raise ValueError(f"Private/reserved IP blocked: {ip_str}")
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError(f"Host validation failed: {exc}") from exc
    return url


def url_cache_key(url: str) -> str:
    return hashlib.sha256(url.strip().lower().encode()).hexdigest()


# ═══════════════════════════════════════════════════════════
# FILE UTILITIES
# ═══════════════════════════════════════════════════════════


def cleanup_path(path: str | Path) -> None:
    try:
        p = Path(path)
        if p.is_dir():
            shutil.rmtree(p, ignore_errors=True)
        elif p.is_file():
            p.unlink(missing_ok=True)
    except Exception as exc:
        logger.warning(f"Cleanup failed for {path}: {exc}")


async def iter_file_range(
    filepath: Path, start: int, end: int, chunk_size: int = config.CHUNK_SIZE
) -> AsyncGenerator[bytes, None]:
    loop = asyncio.get_running_loop()
    remaining = end - start + 1
    with filepath.open("rb") as fh:
        fh.seek(start)
        while remaining > 0:
            to_read = min(chunk_size, remaining)
            chunk = await loop.run_in_executor(None, fh.read, to_read)
            if not chunk:
                break
            remaining -= len(chunk)
            yield chunk


# ═══════════════════════════════════════════════════════════
# PYDANTIC SCHEMAS
# ═══════════════════════════════════════════════════════════


class AudioFormat(str, Enum):
    mp3 = "mp3"
    m4a = "m4a"
    opus = "opus"
    flac = "flac"
    wav = "wav"


class VideoInfoRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    url: str = Field(..., min_length=10, max_length=2048)


class DownloadRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    url: str = Field(..., min_length=10, max_length=2048)
    format_id: str = Field(default="", max_length=64)
    is_audio: bool = False
    audio_format: AudioFormat = AudioFormat.mp3
    webhook_url: str = Field(default="", max_length=2048)


class FormatInfo(BaseModel):
    format_id: str
    quality: str
    ext: str
    filesize: Optional[int] = None
    filesize_approx: Optional[int] = None
    is_audio: bool
    resolution: Optional[str] = None
    fps: Optional[float] = None
    tbr: Optional[float] = None
    vcodec: Optional[str] = None
    acodec: Optional[str] = None


class VideoInfo(BaseModel):
    title: str
    thumbnail: str
    duration: Optional[int] = 0
    uploader: str
    platform: str
    formats: list[FormatInfo]
    webpage_url: str

    @field_validator("duration", mode="before")
    @classmethod
    def validate_duration(cls, v):
        if v is None:
            return 0
        return int(float(v))


class JobResponse(BaseModel):
    job_id: str
    status: JobStatus
    message: str
    poll_url: str


class JobStatusResponse(BaseModel):
    job_id: str
    status: JobStatus
    filename: Optional[str] = None
    error: Optional[str] = None
    progress: float = 0.0
    speed_bps: Optional[float] = None
    eta_sec: Optional[int] = None
    download_token: Optional[str] = None
    created_at: str
    updated_at: str
    expires_at: Optional[str] = None


# ═══════════════════════════════════════════════════════════
# YT-DLP CORE
# ═══════════════════════════════════════════════════════════

QUALITY_ORDER = {"8K": 0, "4K": 1, "2K": 2, "1080p": 3, "720p": 4, "480p": 5, "360p": 6, "audio": 7}

_USER_AGENTS = [
    "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; Pixel 7a) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36",
]

ANTI_BOT_PATTERNS = [
    "Sign in to confirm",
    "This helps protect our community",
    "unavailable for legal reasons",
    "Please log in",
    "bot",
]


def _pick_user_agent() -> str:
    return _USER_AGENTS[int(time.time() / 60) % len(_USER_AGENTS)]


def _build_ydl_common() -> dict[str, Any]:
    # FIX: Removed "skip": ["hls", "dash"] — that was blocking YouTube's primary streams.
    # FIX: Reduced player_client list to the two most stable clients.
    # FIX: Removed youtube_include_dash_manifest / youtube_include_hls_manifest —
    #      they conflict with android client and are controlled by yt-dlp automatically.
    extractor_args: dict[str, Any] = {
        "youtube": {
            "player_client": ["android", "web"],
            "player_skip": ["configs"],
        },
        "facebook": {
            "api": "graphql",
            "format": "hd",
        },
    }

    if config.YT_PO_TOKEN and config.YT_VISITOR_DATA:
        extractor_args["youtube"]["po_token"] = [f"web+{config.YT_PO_TOKEN}"]
        extractor_args["youtube"]["visitor_data"] = config.YT_VISITOR_DATA

    opts: dict[str, Any] = {
        "quiet": not config.DEBUG,
        "no_warnings": not config.DEBUG,
        "verbose": config.DEBUG,
        "noplaylist": True,
        "geo_bypass": True,
        "socket_timeout": config.SOCKET_TIMEOUT,
        "retries": config.MAX_RETRIES,
        "extractor_retries": config.MAX_RETRIES,
        "fragment_retries": config.MAX_RETRIES,
        "file_access_retries": 3,
        "restrictfilenames": True,
        "trim_file_name": 200,
        "extract_flat": False,
        "extractor_args": extractor_args,
        "sleep_interval_requests": 1,
        "sleep_interval": 2,
        "max_sleep_interval": 5,
        "clean_infojson": True,
        # FIX: Render's network uses an intercepting proxy with self-signed certs
        # This causes SSL verification to fail — nocheckcertificate is required
        "nocheckcertificate": True,
        "prefer_insecure": False,
        "http_headers": {
            "User-Agent": _pick_user_agent(),
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.9",
        },
    }

    if RESOLVED_COOKIES_FILE:
        opts["cookiefile"] = RESOLVED_COOKIES_FILE
    if config.HTTP_PROXY:
        opts["proxy"] = config.HTTP_PROXY

    return opts


def _build_download_opts(job: Job, output_template: str) -> dict[str, Any]:
    base: dict[str, Any] = {
        **_build_ydl_common(),
        "outtmpl": output_template,
        "overwrites": True,
        "concurrent_fragment_downloads": config.CONCURRENT_FRAGS,
        "max_filesize": config.MAX_FILESIZE_MB * 1024 * 1024,
    }

    if job.is_audio:
        return {
            **base,
            "format": "bestaudio/best",
            "postprocessors": [
                {
                    "key": "FFmpegExtractAudio",
                    "preferredcodec": job.audio_format,
                    "preferredquality": "0",
                }
            ],
        }

    # FIX: Format selector with safe pre-merged fallbacks.
    # bv*+ba, bv+ba  → best video + best audio (requires ffmpeg merge)
    # b              → best single-file stream (usually 720p/480p with audio)
    # 18             → YouTube's classic 360p MP4 — always available, no auth needed
    # 17             → YouTube 144p 3GP — absolute last resort
    if job.format_id:
        fmt = (
            f"{job.format_id}+ba"
            f"/{job.format_id}+bestaudio"
            f"/{job.format_id}"
            "/bv*+ba/bv+ba/b/18/17"
        )
    else:
        fmt = "bv*+ba/bv+ba/b/18/17"

    return {
        **base,
        "format": fmt,
        "merge_output_format": "mp4",
    }


def _parse_formats(raw_formats: list[dict]) -> list[FormatInfo]:
    out: list[FormatInfo] = []
    for fmt in raw_formats:
        if not fmt.get("format_id"):
            continue
        if fmt.get("protocol") == "m3u8_native":
            continue
        vcodec = fmt.get("vcodec", "none")
        if vcodec == "none" and fmt.get("acodec") == "none":
            continue
        height = fmt.get("height") or 0
        out.append(
            FormatInfo(
                format_id=fmt.get("format_id", ""),
                quality=f"{height}p" if height else "audio",
                ext=fmt.get("ext", "mp4"),
                filesize=fmt.get("filesize"),
                filesize_approx=fmt.get("filesize_approx"),
                is_audio=bool(vcodec == "none"),
                resolution=f'{fmt.get("width")}x{height}' if height else "Adaptive",
                fps=fmt.get("fps"),
                tbr=fmt.get("tbr"),
                vcodec=vcodec,
                acodec=fmt.get("acodec"),
            )
        )
    out.sort(key=lambda x: QUALITY_ORDER.get(x.quality, 999))
    return out


def fetch_video_info_sync(url: str) -> VideoInfo:
    opts = {
        **_build_ydl_common(),
        "skip_download": True,
        # Without this, yt-dlp may fail on restricted videos when no cookies present
        "format": "bv*+ba/bv+ba/b/18/17",
    }
    try:
        with yt_dlp.YoutubeDL(opts) as ydl:
            info = ydl.extract_info(url, download=False)
    except yt_dlp.utils.DownloadError as exc:
        err_str = str(exc)
        if any(p.lower() in err_str.lower() for p in ANTI_BOT_PATTERNS):
            raise api_error(
                403,
                ErrorCode.FETCH_FAILED,
                "YouTube bot detection triggered. Valid cookies required.",
                detail={"cookies_loaded": bool(RESOLVED_COOKIES_FILE)},
            )
        if "Private video" in err_str:
            raise api_error(403, ErrorCode.FETCH_FAILED, "Video is private.")
        if "This video is not available" in err_str:
            raise api_error(404, ErrorCode.FETCH_FAILED, "Video not available in this region.")
        raise api_error(400, ErrorCode.FETCH_FAILED, f"Extraction failed: {exc}")
    except Exception as exc:
        raise api_error(400, ErrorCode.FETCH_FAILED, f"Unexpected error: {exc}")

    if not info or not info.get("formats"):
        raise api_error(400, ErrorCode.FETCH_FAILED, "No downloadable formats found.")

    duration = info.get("duration") or 0
    if duration > config.MAX_DURATION_SEC:
        raise api_error(400, ErrorCode.DURATION_EXCEEDED, "Video exceeds maximum allowed duration.")

    return VideoInfo(
        title=info.get("title", "Unknown"),
        thumbnail=info.get("thumbnail", ""),
        duration=duration,
        uploader=info.get("uploader", "Unknown"),
        platform=info.get("extractor_key", "Web"),
        formats=_parse_formats(info.get("formats", [])),
        webpage_url=url,
    )


# ═══════════════════════════════════════════════════════════
# DOWNLOAD ENGINE
# ═══════════════════════════════════════════════════════════


async def run_download_job(job_id: str) -> None:
    global _download_semaphore

    # Safety net if semaphore wasn't set in lifespan
    if _download_semaphore is None:
        _download_semaphore = asyncio.Semaphore(config.MAX_CONCURRENT_DOWNLOADS)

    async with _job_store_lock:
        job = _job_store.get(job_id)
        if not job:
            return
        job.status = JobStatus.PROCESSING
        job.updated_at = datetime.now(UTC).isoformat()

    prom_active_jobs.inc()
    out_dir = config.DOWNLOAD_DIR / job_id
    out_dir.mkdir(parents=True, exist_ok=True)
    start_time = time.monotonic()

    def _progress_hook(d: dict) -> None:
        if d.get("status") != "downloading":
            return
        total = d.get("total_bytes") or d.get("total_bytes_estimate") or 0
        downloaded = d.get("downloaded_bytes", 0)
        pct = downloaded / total * 100 if total else 0.0

        async def _update() -> None:
            async with _job_store_lock:
                if job_id not in _job_store:
                    return
                job.progress = round(pct, 1)
                job.speed_bps = d.get("speed")
                job.eta_sec = d.get("eta")
                job.updated_at = datetime.now(UTC).isoformat()

        try:
            asyncio.get_running_loop().create_task(_update())
        except RuntimeError:
            pass

    try:
        _, _, free_b = shutil.disk_usage(config.DOWNLOAD_DIR)
        if free_b < (config.MAX_FILESIZE_MB * 1024 * 1024):
            raise OSError("Insufficient disk space for download.")

        opts = _build_download_opts(job, str(out_dir / "%(title)s.%(ext)s"))
        opts["progress_hooks"] = [_progress_hook]

        def _blocking_download():
            with yt_dlp.YoutubeDL(opts) as ydl:
                ydl.extract_info(job.url, download=True)

        async with _download_semaphore:
            if _shutdown_event.is_set():
                raise asyncio.CancelledError()
            await asyncio.wait_for(
                asyncio.to_thread(_blocking_download),
                timeout=config.DOWNLOAD_TIMEOUT_SEC,
            )

        files = sorted(
            [
                f for f in out_dir.iterdir()
                if f.suffix in {".mp4", ".mp3", ".mkv", ".webm", ".m4a", ".opus", ".flac", ".wav"}
            ],
            key=lambda f: f.stat().st_mtime,
            reverse=True,
        )

        if not files:
            raise FileNotFoundError("No output file found after download.")

        chosen = files[0]
        prom_dl_bytes.inc(chosen.stat().st_size)

        async with _job_store_lock:
            if job_id not in _job_store:
                return
            job.status = JobStatus.DONE
            job.filename = str(chosen)
            job.safe_name = sanitize(chosen.name)
            job.progress = 100.0
            job.updated_at = datetime.now(UTC).isoformat()
            job.expires_at = (datetime.now(UTC) + timedelta(seconds=config.JOB_TTL_SEC)).isoformat()

        prom_downloads.labels(type="audio" if job.is_audio else "video").inc()
        prom_dl_seconds.observe(time.monotonic() - start_time)

    except asyncio.CancelledError:
        async with _job_store_lock:
            if job_id in _job_store:
                job.status = JobStatus.CANCELLED
                job.error = "Job was cancelled."
                job.expires_at = (datetime.now(UTC) + timedelta(seconds=config.JOB_TTL_SEC)).isoformat()
        cleanup_path(out_dir)

    except Exception as exc:
        err_msg = str(exc)
        async with _job_store_lock:
            if job_id in _job_store:
                job.status = JobStatus.FAILED
                job.error = (
                    "YouTube bot detection triggered — cookies required."
                    if any(p.lower() in err_msg.lower() for p in ANTI_BOT_PATTERNS)
                    else err_msg
                )
                # FIX: Failed jobs now also get expires_at so cleanup works
                job.expires_at = (datetime.now(UTC) + timedelta(seconds=config.JOB_TTL_SEC)).isoformat()
        cleanup_path(out_dir)
        prom_errors.labels(code=ErrorCode.INTERNAL_ERROR).inc()

    finally:
        prom_active_jobs.dec()
        _running_tasks.pop(job_id, None)


async def _cleanup_scheduler():
    while not _shutdown_event.is_set():
        await asyncio.sleep(config.CLEANUP_INTERVAL)
        now = datetime.now(UTC)
        async with _job_store_lock:
            expired = [
                jid
                for jid, job in _job_store.items()
                if job.expires_at and datetime.fromisoformat(job.expires_at) < now
            ]
            for jid in expired:
                job = _job_store.get(jid)
                if job and not job.is_streaming:
                    _job_store.pop(jid, None)
                    if job.filename:
                        cleanup_path(Path(job.filename).parent)


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _download_semaphore
    _download_semaphore = asyncio.Semaphore(config.MAX_CONCURRENT_DOWNLOADS)

    if not shutil.which("ffmpeg"):
        logger.error("ffmpeg not found — required for merging video+audio streams.")
        raise RuntimeError("ffmpeg not found. Install ffmpeg and ensure it is on PATH.")

    logger.info(f"Starting {config.APP_NAME} v{config.VERSION}")
    logger.info(f"yt-dlp version: {yt_dlp.version.__version__}")
    logger.info(f"Cookies: {RESOLVED_COOKIES_FILE or '(none)'}")

    cleanup_task = asyncio.create_task(_cleanup_scheduler())
    yield
    _shutdown_event.set()
    cleanup_task.cancel()
    for task in list(_running_tasks.values()):
        task.cancel()


# ═══════════════════════════════════════════════════════════
# FASTAPI APP
# ═══════════════════════════════════════════════════════════

app = FastAPI(title=config.APP_NAME, version=config.VERSION, lifespan=lifespan)
app.state.limiter = limiter

_has_wildcard = "*" in config.ALLOWED_ORIGINS
app.add_middleware(
    CORSMiddleware,
    allow_origins=config.ALLOWED_ORIGINS,
    allow_credentials=not _has_wildcard,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["X-API-Key", "Content-Type", "Range"],
    expose_headers=["Content-Disposition", "Content-Range", "Accept-Ranges", "X-Request-ID"],
)


@app.middleware("http")
async def request_id_middleware(request: Request, call_next):
    prom_requests.labels(endpoint=request.url.path).inc()
    rid = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    request.state.id = rid
    response = await call_next(request)
    response.headers["X-Request-ID"] = rid
    return response


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=429,
        content={"error": "Rate limit exceeded", "code": ErrorCode.RATE_LIMITED},
    )


_auth = Depends(require_api_key)

# ═══════════════════════════════════════════════════════════
# ENDPOINTS
# ═══════════════════════════════════════════════════════════


@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "version": config.VERSION,
        "timestamp": datetime.now(UTC).isoformat(),
        "cookies_loaded": bool(RESOLVED_COOKIES_FILE),
        "ffmpeg_available": bool(shutil.which("ffmpeg")),
    }


@app.get("/metrics", include_in_schema=False)
async def metrics():
    return StreamingResponse(iter([generate_latest()]), media_type=CONTENT_TYPE_LATEST)


@app.post("/api/info", response_model=VideoInfo, dependencies=[_auth])
@limiter.limit(config.RATE_LIMIT_INFO)
async def get_info(request: Request, req: VideoInfoRequest, response: Response):
    resolved_url = await resolve_redirect_url(req.url)
    try:
        clean_url = validate_url(resolved_url)
    except ValueError as exc:
        raise api_error(400, ErrorCode.INVALID_URL, str(exc))

    key = url_cache_key(clean_url)
    async with cache_lock:
        if key in video_info_cache:
            prom_cache_hits.inc()
            response.headers["X-Cache"] = "HIT"
            return video_info_cache[key]

    try:
        info = await asyncio.wait_for(
            asyncio.to_thread(fetch_video_info_sync, clean_url), timeout=30.0
        )
    except asyncio.TimeoutError:
        raise api_error(408, ErrorCode.DOWNLOAD_TIMEOUT, "Metadata fetch timed out.")

    async with cache_lock:
        video_info_cache[key] = info
    response.headers["X-Cache"] = "MISS"
    return info


@app.get("/api/info", response_model=VideoInfo, dependencies=[_auth])
@limiter.limit(config.RATE_LIMIT_INFO)
async def get_info_browser(
    request: Request,
    url: str = Query(..., min_length=10, max_length=2048),
    response: Response = None,
):
    resolved_url = await resolve_redirect_url(url)
    try:
        clean_url = validate_url(resolved_url)
    except ValueError as exc:
        raise api_error(400, ErrorCode.INVALID_URL, str(exc))

    key = url_cache_key(clean_url)
    async with cache_lock:
        if key in video_info_cache:
            prom_cache_hits.inc()
            if response:
                response.headers["X-Cache"] = "HIT"
            return video_info_cache[key]

    try:
        info = await asyncio.wait_for(
            asyncio.to_thread(fetch_video_info_sync, clean_url), timeout=30.0
        )
    except asyncio.TimeoutError:
        raise api_error(408, ErrorCode.DOWNLOAD_TIMEOUT, "Metadata fetch timed out.")

    async with cache_lock:
        video_info_cache[key] = info
    if response:
        response.headers["X-Cache"] = "MISS"
    return info


@app.post("/api/formats", response_model=list[FormatInfo], dependencies=[_auth])
@limiter.limit(config.RATE_LIMIT_INFO)
async def get_formats(request: Request, req: VideoInfoRequest):
    resolved_url = await resolve_redirect_url(req.url)
    try:
        clean_url = validate_url(resolved_url)
    except ValueError as exc:
        raise api_error(400, ErrorCode.INVALID_URL, str(exc))

    try:
        info = await asyncio.wait_for(
            asyncio.to_thread(fetch_video_info_sync, clean_url), timeout=30.0
        )
    except asyncio.TimeoutError:
        raise api_error(408, ErrorCode.DOWNLOAD_TIMEOUT, "Metadata fetch timed out.")
    return info.formats


@app.post("/api/download/start", response_model=JobResponse, status_code=202, dependencies=[_auth])
@limiter.limit(config.RATE_LIMIT_DOWNLOAD)
async def start_download(request: Request, req: DownloadRequest):
    resolved_url = await resolve_redirect_url(req.url)
    # FIX: validate_url was missing from download/start — SSRF gap
    try:
        clean_url = validate_url(resolved_url)
    except ValueError as exc:
        raise api_error(400, ErrorCode.INVALID_URL, str(exc))

    job_id = str(uuid.uuid4())
    job = Job(
        job_id=job_id,
        url=clean_url,
        is_audio=req.is_audio,
        format_id=req.format_id,
        audio_format=req.audio_format,
        webhook_url=req.webhook_url,
    )

    async with _job_store_lock:
        _job_store[job_id] = job

    task = asyncio.create_task(run_download_job(job_id))
    _running_tasks[job_id] = task

    return JobResponse(
        job_id=job_id,
        status=JobStatus.PENDING,
        message="Job enqueued",
        poll_url=f"/api/download/status/{job_id}",
    )


@app.get("/api/download/status/{job_id}", response_model=JobStatusResponse, dependencies=[_auth])
async def download_status(job_id: str):
    async with _job_store_lock:
        job = _job_store.get(job_id)
    if not job:
        raise api_error(404, ErrorCode.JOB_NOT_FOUND, "Job not found")
    token = _make_token(job_id) if job.status == JobStatus.DONE else None
    return JobStatusResponse(
        job_id=job_id,
        status=job.status,
        filename=job.safe_name,
        error=job.error,
        progress=job.progress,
        speed_bps=job.speed_bps,
        eta_sec=job.eta_sec,
        download_token=token,
        created_at=job.created_at,
        updated_at=job.updated_at,
        expires_at=job.expires_at,
    )


@app.get("/api/download/file/{job_id}", dependencies=[_auth])
async def get_file(job_id: str, token: str, request: Request):
    verified_job_id = _verify_token(token)
    if verified_job_id != job_id:
        raise api_error(401, ErrorCode.INVALID_TOKEN, "Token/job mismatch")

    async with _job_store_lock:
        job_obj = _job_store.get(job_id)

    if not job_obj:
        raise api_error(404, ErrorCode.JOB_NOT_FOUND, "Job not found")
    if job_obj.status != JobStatus.DONE:
        raise api_error(400, ErrorCode.JOB_STILL_PROCESSING, "Job still processing")

    filepath = Path(job_obj.filename) if job_obj.filename else None
    if not filepath or not filepath.is_file():
        raise api_error(404, ErrorCode.FILE_MISSING, "File not found on disk")

    file_size = filepath.stat().st_size
    media_type = (
        f"audio/{job_obj.audio_format}"
        if job_obj.is_audio
        else (mimetypes.guess_type(str(filepath))[0] or "video/mp4")
    )

    range_header = request.headers.get("Range")
    start, end = 0, file_size - 1

    if range_header:
        # FIX: Anchored regex to avoid partial matches
        match = re.match(r"^bytes=(\d+)-(\d*)$", range_header)
        if match:
            start = int(match.group(1))
            end = int(match.group(2)) if match.group(2) else file_size - 1
            end = min(end, file_size - 1)
            if start >= file_size or start > end:
                raise HTTPException(status_code=416, detail="Range not satisfiable")

    content_length = end - start + 1
    is_partial = start > 0 or end < file_size - 1

    headers = {
        "Content-Disposition": f'attachment; filename="{job_obj.safe_name}"',
        "Accept-Ranges": "bytes",
        "Content-Length": str(content_length),
    }
    if is_partial:
        headers["Content-Range"] = f"bytes {start}-{end}/{file_size}"

    async with _job_store_lock:
        job_obj.is_streaming = True

    # FIX: BackgroundTask cannot run coroutines directly.
    # We use a sync wrapper that schedules the async cleanup on the event loop.
    def _sync_purge():
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                loop.create_task(_async_purge())
            else:
                loop.run_until_complete(_async_purge())
        except Exception as exc:
            logger.warning(f"Purge scheduling error: {exc}")

    async def _async_purge():
        await asyncio.sleep(config.STREAM_PURGE_DELAY_SEC)
        async with _job_store_lock:
            existing = _job_store.get(job_id)
            if existing:
                existing.is_streaming = False
                _job_store.pop(job_id, None)
        cleanup_path(filepath.parent)

    return StreamingResponse(
        iter_file_range(filepath, start, end),
        status_code=206 if is_partial else 200,
        media_type=media_type,
        headers=headers,
        background=BackgroundTask(_sync_purge),
    )


@app.delete("/api/download/cancel/{job_id}", dependencies=[_auth])
async def cancel_job(job_id: str):
    async with _job_store_lock:
        job = _job_store.get(job_id)
        if not job:
            raise api_error(404, ErrorCode.JOB_NOT_FOUND, "Job not found")
        task = _running_tasks.get(job_id)
        if task and not task.done():
            task.cancel()
        job.status = JobStatus.CANCELLED
        job.updated_at = datetime.now(UTC).isoformat()
        job.expires_at = (datetime.now(UTC) + timedelta(seconds=config.JOB_TTL_SEC)).isoformat()

    cleanup_path(config.DOWNLOAD_DIR / job_id)
    return {"message": f"Job {job_id} cancelled."}


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=config.PORT,
        reload=config.DEBUG,
        workers=1,  # Always 1 — in-memory store breaks with multiple workers
        server_header=False,
        date_header=False,
    )
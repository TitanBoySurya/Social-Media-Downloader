from __future__ import annotations


import asyncio
import hashlib
import hmac
import ipaddress
import json
import logging
import mimetypes
import os
import re
import secrets
import shutil
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

# ═══════════════════════════════════════════════════════════
# CONFIG
# ═══════════════════════════════════════════════════════════

UTC = timezone.utc


def _env_list(key: str, default: str) -> list[str]:
    return [x.strip() for x in os.getenv(key, default).split(",") if x.strip()]


def _env_bool(key: str, default: bool = False) -> bool:
    return os.getenv(key, str(default)).lower() in ("1", "true", "yes")


class Config:
    APP_NAME: str = os.getenv("APP_NAME", "VideoSnap API")
    VERSION: str = "6.3.0"

    PORT: int = int(os.getenv("PORT", "8000"))
    DEBUG: bool = _env_bool("DEBUG")
    WORKERS: int = int(os.getenv("WORKERS", "1"))

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
    MAX_RETRIES: int = int(os.getenv("MAX_RETRIES", "5"))
    SOCKET_TIMEOUT: int = int(os.getenv("SOCKET_TIMEOUT", "30"))
    CONCURRENT_FRAGS: int = int(os.getenv("CONCURRENT_FRAGS", "4"))

    JOB_TTL_SEC: int = int(os.getenv("JOB_TTL_SEC", "600"))
    CLEANUP_INTERVAL: int = int(os.getenv("CLEANUP_INTERVAL", "120"))
    MAX_CONCURRENT_DOWNLOADS: int = int(
        os.getenv("MAX_CONCURRENT_DOWNLOADS", "3")
    )
    DOWNLOAD_TIMEOUT_SEC: int = int(
        os.getenv("DOWNLOAD_TIMEOUT_SEC", "900")
    )

    COOKIES_FILE: str = os.getenv("COOKIES_FILE", "")
    HTTP_PROXY: str = os.getenv("HTTP_PROXY", "")

    WEBHOOK_SECRET: str = os.getenv("WEBHOOK_SECRET", "")
    WEBHOOK_TIMEOUT_SEC: int = int(
        os.getenv("WEBHOOK_TIMEOUT_SEC", "10")
    )

    ALLOWED_PLATFORMS: set[str] = set(_env_list("ALLOWED_PLATFORMS", ""))

    BLOCKED_HOSTS: frozenset[str] = frozenset(
        {
            "localhost",
            "127.0.0.1",
            "0.0.0.0",
            "::1",
            "169.254.169.254",
            "metadata.google.internal",
        }
    )

    CHUNK_SIZE: int = int(os.getenv("CHUNK_SIZE", str(64 * 1024)))


config = Config()
config.DOWNLOAD_DIR.mkdir(parents=True, exist_ok=True)

# ═══════════════════════════════════════════════════════════
# LOGGING
# ═══════════════════════════════════════════════════════════

logging.basicConfig(
    level=logging.DEBUG if config.DEBUG else logging.INFO,
    format='{"ts":"%(asctime)s","lvl":"%(levelname)s","logger":"%(name)s","msg":%(message)r}',
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
logger = logging.getLogger("videosnap")

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


def api_error(
    status: int,
    code: ErrorCode,
    message: str,
    *,
    detail: Any = None,
) -> HTTPException:
    return HTTPException(
        status_code=status,
        detail={
            "error": message,
            "code": code,
            "detail": detail,
        },
    )


# ═══════════════════════════════════════════════════════════
# METRICS
# ═══════════════════════════════════════════════════════════


def _metric(cls, name, doc, labels=None):
    existing = REGISTRY._names_to_collectors.get(name)
    if existing:
        return existing
    return cls(name, doc, labels) if labels else cls(name, doc)


prom_requests = _metric(
    Counter, "vs_requests_total", "Total API requests", ["endpoint"]
)
prom_downloads = _metric(
    Counter, "vs_downloads_total", "Completed downloads", ["type"]
)
prom_errors = _metric(Counter, "vs_errors_total", "Errors", ["code"])
prom_cache_hits = _metric(Counter, "vs_cache_hits_total", "Info cache hits")
prom_active_jobs = _metric(Gauge, "vs_active_jobs", "Active download jobs")
prom_dl_seconds = _metric(
    Histogram, "vs_download_duration_seconds", "Download wall time"
)
prom_dl_bytes = _metric(
    Counter, "vs_download_bytes_total", "Bytes downloaded"
)

# ═══════════════════════════════════════════════════════════
# CACHE & STORAGE
# ═══════════════════════════════════════════════════════════

video_info_cache: TTLCache = TTLCache(
    maxsize=config.CACHE_MAX_SIZE,
    ttl=config.CACHE_TTL,
)
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

    created_at: str = field(
        default_factory=lambda: datetime.now(UTC).isoformat()
    )
    updated_at: str = field(
        default_factory=lambda: datetime.now(UTC).isoformat()
    )
    expires_at: Optional[str] = None

    def to_dict(self) -> dict:
        d = asdict(self)
        d.pop("is_streaming", None)
        return d


_job_store: dict[str, Job] = {}
_job_store_lock = asyncio.Lock()

_download_semaphore: asyncio.Semaphore
_running_tasks: dict[str, asyncio.Task] = {}
_shutdown_event = asyncio.Event()

# ═══════════════════════════════════════════════════════════
# AUTH
# ═══════════════════════════════════════════════════════════

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
limiter = Limiter(key_func=get_remote_address)


async def require_api_key(
    api_key: str = Security(_api_key_header),
) -> None:
    if not config.API_KEY:
        return

    if not api_key or not secrets.compare_digest(api_key, config.API_KEY):
        prom_errors.labels(code=ErrorCode.UNAUTHORIZED).inc()
        raise HTTPException(
            status_code=401,
            detail={
                "error": "Invalid or missing API key",
                "code": ErrorCode.UNAUTHORIZED,
            },
        )


def _make_token(job_id: str) -> str:
    expires = int(time.time()) + config.TOKEN_TTL_SEC
    payload = f"{job_id}.{expires}"
    sig = hmac.new(
        config.TOKEN_SECRET.encode(), payload.encode(), hashlib.sha256
    ).hexdigest()
    return f"{payload}.{sig}"


def _verify_token(token: str) -> str:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError

        job_id, expires_str, sig = parts
        payload = f"{job_id}.{expires_str}"

        expected = hmac.new(
            config.TOKEN_SECRET.encode(), payload.encode(), hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(sig, expected):
            raise api_error(401, ErrorCode.INVALID_TOKEN, "Invalid token")

        if int(time.time()) > int(expires_str):
            raise api_error(401, ErrorCode.TOKEN_EXPIRED, "Token expired")

        return job_id
    except HTTPException:
        raise
    except Exception:
        raise api_error(401, ErrorCode.INVALID_TOKEN, "Malformed token")


# ═══════════════════════════════════════════════════════════
# SECURITY
# ═══════════════════════════════════════════════════════════


def validate_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only HTTP/HTTPS URLs are allowed")

    host = (parsed.hostname or "").lower().rstrip(".")
    if host in config.BLOCKED_HOSTS:
        raise ValueError(f"Blocked host: {host}")

    try:
        addr_info = socket.getaddrinfo(host, None)
        for res in addr_info:
            ip_str = res[4][0]
            ip = ipaddress.ip_address(ip_str)
            if (
                ip.is_private
                or ip.is_loopback
                or ip.is_reserved
                or ip.is_link_local
            ):
                raise ValueError(f"Private/reserved IP blocked: {ip_str}")
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError(f"Host resolution failed: {exc}") from exc

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
    filepath: Path,
    start: int,
    end: int,
    chunk_size: int = config.CHUNK_SIZE,
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
# MODELS
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

    @field_validator("url")
    @classmethod
    def _validate_url(cls, v: str) -> str:
        return validate_url(v)


class DownloadRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    url: str = Field(..., min_length=10, max_length=2048)
    format_id: str = Field(default="", max_length=64)
    is_audio: bool = False
    audio_format: AudioFormat = AudioFormat.mp3
    webhook_url: str = Field(default="", max_length=2048)

    @field_validator("url")
    @classmethod
    def _validate_url(cls, v: str) -> str:
        return validate_url(v)

    @field_validator("webhook_url")
    @classmethod
    def _validate_webhook(cls, v: str) -> str:
        if not v:
            return v
        return validate_url(v)


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
# YT-DLP (ANTI-BOT STRATEGIES IMPLEMENTED)
# ═══════════════════════════════════════════════════════════

QUALITY_ORDER = {
    "8K": 0,
    "4K": 1,
    "2K": 2,
    "1080p": 3,
    "720p": 4,
    "480p": 5,
    "360p": 6,
}

_YDL_COMMON: dict[str, Any] = {
    "quiet": True,
    "no_warnings": True,
    "noplaylist": True,
    "geo_bypass": True,
    "socket_timeout": config.SOCKET_TIMEOUT,
    "retries": config.MAX_RETRIES,
    "restrictfilenames": True,
    "trim_file_name": 200,
    "extractor_args": {
        "youtube": {
            "player_client": ["android", "web"],
            "player_skip": ["configs"],
        }
    },
    "sleep_interval_requests": 1,
    "sleep_interval": 1,
    "max_sleep_interval": 3,
    "http_headers": {
        "User-Agent": "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36"
    },
    **({"cookiefile": config.COOKIES_FILE} if config.COOKIES_FILE else {}),
    **({"proxy": config.HTTP_PROXY} if config.HTTP_PROXY else {}),
}


def _build_download_opts(
    job: Job,
    output_template: str,
) -> dict[str, Any]:
    base: dict[str, Any] = {
        **_YDL_COMMON,
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

    return {
        **base,
        "format": (
            f"{job.format_id}+bestaudio/best"
            if job.format_id
            else "bestvideo+bestaudio/best"
        ),
        "merge_output_format": "mp4",
    }


def _parse_formats(raw_formats: list[dict]) -> list[FormatInfo]:
    out: list[FormatInfo] = []
    for fmt in raw_formats:
        height = fmt.get("height")
        vcodec = fmt.get("vcodec", "none")
        if vcodec == "none" or not height:
            continue

        out.append(
            FormatInfo(
                format_id=fmt.get("format_id", ""),
                quality=f"{height}p",
                ext=fmt.get("ext", "mp4"),
                filesize=fmt.get("filesize"),
                filesize_approx=fmt.get("filesize_approx"),
                is_audio=False,
                resolution=f'{fmt.get("width")}x{height}',
                fps=fmt.get("fps"),
                tbr=fmt.get("tbr"),
                vcodec=vcodec,
                acodec=fmt.get("acodec"),
            )
        )
    out.sort(key=lambda x: QUALITY_ORDER.get(x.quality, 999))
    return out


def fetch_video_info_sync(url: str) -> VideoInfo:
    try:
        with yt_dlp.YoutubeDL({**_YDL_COMMON, "skip_download": True}) as ydl:
            info = ydl.extract_info(url, download=False)
    except Exception as exc:
        raise api_error(
            400, ErrorCode.FETCH_FAILED, f"Could not fetch info: {exc}"
        )

    duration = info.get("duration") or 0
    if duration > config.MAX_DURATION_SEC:
        raise api_error(400, ErrorCode.DURATION_EXCEEDED, "Video too long")

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

        total = (
            d.get("total_bytes") or d.get("total_bytes_estimate") or 0
        )
        downloaded = d.get("downloaded_bytes", 0)
        pct = downloaded / total * 100 if total else 0.0

        speed = d.get("speed")
        eta = d.get("eta")

        async def _update() -> None:
            async with _job_store_lock:
                if job_id not in _job_store:
                    return
                job.progress = round(pct, 1)
                job.speed_bps = speed
                job.eta_sec = eta
                job.updated_at = datetime.now(UTC).isoformat()

        try:
            loop = asyncio.get_running_loop()
            loop.create_task(_update())
        except RuntimeError:
            pass

    try:
        total_b, used_b, free_b = shutil.disk_usage(config.DOWNLOAD_DIR)
        if free_b < (config.MAX_FILESIZE_MB * 1024 * 1024):
            raise OSError("Insufficient system disk space remaining.")

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
                f
                for f in out_dir.iterdir()
                if f.suffix
                in {
                    ".mp4",
                    ".mp3",
                    ".mkv",
                    ".webm",
                    ".m4a",
                    ".opus",
                    ".flac",
                    ".wav",
                }
            ],
            key=lambda f: f.stat().st_mtime,
            reverse=True,
        )

        if not files:
            raise FileNotFoundError("Downloaded file not found")

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
            job.expires_at = (
                datetime.now(UTC) + timedelta(seconds=config.JOB_TTL_SEC)
            ).isoformat()

        prom_downloads.labels(type="audio" if job.is_audio else "video").inc()
        prom_dl_seconds.observe(time.monotonic() - start_time)

    except asyncio.CancelledError:
        async with _job_store_lock:
            if job_id in _job_store:
                job.status = JobStatus.CANCELLED
                job.error = "Job cancelled by request."
        cleanup_path(out_dir)

    except Exception as exc:
        async with _job_store_lock:
            if job_id in _job_store:
                job.status = JobStatus.FAILED
                job.error = str(exc)
        cleanup_path(out_dir)
        prom_errors.labels(code=ErrorCode.INTERNAL_ERROR).inc()

    finally:
        prom_active_jobs.dec()
        _running_tasks.pop(job_id, None)


# ═══════════════════════════════════════════════════════════
# CLEANUP
# ═══════════════════════════════════════════════════════════


async def _cleanup_scheduler():
    while not _shutdown_event.is_set():
        await asyncio.sleep(config.CLEANUP_INTERVAL)
        now = datetime.now(UTC)

        async with _job_store_lock:
            expired = [
                jid
                for jid, job in _job_store.items()
                if job.expires_at
                and datetime.fromisoformat(job.expires_at) < now
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
        logger.warning("Missing ffmpeg binary executable module environment targets.")

    cleanup_task = asyncio.create_task(_cleanup_scheduler())
    yield
    _shutdown_event.set()
    cleanup_task.cancel()

    for task in list(_running_tasks.values()):
        task.cancel()


# ═══════════════════════════════════════════════════════════
# FASTAPI
# ═══════════════════════════════════════════════════════════

app = FastAPI(
    title=config.APP_NAME,
    version=config.VERSION,
    lifespan=lifespan,
)
app.state.limiter = limiter

_has_wildcard = "*" in config.ALLOWED_ORIGINS
app.add_middleware(
    CORSMiddleware,
    allow_origins=config.ALLOWED_ORIGINS,
    allow_credentials=not _has_wildcard,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["X-API-Key", "Content-Type", "Range"],
    expose_headers=[
        "Content-Disposition",
        "Content-Range",
        "Accept-Ranges",
        "X-Request-ID",
    ],
)


@app.middleware("http")
async def request_id_middleware(request: Request, call_next):
    prom_requests.labels(endpoint=request.url.path).inc()
    rid = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    response = await call_next(request)
    response.headers["X-Request-ID"] = rid
    return response


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=429,
        content={
            "error": "Rate limit exceeded",
            "code": ErrorCode.RATE_LIMITED,
        },
    )


_auth = Depends(require_api_key)

# ═══════════════════════════════════════════════════════════
# ROUTES
# ═══════════════════════════════════════════════════════════


@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "version": config.VERSION,
        "timestamp": datetime.now(UTC).isoformat(),
    }


@app.get("/metrics", include_in_schema=False)
async def metrics():
    return StreamingResponse(
        iter([generate_latest()]),
        media_type=CONTENT_TYPE_LATEST,
    )


@app.post(
    "/api/info",
    response_model=VideoInfo,
    dependencies=[_auth],
)
@limiter.limit(config.RATE_LIMIT_INFO)
async def get_info(
    request: Request,
    req: VideoInfoRequest,
    response: Response,
):
    key = url_cache_key(req.url)
    async with cache_lock:
        if key in video_info_cache:
            prom_cache_hits.inc()
            response.headers["X-Cache"] = "HIT"
            return video_info_cache[key]

    try:
        info = await asyncio.wait_for(
            asyncio.to_thread(fetch_video_info_sync, req.url), timeout=15.0
        )
    except asyncio.TimeoutError:
        raise api_error(
            408, ErrorCode.DOWNLOAD_TIMEOUT, "Metadata query timed out."
        )

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
    try:
        clean_url = validate_url(url)
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
            asyncio.to_thread(fetch_video_info_sync, clean_url), timeout=15.0
        )
    except asyncio.TimeoutError:
        raise api_error(
            408, ErrorCode.DOWNLOAD_TIMEOUT, "Metadata query timed out."
        )

    async with cache_lock:
        video_info_cache[key] = info

    response.headers["X-Cache"] = "MISS"
    return info


@app.post(
    "/api/formats",
    response_model=list[FormatInfo],
    dependencies=[_auth],
)
@limiter.limit(config.RATE_LIMIT_INFO)
async def get_formats(
    request: Request,
    req: VideoInfoRequest,
):
    try:
        info = await asyncio.wait_for(
            asyncio.to_thread(fetch_video_info_sync, req.url), timeout=15.0
        )
    except asyncio.TimeoutError:
        raise api_error(
            408, ErrorCode.DOWNLOAD_TIMEOUT, "Metadata query timed out."
        )
    return info.formats


@app.post(
    "/api/download/start",
    response_model=JobResponse,
    status_code=202,
    dependencies=[_auth],
)
@limiter.limit(config.RATE_LIMIT_DOWNLOAD)
async def start_download(
    request: Request,
    req: DownloadRequest,
):
    job_id = str(uuid.uuid4())
    job = Job(
        job_id=job_id,
        url=req.url,
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


@app.get(
    "/api/download/status/{job_id}",
    response_model=JobStatusResponse,
    dependencies=[_auth],
)
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
async def get_file(
    job_id: str,
    token: str,
    request: Request,
):
    verified_job_id = _verify_token(token)
    if verified_job_id != job_id:
        raise api_error(401, ErrorCode.INVALID_TOKEN, "Invalid token")

    async with _job_store_lock:
        job_obj = _job_store.get(job_id)

    if not job_obj:
        raise api_error(404, ErrorCode.JOB_NOT_FOUND, "Job not found")

    if job_obj.status != JobStatus.DONE:
        raise api_error(
            400, ErrorCode.JOB_STILL_PROCESSING, "Job still processing"
        )

    filepath = Path(job_obj.filename) if job_obj.filename else None
    if not filepath or not filepath.is_file():
        raise api_error(404, ErrorCode.FILE_MISSING, "File missing")

    file_size = filepath.stat().st_size
    media_type = (
        f"audio/{job_obj.audio_format}"
        if job_obj.is_audio
        else (mimetypes.guess_type(str(filepath))[0] or "video/mp4")
    )

    range_header = request.headers.get("Range")
    start = 0
    end = file_size - 1

    if range_header:
        match = re.match(r"bytes=(\d+)-(\d*)", range_header)
        if match:
            start = int(match.group(1))
            end = int(match.group(2)) if match.group(2) else file_size - 1
            end = min(end, file_size - 1)

            if start >= file_size or start > end:
                raise HTTPException(status_code=416, detail="Invalid range")

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

    async def purge_after_stream():
        async with _job_store_lock:
            _job_store.pop(job_id, None)
        cleanup_path(filepath.parent)

    return StreamingResponse(
        iter_file_range(filepath, start, end),
        status_code=206 if is_partial else 200,
        media_type=media_type,
        headers=headers,
        background=BackgroundTask(purge_after_stream),
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

    cleanup_path(config.DOWNLOAD_DIR / job_id)
    return {"message": f"Job [{job_id}] cancelled successfully."}


if __name__ == "__main__":
    print("COOKIES FILE:", config.COOKIES_FILE)
    print("FILE EXISTS:", os.path.exists(config.COOKIES_FILE))

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=config.PORT,
        reload=config.DEBUG,
        workers=config.WORKERS if not config.DEBUG else 1,
        server_header=False,
        date_header=False,
    )
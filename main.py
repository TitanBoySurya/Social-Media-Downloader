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
from dataclasses import dataclass, field, asdict
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
    BackgroundTasks,
    Depends,
    FastAPI,
    HTTPException,
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
from pydantic import BaseModel, Field, field_validator, ConfigDict
from sanitize_filename import sanitize
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

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
    VERSION: str = "6.1.0"

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
    MAX_CONCURRENT_DOWNLOADS: int = int(os.getenv("MAX_CONCURRENT_DOWNLOADS", "3"))
    DOWNLOAD_TIMEOUT_SEC: int = int(os.getenv("DOWNLOAD_TIMEOUT_SEC", "900"))

    COOKIES_FILE: str = os.getenv("COOKIES_FILE", "")
    HTTP_PROXY: str = os.getenv("HTTP_PROXY", "")

    WEBHOOK_SECRET: str = os.getenv("WEBHOOK_SECRET", "")
    WEBHOOK_TIMEOUT_SEC: int = int(os.getenv("WEBHOOK_TIMEOUT_SEC", "10"))

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
# STORAGE STORES
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
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    expires_at: Optional[str] = None
    cancel_event: asyncio.Event = field(default_factory=asyncio.Event)
    is_streaming: bool = False

    def to_dict(self) -> dict:
        d = asdict(self)
        d.pop("cancel_event", None)
        d.pop("is_streaming", None)
        return d


_job_store: dict[str, Job] = {}
_job_store_lock = asyncio.Lock()
_download_semaphore: asyncio.Semaphore
_sse_subscribers: dict[str, set[asyncio.Queue]] = {}

# ═══════════════════════════════════════════════════════════
# SECURITY AUDIT PROTOCOLS
# ═══════════════════════════════════════════════════════════

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def require_api_key(api_key: str = Security(_api_key_header)) -> None:
    if not config.API_KEY:
        return
    if not api_key or not secrets.compare_digest(api_key, config.API_KEY):
        prom_errors.labels(code=ErrorCode.UNAUTHORIZED).inc()
        raise HTTPException(
            status_code=401, 
            detail={"error": "Invalid or missing API key", "code": ErrorCode.UNAUTHORIZED}
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
            raise ValueError
        job_id, expires_str, sig = parts
        payload = f"{job_id}.{expires_str}"
        expected = hmac.new(config.TOKEN_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            raise api_error(401, ErrorCode.INVALID_TOKEN, "Invalid download token")
        if int(time.time()) > int(expires_str):
            raise api_error(401, ErrorCode.TOKEN_EXPIRED, "Download token expired")
        return job_id
    except HTTPException:
        raise
    except Exception:
        raise api_error(401, ErrorCode.INVALID_TOKEN, "Malformed download token")


limiter = Limiter(key_func=get_remote_address)


def validate_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only HTTP/HTTPS URLs are allowed")

    host = (parsed.hostname or "").lower().rstrip(".")
    if host in config.BLOCKED_HOSTS:
        raise ValueError(f"Blocked host: {host}")

    try:
        # IPv4 aur IPv6 dono checked records compile karne ke liye getaddrinfo use kiya hai
        addr_info = socket.getaddrinfo(host, None)
        for res in addr_info:
            ip_str = res[4][0]
            ip = ipaddress.ip_address(ip_str)
            if ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local:
                raise ValueError(f"Private or reserved IP blocked: {ip_str}")
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError(f"Host resolution failed: {exc}") from exc

    return url


def url_cache_key(url: str) -> str:
    return hashlib.sha256(url.strip().lower().encode()).hexdigest()

# ═══════════════════════════════════════════════════════════
# FILE MANAGER ENGINE
# ═══════════════════════════════════════════════════════════


def cleanup_path(path: str | Path) -> None:
    try:
        p = Path(path)
        if p.is_dir():
            shutil.rmtree(p)
        elif p.is_file():
            p.unlink()
    except Exception as exc:
        logger.warning(f"Cleanup failed for {path}: {exc}")


async def iter_file_range(filepath: Path, start: int, end: int, chunk_size: int = config.CHUNK_SIZE) -> AsyncGenerator[bytes, None]:
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
# MODEL PARAMETERS
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
        try:
            return validate_url(v)
        except ValueError as exc:
            raise ValueError(str(exc)) from exc


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
        try:
            return validate_url(v)
        except ValueError as exc:
            raise ValueError(str(exc)) from exc

    @field_validator("webhook_url")
    @classmethod
    def _validate_webhook(cls, v: str) -> str:
        if not v:
            return v
        try:
            return validate_url(v)
        except ValueError as exc:
            raise ValueError(f"Invalid webhook_url: {exc}") from exc


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
    duration: int
    uploader: str
    platform: str
    formats: list[FormatInfo]
    webpage_url: str
    age_limit: int = 0
    upload_date: Optional[str] = None
    view_count: Optional[int] = None
    like_count: Optional[int] = None
    description: Optional[str] = None


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
# YT-DLP EXTRACTION TOOLS
# ═══════════════════════════════════════════════════════════

QUALITY_ORDER = {"8K": 0, "4K": 1, "2K": 2, "1080p": 3, "720p": 4, "480p": 5, "360p": 6}

_YDL_COMMON: dict[str, Any] = {
    "quiet": True,
    "no_warnings": True,
    "noplaylist": True,
    "geo_bypass": True,
    "socket_timeout": config.SOCKET_TIMEOUT,
    "retries": config.MAX_RETRIES,
    "restrictfilenames": True,
    "trim_file_name": 200,
    "http_headers": {"User-Agent": "Mozilla/5.0 (compatible; VideoSnap/6.0)"},
    **({"cookiefile": config.COOKIES_FILE} if config.COOKIES_FILE else {}),
    **({"proxy": config.HTTP_PROXY} if config.HTTP_PROXY else {}),
}


def _build_download_opts(job: Job, output_template: str) -> dict[str, Any]:
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
        "format": f"{job.format_id}+bestaudio/best" if job.format_id else "bestvideo+bestaudio/best",
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
        raise api_error(400, ErrorCode.FETCH_FAILED, f"Could not fetch video info: {exc}")

    extractor = info.get("extractor_key", info.get("extractor", "")).lower()
    if config.ALLOWED_PLATFORMS and extractor not in config.ALLOWED_PLATFORMS:
        raise api_error(403, ErrorCode.UNSUPPORTED_PLATFORM, f"Platform '{extractor}' is not allowed")

    duration = info.get("duration") or 0
    if duration > config.MAX_DURATION_SEC:
        raise api_error(400, ErrorCode.DURATION_EXCEEDED, "Video exceeds maximum allowed duration")

    return VideoInfo(
        title=info.get("title", "Unknown"),
        thumbnail=info.get("thumbnail", ""),
        duration=duration,
        uploader=info.get("uploader", "Unknown"),
        platform=info.get("extractor_key", info.get("extractor", "Web")),
        formats=_parse_formats(info.get("formats", []),),
        webpage_url=url,
        age_limit=info.get("age_limit", 0),
        upload_date=info.get("upload_date"),
        view_count=info.get("view_count"),
        like_count=info.get("like_count"),
        description=(info.get("description") or "")[:500] or None,
    )


async def _fire_webhook(job: Job) -> None:
    if not job.webhook_url:
        return
    payload = {
        "job_id": job.job_id,
        "status": job.status,
        "filename": job.safe_name,
        "error": job.error,
        "timestamp": datetime.now(UTC).isoformat(),
    }
    headers: dict[str, str] = {"Content-Type": "application/json"}
    if config.WEBHOOK_SECRET:
        sig = hmac.new(config.WEBHOOK_SECRET.encode(), json.dumps(payload, sort_keys=True).encode(), hashlib.sha256).hexdigest()
        headers["X-VideoSnap-Signature"] = f"sha256={sig}"
    try:
        async with httpx.AsyncClient(timeout=config.WEBHOOK_TIMEOUT_SEC) as client:
            await client.post(job.webhook_url, json=payload, headers=headers)
    except Exception as exc:
        logger.warning(f"Webhook delivery failed for job {job.job_id}: {exc}")


async def _push_progress(job_id: str, data: dict) -> None:
    subs = _sse_subscribers.get(job_id, set())
    for q in list(subs):
        try:
            q.put_nowait(data)
        except asyncio.QueueFull:
            pass


# ═══════════════════════════════════════════════════════════
# ENGINE CORE RUNTIME PIPELINES
# ═══════════════════════════════════════════════════════════

_shutdown_event = asyncio.Event()


async def run_download_job(job_id: str) -> None:
    async with _job_store_lock:
        job = _job_store.get(job_id)
        if not job or job.status == JobStatus.CANCELLED:
            return
        job.status = JobStatus.PROCESSING
        job.updated_at = datetime.now(UTC).isoformat()

    prom_active_jobs.inc()
    out_dir = config.DOWNLOAD_DIR / job_id
    out_dir.mkdir(parents=True, exist_ok=True)
    start_time = time.monotonic()

    def _progress_hook(d: dict) -> None:
        # True cancellation hook injected safely into execution fragments
        if job.cancel_event.is_set():
            raise yt_dlp.utils.DownloadError("Job force-killed via explicit user cancellation stream.")

        if d.get("status") == "downloading":
            total = d.get("total_bytes") or d.get("total_bytes_estimate") or 0
            downloaded = d.get("downloaded_bytes", 0)
            pct = (downloaded / total * 100) if total else 0.0
            speed = d.get("speed")
            eta = d.get("eta")

            async def _update() -> None:
                async with _job_store_lock:
                    if job.status == JobStatus.CANCELLED:
                        return
                    job.progress = round(pct, 1)
                    job.speed_bps = speed
                    job.eta_sec = eta
                    job.updated_at = datetime.now(UTC).isoformat()
                await _push_progress(job_id, {"progress": job.progress, "speed_bps": speed, "eta_sec": eta, "status": "processing"})

            try:
                loop = asyncio.get_event_loop()
                loop.call_soon_threadsafe(lambda: asyncio.ensure_future(_update()))
            except Exception:
                pass

    try:
        # Disk protection validation checkpoint
        total_b, used_b, free_b = shutil.disk_usage(config.DOWNLOAD_DIR)
        if free_b < (config.MAX_FILESIZE_MB * 1024 * 1024):
            raise OSError("Insufficient system disk space remaining.")

        opts = _build_download_opts(job, str(out_dir / "%(title)s.%(ext)s"))
        opts["progress_hooks"] = [_progress_hook]

        def _blocking_download() -> None:
            with yt_dlp.YoutubeDL(opts) as ydl:
                ydl.extract_info(job.url, download=True)

        async with _download_semaphore:
            if _shutdown_event.is_set() or job.cancel_event.is_set():
                raise asyncio.CancelledError("Download sequence broken via system cancellation.")
            await asyncio.wait_for(asyncio.to_thread(_blocking_download), timeout=config.DOWNLOAD_TIMEOUT_SEC)

        if job.cancel_event.is_set():
            raise asyncio.CancelledError("Download sequence broken via system cancellation.")

        files = sorted(
            [f for f in out_dir.iterdir() if f.suffix in {".mp4", ".mp3", ".mkv", ".webm", ".m4a", ".opus", ".flac", ".wav"}],
            key=lambda f: f.stat().st_mtime,
            reverse=True,
        )
        if not files:
            raise FileNotFoundError("Downloaded file not found")

        chosen = files[0]
        file_size = chosen.stat().st_size
        prom_dl_bytes.inc(file_size)

        async with _job_store_lock:
            if job_id in _job_store and job.status != JobStatus.CANCELLED:
                job.status = JobStatus.DONE
                job.filename = str(chosen)
                job.safe_name = sanitize(chosen.name)
                job.progress = 100.0
                job.updated_at = datetime.now(UTC).isoformat()
                job.expires_at = (datetime.now(UTC) + timedelta(seconds=config.JOB_TTL_SEC)).isoformat()

        prom_downloads.labels(type="audio" if job.is_audio else "video").inc()
        prom_dl_seconds.observe(time.monotonic() - start_time)
        await _push_progress(job_id, {"status": "done", "progress": 100.0})
        await _fire_webhook(job)

    except (asyncio.CancelledError, yt_dlp.utils.DownloadError):
        async with _job_store_lock:
            if job_id in _job_store:
                job.status = JobStatus.CANCELLED
                job.error = "Job cancelled by request."
                job.updated_at = datetime.now(UTC).isoformat()
        cleanup_path(out_dir)
    except Exception as exc:
        async with _job_store_lock:
            if job_id in _job_store and job.status != JobStatus.CANCELLED:
                job.status = JobStatus.FAILED
                job.error = str(exc)
                job.updated_at = datetime.now(UTC).isoformat()
        cleanup_path(out_dir)
        await _fire_webhook(job)
        prom_errors.labels(code=ErrorCode.INTERNAL_ERROR).inc()
    finally:
        prom_active_jobs.dec()
        await _push_progress(job_id, {"status": job.status, "done": True})
        _sse_subscribers.pop(job_id, None)


async def _cleanup_scheduler() -> None:
    while not _shutdown_event.is_set():
        await asyncio.sleep(config.CLEANUP_INTERVAL)
        now = datetime.now(UTC)
        async with _job_store_lock:
            expired = [jid for jid, job in _job_store.items() if job.expires_at and datetime.fromisoformat(job.expires_at) < now]
            for jid in expired:
                job = _job_store.get(jid)
                if job and not job.is_streaming:
                    _job_store.pop(jid, None)
                    if job.filename:
                        cleanup_path(Path(job.filename).parent)
        if expired:
            logger.info(f"Cleaned up {len(expired)} expired execution context paths.")


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _download_semaphore
    _download_semaphore = asyncio.Semaphore(config.MAX_CONCURRENT_DOWNLOADS)
    
    if not shutil.which("ffmpeg"):
        logger.warning("[self-test] Missing ffmpeg binary executable module environment targets.")
    
    cleanup_task = asyncio.create_task(_cleanup_scheduler())
    yield
    _shutdown_event.set()
    cleanup_task.cancel()
    logger.info("Core engine interface shutdown routine execution finalized successfully.")


# ═══════════════════════════════════════════════════════════
# FASTAPI APPLICATION DEPLOYMENT INTERFACE
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
async def _request_id_middleware(request: Request, call_next):
    rid = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    response = await call_next(request)
    response.headers["X-Request-ID"] = rid
    return response


@app.exception_handler(RateLimitExceeded)
async def _rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(status_code=429, content={"error": "Rate limit exceeded", "code": ErrorCode.RATE_LIMITED})


_auth = Depends(require_api_key)

# ── ROUTES INTERFACE CONTROL PANELS ─────────────────────────

@app.get("/health", tags=["system"])
async def health():
    return {"status": "healthy", "version": config.VERSION, "timestamp": datetime.now(UTC).isoformat()}


@app.get("/metrics", tags=["system"], include_in_schema=False)
async def metrics():
    return StreamingResponse(iter([generate_latest()]), media_type=CONTENT_TYPE_LATEST)


@app.post("/api/info", tags=["info"], response_model=VideoInfo, dependencies=[_auth])
@limiter.limit(config.RATE_LIMIT_INFO)
async def get_info(request: Request, req: VideoInfoRequest, response: Response):
    key = url_cache_key(req.url)
    async with cache_lock:
        if key in video_info_cache:
            prom_cache_hits.inc()
            response.headers["X-Cache"] = "HIT"
            return video_info_cache[key]

    try:
        info = await asyncio.wait_for(
            asyncio.to_thread(fetch_video_info_sync, req.url),
            timeout=15.0
        )
    except asyncio.TimeoutError:
        raise api_error(408, ErrorCode.DOWNLOAD_TIMEOUT, "Metadata extraction query timed out.")

    async with cache_lock:
        video_info_cache[key] = info
    response.headers["X-Cache"] = "MISS"
    return info


@app.post("/api/formats", tags=["info"], response_model=list[FormatInfo], dependencies=[_auth])
@limiter.limit(config.RATE_LIMIT_INFO)
async def get_formats(request: Request, req: VideoInfoRequest):
    try:
        info = await asyncio.wait_for(
            asyncio.to_thread(fetch_video_info_sync, req.url),
            timeout=15.0
        )
    except asyncio.TimeoutError:
        raise api_error(408, ErrorCode.DOWNLOAD_TIMEOUT, "Metadata extraction query timed out.")
    return info.formats


@app.post("/api/download/start", tags=["download"], response_model=JobResponse, status_code=202, dependencies=[_auth])
@limiter.limit(config.RATE_LIMIT_DOWNLOAD)
async def start_download(request: Request, req: DownloadRequest, background_tasks: BackgroundTasks):
    job_id = str(uuid.uuid4())
    job = Job(job_id=job_id, url=req.url, is_audio=req.is_audio, format_id=req.format_id, audio_format=req.audio_format, webhook_url=req.webhook_url)
    
    async with _job_store_lock:
        _job_store[job_id] = job
        
    background_tasks.add_task(run_download_job, job_id)
    return JobResponse(job_id=job_id, status=JobStatus.PENDING, message="Job enqueued", poll_url=f"/api/download/status/{job_id}")


@app.get("/api/download/status/{job_id}", tags=["download"], response_model=JobStatusResponse, dependencies=[_auth])
async def download_status(job_id: str):
    async with _job_store_lock:
        job = _job_store.get(job_id)
    if not job:
        raise api_error(404, ErrorCode.JOB_NOT_FOUND, "Job not found")
    token = _make_token(job_id) if job.status == JobStatus.DONE else None
    return JobStatusResponse(
        job_id=job_id, status=job.status, filename=job.safe_name, error=job.error, progress=job.progress,
        speed_bps=job.speed_bps, eta_sec=job.eta_sec, download_token=token, created_at=job.created_at, updated_at=job.updated_at, expires_at=job.expires_at
    )


@app.get("/api/download/progress/{job_id}", tags=["download"], dependencies=[_auth])
async def download_progress_sse(job_id: str, request: Request):
    async with _job_store_lock:
        if job_id not in _job_store:
            raise api_error(404, ErrorCode.JOB_NOT_FOUND, "Job not found")

    q: asyncio.Queue = asyncio.Queue(maxsize=64)
    _sse_subscribers.setdefault(job_id, set()).add(q)

    async def _event_stream() -> AsyncGenerator[bytes, None]:
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    data = await asyncio.wait_for(q.get(), timeout=30)
                except asyncio.TimeoutError:
                    yield b": keepalive\n\n"
                    continue
                yield f"data: {json.dumps(data)}\n\n".encode()
                if data.get("done") or data.get("status") in ("done", "failed", "cancelled"):
                    break
        finally:
            async with _job_store_lock:
                if job_id in _sse_subscribers:
                    _sse_subscribers[job_id].discard(q)
                    if not _sse_subscribers[job_id]:
                        _sse_subscribers.pop(job_id, None)

    return StreamingResponse(
        _event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/api/download/file/{job_id}", tags=["download"], dependencies=[_auth])
async def get_file(job_id: str, token: str, request: Request):
    verified_job_id = _verify_token(token)
    if verified_job_id != job_id:
        raise api_error(401, ErrorCode.INVALID_TOKEN, "Token signature mismatch.")

    async with _job_store_lock:
        job_obj = _job_store.get(job_id)

    if not job_obj:
        raise api_error(404, ErrorCode.JOB_NOT_FOUND, "Resource tracking context missing.")
    if job_obj.status != JobStatus.DONE:
        raise api_error(400, ErrorCode.JOB_STILL_PROCESSING, "Data chunk formatting incomplete.")

    filepath = Path(job_obj.filename) if job_obj.filename else None
    if not filepath or not filepath.is_file():
        raise api_error(404, ErrorCode.FILE_MISSING, "Downloaded file not found")

    file_size = filepath.stat().st_size
    media_type = f"audio/{job_obj.audio_format}" if job_obj.is_audio else mimetypes.guess_type(str(filepath))[0] or "video/mp4"

    range_header = request.headers.get("Range")
    start, end = 0, file_size - 1
    if range_header:
        match = re.match(r"bytes=(\d+)-(\d*)", range_header)
        if match:
            start = int(match.group(1))
            end = int(match.group(2)) if match.group(2) else file_size - 1
            end = min(end, file_size - 1)

    content_length = end - start + 1
    is_partial = start > 0 or end < file_size - 1

    headers = {
        "Content-Disposition": f'attachment; filename="{job_obj.safe_name}"',
        "Accept-Ranges": "bytes",
        "Content-Length": str(content_length),
        "Content-Range": f"bytes {start}-{end}/{file_size}" if is_partial else f"bytes 0-{end}/{file_size}",
    }

    async with _job_store_lock:
        job_obj.is_streaming = True

    async def purge_resource_after_streaming():
        async with _job_store_lock:
            _job_store.pop(job_id, None)
        cleanup_path(filepath.parent)

    bg = BackgroundTasks()
    bg.add_task(purge_resource_after_streaming)

    return StreamingResponse(
        iter_file_range(filepath, start, end),
        status_code=206 if is_partial else 200,
        media_type=media_type,
        headers=headers,
        background=bg
    )


@app.delete("/api/download/cancel/{job_id}", tags=["download"], dependencies=[_auth])
async def cancel_job(job_id: str):
    async with _job_store_lock:
        job = _job_store.get(job_id)
        if not job:
            raise api_error(404, ErrorCode.JOB_NOT_FOUND, "Job missing.")
        
        job.cancel_event.set()
        job.status = JobStatus.CANCELLED
        
    cleanup_path(config.DOWNLOAD_DIR / job_id)
    async with _job_store_lock:
        _job_store.pop(job_id, None)
    return {"message": f"Job [{job_id}] cancelled correctly."}


if __name__ == "__main__":
    uvicorn.run(
        "main:app", 
        host="0.0.0.0", 
        port=config.PORT, 
        reload=config.DEBUG, 
        workers=config.WORKERS
    )
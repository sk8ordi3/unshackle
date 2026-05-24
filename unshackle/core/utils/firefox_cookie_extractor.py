"""
Firefox Cookie and LocalStorage Extractor Utility for unshackle.
Provides a read-only mechanism to extract authentication tokens from Firefox.
"""

import sqlite3
import platform
import os
import time
import shutil
from pathlib import Path
from tempfile import gettempdir
from http.cookiejar import CookieJar, Cookie
from typing import Dict, Optional, List


def get_firefox_root() -> Path:
    """Locates the operating system specific root directory for Firefox profiles."""
    system = platform.system()
    home = Path.home()
    
    if system == 'Windows':
        return Path(os.getenv('APPDATA', '')) / 'Mozilla' / 'Firefox'
    elif system == 'Darwin':
        return home / 'Library' / 'Application Support' / 'Firefox'
    elif system == 'Linux':
        paths = [
            home / '.mozilla' / 'firefox',
            home / 'snap' / 'firefox' / 'common' / '.mozilla' / 'firefox',
            home / '.var' / 'app' / 'org.mozilla.firefox' / '.mozilla' / 'firefox'
        ]
        for p in paths:
            if p.exists():
                return p
        return paths[0]
    else:
        raise RuntimeError(f"Unsupported operating system discovered: {system}")


def get_latest_profile_path(firefox_root: Path) -> Path:
    """Finds the most recently modified valid Firefox profile subdirectory."""
    search_dirs = [firefox_root / 'Profiles', firefox_root]
    valid_profiles = []
    
    for base_dir in search_dirs:
        if base_dir.exists():
            for p in base_dir.iterdir():
                if p.is_dir() and (p / 'cookies.sqlite').exists():
                    valid_profiles.append(p)
    
    if not valid_profiles:
        raise FileNotFoundError(f"No active Firefox profiles detected at: {firefox_root}")

    return max(valid_profiles, key=lambda p: (p / 'cookies.sqlite').stat().st_mtime)


def get_local_storage_data(profile_path: Path, hosts: List[str]) -> Dict[str, str]:
    """
    Safely extracts key-value tokens from Firefox LocalStorage (webappsstore.sqlite).
    """
    ls_db = profile_path / 'webappsstore.sqlite'
    if not ls_db.exists():
        return {}
        
    temp_db = Path(gettempdir()) / f"unshackle_ls_{int(time.time())}.sqlite"
    extracted_storage = {}
    
    try:
        shutil.copy2(ls_db, temp_db)
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()
        
        for host in hosts:
            reversed_host = host[::-1]
            query = "SELECT key, value FROM webappsstore2 WHERE originKey LIKE ? OR originKey LIKE ?"
            cursor.execute(query, (f'%{host}%', f'%{reversed_host}%'))
            
            for key, value in cursor.fetchall():
                extracted_storage[key] = value
                
        conn.close()
    except Exception:
        pass
    finally:
        if temp_db.exists():
            os.remove(temp_db)
            
    return extracted_storage


def get_firefox_cookies(service_settings: dict) -> Optional[CookieJar]:
    """
    Extracts cookies and localstorage from Firefox based on provided host patterns.
    Returns a standard CookieJar.
    """
    priority_hosts = service_settings.get('hosts', [])
    include_filter = service_settings.get('include', [])

    try:
        firefox_root = get_firefox_root()
        profile_path = get_latest_profile_path(firefox_root)
    except Exception:
        return None
    
    temp_db = Path(gettempdir()) / f"unshackle_cookies_{int(time.time())}.sqlite"
    cookie_jar = CookieJar()
    
    try:
        shutil.copy2(profile_path / 'cookies.sqlite', temp_db)
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()

        host_patterns = [f"%{h}%" for h in priority_hosts]
        if not host_patterns:
            return None

        query = "SELECT host, name, value, path, expiry FROM moz_cookies WHERE " + " OR ".join(["host LIKE ?"] * len(host_patterns))
        cursor.execute(query, host_patterns)
        rows = cursor.fetchall()

        for host, name, value, path, expiry in rows:
            if include_filter and name not in include_filter:
                continue
                
            c = Cookie(
                version=0, name=name, value=value,
                port=None, port_specified=False,
                domain=host, domain_specified=True, domain_initial_dot=host.startswith('.'),
                path=path, path_specified=True,
                secure=False, expires=expiry, discard=False, comment=None, comment_url=None, rest={'HttpOnly': None}, rfc2109=False
            )
            cookie_jar.set_cookie(c)
            
        conn.close()
    except Exception:
        return None
    finally:
        if temp_db.exists():
            os.remove(temp_db)

    # Supplement with LocalStorage data
    storage_data = get_local_storage_data(profile_path, priority_hosts)
    for key, val in storage_data.items():
        if include_filter and key not in include_filter:
            continue
            
        c = Cookie(
            version=0, name=key, value=val,
            port=None, port_specified=False,
            domain=".localstorage", domain_specified=True, domain_initial_dot=False,
            path='/', path_specified=True,
            secure=False, expires=None, discard=True, comment=None, comment_url=None, rest={}, rfc2109=False
        )
        cookie_jar.set_cookie(c)

    return cookie_jar if len(list(cookie_jar)) > 0 else None
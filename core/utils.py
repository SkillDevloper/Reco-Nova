"""
Stealth & WAF Resilience Module for Reco-Nova.

Provides global header rotation and User-Agent randomization
to minimize detection and bypass WAF restrictions.

Developer: Daniyal Shahid | v1.2
"""

import random
from typing import Dict, Any, Optional


# Modern User-Agent rotation pool (10+ UAs across Chrome, Firefox, Safari)
USER_AGENTS = [
    # Chrome on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    
    # Chrome on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    
    # Chrome on Linux
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    
    # Firefox on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/120.0",
    
    # Firefox on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/120.0",
    
    # Firefox on Linux
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/120.0",
    
    # Safari on macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    
    # Edge on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    
    # Opera on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 OPR/105.0.0.0",
]

# Fake Referer pool - common legitimate referers
REFERERS = [
    "https://www.google.com/",
    "https://www.bing.com/",
    "https://duckduckgo.com/",
    "https://search.yahoo.com/",
    "https://www.reddit.com/",
    "https://www.facebook.com/",
    "https://twitter.com/",
    "https://www.linkedin.com/",
    "https://github.com/",
    "https://stackoverflow.com/",
    "https://www.wikipedia.org/",
    "https://www.quora.com/",
    "https://news.ycombinator.com/",
    "https://www.producthunt.com/",
]

# Accept headers by browser type
ACCEPT_HEADERS = {
    "chrome": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
    "firefox": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "safari": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "edge": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
    "default": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

# Accept-Language headers
ACCEPT_LANGUAGES = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9",
    "en-US,en-GB;q=0.9,en;q=0.8",
    "en-US,en;q=0.9,fr;q=0.8",
    "en;q=0.9",
]

# Accept-Encoding headers
ACCEPT_ENCODINGS = [
    "gzip, deflate, br",
    "gzip, deflate",
    "gzip",
]


def get_random_ua() -> str:
    """
    Get a random User-Agent from the rotation pool.
    
    Returns:
        A randomly selected modern User-Agent string
    """
    return random.choice(USER_AGENTS)


def get_random_referer() -> str:
    """
    Get a random fake Referer header.
    
    Returns:
        A randomly selected legitimate-looking Referer URL
    """
    return random.choice(REFERERS)


def detect_browser_type(ua: str) -> str:
    """
    Detect browser type from User-Agent string.
    
    Args:
        ua: User-Agent string
        
    Returns:
        Browser type identifier (chrome, firefox, safari, edge, etc.)
    """
    ua_lower = ua.lower()
    if "chrome" in ua_lower and "edg" not in ua_lower:
        return "chrome"
    elif "firefox" in ua_lower:
        return "firefox"
    elif "safari" in ua_lower and "chrome" not in ua_lower:
        return "safari"
    elif "edg" in ua_lower:
        return "edge"
    return "default"


def get_stealth_headers(
    custom_headers: Optional[Dict[str, str]] = None,
    include_referer: bool = True,
    include_accept: bool = True
) -> Dict[str, str]:
    """
    Generate stealth headers with randomized User-Agent and optional Referer.
    
    Args:
        custom_headers: Optional custom headers to include/override
        include_referer: Whether to include a fake Referer header
        include_accept: Whether to include Accept headers
        
    Returns:
        Dictionary of HTTP headers for stealth requests
    """
    # Get random User-Agent
    ua = get_random_ua()
    browser_type = detect_browser_type(ua)
    
    # Base headers
    headers = {
        "User-Agent": ua,
        "Accept": ACCEPT_HEADERS.get(browser_type, ACCEPT_HEADERS["default"]),
        "Accept-Language": random.choice(ACCEPT_LANGUAGES),
        "Accept-Encoding": random.choice(ACCEPT_ENCODINGS),
        "DNT": "1",  # Do Not Track
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none" if not include_referer else "cross-site",
        "Sec-Fetch-User": "?1",
        "Cache-Control": random.choice(["max-age=0", "no-cache", "no-store"]),
    }
    
    # Add fake Referer for some requests (not all, to appear more natural)
    if include_referer and random.random() > 0.3:  # 70% chance to include referer
        headers["Referer"] = get_random_referer()
    
    # Add custom headers (override defaults if provided)
    if custom_headers:
        headers.update(custom_headers)
    
    return headers


def get_api_headers(
    custom_headers: Optional[Dict[str, str]] = None
) -> Dict[str, str]:
    """
    Generate headers optimized for API requests (JSON, etc.).
    
    Args:
        custom_headers: Optional custom headers to include/override
        
    Returns:
        Dictionary of HTTP headers for API requests
    """
    headers = {
        "User-Agent": get_random_ua(),
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": random.choice(ACCEPT_LANGUAGES),
        "Accept-Encoding": random.choice(ACCEPT_ENCODINGS),
        "Content-Type": "application/json",
        "X-Requested-With": "XMLHttpRequest",
        "Connection": "keep-alive",
    }
    
    if custom_headers:
        headers.update(custom_headers)
    
    return headers


def get_mobile_headers(
    custom_headers: Optional[Dict[str, str]] = None
) -> Dict[str, str]:
    """
    Generate headers that appear to be from a mobile device.
    
    Args:
        custom_headers: Optional custom headers to include/override
        
    Returns:
        Dictionary of HTTP headers mimicking mobile browser
    """
    # Mobile User-Agents
    mobile_uas = [
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36",
    ]
    
    headers = {
        "User-Agent": random.choice(mobile_uas),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": random.choice(ACCEPT_LANGUAGES),
        "Accept-Encoding": random.choice(ACCEPT_ENCODINGS),
        "DNT": "1",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
    }
    
    if custom_headers:
        headers.update(custom_headers)
    
    return headers


def rotate_session_headers() -> Dict[str, str]:
    """
    Get completely fresh set of randomized headers for a new session.
    Useful when starting a new scanning session to avoid pattern detection.
    
    Returns:
        Dictionary of randomized HTTP headers
    """
    return get_stealth_headers(
        include_referer=random.choice([True, False]),
        include_accept=True
    )


# Convenience function for backwards compatibility
def get_headers() -> Dict[str, str]:
    """
    Simple wrapper to get stealth headers (backward compatible).
    
    Returns:
        Dictionary of stealth HTTP headers
    """
    return get_stealth_headers()

#!/usr/bin/env python3
"""
geoip.py -- offline, dependency-free geolocation for the live request path.

Before v1.4.0 the running app always sent geo_lat / geo_lon = 0.0, so the two
geographic features were dead weight in production (the offline evaluation faked
them). This module turns a country code (and, where possible, an IP address) into
real coordinates using a small built-in table of country centroids -- no network
call, no external database, no extra dependency.

It is deliberately pluggable: `resolve()` is the one function the app calls, and
a future MaxMind / GeoLite2 lookup can slot in behind it without touching app.py.

Country codes are ISO 3166-1 alpha-2. Coordinates are the approximate geographic
centre of the country (enough to make "impossible travel" between countries show
a large distance; not meant for city-level precision).
"""
import ipaddress

# Approximate country centroids (lat, lon). Covers the countries used across the
# demo and synthetic data plus common ones; unknown codes fall back to (0.0, 0.0).
COUNTRY_CENTROIDS = {
    "IE": (53.41, -8.24),   "GB": (54.00, -2.00),   "US": (39.83, -98.58),
    "CA": (56.13, -106.35), "DE": (51.17, 10.45),   "FR": (46.23, 2.21),
    "ES": (40.46, -3.75),   "IT": (41.87, 12.57),   "NL": (52.13, 5.29),
    "SE": (60.13, 18.64),   "NO": (60.47, 8.47),    "PL": (51.92, 19.15),
    "RU": (61.52, 105.32),  "CN": (35.86, 104.20),  "IN": (20.59, 78.96),
    "JP": (36.20, 138.25),  "KR": (35.91, 127.77),  "BR": (-14.24, -51.93),
    "AU": (-25.27, 133.78), "ZA": (-30.56, 22.94),  "NG": (9.08, 8.68),
    "AE": (23.42, 53.85),   "SG": (1.35, 103.82),   "MX": (23.63, -102.55),
    "AR": (-38.42, -63.62), "UA": (48.38, 31.17),   "TR": (38.96, 35.24),
}

# RFC 1918 / loopback ranges -> treated as "local" (the host's own country).
_PRIVATE_NETS = [ipaddress.ip_network(c) for c in
                 ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8")]

DEFAULT_COUNTRY = "IE"   # where the service itself runs (used for private/loopback IPs)


def country_centroid(country_code):
    """Return (lat, lon) for an ISO country code, or (0.0, 0.0) if unknown."""
    if not country_code:
        return (0.0, 0.0)
    return COUNTRY_CENTROIDS.get(country_code.strip().upper(), (0.0, 0.0))


def _is_private(ip):
    """True if the IP is loopback or in a private (RFC 1918) range."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _PRIVATE_NETS)


def resolve(ip=None, country_hint=None):
    """Resolve a request's geolocation.

    Preference order:
      1. An explicit country hint (e.g. the X-Geo-Country header, or a real
         GeoIP lookup wired in here later) -> that country's centroid.
      2. A private / loopback IP -> DEFAULT_COUNTRY (the service's own location).
      3. Otherwise unknown -> country "" and (0.0, 0.0).

    Returns {'country': <code>, 'lat': <float>, 'lon': <float>}.
    """
    if country_hint:
        code = country_hint.strip().upper()
        lat, lon = country_centroid(code)
        return {"country": code, "lat": lat, "lon": lon}

    if ip and _is_private(ip):
        lat, lon = country_centroid(DEFAULT_COUNTRY)
        return {"country": DEFAULT_COUNTRY, "lat": lat, "lon": lon}

    return {"country": "", "lat": 0.0, "lon": 0.0}


if __name__ == "__main__":
    # Tiny self-check.
    for ip, hint in [(None, "RU"), (None, "ie"), ("127.0.0.1", None),
                     ("8.8.8.8", None), ("10.1.2.3", None)]:
        print(f"ip={ip!s:14} hint={hint!s:4} -> {resolve(ip, hint)}")

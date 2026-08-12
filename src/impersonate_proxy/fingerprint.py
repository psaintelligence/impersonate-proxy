"""Realistic browser client-hint header fingerprints.

The curl_cffi impersonation profiles scrub the User-Agent build number
(e.g. ``Chrome/150.0.0.0``) and omit the full Sec-CH-UA family that a genuine
browser sends over HTTPS. This module supplies platform-coherent header sets
that the proxy injects on top of curl_cffi's TLS impersonation so the resulting
request looks like a real browser rather than a reconstructed identity.

Every fingerprint is *platform-coherent*: the User-Agent platform token matches
``Sec-CH-UA-Platform`` and ``Sec-CH-UA-Platform-Version``. Splitting 101_0000000
(e.g. a Windows UA with ``Sec-CH-UA-Platform: "macOS"``) is an instant bot tell.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Latest stable Chromium major this package is curated against. Keep in sync
# with the newest supported curl_cffi chrome target (chrome150 as of 0.16.1b1).
# For newer versions: extend _FINGERPRINTS with a new entry and bump DEFAULT_MAJOR.
DEFAULT_MAJOR: int = 150
DEFAULT_BUILD: str = "150.0.6585.24"

# Canonical HTTP/2 header order for a desktop-Chrome navigation request. Mirrors
# what genuine Chrome emits; unused headers are appended by curl_cffi after this
# list rather than scattered, so mapping only the browser-shape headers suffices.
_DEFAULT_HEADER_ORDER: str = (
    "sec-ch-ua,"
    "sec-ch-ua-mobile,"
    "sec-ch-ua-platform,"
    "sec-ch-ua-arch,"
    "sec-ch-ua-bitness,"
    "sec-ch-ua-full-version-list,"
    "sec-ch-ua-model,"
    "sec-ch-ua-platform-version,"
    "upgrade-insecure-requests,"
    "user-agent,"
    "accept,"
    "sec-fetch-site,"
    "sec-fetch-mode,"
    "sec-fetch-user,"
    "sec-fetch-dest,"
    "accept-encoding,"
    "accept-language,"
    "priority"
)


@dataclass(frozen=True)
class BrowserFingerprint:
    """A coherent set of request headers describing a real desktop browser."""

    user_agent: str
    # Base Sec-CH-UA triplet. Must carry the same major as UA / Full-Version-List.
    sec_ch_ua: str
    sec_ch_ua_full_version_list: str
    sec_ch_ua_platform: str
    sec_ch_ua_platform_version: str
    sec_ch_ua_arch: str
    sec_ch_ua_bitness: str
    sec_ch_ua_model: str = ""
    # Canonical HTTP/2 header order for a real desktop-Chrome navigation request.
    # curl_cffi sends headers not listed here appended after the listed order, so
    # this covers the browser-shape headers; request-specific ones trail.
    header_order: str = field(default=_DEFAULT_HEADER_ORDER)

    def to_headers(self) -> dict[str, str]:
        """Return this fingerprint as a header dict, dropping empty fields."""
        headers = {
            "User-Agent": self.user_agent,
            "Sec-CH-UA": self.sec_ch_ua,
            "Sec-CH-UA-Full-Version-List": self.sec_ch_ua_full_version_list,
            "Sec-CH-UA-Platform": self.sec_ch_ua_platform,
            "Sec-CH-UA-Platform-Version": self.sec_ch_ua_platform_version,
            "Sec-CH-UA-Arch": self.sec_ch_ua_arch,
            "Sec-CH-UA-Bitness": self.sec_ch_ua_bitness,
        }
        if self.sec_ch_ua_model:
            headers["Sec-CH-UA-Model"] = self.sec_ch_ua_model
        return headers


def _chrome(
    major: int,
    build: str,
    platform_ua: str,
    platform_value: str,
    platform_version: str,
    arch: str = "x86",
    bitness: str = "64",
) -> BrowserFingerprint:
    """Build a desktop-Chrome fingerprint consistent with major/build/platform.

    ``platform_ua`` is the token inside the UA parentheses (e.g. ``Windows NT
    10.0; Win64; x64``); ``platform_value`` is the bare value for the
    ``Sec-CH-UA-Platform`` header (e.g. ``Windows``). These differ — a UA that
    says Win64 must pair with ``Sec-CH-UA-Platform: "Windows"``.
    """
    ua = f"Mozilla/5.0 ({platform_ua}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{build} Safari/537.36"
    # Brand list mirrors what current Chrome emits; "Not/A)Brand" is a real brand.
    short = f'"Not/A)Brand";v="{major - 8}", "Chromium";v="{major}", "Google Chrome";v="{major}"'
    full = f'"Not/A)Brand";v="{major - 8}.0.0.0", "Chromium";v="{build}", "Google Chrome";v="{build}"'
    return BrowserFingerprint(
        user_agent=ua,
        sec_ch_ua=short,
        sec_ch_ua_full_version_list=full,
        sec_ch_ua_platform=f'"{platform_value}"',
        sec_ch_ua_platform_version=f'"{platform_version}"',
        sec_ch_ua_arch=f'"{arch}"',
        sec_ch_ua_bitness=f'"{bitness}"',
    )


# Curated fingerprints keyed by recognized chrome target string.
# Windows NT 10.0; Win64; x64 is the most common desktop shape.
_FINGERPRINTS: dict[str, BrowserFingerprint] = {
    "chrome": _chrome(
        DEFAULT_MAJOR,
        DEFAULT_BUILD,
        "Windows NT 10.0; Win64; x64",
        "Windows",
        "10.0.0",
    ),
    "chrome150": _chrome(
        150,
        DEFAULT_BUILD,
        "Windows NT 10.0; Win64; x64",
        "Windows",
        "10.0.0",
    ),
    "chrome146": _chrome(
        146,
        "146.0.6004.99",
        "Windows NT 10.0; Win64; x64",
        "Windows",
        "10.0.0",
    ),
}

# curl_cffi's bare aliases ("chrome" defaults to the newest supported target).
_ALIASES: dict[str, str] = {
    "chrome": "chrome150",
}


def _canonical_target(target: str) -> str:
    return _ALIASES.get(target, target)


def fingerprint_for(target: str) -> BrowserFingerprint | None:
    """Return the curated fingerprint for a recognized target, else None.

    ``None`` signals "no curated fingerprint — leave curl_cffi's profile headers
    untouched" (used for unsupported/unknown impersonate targets).
    """
    return _FINGERPRINTS.get(_canonical_target(target))

"""Realistic browser client-hint header fingerprints.

The curl_cffi impersonation profiles scrub the User-Agent build number
(e.g. ``Chrome/152.0.0.0``) and omit the full Sec-CH-UA family that a genuine
browser sends over HTTPS. This module supplies platform-coherent header sets
that the proxy injects on top of curl_cffi's TLS impersonation so the resulting
request looks like a real browser rather than a reconstructed identity.

Every fingerprint is *platform-coherent*: the User-Agent platform token matches
``Sec-CH-UA-Platform`` and ``Sec-CH-UA-Platform-Version``. Splitting platforms
(e.g. a Windows UA with ``Sec-CH-UA-Platform: "macOS"``) is an instant bot tell.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Latest stable Chromium major this package is curated against. Keep in sync
# with the newest supported curl_cffi chrome target (chrome152 as of 0.17.0).
# For newer versions: extend _FINGERPRINTS with a new entry and bump DEFAULT_MAJOR.
DEFAULT_MAJOR: int = 152
# Real Chrome 152 Desktop Stable build (Windows/macOS security patch build).
DEFAULT_BUILD: str = "152.0.7977.83"

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
    # Empty for browsers that send no client hints (Firefox).
    sec_ch_ua: str = ""
    sec_ch_ua_full_version_list: str = ""
    sec_ch_ua_platform: str = ""
    sec_ch_ua_platform_version: str = ""
    sec_ch_ua_arch: str = ""
    sec_ch_ua_bitness: str = ""
    sec_ch_ua_model: str = ""
    # Canonical HTTP/2 header order for a real desktop-Chrome navigation request.
    # curl_cffi sends headers not listed here appended after the listed order, so
    # this covers the browser-shape headers; request-specific ones trail.
    # Empty for browsers whose curl_cffi profile already carries the authentic
    # captured order (Firefox) — the proxy must not override it.
    header_order: str = field(default=_DEFAULT_HEADER_ORDER)
    # Browser family whose header shape this fingerprint models.
    browser: str = "chrome"

    def to_headers(self) -> dict[str, str]:
        """Return this fingerprint as a header dict, dropping empty fields."""
        headers = {"User-Agent": self.user_agent}
        if self.browser == "firefox":
            # Firefox sends no client hints — UA-only curation.
            return headers
        headers.update(
            {
                "Sec-CH-UA": self.sec_ch_ua,
                "Sec-CH-UA-Full-Version-List": self.sec_ch_ua_full_version_list,
                "Sec-CH-UA-Platform": self.sec_ch_ua_platform,
                "Sec-CH-UA-Platform-Version": self.sec_ch_ua_platform_version,
                "Sec-CH-UA-Arch": self.sec_ch_ua_arch,
                "Sec-CH-UA-Bitness": self.sec_ch_ua_bitness,
            }
        )
        if self.sec_ch_ua_model:
            headers["Sec-CH-UA-Model"] = self.sec_ch_ua_model
        return headers


def _chrome(
    major: int,
    build: str,
    platform_ua: str,
    platform_value: str,
    platform_version: str,
    *,
    grease_brand: str,
    grease_version: str,
    brand_order: tuple[str, str, str],
    arch: str = "x86",
    bitness: str = "64",
) -> BrowserFingerprint:
    """Build a desktop-Chrome fingerprint consistent with major/build/platform.

    ``platform_ua`` is the token inside the UA parentheses (e.g. ``Windows NT
    10.0; Win64; x64``); ``platform_value`` is the bare value for the
    ``Sec-CH-UA-Platform`` header (e.g. ``Windows``). These differ — a UA that
    says Win64 must pair with ``Sec-CH-UA-Platform: "Windows"``.

    ``grease_brand``, ``grease_version`` (always one of Chrome's ``8``/``24``/``99``),
    and ``brand_order`` mirror Chromium's deterministic per-major GREASE brand
    list so ``Sec-CH-UA`` and ``Sec-CH-UA-Full-Version-List`` match real Chrome
    and ``curl_cffi``'s captured signature verbatim.
    """
    ua = f"Mozilla/5.0 ({platform_ua}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{build} Safari/537.36"
    short_brands = {
        "grease": f'"{grease_brand}";v="{grease_version}"',
        "chromium": f'"Chromium";v="{major}"',
        "chrome": f'"Google Chrome";v="{major}"',
    }
    full_brands = {
        "grease": f'"{grease_brand}";v="{grease_version}.0.0.0"',
        "chromium": f'"Chromium";v="{build}"',
        "chrome": f'"Google Chrome";v="{build}"',
    }
    short = ", ".join(short_brands[k] for k in brand_order)
    full = ", ".join(full_brands[k] for k in brand_order)
    return BrowserFingerprint(
        user_agent=ua,
        sec_ch_ua=short,
        sec_ch_ua_full_version_list=full,
        sec_ch_ua_platform=f'"{platform_value}"',
        sec_ch_ua_platform_version=f'"{platform_version}"',
        sec_ch_ua_arch=f'"{arch}"',
        sec_ch_ua_bitness=f'"{bitness}"',
    )


def _firefox(major: int, platform_ua: str) -> BrowserFingerprint:
    """Build a desktop-Firefox fingerprint: UA-only, platform-coherent.

    Firefox sends no client hints and its UA carries no scrubbed-build tell
    (``rv`` always matches the ``Firefox/`` version), so the curation pins a
    full, platform-coherent UA on the most common desktop shape (Windows /
    Win64 / x64 — consistent with the Chrome family default). ``header_order``
    stays empty: curl_cffi's firefox profiles ship the authentic captured
    order, which must not be overridden.
    """
    ua = f"Mozilla/5.0 ({platform_ua}; rv:{major}.0) Gecko/20100101 Firefox/{major}.0"
    return BrowserFingerprint(user_agent=ua, header_order="", browser="firefox")


# Curated fingerprints keyed by recognized curl_cffi target string.
# Windows NT 10.0; Win64; x64 is the most common desktop shape; explicit
# ``*_macos`` targets keep macOS platform coherence.
_FINGERPRINTS: dict[str, BrowserFingerprint] = {
    "chrome152": _chrome(
        152,
        DEFAULT_BUILD,
        "Windows NT 10.0; Win64; x64",
        "Windows",
        "10.0.0",
        grease_brand="Not?A_Brand",
        grease_version="24",
        brand_order=("chromium", "grease", "chrome"),
    ),
    "chrome152_macos": _chrome(
        152,
        DEFAULT_BUILD,
        "Macintosh; Intel Mac OS X 10_15_7",
        "macOS",
        "15.6.0",
        grease_brand="Not?A_Brand",
        grease_version="24",
        brand_order=("chromium", "grease", "chrome"),
        arch="arm",
    ),
    "chrome151": _chrome(
        151,
        # Final Chrome 151 Desktop Stable build (151.0.7922.x series).
        "151.0.7922.174",
        "Windows NT 10.0; Win64; x64",
        "Windows",
        "10.0.0",
        grease_brand="Not=A?Brand",
        grease_version="99",
        brand_order=("grease", "chrome", "chromium"),
    ),
    "chrome151_macos": _chrome(
        151,
        "151.0.7922.174",
        "Macintosh; Intel Mac OS X 10_15_7",
        "macOS",
        "15.6.0",
        grease_brand="Not=A?Brand",
        grease_version="99",
        brand_order=("grease", "chrome", "chromium"),
        arch="arm",
    ),
    "chrome150": _chrome(
        150,
        # Final Chrome 150 stable build (last 150-series patch before 151).
        "150.0.7871.189",
        "Windows NT 10.0; Win64; x64",
        "Windows",
        "10.0.0",
        grease_brand="Not;A=Brand",
        grease_version="8",
        brand_order=("grease", "chromium", "chrome"),
    ),
    "chrome146": _chrome(
        146,
        # Final Chrome 146 stable build (last 146-series patch before the
        # 147 rollout; real-world builds were 146.0.7680.x).
        "146.0.7680.180",
        "Windows NT 10.0; Win64; x64",
        "Windows",
        "10.0.0",
        grease_brand="Not-A.Brand",
        grease_version="24",
        brand_order=("chromium", "grease", "chrome"),
    ),
    "firefox155": _firefox(155, "Windows NT 10.0; Win64; x64"),
    "firefox154": _firefox(154, "Windows NT 10.0; Win64; x64"),
    "firefox153": _firefox(153, "Windows NT 10.0; Win64; x64"),
    "firefox147": _firefox(147, "Windows NT 10.0; Win64; x64"),
}

# curl_cffi's bare aliases ("chrome"/"firefox" default to the newest supported
# target; mirror curl_cffi's own DEFAULT_* resolution).
_ALIASES: dict[str, str] = {
    "chrome": "chrome152",
    "firefox": "firefox155",
}


def _canonical_target(target: str) -> str:
    return _ALIASES.get(target, target)


def fingerprint_for(target: str) -> BrowserFingerprint | None:
    """Return the curated fingerprint for a recognized target, else None.

    ``None`` signals "no curated fingerprint — leave curl_cffi's profile headers
    untouched" (used for unsupported/unknown impersonate targets).
    """
    return _FINGERPRINTS.get(_canonical_target(target))

"""GitHub Releases updates with fallback to the legacy RCS endpoint."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from . import __version__

GITHUB_REPOSITORY = "RinCynar/rcs.aGmua"
GITHUB_RELEASES_URL = (
    f"https://api.github.com/repos/{GITHUB_REPOSITORY}/releases/latest"
)
LEGACY_UPDATE_URLS = (
    "https://aGmua.dpdns.org",
    "http://aGmua.dpdns.org",
)


@dataclass
class ReleaseInfo:
    version: str
    tag_name: str = ""
    url: str = "https://github.com/RinCynar/rcs.aGmua/releases/latest"
    assets: list[dict[str, str]] = field(default_factory=list)
    source: str = "github"

    @property
    def version_tuple(self) -> tuple[int, ...]:
        return tuple(int(part) for part in self.version.split("."))

    @property
    def is_newer(self) -> bool:
        current = tuple(int(part) for part in __version__.split("."))
        return self.version_tuple > current


def _request(url: str) -> bytes:
    request = Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "RCS-aGmua",
        },
    )
    with urlopen(request, timeout=8) as response:
        return response.read()


def _version(value: str) -> str | None:
    match = re.search(r"(?<!\d)(\d+(?:\.\d+){1,2})(?!\d)", value)
    return match.group(1) if match else None


def _github_release() -> ReleaseInfo:
    payload = json.loads(_request(GITHUB_RELEASES_URL).decode("utf-8"))
    tag = str(payload.get("tag_name", ""))
    version = _version(tag) or _version(str(payload.get("name", "")))
    if not version:
        raise ValueError("GitHub release has no parseable version")
    assets = [
        {
            "name": str(asset.get("name", "")),
            "url": str(asset.get("browser_download_url", "")),
        }
        for asset in payload.get("assets", [])
        if asset.get("name") and asset.get("browser_download_url")
    ]
    return ReleaseInfo(
        version=version,
        tag_name=tag,
        url=str(payload.get("html_url") or "https://github.com/RinCynar/rcs.aGmua/releases"),
        assets=assets,
        source="github",
    )


def _legacy_release() -> ReleaseInfo:
    last_error: Exception | None = None
    for url in LEGACY_UPDATE_URLS:
        try:
            text = _request(url).decode("utf-8", errors="replace").strip()
            version = _version(text)
            if not version:
                raise ValueError("Legacy endpoint has no parseable version")
            links = re.findall(r"https?://[^\s]+", text)
            download_url = links[-1].rstrip(".,)") if links else url
            return ReleaseInfo(
                version=version,
                url=download_url,
                assets=[],
                source="legacy",
            )
        except (HTTPError, URLError, TimeoutError, ValueError, UnicodeError) as error:
            last_error = error
    raise RuntimeError("No update endpoint available") from last_error


def check_for_updates() -> ReleaseInfo | None:
    try:
        return _github_release()
    except (HTTPError, URLError, TimeoutError, ValueError, json.JSONDecodeError):
        try:
            return _legacy_release()
        except RuntimeError:
            return None

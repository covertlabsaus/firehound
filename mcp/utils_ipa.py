from __future__ import annotations

import io
import os
import plistlib
import zipfile
from typing import Optional


def extract_bundle_id_from_ipa(path: str, max_size_mb: int = 50) -> Optional[str]:
    if not os.path.isfile(path):
        raise FileNotFoundError(path)
    if os.path.getsize(path) > max_size_mb * 1024 * 1024:
        raise ValueError("IPA too large")

    with zipfile.ZipFile(path, "r") as zf:
        # Find Payload/*.app/Info.plist
        info_paths = [p for p in zf.namelist() if p.count("/") >= 2 and p.endswith("Info.plist") and "/Payload/" in p]
        if not info_paths:
            return None
        with zf.open(info_paths[0]) as f:
            data = f.read()
            plist = plistlib.loads(data)
            return plist.get("CFBundleIdentifier")



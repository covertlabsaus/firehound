import os
import re
import shlex
import shutil
import sys
import subprocess
import zipfile
import plistlib
from pathlib import Path
from typing import Optional, Tuple, List

from .models import AppScan, ScanRun
from .utils import vprint, BLUE, GREEN, GREY, MAGENTA, RED

class Fetcher:
    def __init__(self, scan_run: ScanRun):
        self.scan_run = scan_run
        self.passphrase = self.scan_run.config.get("passphrase", "1")
        self.timeout = self.scan_run.config.get("timeout", 60)

    def run(self):
        vprint(f"Starting fetch stage for run: {self.scan_run.run_id}", MAGENTA)
        for app_scan in self.scan_run.app_scans:
            self._process_bundle_id(app_scan)

    def _process_bundle_id(self, app_scan: AppScan):
        try:
            app_scan.status = "fetching"
            self._download_and_extract(app_scan)
            if app_scan.google_service_plist_path:
                app_scan.status = "fetched"
                vprint(f"EXTRACTED: {app_scan.bundle_id} -> {app_scan.scan_dir}", GREEN)
            else:
                app_scan.status = "failed"
                app_scan.error_message = "GoogleService-Info.plist not found"
                vprint(f"FAILED: {app_scan.bundle_id} (GoogleService-Info.plist not found)", RED)

        except Exception as e:
            app_scan.status = "failed"
            app_scan.error_message = str(e)
            vprint(f"FAILED: {app_scan.bundle_id} ({e})", RED)

    def _download_and_extract(self, app_scan: AppScan):
        app_scan.scan_dir.mkdir(parents=True, exist_ok=True)
        ipa_path = app_scan.scan_dir / f"{app_scan.bundle_id}.ipa"
        app_scan.ipa_path = ipa_path

        vprint(f"Downloading IPA for {app_scan.bundle_id}", BLUE)
        ok, output = self._run_ipatool_download(app_scan.bundle_id, ipa_path)
        if output:
            vprint(output, GREY)

        if not ok:
            error_detail = f"ipatool output: {output}" if output else "No output from ipatool."
            raise Exception(f"Failed to download IPA. {error_detail}")

        try:
            with zipfile.ZipFile(ipa_path) as zf:
                info_member, google_member = self._find_members(zf)
                if info_member:
                    app_scan.info_plist_path = self._extract_member_to_basename(zf, info_member, app_scan.scan_dir)
                    self._convert_plist_to_xml_if_binary(app_scan.info_plist_path)
                if google_member:
                    app_scan.google_service_plist_path = self._extract_member_to_basename(zf, google_member, app_scan.scan_dir)
                    self._convert_plist_to_xml_if_binary(app_scan.google_service_plist_path)
        finally:
            if ipa_path.exists():
                ipa_path.unlink()

    def _run_ipatool_download(self, bundle_id: str, ipa_path: Path) -> Tuple[bool, Optional[str]]:
        cmd_str = (
            f"ipatool download --bundle-identifier {shlex.quote(bundle_id)} "
            f"--purchase --output {shlex.quote(str(ipa_path))}"
        )
        env = os.environ.copy()
        env.setdefault("IPATOOL_PASSPHRASE", self.passphrase)

        if shutil.which("script"):
            cmd = ["script", "-q", "/dev/null", "-c", cmd_str]
        else:
            cmd = shlex.split(cmd_str)

        try:
            proc = subprocess.run(
                cmd,
                input=(self.passphrase + "\n").encode("utf-8"),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                env=env,
                timeout=self.timeout,
                check=False,
            )
            output_text = proc.stdout.decode(errors="replace")
        except subprocess.TimeoutExpired:
            return False, "Timed out while running ipatool"
        except Exception as exc:
            return False, f"Failed to run ipatool: {exc}"

        return ipa_path.is_file(), output_text

    def _find_members(self, zf: zipfile.ZipFile) -> Tuple[Optional[str], Optional[str]]:
        names = zf.namelist()
        info_regex = re.compile(r"^Payload/[^/]+\.app/Info\.plist$")
        google_regex = re.compile(r"^Payload/[^/]+\.app/GoogleService-Info\.plist$")
        info_path = next((n for n in names if info_regex.match(n)), None)
        google_path = next((n for n in names if google_regex.match(n)), None)
        return info_path, google_path

    def _extract_member_to_basename(self, zf: zipfile.ZipFile, member: str, out_dir: Path) -> Path:
        out_path = out_dir / Path(member).name
        with zf.open(member) as src, open(out_path, "wb") as dst:
            dst.write(src.read())
        return out_path

    def _convert_plist_to_xml_if_binary(self, plist_path: Path) -> None:
        if not plist_path.is_file():
            return
        try:
            with open(plist_path, "rb") as fp:
                header = fp.read(8)
            if header.startswith(b"bplist00"):
                with open(plist_path, "rb") as fp:
                    data = plistlib.load(fp)
                with open(plist_path, "wb") as fp:
                    plistlib.dump(data, fp, fmt=plistlib.FMT_XML)
        except Exception:
            pass

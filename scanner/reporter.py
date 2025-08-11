from .models import ScanRun

class Reporter:
    def __init__(self, scan_run: ScanRun):
        self.scan_run = scan_run

    def run(self):
        # This will contain the logic for writing the final
        # JSON summary files to disk.
        pass

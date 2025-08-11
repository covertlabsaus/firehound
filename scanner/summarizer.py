from .models import ScanRun

class Summarizer:
    def __init__(self, scan_run: ScanRun):
        self.scan_run = scan_run

    def run(self):
        # This will contain the logic from the original summarize.py
        # for counting findings and deciding which apps are interesting.
        pass

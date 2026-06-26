"""
Concurrent multi-repo scan queue using stdlib queue.Queue + threading.
"""

import queue
import threading
from pathlib import Path
from typing import Optional


class ScanQueue:
    """Thread-safe concurrent scan queue."""

    def __init__(self, max_workers: int = 4):
        self.max_workers = max_workers
        self._queue: queue.Queue = queue.Queue()
        self._lock = threading.Lock()
        self.completed: list[str] = []
        self.failed: list[str] = []
        self.results: list[dict] = []
        self._total = 0

    def add_repo(self, repo_url: str) -> None:
        """Add a repository URL to the scan queue."""
        self._queue.put(repo_url)
        with self._lock:
            self._total += 1

    def start(self, args, out_dir: Path) -> None:
        """Start worker threads and begin processing the queue."""
        self._args = args
        self._out_dir = out_dir
        self._threads: list[threading.Thread] = []
        for _ in range(self.max_workers):
            t = threading.Thread(target=self._worker, daemon=True)
            t.start()
            self._threads.append(t)

    def _worker(self) -> None:
        """Worker thread: pull repos from queue and scan each."""
        while True:
            try:
                repo_url = self._queue.get(timeout=2)
            except queue.Empty:
                break

            try:
                self._scan_one(repo_url)
                with self._lock:
                    self.completed.append(repo_url)
            except Exception as exc:
                with self._lock:
                    self.failed.append(repo_url)
                print(f"[queue] ERROR scanning {repo_url}: {exc}")
            finally:
                self._queue.task_done()
                with self._lock:
                    done = len(self.completed) + len(self.failed)
                    total = self._total
                print(f"[queue] {done}/{total} scans done")

    def _scan_one(self, repo_url: str) -> None:
        """Delegate to main._scan_one for a single repo."""
        from main import _scan_one
        _scan_one(repo_url, self._args, self._out_dir)

    def wait(self) -> None:
        """Block until all queued repos have been scanned."""
        self._queue.join()
        for t in self._threads:
            t.join(timeout=5)

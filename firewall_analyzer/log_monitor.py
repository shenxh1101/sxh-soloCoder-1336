import os
import time
import threading
import logging
from typing import Callable, Optional
from queue import Queue

logger = logging.getLogger(__name__)


class LogMonitor:
    def __init__(
        self,
        log_path: str,
        line_callback: Callable[[str], None],
        from_beginning: bool = False,
        poll_interval: float = 1.0,
        encoding: str = "utf-8",
    ):
        self.log_path = os.path.abspath(log_path)
        self.line_callback = line_callback
        self.from_beginning = from_beginning
        self.poll_interval = poll_interval
        self.encoding = encoding
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._current_file_size = 0
        self._current_inode = 0

    def start(self):
        if self._thread and self._thread.is_alive():
            logger.warning("Log monitor is already running")
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run,
            name=f"LogMonitor-{os.path.basename(self.log_path)}",
            daemon=True,
        )
        self._thread.start()
        logger.info(f"Started monitoring {self.log_path}")

    def stop(self):
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5.0)
        logger.info(f"Stopped monitoring {self.log_path}")

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def _run(self):
        while not self._stop_event.is_set():
            try:
                if not os.path.exists(self.log_path):
                    logger.debug(f"Log file not found: {self.log_path}, waiting...")
                    time.sleep(self.poll_interval * 2)
                    continue

                self._process_existing_file()
                self._tail_file()

            except Exception as e:
                logger.error(f"Error monitoring {self.log_path}: {e}", exc_info=True)
                time.sleep(self.poll_interval)

    def _process_existing_file(self):
        try:
            stat_info = os.stat(self.log_path)
        except OSError:
            return

        new_size = stat_info.st_size
        new_inode = stat_info.st_ino

        if new_inode != self._current_inode:
            self._current_inode = new_inode
            self._current_file_size = 0
            if self.from_beginning:
                logger.debug(f"New file detected, reading from beginning: {self.log_path}")
                self._read_new_lines(0, read_all=True)
                try:
                    self._current_file_size = os.stat(self.log_path).st_size
                except OSError:
                    pass
                return
            else:
                self._current_file_size = new_size
                return

        if new_size < self._current_file_size:
            logger.debug(f"Log file truncated, resetting position: {self.log_path}")
            self._current_file_size = 0

        if new_size > self._current_file_size:
            self._read_new_lines(self._current_file_size)
            try:
                self._current_file_size = os.stat(self.log_path).st_size
            except OSError:
                pass

    def _tail_file(self):
        while not self._stop_event.is_set():
            try:
                stat_info = os.stat(self.log_path)
            except OSError:
                self._current_file_size = 0
                self._current_inode = 0
                return

            new_size = stat_info.st_size
            new_inode = stat_info.st_ino

            if new_inode != self._current_inode:
                logger.info(f"Log file rotated: {self.log_path}")
                self._current_inode = new_inode
                self._current_file_size = 0
                return

            if new_size < self._current_file_size:
                logger.debug(f"Log file truncated: {self.log_path}")
                self._current_file_size = 0

            if new_size > self._current_file_size:
                self._read_new_lines(self._current_file_size)
                try:
                    self._current_file_size = os.stat(self.log_path).st_size
                except OSError:
                    pass

            time.sleep(self.poll_interval)

    def _read_new_lines(self, start_pos: int, read_all: bool = False):
        try:
            with open(self.log_path, "r", encoding=self.encoding, errors="replace") as f:
                if not read_all:
                    f.seek(start_pos)
                line = f.readline()
                while line:
                    line = line.rstrip("\n\r")
                    if line:
                        try:
                            self.line_callback(line)
                        except Exception as cb_error:
                            logger.error(f"Error in line callback: {cb_error}", exc_info=True)
                    line = f.readline()
        except (OSError, IOError) as e:
            logger.error(f"Error reading log file {self.log_path}: {e}")

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()
        return False


class MultiLogMonitor:
    def __init__(
        self,
        log_paths: list[str],
        line_callback: Callable[[str, str], None],
        from_beginning: bool = False,
        poll_interval: float = 1.0,
        encoding: str = "utf-8",
    ):
        self.log_paths = log_paths
        self.line_callback = line_callback
        self.from_beginning = from_beginning
        self.poll_interval = poll_interval
        self.encoding = encoding
        self._monitors: dict[str, LogMonitor] = {}
        self._line_queue: Queue[tuple[str, str]] = Queue()
        self._dispatcher_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

    def _make_callback(self, path: str) -> Callable[[str], None]:
        def callback(line: str):
            self._line_queue.put((path, line))
        return callback

    def start(self):
        self._stop_event.clear()
        for path in self.log_paths:
            monitor = LogMonitor(
                log_path=path,
                line_callback=self._make_callback(path),
                from_beginning=self.from_beginning,
                poll_interval=self.poll_interval,
                encoding=self.encoding,
            )
            monitor.start()
            self._monitors[path] = monitor

        self._dispatcher_thread = threading.Thread(
            target=self._dispatch_loop,
            name="LogMonitor-Dispatcher",
            daemon=True,
        )
        self._dispatcher_thread.start()
        logger.info(f"Started monitoring {len(self.log_paths)} log files")

    def stop(self):
        self._stop_event.set()
        for monitor in self._monitors.values():
            monitor.stop()
        self._monitors.clear()
        if self._dispatcher_thread:
            self._dispatcher_thread.join(timeout=5.0)
        logger.info("Stopped all log monitors")

    def _dispatch_loop(self):
        while not self._stop_event.is_set():
            try:
                path, line = self._line_queue.get(timeout=0.5)
                try:
                    self.line_callback(path, line)
                except Exception as cb_error:
                    logger.error(f"Error dispatching line from {path}: {cb_error}", exc_info=True)
                self._line_queue.task_done()
            except Exception:
                continue

    def is_running(self) -> bool:
        return any(m.is_running() for m in self._monitors.values())

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()
        return False

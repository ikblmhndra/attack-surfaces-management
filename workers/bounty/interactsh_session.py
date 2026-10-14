"""
ASM Platform — Bug Bounty pipeline: persistent interactsh session management.

Wraps the real `interactsh-client` Go binary as a long-running background
subprocess for the duration of one exploit run's SSRF testing, rather than
reimplementing its RSA-OAEP + AES-256-CTR interaction-decryption protocol in
Python -- too easy to get a crypto detail subtly wrong and silently miss real
interactions. Same "shell out to the real tool" convention every other
Go-based check in this pipeline already follows (tools.py).

interactsh-client has no one-shot flag (it's designed to poll continuously
in the foreground), so this manages its full lifecycle explicitly:
  1. start() -- launch the subprocess, resuming a persisted session (same
     domain) if one was handed in and interactsh-client accepts it, else a
     fresh one. Reads its own startup banner to learn the domain it was
     assigned; that's the value callers pass to run_ssrf() as oob_domain,
     completely unchanged from the existing manual-oob_domain code path.
  2. Caller runs SSRF injection (exploit_worker.py) against the returned
     domain, same as always.
  3. stop_and_collect() -- after all SSRF modules for the run are done, give
     the network a grace period for any in-flight OOB callbacks to arrive,
     terminate the subprocess, and return (interactions, session_yaml) --
     the session file's current content, for the caller to persist back into
     rules_of_engagement, intended so the SAME session identity (correlation-
     id/secret-key) gets reused next run instead of registering fresh every
     time.

     KNOWN BROKEN as of interactsh-client v1.3.1 (and still broken on
     upstream's main branch as of this writing -- verified directly against
     cmd/interactsh-client/main.go, not assumed): the binary's -session-file
     *load* path does `fileutil.Unmarshal(fileutil.YAML,
     []byte(cliOptions.SessionFile), &sessionInfo)` -- it YAML-unmarshals the
     file *path string* itself, never calling anything that reads the file's
     actual bytes first. That unconditionally fails to parse as a
     SessionInfo struct, the error is discarded (`_ = ...`), and a brand-new
     session is minted every single run regardless of what start_session()
     writes into session_file beforehand. The *save* path
     (SaveSessionTo(), called from this process's SIGINT handler) works
     fine -- confirmed live, the file content below is a real, well-formed
     session -- the bug is purely one-directional. We still write and persist
     session_yaml every run (harmless, and in place for if/when this gets
     fixed upstream or we patch-build our own binary), but don't rely on or
     claim resumption working until one of those happens; see the
     `resumed=` field on the "session started" log line below, and the
     Bug Bounty UI's own tooltip, which both now say so.

     Either way, this doesn't affect SSRF *confirmation* accuracy -- each
     run's domain polls and matches its own run's injected payloads fine, a
     fresh identity per run just loses operator-facing continuity, not
     correctness. The actual problem this module exists to fix (see
     CHANGELOG.md 2026-08-04) is the old fully-manual flow -- copy a URL from
     a web page, check a dashboard by hand -- not domain-string identity
     specifically.
"""
import asyncio
import json
import re
import shutil
import signal
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import structlog

log = structlog.get_logger()

_STARTUP_TIMEOUT = 25          # seconds to wait for the assigned-domain banner
_SHUTDOWN_GRACE = 5            # seconds to let the process exit after SIGTERM
_DEFAULT_SERVER = "oast.fun"


class InteractshSession:
    def __init__(self, process: "asyncio.subprocess.Process", domain: str,
                 session_file: Path, output_file: Path, log_lines: List[str]):
        self._process = process
        self.domain = domain
        self._session_file = session_file
        self._output_file = output_file
        self._log_lines = log_lines  # shared list, appended to by the background reader
        self._reader_task: Optional[asyncio.Task] = None

    async def stop_and_collect(self, grace_period: int = 25) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        """Wait `grace_period` seconds for trailing OOB callbacks to land,
        then stop the client and return (interactions, session_yaml)."""
        await asyncio.sleep(max(0, grace_period))

        try:
            # interactsh-client only calls SaveSessionTo() from its SIGINT
            # (os.Interrupt) handler -- confirmed against its actual source,
            # not assumed. A plain terminate() sends SIGTERM, which this
            # binary doesn't handle at all (default OS behavior: dies with
            # no session file written), silently breaking session reuse.
            self._process.send_signal(signal.SIGINT)
            await asyncio.wait_for(self._process.wait(), timeout=_SHUTDOWN_GRACE)
        except (ProcessLookupError, asyncio.TimeoutError):
            try:
                self._process.kill()
                await self._process.wait()
            except ProcessLookupError:
                pass
        if self._reader_task:
            self._reader_task.cancel()
            try:
                await self._reader_task
            except (asyncio.CancelledError, Exception):
                pass

        interactions: List[Dict[str, Any]] = []
        if self._output_file.exists():
            for line in self._output_file.read_text(errors="ignore").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    interactions.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

        session_yaml = None
        if self._session_file.exists():
            try:
                session_yaml = self._session_file.read_text(errors="ignore")
            except Exception:
                pass

        return interactions, session_yaml


async def _drain_stream(stream: asyncio.StreamReader, lines: List[str]) -> None:
    """Keeps a subprocess's stdout/stderr pipe from filling up and blocking
    it -- interactsh-client runs indefinitely, so nothing else will ever
    read this if we don't. Also the only way to observe its startup banner
    while the process keeps running in the background afterward."""
    try:
        while True:
            raw = await stream.readline()
            if not raw:
                break
            lines.append(raw.decode(errors="ignore").rstrip("\n"))
    except Exception:
        pass


def _tool_path(name: str) -> Optional[str]:
    return shutil.which(name)


async def start_session(
    tmpdir: Path, session_yaml: Optional[str] = None, server: str = _DEFAULT_SERVER,
) -> Optional[InteractshSession]:
    """Start (or resume) an interactsh-client session. Returns None if the
    binary isn't installed or the client never announced a domain within
    _STARTUP_TIMEOUT -- callers should treat that exactly like "no oob_domain
    configured" (SSRF module already no-ops without one)."""
    path = _tool_path("interactsh-client")
    if not path:
        log.warning("bounty_interactsh_binary_missing")
        return None

    session_file = tmpdir / "interactsh_session.yaml"
    if session_yaml:
        session_file.write_text(session_yaml)
    output_file = tmpdir / "interactsh_interactions.jsonl"

    cmd = [
        path,
        "-server", server,
        "-session-file", str(session_file),
        "-json",
        "-o", str(output_file),
        "-poll-interval", "5",
        "-disable-update-check",
    ]

    try:
        process = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
    except Exception as exc:
        log.warning("bounty_interactsh_spawn_error", error=str(exc)[:200])
        return None

    log_lines: List[str] = []
    reader_task = asyncio.gather(
        _drain_stream(process.stdout, log_lines),
        _drain_stream(process.stderr, log_lines),
    )

    domain = await _wait_for_domain(log_lines, server, timeout=_STARTUP_TIMEOUT)
    if not domain:
        log.warning("bounty_interactsh_no_domain", banner="\n".join(log_lines[-20:]))
        reader_task.cancel()
        try:
            process.terminate()
        except ProcessLookupError:
            pass
        return None

    session = InteractshSession(process, domain, session_file, output_file, log_lines)
    session._reader_task = reader_task
    # `resumed` is deliberately always False, not bool(session_yaml): a prior
    # session was attempted (session_yaml was non-empty) if `resume_attempted`
    # is true, but interactsh-client v1.3.1's -session-file load path never
    # actually resumes it (see the module docstring) -- this field name would
    # otherwise mislead anyone grepping logs into thinking continuity worked.
    log.info(
        "bounty_interactsh_session_started", domain=domain,
        resume_attempted=bool(session_yaml), resumed=False,
    )
    return session


_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


async def _wait_for_domain(log_lines: List[str], server: str, timeout: int) -> Optional[str]:
    """interactsh-client prints its assigned domain(s) on startup via
    gologger, which prepends an ANSI-colored "[INF]" level tag to every line
    (confirmed live -- the actual output is e.g. "\\x1b[34mINF\\x1b[0m]
    d9onhi....oast.fun", not a bare hostname line as the upstream source
    reading suggested) -- so this searches for the domain pattern anywhere
    in the (ANSI-stripped) line rather than anchoring the whole line to it."""
    pattern = re.compile(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\." + re.escape(server), re.IGNORECASE)
    deadline = asyncio.get_event_loop().time() + timeout
    seen = 0
    while asyncio.get_event_loop().time() < deadline:
        while seen < len(log_lines):
            line = _ANSI_RE.sub("", log_lines[seen])
            seen += 1
            m = pattern.search(line)
            if m:
                return m.group(0)
        await asyncio.sleep(0.5)
    return None

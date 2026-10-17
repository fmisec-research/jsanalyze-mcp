"""`/jsanalyze setup` logic: detect / verify / install the jsluice fork + status.

Stdlib only (subprocess, shutil, os, tempfile, pathlib, json). No third-party deps,
no pip installs.

jsluice invocation contract (do not change):
  * `jsluice <mode> <file>` — NEVER the `-j` / `--raw-input` flag (it reads raw source
    from stdin, which yields empty output here and can hang).
  * EVERY jsluice/go/git call runs with ``stdin=subprocess.DEVNULL`` and a ``timeout``
    so nothing can block the MCP server.

No function here raises to the caller: every failure path returns a human-readable
Markdown report string instead.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from .utils.workspace import REPO_ROOT, load_config, save_config

# A tiny snippet that exercises two fork-only modes at once: a tainted innerHTML sink
# (``sinks``) and a sourceMappingURL comment (``sourcemaps``).
_PROBE_JS = "el.innerHTML = location.hash;\n//# sourceMappingURL=/a.js.map\n"

# The project keeps its own stable copy of the binary here once it has to install one.
_PROJECT_BIN = REPO_ROOT / "bin" / "jsluice"

_JSLUICE_TIMEOUT = 15
_GO_QUERY_TIMEOUT = 15
_GO_BUILD_TIMEOUT = 300


# --- subprocess sandbox -------------------------------------------------------
def _run(cmd, timeout, env=None, cwd=None):
    """Run ``cmd`` fully sandboxed. Returns ``(rc, stdout, stderr, err_label)``.

    ``err_label`` is ``None`` for a process that actually ran (even with a non-zero
    exit code); it is a short string when the process could not be started or timed
    out. Never raises.
    """
    try:
        proc = subprocess.run(
            [str(c) for c in cmd],
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
            timeout=timeout,
            env=env,
            cwd=cwd,
            check=False,
        )
        return proc.returncode, proc.stdout or "", proc.stderr or "", None
    except FileNotFoundError:
        return 127, "", "", f"executable not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", "", f"timed out after {timeout}s: {cmd[0]}"
    except (OSError, subprocess.SubprocessError) as exc:  # defensive catch-all
        return 1, "", "", f"{type(exc).__name__}: {exc}"


def _has_json_line(text: str) -> bool:
    """True if any line of ``text`` is a non-empty JSON object/array."""
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            if isinstance(json.loads(line), (dict, list)):
                return True
        except ValueError:
            continue
    return False


# --- verification -------------------------------------------------------------
def _fork_modes_ok(jsluice_path) -> bool:
    """True if the binary supports the fork-only modes (smoke test on a tiny JS snippet).

    Runs ``jsluice sinks <tmp>`` and ``jsluice sourcemaps <tmp>``; returns True when
    both exit 0 and at least one produces a non-empty JSON line. Upstream jsluice does
    not know these modes and exits non-zero, so this reliably tells the fork apart.
    """
    if not jsluice_path or not os.path.exists(str(jsluice_path)):
        return False
    jsluice_path = str(jsluice_path)
    tmp = None
    try:
        fd, tmp = tempfile.mkstemp(suffix=".js", prefix="jsluice_probe_")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(_PROBE_JS)
        rc_s, out_s, _, err_s = _run([jsluice_path, "sinks", tmp], _JSLUICE_TIMEOUT)
        rc_m, out_m, _, err_m = _run([jsluice_path, "sourcemaps", tmp], _JSLUICE_TIMEOUT)
        if err_s or err_m or rc_s != 0 or rc_m != 0:
            return False
        return _has_json_line(out_s) or _has_json_line(out_m)
    finally:
        _cleanup(tmp)


def _smoke_line(jsluice_path) -> str:
    """Final smoke test: a single ``jsluice sinks`` run; returns a sample output line."""
    tmp = None
    try:
        fd, tmp = tempfile.mkstemp(suffix=".js", prefix="jsluice_smoke_")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(_PROBE_JS)
        rc, out, _, err = _run([str(jsluice_path), "sinks", tmp], _JSLUICE_TIMEOUT)
        if err or rc != 0:
            return ""
        for line in out.splitlines():
            if line.strip():
                return line.strip()[:200]
        return ""
    finally:
        _cleanup(tmp)


def _cleanup(path) -> None:
    if path and os.path.exists(path):
        try:
            os.remove(path)
        except OSError:
            pass


# --- resolution (read-only) ---------------------------------------------------
def _resolve(cfg) -> str | None:
    """Locate an existing jsluice without installing. Order:
    config ``jsluice_path`` -> ``PATH`` -> ``~/go/bin/jsluice`` -> project ``bin/jsluice``.
    """
    configured = cfg.get("jsluice_path")
    if configured and os.path.exists(configured):
        return str(configured)
    on_path = shutil.which("jsluice")
    if on_path:
        return on_path
    go_bin = Path.home() / "go" / "bin" / "jsluice"
    if go_bin.exists():
        return str(go_bin)
    if _PROJECT_BIN.exists():
        return str(_PROJECT_BIN)
    return None


# --- public API ---------------------------------------------------------------
def ensure_jsluice(cfg=None) -> str:
    """Make jsluice available and verified; persist its path to config. Idempotent.

    Returns a Markdown status report. Never raises.
    """
    cfg = cfg or load_config()
    cfg_path = cfg.get("_config_path", "?")

    # Step 2 — DETECT: resolve an existing binary and verify the fork modes. If it is
    # already the fork, persist its path and stop. Do NOT reinstall.
    resolved = _resolve(cfg)
    if resolved and _fork_modes_ok(resolved):
        cfg["jsluice_path"] = resolved
        save_config(cfg)
        return _report_detected(resolved, cfg_path, _smoke_line(resolved))

    # Step 3 — INSTALL: nothing resolvable, or the binary lacks the fork modes.
    return _install(cfg, cfg_path, resolved)


def status(cfg=None) -> str:
    """Quick READ-ONLY check (never installs). Returns Markdown."""
    cfg = cfg or load_config()
    cfg_path = cfg.get("_config_path", "?")
    resolved = _resolve(cfg)
    go = shutil.which("go")
    modes = cfg.get("modes")

    lines = ["## jsanalyze status", ""]
    if resolved:
        fork_ok = _fork_modes_ok(resolved)
        lines.append(f"- **jsluice:** `{resolved}`")
        if fork_ok:
            lines.append("- **Fork modes:** verified (`sinks`, `sourcemaps` produce JSON)")
        else:
            lines.append(
                "- **Fork modes:** NOT verified — looks like upstream jsluice; "
                "run `/jsanalyze setup`"
            )
    else:
        lines.append("- **jsluice:** NOT FOUND — run `/jsanalyze setup`")
        lines.append("- **Fork modes:** n/a")
    lines.append(
        f"- **Go:** `{go}`" if go else "- **Go:** not installed (needed only to install jsluice)"
    )
    lines.append(f"- **Config:** `{cfg_path}`")
    if isinstance(modes, list) and modes:
        lines.append(f"- **`modes` key:** present ({', '.join(modes)})")
    else:
        lines.append("- **`modes` key:** MISSING")
    lines += _enricher_status_lines(cfg)
    return "\n".join(lines) + "\n"


def _enricher_status_lines(cfg) -> list:
    """Availability of the optional enricher tools (read-only, best-effort)."""
    try:
        from jsanalyze.enrichers import tools as _etools
    except Exception:
        return []
    out = ["", "### Enricher tools"]
    av = _etools.available(cfg)
    present = [k for k, v in av.items() if v]
    absent = [k for k, v in av.items() if not v]
    out.append(f"- **present:** {', '.join(present) or 'none'}")
    if absent:
        out.append(f"- **absent:** {', '.join(absent)}")
    en = cfg.get("enrichers") or {}
    out.append(f"- **enabled:** {', '.join(k for k, v in en.items() if v) or 'none'}")
    out.append(
        f"- **allow_network:** {bool(cfg.get('allow_network', False))} "
        "(external .map fetch / secret verification / introspection = Operator Gate)"
    )
    return out


# --- install path -------------------------------------------------------------
def _install(cfg, cfg_path, resolved) -> str:
    go = shutil.which("go")
    if not go:
        return _report_no_go(cfg_path, resolved)

    install_path = cfg.get("jsluice_install_path") or (
        "github.com/0xshdax/jsluice/cmd/jsluice@latest"
    )
    repo = cfg.get("jsluice_repo") or "https://github.com/0xshdax/jsluice"
    env = os.environ.copy()
    log: list[str] = []
    if resolved:
        log.append(f"note: `{resolved}` found but missing fork modes; installing the fork")

    final = None

    # Primary: `go install <module>@latest` -> GOBIN/GOPATH bin.
    rc, out, err_out, err = _run([go, "install", install_path], _GO_BUILD_TIMEOUT, env=env)
    log.append(f"$ go install {install_path}")
    if err:
        log.append(f"  -> {err}")
    elif rc != 0:
        log.append(f"  -> exit {rc}: {(err_out or out).strip()[:400]}")
    else:
        log.append("  -> ok")
        installed = _locate_installed(go, env)
        if installed:
            final = _adopt(installed, log)
        else:
            log.append("  -> installed but binary not found in GOBIN/GOPATH")

    # Fallback: clone + `go build`, passing the package path as an ARG. We never cd
    # into the untrusted clone to run the build tool (build-tool hygiene); cwd stays
    # at the project root.
    if final is None:
        final = _build_from_source(go, repo, env, log)

    if final is None:
        return _report_install_failed(cfg_path, log)
    if not _fork_modes_ok(final):
        return _report_fork_missing(final, cfg_path, log)

    cfg["jsluice_path"] = final
    save_config(cfg)
    return _report_installed(final, cfg_path, log, _smoke_line(final))


def _locate_installed(go, env) -> str | None:
    """Find the binary produced by `go install`: GOBIN first, then GOPATH/bin, then ~/go/bin."""
    candidates: list[Path] = []
    rc, gobin, _, err = _run([go, "env", "GOBIN"], _GO_QUERY_TIMEOUT, env=env)
    if err is None and rc == 0 and gobin.strip():
        candidates.append(Path(gobin.strip()) / "jsluice")
    rc, gopath, _, err = _run([go, "env", "GOPATH"], _GO_QUERY_TIMEOUT, env=env)
    if err is None and rc == 0 and gopath.strip():
        first = gopath.strip().split(os.pathsep)[0]
        candidates.append(Path(first) / "bin" / "jsluice")
    candidates.append(Path.home() / "go" / "bin" / "jsluice")
    for cand in candidates:
        if cand.exists():
            return str(cand)
    return None


def _adopt(src, log) -> str:
    """Copy ``src`` to the project's stable ``bin/jsluice`` and mark it executable."""
    try:
        _PROJECT_BIN.parent.mkdir(parents=True, exist_ok=True)
        if os.path.abspath(src) != os.path.abspath(_PROJECT_BIN):
            shutil.copy2(src, _PROJECT_BIN)
        os.chmod(_PROJECT_BIN, 0o755)
        log.append(f"  adopted -> {_PROJECT_BIN}")
        return str(_PROJECT_BIN)
    except OSError as exc:
        log.append(f"  adopt failed ({exc}); using {src} in place")
        return str(src)


def _build_from_source(go, repo, env, log) -> str | None:
    git = shutil.which("git")
    if not git:
        log.append("fallback build skipped: `git` not found")
        return None
    tmp = tempfile.mkdtemp(prefix="jsluice-build-")
    try:
        rc, out, err_out, err = _run(
            [git, "clone", "--depth", "1", repo, tmp], _GO_BUILD_TIMEOUT, env=env
        )
        log.append(f"$ git clone --depth 1 {repo}")
        if err or rc != 0:
            log.append(f"  -> {err or (err_out or out).strip()[:400]}")
            return None
        log.append("  -> ok")

        pkg = str(Path(tmp) / "cmd" / "jsluice")
        _PROJECT_BIN.parent.mkdir(parents=True, exist_ok=True)
        # Package path passed as an ARG; cwd = project root, NOT the clone.
        rc, out, err_out, err = _run(
            [go, "build", "-o", str(_PROJECT_BIN), pkg],
            _GO_BUILD_TIMEOUT,
            env=env,
            cwd=str(REPO_ROOT),
        )
        log.append(f"$ go build -o {_PROJECT_BIN} {pkg}")
        if err or rc != 0:
            log.append(f"  -> {err or (err_out or out).strip()[:400]}")
            return None
        log.append("  -> ok")
        try:
            os.chmod(_PROJECT_BIN, 0o755)
        except OSError:
            pass
        return str(_PROJECT_BIN)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# --- reports ------------------------------------------------------------------
def _report_detected(path, cfg_path, smoke) -> str:
    out = [
        "## jsanalyze setup — jsluice ready (detected)",
        "",
        f"- **Binary:** `{path}` (existing fork — not reinstalled)",
        "- **Fork modes verified:** `sinks`, `sourcemaps` (JSON output confirmed)",
        f"- **Config:** `jsluice_path` written to `{cfg_path}`",
    ]
    if smoke:
        out.append(f"- **Smoke test:** `{smoke}`")
    out += ["", "jsluice is the 0xshdax fork and is ready to use."]
    return "\n".join(out) + "\n"


def _report_installed(path, cfg_path, log, smoke) -> str:
    out = [
        "## jsanalyze setup — jsluice installed",
        "",
        f"- **Binary:** `{path}`",
        "- **Fork modes verified:** `sinks`, `sourcemaps` (JSON output confirmed)",
        f"- **Config:** `jsluice_path` written to `{cfg_path}`",
    ]
    if smoke:
        out.append(f"- **Smoke test:** `{smoke}`")
    out += ["", "<details><summary>install log</summary>", "", "```"]
    out += log
    out += ["```", "</details>"]
    return "\n".join(out) + "\n"


def _report_no_go(cfg_path, resolved) -> str:
    out = ["## jsanalyze setup — cannot install jsluice", ""]
    if resolved:
        out.append(f"- Found `{resolved}` but it is missing the fork-only modes.")
    else:
        out.append("- jsluice was not found on this system.")
    out += [
        "- **Go is not installed**, so jsluice cannot be built.",
        "",
        "Install Go and re-run setup:",
        "",
        "```",
        "sudo apt-get install golang-go",
        "```",
        "",
        "Then run `/jsanalyze setup` again.",
    ]
    return "\n".join(out) + "\n"


def _report_install_failed(cfg_path, log) -> str:
    out = [
        "## jsanalyze setup — install FAILED",
        "",
        "Both `go install` and the clone+build fallback failed. jsluice is NOT available.",
        f"Config unchanged (`{cfg_path}`).",
        "",
        "```",
    ]
    out += log
    out += [
        "```",
        "",
        "Check network access and that the repo/module paths in config are correct, "
        "then re-run `/jsanalyze setup`.",
    ]
    return "\n".join(out) + "\n"


def _report_fork_missing(path, cfg_path, log) -> str:
    out = [
        "## jsanalyze setup — installed binary is NOT the fork",
        "",
        f"- Built/installed `{path}`, but it does not support the fork-only modes "
        "(`sinks`, `sourcemaps`).",
        f"- Config left unchanged (`{cfg_path}`).",
        "",
        "```",
    ]
    out += log
    out += [
        "```",
        "",
        "Verify `jsluice_repo` / `jsluice_install_path` point at the 0xshdax fork, "
        "then re-run `/jsanalyze setup`.",
    ]
    return "\n".join(out) + "\n"


if __name__ == "__main__":  # pragma: no cover - manual convenience only
    import sys

    action = sys.argv[1] if len(sys.argv) > 1 else "status"
    print(ensure_jsluice() if action == "setup" else status())

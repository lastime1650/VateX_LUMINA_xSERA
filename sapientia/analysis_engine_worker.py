"""One-shot offline adapters. Only private copied bytes are analyzed, never executed.

This module also runs as trusted source in an isolated direct interpreter. It
has no application imports and emits one bounded JSON object. Tool stdout is
captured with a hard character budget before parsing.
"""
import contextlib
import hashlib
import importlib.metadata
import importlib.util
import io
import json
import os
from pathlib import Path
import sys

MAX_OUTPUT = 2 * 1024 * 1024
PACKAGES = {"capa": "flare-capa", "floss": "flare-floss", "speakeasy": "speakeasy-emulator"}


class BoundedText(io.StringIO):
    def __init__(self):
        super().__init__()
        self.count = 0

    def write(self, value):
        self.count += len(value)
        if self.count > MAX_OUTPUT:
            raise ValueError("Engine output budget exceeded")
        return super().write(value)


def tree_digest(root, suffixes):
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise ValueError("Configured resource directory is unavailable")
    hashes, total = [], 0
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or getattr(path.lstat(), "st_file_attributes", 0) & 0x400:
            raise ValueError("Resource links are not accepted")
        if not path.is_file() or path.suffix.lower() not in suffixes:
            continue
        if len(hashes) >= 20000 or path.stat().st_size > 16 * 1024 * 1024:
            raise ValueError("Resource file budget exceeded")
        content = path.read_bytes()
        total += len(content)
        if total > 64 * 1024 * 1024:
            raise ValueError("Resource pack budget exceeded")
        hashes.append([path.relative_to(root).as_posix(), hashlib.sha256(content).hexdigest()])
    if not hashes:
        raise ValueError("No engine resource files are installed")
    return hashlib.sha256(json.dumps(hashes, separators=(",", ":")).encode()).hexdigest(), len(hashes)


def inventory(engine, request):
    package = PACKAGES[engine]
    try:
        version = importlib.metadata.version(package)
        module = importlib.util.find_spec({"capa": "capa", "floss": "floss", "speakeasy": "speakeasy"}[engine])
        if module is None:
            raise importlib.metadata.PackageNotFoundError(package)
    except (ImportError, importlib.metadata.PackageNotFoundError):
        return {"available": False, "version": None, "rule_digest": None, "reason": "Optional engine is not installed in the configured analysis runtime"}
    resource = request.get("rules")
    if engine == "capa":
        resource = resource or str(Path(module.origin).parent / "rules")
        try:
            manifest_spec = request.get("release_manifest")
            if manifest_spec:
                manifest_path = Path(manifest_spec["path"])
                raw = manifest_path.read_bytes()
                if len(raw) > 4 * 1024 * 1024 or hashlib.sha256(raw).hexdigest() != manifest_spec["sha256"]:
                    raise ValueError("Built-in capa release manifest integrity failed")
                manifest = json.loads(raw)
                expected = {}
                for item in manifest["files"]:
                    relative = Path(item["path"])
                    if relative.is_absolute() or ".." in relative.parts:
                        raise ValueError("Invalid built-in capa resource path")
                    content = (manifest_path.parent / relative).read_bytes()
                    if len(content) != item["bytes"] or hashlib.sha256(content).hexdigest() != item["sha256"]:
                        raise ValueError("Built-in capa resource integrity failed")
                    if relative.parts[0] == "rules":
                        expected[Path(*relative.parts[1:]).as_posix()] = item["sha256"]
                actual = {p.relative_to(resource).as_posix() for p in Path(resource).rglob("*") if p.is_file() and p.suffix in {".yml", ".yaml"}}
                if actual != set(expected):
                    raise ValueError("Built-in capa resource inventory differs from the release")
            digest, count = tree_digest(resource, {".yml", ".yaml"})
        except (OSError, ValueError) as exc:
            return {"available": False, "version": version, "rule_digest": None, "reason": str(exc)}
    else:
        # Hash installed signatures/config as well as the distribution version.
        root = Path(module.origin).parent
        paths = [p for p in (root / "sigs", root / "configs") if p.is_dir()]
        hashes = [tree_digest(p, {".pat", ".sig", ".json", ".gz", ".yaml", ".yml"})[0] for p in paths]
        digest = hashlib.sha256(json.dumps([package, version, hashes]).encode()).hexdigest()
        count = len(paths)
    return {"available": True, "version": version, "rule_digest": digest, "resource_count": count, "resource_path": resource, "reason": None}


def run(request):
    engine = request["engine"]
    details = inventory(engine, request)
    if request["operation"] == "status":
        return details
    if not details["available"]:
        return {"status": "unavailable", "error": details["reason"], "summary": {}, **details}
    if any(details[k] != request["expected"][k] for k in ("version", "rule_digest")):
        return {"status": "error", "error": "Engine resources changed before execution", "summary": {}}
    path = Path(request["path"])
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 32 * 1024 * 1024:
        raise ValueError("Private input is unavailable or over budget")
    if hashlib.sha256(path.read_bytes()).hexdigest() != request["sha256"]:
        raise ValueError("Private input digest mismatch")
    output, errors = BoundedText(), BoundedText()
    with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
        if engine == "capa":
            from capa.main import main
            # Optional FLIRT databases are not shipped by flare-capa's wheel.
            # Explicitly disable library recognition rather than borrowing an
            # unreviewed external signature pack. This limitation is reported.
            signatures = Path.cwd() / "empty-flirt"
            signatures.mkdir()
            code = main(["-j", "-q", "-r", details["resource_path"], "-s", str(signatures), str(path)])
        elif engine == "floss":
            from floss.main import main
            code = main(["-j", "-q", str(path)])
        else:
            import speakeasy
            emulator = speakeasy.Speakeasy()
            module = emulator.load_module(str(path))
            emulator.run_module(module)
            output.write(json.dumps(emulator.get_report()))
            if callable(getattr(emulator, "shutdown", None)):
                emulator.shutdown()
            code = 0
    if code not in (0, None):
        return {"status": "error", "error": "Engine rejected or could not analyze this input", "engine_exit_code": code, "summary": {}, "diagnostic": errors.getvalue()[-2048:]}
    document = json.loads(output.getvalue())
    if not isinstance(document, dict):
        raise ValueError("Engine JSON root must be an object")
    if engine == "capa":
        rules = document.get("rules")
        if not isinstance(rules, dict):
            raise ValueError("Unsupported capa report schema")
        capabilities = []
        for name, value in rules.items():
            meta = value.get("meta", {})
            if meta.get("lib") or meta.get("namespace", "").startswith("internal/"):
                continue
            capabilities.append({"name": str(name)[:256], "namespace": str(meta.get("namespace", ""))[:256], "attack": meta.get("att&ck", [])[:32], "authors": meta.get("authors", []), "references": meta.get("references", []), "match_count": len(value.get("matches", []))})
        summary = {"capabilities": capabilities[:128], "capability_count": len(capabilities), "truncated": len(capabilities) > 128, "library_recognition": False, "meaning": "Program capabilities are observations, not proof of maliciousness; FLIRT library recognition disabled"}
    elif engine == "floss":
        strings = document.get("strings")
        if not isinstance(strings, dict):
            raise ValueError("Unsupported FLOSS report schema")
        items = []
        total = 0
        for category, values in strings.items():
            if not isinstance(values, list):
                continue
            total += len(values)
            for item in values:
                if len(items) >= 256:
                    break
                if isinstance(item, dict) and isinstance(item.get("string"), str):
                    items.append({"kind": str(category)[:64], "value": item["string"][:1024], "offset": item.get("offset")})
        summary = {"strings": items, "string_count": total, "truncated": total > len(items), "meaning": "Extracted strings are untrusted evidence, not a malware verdict"}
    else:
        entries = document.get("entry_points")
        if not isinstance(entries, list):
            raise ValueError("Unsupported Speakeasy report schema")
        calls, errors, count = [], [], 0
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            if entry.get("error"):
                error = entry["error"]
                if isinstance(error, dict):
                    errors.append({key: str(error[key])[:256] for key in ("type", "api_name", "message", "description", "pc", "address") if key in error})
                else:
                    errors.append({"description": str(error)[:1024]})
            apis = entry.get("apis", [])
            if not isinstance(apis, list):
                raise ValueError("Unsupported modeled API schema")
            count += len(apis)
            for call in apis:
                if len(calls) < 128 and isinstance(call, dict):
                    calls.append({"api_name": str(call.get("api_name", ""))[:256], "args": [str(a)[:512] for a in call.get("args", [])[:16]], "return_value": str(call.get("ret_val", ""))[:128]})
        if document.get("errors"):
            errors.append({"description": str(document["errors"])[:1024]})
        summary = {"entry_points": len(entries), "api_calls": count, "api_events": calls, "emulation_errors": errors[:16], "coverage_complete": bool(entries) and not errors, "truncated": count > len(calls), "meaning": "Modeled execution may omit real host behavior; no native sample execution; unsupported paths are explicitly listed"}
    after = inventory(engine, request)
    if any(after.get(k) != details[k] for k in ("version", "rule_digest")):
        raise ValueError("Engine resources changed during analysis")
    return {"status": "completed", "summary": summary, "report_digest": hashlib.sha256(json.dumps(document, sort_keys=True).encode()).hexdigest(), "verdict": "unknown", "engine_version": details["version"], "rule_digest": details["rule_digest"]}


def main():
    try:
        if os.name != "nt":
            import resource
            resource.setrlimit(resource.RLIMIT_AS, (2 * 1024**3, 2 * 1024**3))
            resource.setrlimit(resource.RLIMIT_CPU, (120, 125))
            resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_OUTPUT, MAX_OUTPUT))
        raw = sys.stdin.buffer.readline(65537)
        if len(raw) > 65536 or not raw.endswith(b"\n"):
            raise ValueError("Invalid request frame")
        result = run(json.loads(raw))
    except (Exception, SystemExit) as exc:
        result = {"status": "error", "error": type(exc).__name__ + ": " + str(exc)[:512], "summary": {}}
    encoded = json.dumps(result, ensure_ascii=True, separators=(",", ":"))
    if len(encoded) > MAX_OUTPUT:
        encoded = json.dumps({"status": "error", "error": "Summary output budget exceeded", "summary": {}})
    print(encoded)


if __name__ == "__main__":
    main()

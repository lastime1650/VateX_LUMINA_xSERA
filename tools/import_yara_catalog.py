"""Build a pinned, unchanged, module-free YARA catalog from public rule text.

Only .yar/.yara, top-level LICENSE and README text are fetched. No sample,
executable, repository script, compiled rule or remote code is loaded.
Network fetch is an explicit maintainer action, never a runtime dependency.
"""
import argparse
import concurrent.futures
import hashlib
import json
import re
import subprocess
import sys
from datetime import UTC, datetime
from functools import partial
from pathlib import Path, PurePosixPath
from urllib.parse import quote
from urllib.request import Request, urlopen

from sapientia.yara_runtime import isolated_command

SOURCES = {
    "signature_base": {"repository": "Neo23x0/signature-base", "commit": "94a1c48d7ab499879287ff611dfe7f9c56376030", "license": "DRL-1.1"},
    "reversinglabs": {"repository": "reversinglabs/reversinglabs-yara-rules", "commit": "e0a0be54aa1e11ccfd6854e4f19e9476f328fd84", "license": "MIT"},
    "bartblaze": {"repository": "bartblaze/Yara-rules", "commit": "5cc871d82361de8a80d387ec8bbd01fe4258b4a9", "license": "MIT"},
    "jpcert": {"repository": "JPCERTCC/jpcert-yara", "commit": "7837438e7bcb100bcc7f9d2be09152b19d967c0c", "license": "BSD-3-Clause"},
}
MAX_SOURCE_BYTES = 32768
MAX_STAGING_TEXT = 2 * 1024 * 1024
FORBIDDEN = re.compile(r"\b(?:include|import)\b")
LICENSE_ASSIGNMENT = re.compile(r"(?i)(?<![$\w])(?:license|licence|license_url|licence_url)\s*=(?!=)")
SPDX = re.compile(r"(?i)SPDX-License-Identifier:\s*([A-Za-z0-9.+_-]+)")
RESTRICTED = re.compile(r'(?i)(?:CC[\s_-]*BY[\s_-]*(?:NC|ND)|creativecommons\.org/licenses/[^\s"*]*(?:nc|nd)|non[\s-]?commercial|non[\s-]?derivative|research[\s-]+only)')
ALIASES = {
    "MIT": {"mit", "mit license", "https://opensource.org/licenses/mit", "https://opensource.org/license/mit"},
    "BSD-3-Clause": {"bsd-3-clause", "bsd 3-clause", "bsd 3-clause license", "the 3-clause bsd license"},
    "DRL-1.1": {"drl-1.1", "drl 1.1", "detection rule license 1.1", "detection rule license (drl) 1.1",
                "https://github.com/neo23x0/signature-base/blob/master/license", "https://raw.githubusercontent.com/neo23x0/signature-base/master/license",
                "detection rule license 1.1 https://github.com/neo23x0/signature-base/blob/master/license",
                "detection rule license 1.1 https://github.com/sigmahq/detection-rule-license",
                "https://github.com/sigmahq/detection-rule-license/blob/main/license.detection.rules.md"},
}
VALIDATOR = r"""
import json,sys
request=json.load(sys.stdin)
try:
 import yara
 rules=yara.compile(source=request["source"],includes=False,error_on_warning=True)
 matches=rules.match(data=b"xSERA harmless compatibility probe. No executable or malware is loaded.",timeout=1)
 print(json.dumps({"status":"completed","engine_version":yara.__version__,
  "rules":[{"identifier":r.identifier,"tags":r.tags,"meta":r.meta,"private":r.is_private,"global":r.is_global} for r in rules],
  "harmless_matches":[{"rule":m.rule,"meta":m.meta} for m in matches]},ensure_ascii=True,allow_nan=False))
except Exception as exc:
 print(json.dumps({"status":"failed","reason":type(exc).__name__+": "+str(exc)[:400]}))
"""


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def sha256(body):
    return hashlib.sha256(body).hexdigest()


def safe_path(value):
    if not isinstance(value, str):
        raise TypeError("Only relative upstream text paths are allowed")
    path = PurePosixPath(value)
    if not value or path.is_absolute() or "\\" in value or any(part in {"", ".", ".."} or ":" in part for part in path.parts):
        raise ValueError("Only relative upstream paths are allowed")
    return path


def fetch_text(url, maximum=MAX_STAGING_TEXT):
    with urlopen(Request(url, headers={"User-Agent": "xSERA-pinned-yara-rule-import"}), timeout=20) as response:
        body = response.read(maximum+1)
    if len(body) > maximum or b"\x00" in body:
        raise ValueError("Upstream text exceeds the bound or contains NUL")
    body.decode("utf-8-sig")
    return body


def fetch_upstreams(staging):
    """Explicit pinned fetch, not a general-purpose URL downloader."""
    for key, source in SOURCES.items():
        folder = staging/key
        folder.mkdir(parents=True, exist_ok=True)
        tree = json.loads(fetch_text("https://api.github.com/repos/"+source["repository"]+"/git/trees/"+source["commit"]+"?recursive=1", 4*1024*1024))
        if tree.get("truncated"):
            raise ValueError("Upstream tree was truncated")
        rows = [r for r in tree["tree"] if r["type"] == "blob" and r.get("mode") != "120000" and (
            r["path"].lower().endswith((".yar", ".yara")) or "/" not in r["path"] and r["path"].lower().startswith(("license", "readme")))]
        snapshot = {**source, "files": rows}
        for row in rows:
            relative = safe_path(row["path"])
            if row.get("size", 0) > MAX_STAGING_TEXT:
                continue
            destination = folder/"files"/relative
            if destination.is_file() and blob_valid(destination.read_bytes(), row):
                continue
            body = fetch_text("https://raw.githubusercontent.com/"+source["repository"]+"/"+source["commit"]+"/"+quote(row["path"], safe="/"))
            if not blob_valid(body, row):
                raise ValueError("Pinned upstream Git blob hash mismatch")
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(body)
        (folder/"snapshot.json").write_text(canonical(snapshot)+"\n", encoding="utf-8")


def blob_valid(body, row):
    expected = hashlib.sha1(b"blob "+str(len(body)).encode()+b"\0"+body).hexdigest()
    return expected == row["sha"] and len(body) == row["size"]


def lexical_sections(text):
    """Keep code positions, omitting strings/regex; return actual comments."""
    code, comments = list(text), []
    i = 0
    while i < len(text):
        start = i
        if text.startswith("/*", i):
            end = text.find("*/", i+2)
            i = len(text) if end < 0 else end+2
            comments.append(text[start:i])
        elif text.startswith("//", i):
            end = text.find("\n", i+2)
            i = len(text) if end < 0 else end
            comments.append(text[start:i])
        elif text[i] in {'"', '/'}:
            quote, bracket = text[i], False
            i += 1
            while i < len(text):
                character = text[i]
                if character == "\\":
                    i += 2
                    continue
                if quote == "/":
                    if character == "[": bracket = True
                    elif character == "]": bracket = False
                i += 1
                if character == quote and not bracket:
                    break
        else:
            i += 1
            continue
        for position in range(start, min(i, len(code))):
            if code[position] not in "\r\n":
                code[position] = " "
    return "".join(code), "\n".join(comments)


def license_review(text, default, rules=()):
    declarations = []
    code, comments = lexical_sections(text)
    for match in LICENSE_ASSIGNMENT.finditer(code):
        value = re.match(r'\s*"((?:[^"\\]|\\.)*)"', text[match.end():])
        if not value:
            return {"accepted": False, "reason": "unrecognized_license_value", "declarations": declarations}
        try:
            declarations.append(json.loads('"'+value[1]+'"'))
        except ValueError:
            return {"accepted": False, "reason": "unrecognized_license_escape", "declarations": [value[1]]}
    declarations.extend(SPDX.findall(comments))
    for match in re.finditer(r"(?im)^\s*(?://|\*|/\*)?\s*Licen[sc]e\s*[:=]\s*(.+)", comments):
        value = match[1].strip().removesuffix("*/").strip()
        if value.startswith('"') and value.endswith('"'):
            value = value[1:-1]
        declarations.append(value)
    comment_licenses = set()
    if re.search(r"(?i)\bMIT\s+License\b", comments):
        comment_licenses.add("MIT")
    if re.search(r"(?i)(?:\b(?:2|two)[ -]clause\s+BSD\b|\bBSD[ -](?:2|two)[ -]clause\b)", comments):
        comment_licenses.add("BSD-2-Clause")
    if re.search(r"(?i)(?:\b(?:3|three)[ -]clause\s+BSD\b|\bBSD[ -](?:3|three)[ -]clause\b)", comments):
        comment_licenses.add("BSD-3-Clause")
    if re.search(r"(?i)\b(?:GNU\s+General\s+Public|GPL(?:v?2|v?3)?)\b", comments):
        comment_licenses.add("GPL-not-selected")
    if re.search(r"(?i)\bApache\s+License\b", comments):
        comment_licenses.add("Apache-2.0")
    if re.search(r"(?i)\bRedistribution and use in source and binary forms\b", comments) and default != "BSD-3-Clause":
        comment_licenses.add("embedded-BSD-style-notice")
    declarations.extend(sorted(comment_licenses))
    for rule in rules:
        declarations.extend(value for key, value in rule.get("meta", {}).items() if key.lower() in {"license", "licence", "license_url", "licence_url"} and isinstance(value, str))
    declarations = sorted(set(declarations))
    if RESTRICTED.search(text):
        return {"accepted": False, "reason": "restricted_license_cue", "declarations": declarations}
    unknown = [value for value in declarations if value.strip().lower().rstrip("/") not in ALIASES[default]]
    if unknown:
        return {"accepted": False, "reason": "different_or_unrecognized_license_override", "declarations": declarations}
    return {"accepted": True, "basis": "matching_explicit_override" if declarations else "repository_license_inherited",
            "license": default, "declarations": declarations}


def quality_review(text, rules):
    code, _ = lexical_sections(text)
    conditions = {}
    for match in re.finditer(r"\brule\s+([A-Za-z_]\w*)\s*(?::[A-Za-z_\s\d]*)?\{", code):
        depth, end = 1, match.end()
        while end < len(code) and depth:
            if code[end] == "{": depth += 1
            elif code[end] == "}": depth -= 1
            end += 1
        body = code[match.end():end-1]
        condition = list(re.finditer(r"\bcondition\s*:", body))
        if condition:
            conditions[match[1]] = body[condition[-1].end():].strip()
    primitive = {"true", "false", "filesize", "entrypoint", "and", "or", "not", "KB", "MB", "GB",
                 "uint8", "uint16", "uint32", "uint8be", "uint16be", "uint32be", "int8", "int16", "int32", "int8be", "int16be", "int32be"}
    for rule in rules:
        if rule["private"]:
            continue
        condition = conditions.get(rule["identifier"])
        if condition is None:
            return {"accepted": False, "reason": "quality_condition_not_resolved", "rule": rule["identifier"]}
        category = str(rule["meta"].get("category", "")).casefold()
        if category in {"info", "informational", "filetype", "file_type", "test", "dummy"} or re.search(r"(?i)(?:^|_)(?:test|dummy|example|demo|filetype)(?:_|$)", rule["identifier"]):
            return {"accepted": False, "reason": "informational_or_test_rule", "rule": rule["identifier"]}
        tokens = set(re.findall(r"[A-Za-z_]\w*", re.sub(r"\b(?:0[xX][0-9a-fA-F]+|\d+)\b", " ", condition)))
        if tokens <= primitive and "$" not in condition:
            return {"accepted": False, "reason": "constant_size_or_header_only", "rule": rule["identifier"]}
    return {"accepted": True, "basis": "No public constant/size/header-only or explicit informational/test rule; not real-world precision validation"}

def validate_source(text):
    try:
        result = subprocess.run(isolated_command(VALIDATOR), input=canonical({"source": text}),
            text=True, encoding="utf-8", capture_output=True, timeout=3, check=False,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0)
    except subprocess.TimeoutExpired:
        return {"status": "failed", "reason": "validator_outer_deadline_3s"}
    if result.returncode or len(result.stdout.encode()) > 512*1024:
        return {"status": "failed", "reason": "validator_process_or_output_bound"}
    try:
        answer = json.loads(result.stdout)
    except ValueError:
        return {"status": "failed", "reason": "validator_invalid_json"}
    if not isinstance(answer, dict) or answer.get("status") not in {"completed", "failed"}:
        return {"status": "failed", "reason": "validator_invalid_result"}
    return answer


def assess_file(key, source, folder, row):
    relative = safe_path(row["path"])
    path = folder/"files"/relative
    base = {"source_id": key, "upstream_path": row["path"], "upstream_git_blob": row["sha"], "bytes": row.get("size")}
    if row.get("mode") == "120000":
        return {**base, "included": False, "reason": "upstream_symlink"}
    if not path.is_file():
        return {**base, "included": False, "reason": "staging_text_unavailable"}
    body = path.read_bytes()
    if not blob_valid(body, row):
        raise ValueError("Pinned Git blob changed: "+key+"/"+row["path"])
    base["sha256"] = sha256(body)
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return {**base, "included": False, "reason": "non_utf8_source"}
    review = license_review(text, source["license"])
    base["license_review"] = review
    if not review["accepted"]:
        return {**base, "included": False, "reason": review["reason"]}
    if len(body) > MAX_SOURCE_BYTES or len(text) > MAX_SOURCE_BYTES:
        return {**base, "included": False, "reason": "source_exceeds_32kib"}
    if any(ord(character)<32 and character not in "\t\r\n" for character in text):
        return {**base, "included": False, "reason": "source_control_character"}
    if FORBIDDEN.search(text):
        return {**base, "included": False, "reason": "include_import_keyword"}
    validation = validate_source(text)
    if validation["status"] != "completed":
        return {**base, "included": False, "reason": "compile_or_probe_failed", "detail": validation.get("reason")}
    rules = validation["rules"]
    review = license_review(text, source["license"], rules)
    base["license_review"] = review
    if not review["accepted"]:
        return {**base, "included": False, "reason": review["reason"]}
    if not any(not rule["private"] for rule in rules):
        return {**base, "included": False, "reason": "no_public_rules"}
    quality = quality_review(text, rules)
    if not quality["accepted"]:
        return {**base, "included": False, "reason": quality["reason"], "detail": quality.get("rule")}
    if validation["harmless_matches"]:
        return {**base, "included": False, "reason": "harmless_probe_matched"}
    authors = sorted({str(rule["meta"][name]) for rule in rules for name in ("author", "authors") if name in rule["meta"]})
    descriptions = list(dict.fromkeys(str(rule["meta"]["description"]) for rule in rules if "description" in rule["meta"]))
    identifier = "YC-"+sha256((source["repository"]+"\0"+row["path"]+"\0"+base["sha256"]).encode())[:24]
    return {**base, "included": True, "id": identifier, "name": relative.stem,
        "file_path": str(PurePosixPath("rules")/key/relative), "repository": source["repository"], "commit": source["commit"],
        "upstream_url": "https://github.com/"+source["repository"]+"/blob/"+source["commit"]+"/"+quote(row["path"], safe="/"),
        "license": source["license"], "license_file": "licenses/"+key+"-LICENSE.txt",
        "license_url": "https://github.com/"+source["repository"]+"/blob/"+source["commit"]+"/LICENSE",
        "author": "; ".join(authors), "authors": authors, "description": " / ".join(descriptions)[:2000],
        "rule_count": len(rules), "public_rule_count": sum(not rule["private"] for rule in rules), "rules": rules, "quality_review": quality,
        "validation": {"engine": "yara-python", "version": validation["engine_version"], "includes": False,
            "imports": False, "warnings_rejected": True, "compile_and_harmless_probe_passed": True,
            "outer_deadline_seconds": 3, "match_timeout_seconds": 1, "malware_samples_used": False}}


def build(staging, output):
    from collections import Counter
    entries, exclusions, sources = [], [], []
    duplicate_hashes = set()
    for key, source in SOURCES.items():
        folder = staging/key
        snapshot = json.loads((folder/"snapshot.json").read_text(encoding="utf-8"))
        if snapshot["repository"] != source["repository"] or snapshot["commit"] != source["commit"]:
            raise ValueError("Staging repository/commit differs from the source lock")
        license_row = next(row for row in snapshot["files"] if row["path"] == "LICENSE")
        notice = (folder/"files"/"LICENSE").read_bytes()
        if not blob_valid(notice, license_row):
            raise ValueError("Upstream license blob changed")
        output.joinpath("licenses").mkdir(parents=True, exist_ok=True)
        output.joinpath("licenses", key+"-LICENSE.txt").write_bytes(notice)
        rows = [row for row in snapshot["files"] if row["path"].lower().endswith((".yar", ".yara"))]
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(partial(assess_file, key, source, folder), rows))
        for result in results:
            if result["included"] and result["sha256"] in duplicate_hashes:
                result = {**result, "included": False, "reason": "duplicate_exact_source"}
            if result["included"]:
                duplicate_hashes.add(result["sha256"])
                destination = output/safe_path(result["file_path"])
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes((folder/"files"/safe_path(result["upstream_path"])).read_bytes())
                entries.append({k: v for k, v in result.items() if k != "included"})
            else:
                exclusions.append(result)
        accepted = [r for r in entries if r["source_id"] == key]
        rejected = [r for r in exclusions if r["source_id"] == key]
        sources.append({**source, "id": key, "upstream_url": "https://github.com/"+source["repository"],
            "license_file": "licenses/"+key+"-LICENSE.txt", "license_sha256": sha256(notice),
            "license_git_blob": license_row["sha"], "scanned_files": len(rows), "included_files": len(accepted),
            "rule_count": sum(r["rule_count"] for r in accepted), "public_rule_count": sum(r["public_rule_count"] for r in accepted),
            "excluded_files": len(rejected), "exclusion_reasons": dict(sorted(Counter(r["reason"] for r in rejected).items()))})
        print(key, len(accepted), "files", sum(r["public_rule_count"] for r in accepted), "public rules", flush=True)
    manifest = {"schema": "xsera.yara-catalog.v1", "revision": 1,
        "captured_utc": datetime.now(UTC).isoformat(), "sources": sources, "entries": sorted(entries, key=lambda e:e["id"]),
        "excluded": sorted(exclusions, key=lambda e:(e["source_id"],e["upstream_path"])),
        "constraints": {"maximum_source_bytes": MAX_SOURCE_BYTES, "source_text_unchanged": True, "includes": False, "imports": False,
            "license_policy": "Preserve repository license and accept only absent or identical explicit overrides; restricted/ambiguous/different overrides excluded.",
            "license_review_policy": "xsera.yara-license-review.v2-meta-and-comments",
            "quality_policy": "xsera.yara-default-detection-quality.v1",
            "private_helpers_counted_separately": True, "automatic_response": False, "zero_malware_samples": True}}
    manifest["file_count"] = len(entries)
    manifest["rule_count"] = sum(e["rule_count"] for e in entries)
    manifest["public_rule_count"] = sum(e["public_rule_count"] for e in entries)
    active_paths = {entry["file_path"] for entry in entries}
    # Explicitly remove obsolete rule files from this owned output directory:
    # licensing exclusions must not remain silently shipped outside manifest.
    boundary = output.resolve()
    for candidate in output.joinpath("rules").rglob("*"):
        if candidate.is_file() and candidate.suffix.lower() in {".yar", ".yara"} and candidate.relative_to(output).as_posix() not in active_paths:
            if not candidate.resolve().is_relative_to(boundary):
                raise ValueError("Refuse stale source cleanup outside catalog output")
            candidate.unlink()
    output.mkdir(parents=True, exist_ok=True)
    (output/"manifest.json").write_text(canonical(manifest)+"\n", encoding="utf-8")
    print(canonical({key:manifest[key] for key in ("file_count","rule_count","public_rule_count")}), flush=True)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--staging", type=Path)
    parser.add_argument("--output", type=Path, default=Path("sapientia/catalogs/yara"))
    parser.add_argument("--fetch", action="store_true", help="Explicitly fetch only pinned public rule/license text")
    parser.add_argument("--validate", action="store_true", help="Verify the installed catalog without network or rebuilding")
    args = parser.parse_args()
    if args.validate:
        from sapientia import yara_catalog
        print(canonical(yara_catalog.verify(compile_rules=True)))
        return
    if args.staging is None:
        parser.error("--staging is required to import")
    if args.fetch:
        fetch_upstreams(args.staging)
    build(args.staging, args.output)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
import os
import json
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
MAL_DIR = os.path.join(SCRIPT_DIR, "malicious-packages", "osv", "malicious")
OUT = os.path.join(SCRIPT_DIR, "data", "malicious_index.json")


def load_malicious_index():
    if not os.path.isdir(MAL_DIR):
        print(f"[!] Malicious packages not found at {MAL_DIR}", file=sys.stderr)
        return False

    idx = {}
    total_files = 0
    processed_files = 0

    print(f"[*] Using malicious packages from: {MAL_DIR}", file=sys.stderr)

    try:
        for root, dirs, files in os.walk(MAL_DIR):
            for f in files:
                if f.endswith(".json"):
                    total_files += 1
    except Exception as e:
        print(f"[!] Error counting files: {e}", file=sys.stderr)
        return False

    if total_files == 0:
        print(f"[!] No JSON files found in {MAL_DIR}", file=sys.stderr)
        return False

    print(f"[*] Indexing {total_files} malicious package definitions...", file=sys.stderr)

    try:
        for root, dirs, files in os.walk(MAL_DIR):
            for f in files:
                if not f.endswith(".json"):
                    continue

                processed_files += 1
                if processed_files % 100 == 0:
                    pct = (processed_files / total_files) * 100 if total_files > 0 else 0
                    print(f"[*] Indexing progress: {processed_files}/{total_files} ({pct:.0f}%)", file=sys.stderr)

                full_path = os.path.join(root, f)

                try:
                    with open(full_path, 'r', encoding='utf-8') as fp:
                        d = json.load(fp)
                        advisory_id = d.get("id", "")

                        for a in d.get("affected", []):
                            pkg = a.get("package", {})
                            name = pkg.get("name")

                            path_parts = root.split(os.sep)
                            ecosystem = None

                            for i, part in enumerate(path_parts):
                                if part == "malicious" and i + 1 < len(path_parts):
                                    ecosystem = path_parts[i + 1]
                                    break

                            if not (name and ecosystem):
                                continue

                            # --- THE FIX ---
                            # Previously this only recorded `idx[ecosystem][name] = True`,
                            # discarding the affected version data entirely, so every
                            # version of a flagged package matched. Now we capture the
                            # explicit "versions" list and any semver "ranges" from the
                            # OSV advisory, so matching can be version-aware.
                            explicit_versions = a.get("versions", []) or []

                            ranges = []
                            for r in a.get("ranges", []) or []:
                                ranges.append({
                                    "type": r.get("type", ""),
                                    "events": r.get("events", [])
                                })

                            if ecosystem not in idx:
                                idx[ecosystem] = {}
                            if name not in idx[ecosystem]:
                                idx[ecosystem][name] = {
                                    "versions": [],
                                    "ranges": [],
                                    "advisory_ids": []
                                }

                            entry = idx[ecosystem][name]
                            for v in explicit_versions:
                                if v not in entry["versions"]:
                                    entry["versions"].append(v)
                            for rg in ranges:
                                if rg not in entry["ranges"]:
                                    entry["ranges"].append(rg)
                            if advisory_id and advisory_id not in entry["advisory_ids"]:
                                entry["advisory_ids"].append(advisory_id)

                except json.JSONDecodeError as e:
                    print(f"[!] JSON decode error in {f}: {e}", file=sys.stderr)
                except Exception as e:
                    print(f"[!] Error processing {f}: {e}", file=sys.stderr)
    except Exception as e:
        print(f"[!] Error scanning directories: {e}", file=sys.stderr)
        return False

    try:
        os.makedirs(os.path.dirname(OUT), exist_ok=True)
    except Exception as e:
        print(f"[!] Error creating data directory: {e}", file=sys.stderr)
        return False

    try:
        with open(OUT, 'w') as fp:
            json.dump(idx, fp, indent=2)
    except Exception as e:
        print(f"[!] Error writing index file: {e}", file=sys.stderr)
        return False

    total_packages = sum(len(v) for v in idx.values())
    total_versions = sum(
        len(pkg_data["versions"])
        for eco_data in idx.values()
        for pkg_data in eco_data.values()
    )
    print(f"[+] Index built successfully: {total_packages} malicious packages indexed "
          f"({total_versions} known-malicious version pins)", file=sys.stderr)

    for eco in sorted(idx.keys()):
        count = len(idx[eco])
        if count > 0:
            print(f"    {eco}: {count} packages", file=sys.stderr)

    return True


if __name__ == "__main__":
    success = load_malicious_index()
    sys.exit(0 if success else 1)

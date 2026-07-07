#!/usr/bin/env python3
"""
Enhanced Risk Engine: OpenSSF + OSV Dataset Integration
Combines OpenSSF malicious packages database with OSV vulnerability database
for improved accuracy in detecting malicious and vulnerable packages.
"""

import sys
import json
import requests
import argparse
import os
import re
from datetime import datetime, timedelta
from difflib import SequenceMatcher
from pathlib import Path
import hashlib
from typing import Dict, List, Optional, Tuple

# ============================================================================
# CONFIGURATION & SETUP
# ============================================================================

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
MAL_DB_PATH = os.path.join(SCRIPT_DIR, "data", "malicious_index.json")
OSV_CACHE_DIR = os.path.join(SCRIPT_DIR, "osv-data")
OSV_CACHE_VALIDITY = timedelta(hours=24)

# Ensure directories exist
os.makedirs(os.path.dirname(MAL_DB_PATH), exist_ok=True)
os.makedirs(OSV_CACHE_DIR, exist_ok=True)

# Load OpenSSF malicious packages index
try:
    with open(MAL_DB_PATH) as f:
        MAL_DB = json.load(f)
except FileNotFoundError:
    MAL_DB = {}

# Common/popular packages for typosquatting detection
POPULAR = ["requests", "flask", "django", "lodash", "react", "express",
           "numpy", "pandas", "tensorflow", "pytest", "pip", "setuptools"]

# Ecosystem mappings
ECOSYSTEM_MAPPINGS = {
    "pypi": {"osv_name": "PyPI", "api_domain": "pypi.org"},
    "npm": {"osv_name": "npm", "api_domain": "npmjs.org"},
    "maven": {"osv_name": "Maven", "api_domain": "maven.org"},
    "rubygems": {"osv_name": "RubyGems", "api_domain": "rubygems.org"},
    "nuget": {"osv_name": "NuGet", "api_domain": "nuget.org"},
    "golang": {"osv_name": "Go", "api_domain": "golang.org"},
    "go": {"osv_name": "Go", "api_domain": "golang.org"},
    "crates": {"osv_name": "crates.io", "api_domain": "crates.io"},
    "packagist": {"osv_name": "Packagist", "api_domain": "packagist.org"},
}

# ============================================================================
# UTILITIES
# ============================================================================

def similarity(a: str, b: str) -> float:
    """Calculate string similarity ratio"""
    return SequenceMatcher(None, a.lower(), b.lower()).ratio()

def get_osv_cache_path(purl: str) -> str:
    """Get cache file path for OSV query"""
    purl_hash = hashlib.sha256(purl.encode()).hexdigest()[:12]
    return os.path.join(OSV_CACHE_DIR, f"{purl_hash}.json")

def is_cache_valid(cache_path: str) -> bool:
    """Check if cache file is still valid"""
    if not os.path.exists(cache_path):
        return False
    try:
        cached_time = datetime.fromisoformat(
            json.load(open(cache_path))["cached_at"]
        )
        return datetime.now() - cached_time < OSV_CACHE_VALIDITY
    except Exception:
        return False

# ============================================================================
# VERSION COMPARISON (generic, dependency-free)
# ============================================================================
# OSV advisories express affected versions either as an explicit list
# ("versions": ["1.2.3", "1.2.4"]) or as semver-style ranges ("ranges":
# [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]).
# This is a lightweight, dependency-free comparator good enough for the
# dotted-numeric versions used by npm/PyPI/etc. It intentionally does not
# try to be a full semver/PEP440 implementation.

def _parse_version(v: str) -> Tuple[int, ...]:
    """Parse a version string into a comparable tuple of ints.
    Strips prerelease/build metadata (anything after '-' or '+')."""
    if v is None:
        return (0,)
    core = re.split(r"[-+]", v, 1)[0]
    parts = core.split(".")
    out = []
    for p in parts:
        m = re.match(r"\d+", p)
        out.append(int(m.group()) if m else 0)
    return tuple(out) if out else (0,)

def _cmp_versions(a: str, b: str) -> int:
    """Return -1, 0, or 1 comparing version a to version b."""
    ta, tb = _parse_version(a), _parse_version(b)
    length = max(len(ta), len(tb))
    ta = ta + (0,) * (length - len(ta))
    tb = tb + (0,) * (length - len(tb))
    if ta < tb:
        return -1
    if ta > tb:
        return 1
    return 0

def _version_in_ranges(version: str, ranges: List[Dict]) -> bool:
    """Check whether `version` falls inside any OSV-style range."""
    for r in ranges or []:
        if r.get("type") not in ("SEMVER", "ECOSYSTEM"):
            continue
        events = r.get("events", [])
        introduced = None
        fixed = None
        last_affected = None
        for e in events:
            if "introduced" in e:
                introduced = e["introduced"]
            if "fixed" in e:
                fixed = e["fixed"]
            if "last_affected" in e:
                last_affected = e["last_affected"]

        if introduced is not None and introduced != "0":
            if _cmp_versions(version, introduced) < 0:
                continue
        if fixed is not None:
            if _cmp_versions(version, fixed) >= 0:
                continue
        if last_affected is not None:
            if _cmp_versions(version, last_affected) > 0:
                continue
        return True
    return False

# ============================================================================
# OPENSSF CHECKS
# ============================================================================

def check_openssf(package: str, ecosystem: str, version: Optional[str] = None) -> Dict:
    """
    Check package against OpenSSF malicious packages database.

    THE FIX: this now takes `version` and only reports a CRITICAL / MALICIOUS_KNOWN
    match when the queried version actually falls within the advisory's affected
    versions/ranges. Previously this matched on package name alone, so every
    version of a package that ever had *any* malicious release (e.g. ansi-styles,
    color, chalk) was flagged CRITICAL, even versions published years before the
    compromise.

    If no version is supplied, we can't confirm an exact match, so we surface a
    lower-confidence NEEDS_REVIEW finding instead of a false CRITICAL, and list
    the actually-known-malicious versions so the caller can compare manually.

    Returns: {"found": bool, "matches": [], "risk_level": str, "risk_score": int}
    """
    result = {
        "source": "openssf",
        "found": False,
        "matches": [],
        "risk_level": "SAFE",
        "risk_score": 0
    }

    eco = ecosystem.lower()

    if eco not in MAL_DB:
        return result

    for mal_pkg, entry in MAL_DB[eco].items():
        if mal_pkg.lower() != package.lower():
            continue

        # Backward-compat: tolerate an old-format index (bool) if someone
        # hasn't rebuilt it yet, by treating it as "no version data available".
        if not isinstance(entry, dict):
            entry = {"versions": [], "ranges": [], "advisory_ids": []}

        known_versions = entry.get("versions", [])
        ranges = entry.get("ranges", [])
        advisory_ids = entry.get("advisory_ids", [])

        if version:
            version_matches = (
                version in known_versions or _version_in_ranges(version, ranges)
            )
            if version_matches:
                result["found"] = True
                result["risk_level"] = "CRITICAL"
                result["risk_score"] = 100
                result["matches"].append({
                    "package": mal_pkg,
                    "ecosystem": eco,
                    "type": "MALICIOUS_KNOWN",
                    "matched_version": version,
                    "known_malicious_versions": known_versions,
                    "advisory_ids": advisory_ids,
                    "description": "Version confirmed in OpenSSF malicious packages database"
                })
            # else: name matches a package with a known bad release, but this
            # specific version isn't one of them -> leave as SAFE (no match).
        else:
            # No version provided at all (e.g. a bare package-name lookup).
            # Don't claim CRITICAL without evidence this version is affected.
            result["found"] = True
            result["risk_level"] = "HIGH"
            result["risk_score"] = 60
            result["matches"].append({
                "package": mal_pkg,
                "ecosystem": eco,
                "type": "NEEDS_VERSION_CHECK",
                "known_malicious_versions": known_versions,
                "advisory_ids": advisory_ids,
                "description": (
                    "Package has known malicious version(s) in OpenSSF database, "
                    "but no version was supplied to confirm an exact match"
                )
            })
        break

    return result

# ============================================================================
# OSV API CHECKS
# ============================================================================

def build_purl(package: str, ecosystem: str, version: Optional[str] = None) -> str:
    """Build a Package URL (PURL) for OSV queries"""
    purl = f"pkg:{ecosystem}/{package}"
    if version:
        purl += f"@{version}"
    return purl

def query_osv_api(purl: str) -> Optional[Dict]:
    """
    Query OSV API for vulnerabilities
    Returns API response or None if error
    """
    try:
        url = "https://api.osv.dev/v1/query"
        payload = {"package": {"purl": purl}}

        response = requests.post(
            url,
            json=payload,
            timeout=10,
            headers={"User-Agent": "mallscan-enhanced/1.0"}
        )

        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            return {"vulns": []}
        else:
            print(f"[!] OSV API error {response.status_code}", file=sys.stderr)
            return None
    except requests.exceptions.Timeout:
        print(f"[!] OSV API timeout for {purl}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"[!] OSV API error: {e}", file=sys.stderr)
        return None

def check_osv(package: str, ecosystem: str, version: Optional[str] = None) -> Dict:
    """
    Check package against OSV vulnerability database
    Returns: {"found": bool, "vulnerabilities": [], "risk_score": int}
    """
    result = {
        "source": "osv",
        "found": False,
        "vulnerabilities": [],
        "risk_level": "SAFE",
        "risk_score": 0
    }

    purl = build_purl(package, ecosystem, version)
    cache_path = get_osv_cache_path(purl)

    # Try cache first
    osv_data = None
    if is_cache_valid(cache_path):
        try:
            cached = json.load(open(cache_path))
            osv_data = cached["data"]
        except Exception:
            pass

    # Query API if not cached
    if osv_data is None:
        osv_data = query_osv_api(purl)
        if osv_data is None:
            result["risk_level"] = "UNKNOWN"
            return result

        # Cache the result
        try:
            cache_data = {
                "purl": purl,
                "cached_at": datetime.now().isoformat(),
                "data": osv_data
            }
            with open(cache_path, 'w') as f:
                json.dump(cache_data, f)
        except Exception as e:
            print(f"[!] Failed to cache OSV data: {e}", file=sys.stderr)

    # Process vulnerabilities
    vulns = osv_data.get("vulns", [])
    if vulns:
        result["found"] = True

        # Calculate risk score based on severity
        severity_scores = {"CRITICAL": 100, "HIGH": 80, "MEDIUM": 50, "LOW": 20}
        max_score = 0

        for vuln in vulns:
            vuln_entry = {
                "id": vuln.get("id", ""),
                "summary": vuln.get("summary", ""),
                "published": vuln.get("published", ""),
                "severity": "",
                "affected_ranges": []
            }

            # Extract severity if available
            severity = "MEDIUM"  # default
            if "severity" in vuln:
                severity = vuln["severity"][0].get("type", "MEDIUM")
            elif "details" in vuln:
                details = vuln["details"].lower()
                if "critical" in details or "critical impact" in details:
                    severity = "CRITICAL"
                elif "high" in details:
                    severity = "HIGH"

            vuln_entry["severity"] = severity

            # Check if version is affected
            if version and "affected" in vuln:
                affected = vuln["affected"]
                for aff in affected:
                    if aff.get("package", {}).get("name", "").lower() == package.lower():
                        ranges = aff.get("ranges", [])
                        vuln_entry["affected_ranges"] = ranges

            result["vulnerabilities"].append(vuln_entry)
            max_score = max(max_score, severity_scores.get(severity, 20))

        result["risk_score"] = max_score

        # Determine risk level
        if max_score >= 80:
            result["risk_level"] = "CRITICAL"
        elif max_score >= 50:
            result["risk_level"] = "HIGH"
        elif max_score >= 20:
            result["risk_level"] = "MEDIUM"
        else:
            result["risk_level"] = "LOW"

    return result

# ============================================================================
# HEURISTIC CHECKS
# ============================================================================

def check_typosquatting(package: str) -> Tuple[bool, List[str]]:
    """Detect potential typosquatting"""
    candidates = []
    for popular in POPULAR:
        if similarity(package, popular) > 0.75 and package.lower() != popular.lower():
            candidates.append(popular)
    return len(candidates) > 0, candidates

def check_new_package(package: str, ecosystem: str) -> Tuple[bool, Optional[int]]:
    """Check if package is suspiciously new"""
    try:
        if ecosystem == "pypi":
            r = requests.get(f"https://pypi.org/pypi/{package}/json", timeout=5)
            if r.status_code == 200:
                data = r.json()
                releases = data.get("releases", {})
                if releases:
                    first_release = list(releases.keys())[0]
                    first_upload = releases[first_release][0]["upload_time_iso_8601"]
                    upload_date = datetime.fromisoformat(first_upload.replace("Z", "+00:00"))
                    age_days = (datetime.now(upload_date.tzinfo) - upload_date).days
                    if age_days < 7:
                        return True, age_days

        elif ecosystem == "npm":
            r = requests.get(f"https://registry.npmjs.org/{package}", timeout=5)
            if r.status_code == 200:
                data = r.json()
                created = data.get("time", {}).get("created")
                if created:
                    created_date = datetime.fromisoformat(created.replace("Z", "+00:00"))
                    age_days = (datetime.now(created_date.tzinfo) - created_date).days
                    if age_days < 7:
                        return True, age_days
    except Exception:
        pass

    return False, None

def check_low_popularity(package: str, ecosystem: str) -> Tuple[bool, Optional[int]]:
    """Check for suspiciously low popularity"""
    try:
        if ecosystem == "npm":
            r = requests.get(f"https://registry.npmjs.org/{package}", timeout=5)
            if r.status_code == 200:
                data = r.json()
                version_count = len(data.get("versions", {}))
                if version_count < 3:
                    return True, version_count
    except Exception:
        pass

    return False, None

def run_heuristic_checks(package: str, ecosystem: str) -> List[Dict]:
    """Run all heuristic checks"""
    risks = []

    # Typosquatting check
    is_typo, candidates = check_typosquatting(package)
    if is_typo:
        risks.append({
            "type": "TYPOSQUAT",
            "severity": "MEDIUM",
            "description": f"Resembles legitimate package(s): {', '.join(candidates)}",
            "score": 40
        })

    # New package check
    is_new, age = check_new_package(package, ecosystem)
    if is_new:
        risks.append({
            "type": "NEW_PACKAGE",
            "severity": "LOW",
            "description": f"Published {age} day(s) ago",
            "score": 20
        })

    # Low popularity check
    is_unpopular, count = check_low_popularity(package, ecosystem)
    if is_unpopular:
        risks.append({
            "type": "LOW_POPULARITY",
            "severity": "LOW",
            "description": f"Only {count} version(s) published",
            "score": 15
        })

    return risks

# ============================================================================
# RESULT COMBINATION & SCORING
# ============================================================================

def combine_results(
    openssf_result: Dict,
    osv_result: Dict,
    heuristic_risks: List[Dict]
) -> Dict:
    """
    Combine results from all sources
    OpenSSF (malicious) > OSV (vulnerabilities) > Heuristics
    """
    combined = {
        "package": "",
        "ecosystem": "",
        "version": "",
        "timestamp": datetime.now().isoformat(),
        "sources": {
            "openssf": openssf_result,
            "osv": osv_result,
            "heuristics": heuristic_risks
        },
        "findings": [],
        "risk_level": "SAFE",
        "risk_score": 0
    }

    # If found in OpenSSF (malicious), highest priority
    if openssf_result["found"]:
        combined["risk_level"] = openssf_result["risk_level"]
        combined["risk_score"] = openssf_result["risk_score"]
        combined["findings"].append({
            "category": "MALICIOUS",
            "source": "openssf",
            "description": "Package matched OpenSSF malicious packages database",
            "details": openssf_result["matches"]
        })
        # A confirmed CRITICAL match short-circuits (this is a genuine hit).
        # A HIGH "needs version check" finding still lets OSV/heuristics add
        # more context below rather than masking everything.
        if openssf_result["risk_level"] == "CRITICAL":
            return combined

    # OSV vulnerabilities
    if osv_result["found"]:
        combined["findings"].append({
            "category": "VULNERABILITIES",
            "source": "osv",
            "count": len(osv_result["vulnerabilities"]),
            "details": osv_result["vulnerabilities"]
        })
        combined["risk_score"] = max(combined["risk_score"], osv_result["risk_score"])

    # Heuristic risks
    if heuristic_risks:
        combined["findings"].append({
            "category": "HEURISTICS",
            "source": "heuristics",
            "count": len(heuristic_risks),
            "details": heuristic_risks
        })
        heuristic_score = sum(r.get("score", 0) for r in heuristic_risks)
        combined["risk_score"] = min(combined["risk_score"] + heuristic_score, 100)

    # Determine final risk level (skip if openssf already set CRITICAL and returned above)
    if combined["risk_score"] >= 80:
        combined["risk_level"] = "CRITICAL"
    elif combined["risk_score"] >= 50:
        combined["risk_level"] = "HIGH"
    elif combined["risk_score"] >= 20:
        combined["risk_level"] = "MEDIUM"
    else:
        combined["risk_level"] = combined["risk_level"] if combined["risk_level"] != "SAFE" else "SAFE"

    return combined

# ============================================================================
# TERMINAL OUTPUT FORMATTING
# ============================================================================

def format_terminal_output(result: Dict) -> int:
    """Format and print results for terminal"""
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    MAGENTA = '\033[0;35m'
    NC = '\033[0m'

    # Status indicators
    risk_level = result["risk_level"]
    risk_score = result["risk_score"]

    if risk_level == "CRITICAL":
        status = f"{RED}🚨 CRITICAL{NC}"
        color = RED
    elif risk_level == "HIGH":
        status = f"{YELLOW}⚠️  HIGH RISK{NC}"
        color = YELLOW
    elif risk_level == "MEDIUM":
        status = f"{YELLOW}⚠️  CAUTION{NC}"
        color = YELLOW
    else:
        status = f"{GREEN}✅ SAFE{NC}"
        color = GREEN

    # Header
    print(f"\n{BLUE}{'='*70}{NC}")
    print(f"{BLUE}Package Analysis Report (OpenSSF + OSV){NC}")
    print(f"{BLUE}{'='*70}{NC}\n")

    # Basic info
    print(f"Package:      {result.get('package', 'N/A')}")
    print(f"Ecosystem:    {result.get('ecosystem', 'N/A')}")
    if result.get('version'):
        print(f"Version:      {result['version']}")
    print(f"Status:       {status}")
    print(f"Risk Score:   {color}{risk_score}/100{NC}")
    print(f"Timestamp:    {result['timestamp']}\n")

    # Findings
    findings = result.get("findings", [])
    if findings:
        print(f"{MAGENTA}Findings:{NC}")
        for i, finding in enumerate(findings, 1):
            category = finding["category"]
            source = finding["source"]

            if category == "MALICIOUS":
                print(f"\n  {i}. {RED}[{source.upper()}] MALICIOUS PACKAGE{NC}")
                for match in finding["details"]:
                    print(f"     - {match['description']}")
                    if match.get("matched_version"):
                        print(f"       Matched version: {match['matched_version']}")
                    if match.get("known_malicious_versions"):
                        print(f"       Known malicious versions: {', '.join(match['known_malicious_versions'])}")

            elif category == "VULNERABILITIES":
                count = finding["count"]
                print(f"\n  {i}. {YELLOW}[{source.upper()}] {count} VULNERABILITY/IES{NC}")
                for vuln in finding["details"][:3]:  # Show top 3
                    severity = vuln.get("severity", "UNKNOWN")
                    sev_color = RED if severity == "CRITICAL" else YELLOW if severity in ["HIGH", "MEDIUM"] else GREEN
                    print(f"     - {vuln['id']}: {vuln['summary'][:60]}...")
                    print(f"       Severity: {sev_color}{severity}{NC}")

            elif category == "HEURISTICS":
                count = finding["count"]
                print(f"\n  {i}. {YELLOW}[{source.upper()}] {count} HEURISTIC RISK(S){NC}")
                for risk in finding["details"]:
                    print(f"     - {risk['type']}: {risk['description']}")
    else:
        print(f"{GREEN}No risks detected{NC}")

    print(f"\n{BLUE}{'='*70}{NC}\n")

    # Return exit code
    return 0 if risk_level == "SAFE" else 1

# ============================================================================
# MAIN LOGIC
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Enhanced package security scanner (OpenSSF + OSV)"
    )
    parser.add_argument("--name", required=True, help="Package name")
    parser.add_argument("--ecosystem", required=True, help="Package ecosystem (pypi, npm, etc.)")
    parser.add_argument("--version", help="Package version (optional)")
    parser.add_argument("--terminal", action="store_true", help="Format output for terminal")
    parser.add_argument("--combine-sources", action="store_true", help="Combine all sources (default)")

    args = parser.parse_args()

    package = args.name
    ecosystem = args.ecosystem.lower()
    version = args.version

    # Run checks from all sources
    openssf_result = check_openssf(package, ecosystem, version)
    osv_result = check_osv(package, ecosystem, version)
    heuristic_risks = run_heuristic_checks(package, ecosystem)

    # Combine results
    combined = combine_results(openssf_result, osv_result, heuristic_risks)
    combined["package"] = package
    combined["ecosystem"] = ecosystem
    if version:
        combined["version"] = version

    # Output
    if args.terminal:
        exit_code = format_terminal_output(combined)
    else:
        print(json.dumps(combined, indent=2))
        exit_code = 0

    sys.exit(exit_code)

if __name__ == "__main__":
    main()

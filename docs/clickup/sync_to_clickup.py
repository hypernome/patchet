#!/usr/bin/env python3
"""
sync_to_clickup.py — sync the breach-replay markdown into ClickUp.

Idempotent: re-running this script will UPDATE existing pages by name rather
than create duplicates. Run --dry-run first to inspect the planned API calls
without touching the workspace.

Required env vars (source /Users/ago/.clickup_creds first):
    CLICKUP_TOKEN
    CLICKUP_WORKSPACE_ID
    CLICKUP_SPACE_ID

Source-of-truth: the markdown file.
ClickUp side: derived from the markdown on every run. Manual edits in
ClickUp WILL be overwritten on the next sync — keep edits in the .md file.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests

API_BASE = "https://api.clickup.com/api"

# Canonical ClickUp names that this script manages.
FOLDER_NAME = "Real World Breaches"
DOC_NAME = "Patchet vs OAuth — Real-World Breach Replays"

# Use-case page titles in the order they should appear under the parent.
USE_CASE_TITLES: Dict[str, str] = {
    "T1": "T1 — Identity Spoofing (SolarWinds replay)",
    "T7": "T7 — Cross-Agent Privilege Escalation (Uber replay)",
    "T2": "T2 — Token Replay (Okta replay)",
}

DEFAULT_MD = Path(__file__).parent / "real_world_breaches.md"


# ──────────────────────────────────────────────────────────────────────────
# Markdown parsing
# ──────────────────────────────────────────────────────────────────────────


def parse_markdown(md_path: Path) -> Dict[str, Any]:
    """Split the markdown into a parent overview + per-use-case child sections.

    Returns:
        {
          "parent_content": <markdown for the top-level page>,
          "children": [
            {"key": "T1", "title": "...", "content": <markdown>},
            {"key": "T7", ...},
            {"key": "T2", ...},
          ],
        }
    """
    text = md_path.read_text()
    # Split on H1 boundaries (the lookahead keeps the heading line attached
    # to its content). Also strip horizontal-rule separators that sit
    # between sections.
    parts = re.split(r"\n(?=# [^#])", text)

    parent_chunks: List[str] = []
    children: Dict[str, str] = {}

    use_case_re = re.compile(r"^# Use Case \d+ — (T\d+) —", re.MULTILINE)

    for chunk in parts:
        chunk = chunk.strip()
        if not chunk:
            continue
        m = use_case_re.search(chunk)
        if m:
            key = m.group(1)
            # Strip the "Use Case N — " prefix from the H1 so the page's
            # own H1 inside ClickUp reads cleanly: "# T1 — Identity ..."
            cleaned = re.sub(
                r"^# Use Case \d+ — ", "# ", chunk, count=1, flags=re.MULTILINE
            )
            # Drop trailing horizontal-rule separators if present.
            cleaned = re.sub(r"\n+---\s*$", "", cleaned)
            children[key] = cleaned
        else:
            # Drop trailing horizontal-rule separators.
            cleaned = re.sub(r"\n+---\s*$", "", chunk)
            parent_chunks.append(cleaned)

    parent_content = "\n\n".join(parent_chunks).strip()

    children_ordered: List[Dict[str, str]] = []
    for key in ("T1", "T7", "T2"):
        if key in children:
            children_ordered.append(
                {
                    "key": key,
                    "title": USE_CASE_TITLES[key],
                    "content": children[key],
                }
            )
        else:
            print(f"WARNING: no use-case section found for {key}", file=sys.stderr)

    return {"parent_content": parent_content, "children": children_ordered}


# ──────────────────────────────────────────────────────────────────────────
# ClickUp API client
# ──────────────────────────────────────────────────────────────────────────


class ClickUp:
    def __init__(self, token: str, workspace_id: str, space_id: str, dry_run: bool):
        self.token = token
        self.workspace_id = workspace_id
        self.space_id = space_id
        self.dry_run = dry_run
        self.session = requests.Session()
        self.session.headers.update(
            {"Authorization": token, "Content-Type": "application/json"}
        )

    def _req(self, method: str, url: str, **kwargs) -> Dict[str, Any]:
        r = self.session.request(method, url, timeout=30, **kwargs)
        if r.status_code >= 400:
            print(f"  HTTP {r.status_code} {method} {url}", file=sys.stderr)
            print(f"  body: {r.text[:600]}", file=sys.stderr)
            r.raise_for_status()
        if not r.text:
            return {}
        return r.json()

    # ---- folders ----

    def find_folder(self, name: str) -> Optional[Dict]:
        url = f"{API_BASE}/v2/space/{self.space_id}/folder?archived=false"
        data = self._req("GET", url)
        for f in data.get("folders", []):
            if f.get("name") == name:
                return f
        return None

    def create_folder(self, name: str) -> Dict:
        if self.dry_run:
            print(f"  [DRY-RUN] would CREATE folder: {name!r}")
            return {"id": "<dry-run>", "name": name}
        url = f"{API_BASE}/v2/space/{self.space_id}/folder"
        return self._req("POST", url, json={"name": name})

    # ---- docs ----

    def find_doc_in_folder(self, folder_id: str, name: str) -> Optional[Dict]:
        url = (
            f"{API_BASE}/v3/workspaces/{self.workspace_id}/docs"
            f"?parent_id={folder_id}&parent_type=5"
            f"&deleted=false&archived=false&limit=100"
        )
        data = self._req("GET", url)
        for d in data.get("docs", []):
            if d.get("name") == name:
                return d
        return None

    def create_doc(self, folder_id: str, name: str) -> Dict:
        if self.dry_run:
            print(f"  [DRY-RUN] would CREATE doc: {name!r} in folder {folder_id}")
            return {"id": "<dry-run>", "name": name}
        url = f"{API_BASE}/v3/workspaces/{self.workspace_id}/docs"
        body = {
            "name": name,
            "parent": {"id": folder_id, "type": 5},  # 5 = folder
            "visibility": "PUBLIC",
            "create_page": True,
        }
        return self._req("POST", url, json=body)

    # ---- pages ----

    def list_pages(self, doc_id: str) -> List[Dict]:
        # max_page_depth=-1 returns the full tree.
        url = (
            f"{API_BASE}/v3/workspaces/{self.workspace_id}/docs/{doc_id}/pageListing"
            f"?max_page_depth=-1"
        )
        data = self._req("GET", url)
        # Response is either a list (older API) or {"pages": [...]} — normalize.
        if isinstance(data, list):
            return _flatten_pages(data)
        return _flatten_pages(data.get("pages", []))

    def create_page(
        self,
        doc_id: str,
        name: str,
        content: str,
        parent_page_id: Optional[str] = None,
    ) -> Dict:
        kind = "child" if parent_page_id else "top-level"
        if self.dry_run:
            print(
                f"  [DRY-RUN] would CREATE {kind} page {name!r} "
                f"({len(content):,} chars)"
            )
            return {"id": "<dry-run>", "name": name}
        url = f"{API_BASE}/v3/workspaces/{self.workspace_id}/docs/{doc_id}/pages"
        body: Dict[str, Any] = {
            "name": name,
            "content": content,
            "content_format": "text/md",
        }
        if parent_page_id:
            body["parent_page_id"] = parent_page_id
        return self._req("POST", url, json=body)

    def update_page(
        self, doc_id: str, page_id: str, name: str, content: str
    ) -> Dict:
        if self.dry_run:
            print(
                f"  [DRY-RUN] would UPDATE page {name!r} "
                f"({len(content):,} chars)"
            )
            return {"id": page_id, "name": name}
        url = (
            f"{API_BASE}/v3/workspaces/{self.workspace_id}"
            f"/docs/{doc_id}/pages/{page_id}"
        )
        body = {
            "name": name,
            "content": content,
            "content_format": "text/md",
            "content_edit_mode": "replace",
        }
        return self._req("PUT", url, json=body)


def _flatten_pages(tree: List[Dict]) -> List[Dict]:
    """ClickUp returns nested pages (each with a 'pages' or 'children' key).
    Flatten so we can search by name regardless of depth."""
    flat: List[Dict] = []
    for node in tree or []:
        flat.append(node)
        for key in ("pages", "children"):
            if key in node and isinstance(node[key], list):
                flat.extend(_flatten_pages(node[key]))
    return flat


def find_page(pages: List[Dict], name: str) -> Optional[Dict]:
    for p in pages:
        if p.get("name") == name:
            return p
    return None


# ──────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="Show planned actions without calling write endpoints.",
    )
    ap.add_argument(
        "--md-file",
        type=Path,
        default=DEFAULT_MD,
        help=f"Source markdown file (default: {DEFAULT_MD}).",
    )
    args = ap.parse_args()

    token = os.environ.get("CLICKUP_TOKEN")
    workspace_id = os.environ.get("CLICKUP_WORKSPACE_ID")
    space_id = os.environ.get("CLICKUP_SPACE_ID")

    missing = [
        n
        for n, v in [
            ("CLICKUP_TOKEN", token),
            ("CLICKUP_WORKSPACE_ID", workspace_id),
            ("CLICKUP_SPACE_ID", space_id),
        ]
        if not v
    ]
    if missing:
        print(f"ERROR: missing env vars: {', '.join(missing)}", file=sys.stderr)
        print(
            "Hint: source /Users/ago/.clickup_creds before running this script.",
            file=sys.stderr,
        )
        return 2

    if not args.md_file.exists():
        print(f"ERROR: markdown file not found: {args.md_file}", file=sys.stderr)
        return 2

    print(f"Source:    {args.md_file}")
    print(f"Workspace: {workspace_id}")
    print(f"Space:     {space_id}")
    print(f"Dry run:   {args.dry_run}")
    print()

    parsed = parse_markdown(args.md_file)
    print(f"Parsed parent overview: {len(parsed['parent_content']):,} chars")
    print(f"Parsed {len(parsed['children'])} child sections:")
    for c in parsed["children"]:
        print(f"  {c['key']:>3}  {c['title']!r}  ({len(c['content']):,} chars)")
    print()

    cu = ClickUp(token, workspace_id, space_id, dry_run=args.dry_run)

    # Step 1 — folder
    print("Step 1/4: Folder")
    folder = cu.find_folder(FOLDER_NAME)
    if folder:
        print(f"  ✓ found existing folder {folder['name']!r} (id={folder['id']})")
    else:
        folder = cu.create_folder(FOLDER_NAME)
        print(f"  ✓ created folder {folder['name']!r} (id={folder['id']})")

    # Step 2 — doc
    print("\nStep 2/4: Doc")
    doc = cu.find_doc_in_folder(folder["id"], DOC_NAME)
    if doc:
        print(f"  ✓ found existing doc {doc['name']!r} (id={doc['id']})")
    else:
        doc = cu.create_doc(folder["id"], DOC_NAME)
        print(f"  ✓ created doc {doc['name']!r} (id={doc['id']})")

    # Step 3 — parent page (the doc's root page, same name as the doc)
    print("\nStep 3/4: Parent page")
    pages = [] if args.dry_run else cu.list_pages(doc["id"])
    parent_page = find_page(pages, DOC_NAME)
    if parent_page:
        cu.update_page(
            doc["id"], parent_page["id"], DOC_NAME, parsed["parent_content"]
        )
        print(f"  ✓ updated parent page (id={parent_page['id']})")
    else:
        parent_page = cu.create_page(doc["id"], DOC_NAME, parsed["parent_content"])
        print(f"  ✓ created parent page (id={parent_page['id']})")

    # Step 4 — child pages
    print("\nStep 4/4: Child pages")
    for child in parsed["children"]:
        existing = find_page(pages, child["title"])
        if existing:
            cu.update_page(
                doc["id"], existing["id"], child["title"], child["content"]
            )
            print(f"  ✓ updated child {child['title']!r} (id={existing['id']})")
        else:
            new_page = cu.create_page(
                doc["id"],
                child["title"],
                child["content"],
                parent_page_id=parent_page["id"],
            )
            print(f"  ✓ created child {child['title']!r} (id={new_page['id']})")
            # Small spacing between writes to be polite to the API.
            if not args.dry_run:
                time.sleep(0.3)

    print("\nDone.")
    if args.dry_run:
        print("(no API writes performed — re-run without --dry-run to apply)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

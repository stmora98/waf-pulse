"""Builds the compact checklist files the collector ships with.

Source: https://github.com/Azure/review-checklists (MIT, Copyright (c) Microsoft Corporation).
Only items that carry an Azure Resource Graph query ("graph") are kept, with just the fields the collector uses.

Usage:
    git clone https://github.com/Azure/review-checklists
    python tools/update_checklists.py --source review-checklists/checklists
"""
import argparse
import json
from pathlib import Path

KEEP = ("guid", "id", "text", "severity", "waf", "category", "subcategory", "service", "link", "graph")
DEFAULT_OUTPUT = Path(__file__).resolve().parent.parent / "src" / "collector" / "waf_pulse" / "checklists"


def slim(checklist, stem):
    items = []
    for item in checklist.get("items", []):
        graph = str(item.get("graph") or "").strip()
        if not graph or not item.get("guid"):
            continue
        entry = {key: item.get(key) for key in KEEP if item.get(key) is not None}
        entry["graph"] = graph
        items.append(entry)
    name = checklist.get("metadata", {}).get("name") or stem
    return {"name": name, "items": items}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source", required=True, help="folder with the *_checklist.en.json files")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT), help="destination folder")
    args = parser.parse_args()

    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    for stale in output.glob("*.json"):
        stale.unlink()

    total = 0
    for path in sorted(Path(args.source).glob("*_checklist.en.json")):
        stem = path.name.replace("_checklist.en.json", "")
        result = slim(json.loads(path.read_text(encoding="utf-8")), stem)
        if not result["items"]:
            continue
        (output / f"{stem}.json").write_text(json.dumps(result, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
        total += len(result["items"])
        print(f"{stem:<28}{len(result['items']):>5} automated checks")
    print(f"{'total':<28}{total:>5}")


if __name__ == "__main__":
    main()

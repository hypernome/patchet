#!/usr/bin/env python3
"""Export complete LangSmith traces to JSON"""

from langsmith import Client
import json
from datetime import datetime
from uuid import UUID
from decimal import Decimal
from typing import Any
import os
import time

def serialize_run(obj: Any) -> Any:
    """Recursively serialize Run object to JSON-compatible format"""
    
    # Handle None
    if obj is None:
        return None
    
    # Handle datetime objects
    if isinstance(obj, datetime):
        return obj.isoformat()
    
    # Handle UUID objects
    if isinstance(obj, UUID):
        return str(obj)
    
    # Handle Decimal objects (convert to float)
    if isinstance(obj, Decimal):
        return float(obj)
    
    # Handle dictionaries
    if isinstance(obj, dict):
        return {key: serialize_run(value) for key, value in obj.items()}
    
    # Handle lists/tuples
    if isinstance(obj, (list, tuple)):
        return [serialize_run(item) for item in obj]
    
    # Handle Pydantic models (Run objects)
    if hasattr(obj, 'dict'):
        return serialize_run(obj.dict())
    
    # Handle Pydantic v2 models
    if hasattr(obj, 'model_dump'):
        return serialize_run(obj.model_dump())
    
    # Handle other objects with __dict__
    if hasattr(obj, '__dict__'):
        return serialize_run(obj.__dict__)
    
    # Return primitive types as-is
    return obj


def fetch_run_with_children(client: Client, run_id: str, depth: int = 0, retry_count: int = 0) -> dict:
    """Recursively fetch a run and all its children with rate limiting
    
    Args:
        client: LangSmith client
        run_id: UUID of the run to fetch
        depth: Current recursion depth (for logging)
        retry_count: Number of retries attempted
        
    Returns:
        Complete run dict with nested child_runs
    """
    indent = "  " * depth
    
    try:
        print(f"{indent}Fetching run: {run_id[:8]}...")
        
        # Add delay to avoid rate limits (1 second between requests)
        time.sleep(1.0)
        
        # Fetch this run
        run = client.read_run(run_id)
        
        # Serialize to dict
        run_dict = serialize_run(run)
        
        # If this run has children, fetch them recursively
        if run_dict.get('child_run_ids'):
            print(f"{indent}  → Found {len(run_dict['child_run_ids'])} child runs")
            
            child_runs = []
            for child_id in run_dict['child_run_ids']:
                try:
                    child_run = fetch_run_with_children(client, child_id, depth + 1)
                    child_runs.append(child_run)
                except Exception as e:
                    print(f"{indent}  ✗ Error fetching child {child_id[:8]}: {e}")
                    # Continue with other children even if one fails
            
            # Replace null child_runs with actual data
            run_dict['child_runs'] = child_runs
            print(f"{indent}  ✓ Fetched {len(child_runs)} children")
        
        return run_dict
        
    except Exception as e:
        # Check if it's a rate limit error
        if "429" in str(e) or "too many requests" in str(e).lower():
            if retry_count < 3:
                wait_time = 30 * (retry_count + 1)  # 30s, 60s, 90s
                print(f"{indent}⚠ Rate limited! Waiting {wait_time}s before retry...")
                time.sleep(wait_time)
                return fetch_run_with_children(client, run_id, depth, retry_count + 1)
            else:
                print(f"{indent}✗ Max retries exceeded for {run_id[:8]}")
                raise
        else:
            raise


def export_trace(trace_id: str, output_path: str) -> bool:
    """Export a complete trace to JSON with all child runs
    
    Args:
        trace_id: Full UUID or 8-char prefix of the trace
        output_path: Path to save JSON file
        
    Returns:
        True if successful, False otherwise
    """
    try:
        client = Client()
        
        print(f"\n{'='*60}")
        print(f"Exporting trace: {trace_id}")
        print(f"{'='*60}\n")
        
        # Recursively fetch the entire execution tree
        run_dict = fetch_run_with_children(client, trace_id, depth=0)
        
        print(f"\n{'='*60}")
        print(f"Converting to JSON...")
        
        # Create output directory if it doesn't exist
        os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else '.', exist_ok=True)
        
        # Write to JSON file
        with open(output_path, 'w') as f:
            json.dump(run_dict, f, indent=2)
        
        print(f"✓ Successfully exported to: {output_path}")
        print(f"  File size: {os.path.getsize(output_path) / 1024:.1f} KB")
        print(f"{'='*60}\n")
        
        return True
        
    except Exception as e:
        print(f"\n{'='*60}")
        print(f"✗ Error exporting trace: {e}")
        print(f"{'='*60}\n")
        import traceback
        traceback.print_exc()
        return False


def export_all_traces(trace_mapping: dict, output_dir: str = "archived_traces") -> None:
    """Export all traces from the mapping with resume capability
    
    Args:
        trace_mapping: Dict of {filename: full_trace_id}
        output_dir: Directory to save JSON files
    """
    
    total = len(trace_mapping)
    success = 0
    failed = []
    skipped = 0
    
    print(f"\nExporting {total} traces to {output_dir}/\n")
    print(f"Rate limiting: 1 second delay between requests")
    print(f"Resume: Will skip already-exported files\n")
    
    for i, (filename, trace_id) in enumerate(trace_mapping.items(), 1):
        output_path = os.path.join(output_dir, filename)
        
        # Skip if already exported
        if os.path.exists(output_path):
            print(f"[{i}/{total}] {filename} - ALREADY EXISTS, skipping...")
            skipped += 1
            continue
        
        print(f"[{i}/{total}] {filename}...")
        
        if export_trace(trace_id, output_path):
            success += 1
        else:
            failed.append(filename)
        
        print()  # Blank line between traces
    
    # Summary
    print("=" * 60)
    print(f"Export complete:")
    print(f"  Successfully exported: {success}/{total}")
    print(f"  Skipped (already exist): {skipped}/{total}")
    print(f"  Failed: {len(failed)}/{total}")
    
    if failed:
        print(f"\nFailed traces:")
        for name in failed:
            print(f"  - {name}")
        print(f"\nYou can re-run the script to retry failed traces")
    else:
        print("\n✓ All traces exported successfully!")
    
    print("=" * 60)


if __name__ == "__main__":
    
    # You'll need to get the FULL trace IDs from LangSmith
    # Open each trace in browser and get the full UUID from the URL
    
    trace_mapping = {
        # T1: Agent Identity Spoofing
        "T01_41ac65e8_oauth.json": "41ac65e8-591a-42f9-b7cc-823f6094c2a1",
        "T01_0ca33d76_ajwt.json": "0ca33d76-d66a-45ff-abfc-c50f3f3b3d66",
        
        # T2: Token Replay Attacks
        "T02_8fd4713c_oauth.json": "8fd4713c-2204-4f9f-b619-6d1a49d2577c",
        "T02_f7b8a5cf_ajwt.json": "f7b8a5cf-e637-4db0-a8a9-8e0476830f14",
        
        # T3: Shim Library Impersonation
        "T03_9c1b5d1e_oauth.json": "9c1b5d1e-5639-423d-9a71-d2a56846fb01",
        "T03_80805ddb_ajwt.json": "80805ddb-a50e-4f07-97b3-eb41b4e6ec3c",
        
        # T4: Runtime Code Modification
        "T04_70174696_oauth.json": "70174696-8094-4c7e-9609-efec46409e9e",
        "T04_48bdd65b_ajwt.json": "48bdd65b-bb57-4db0-a89e-e7c990bc3b2d",
        
        # T5: Prompt Injection Attacks
        "T05_1be5a858_oauth.json": "1be5a858-04bc-46fc-abef-1e433a8afa0a",
        "T05_f1062192_ajwt.json": "f1062192-a5ae-4802-b49b-eb967daf9a1d",
        
        # T6: Workflow Definition Tampering
        "T06_5f14eabb_oauth.json": "5f14eabb-1684-4b70-a0ad-705ff369be8c",
        "T06_0da6cf62_ajwt.json": "0da6cf62-603c-418a-b5ee-054de93b6fe5",
        
        # T7: Cross-Agent Privilege Escalation
        "T07_6a04b024_oauth.json": "6a04b024-742a-417f-8ae1-13165189bc30",
        "T07_44d2f82f_ajwt.json": "44d2f82f-567f-499a-ab0c-5e1b1ba4b7e2",
        
        # T8: Workflow Step Bypass
        "T08_4c9613f7_oauth.json": "4c9613f7-6e9c-44ec-9fb8-78b12e5367d6",
        "T08_eaa46e6f_ajwt.json": "eaa46e6f-48d7-49f5-92dc-dce3c740fe80",
        
        # T9: Scope Inflation
        "T09_e352575c_oauth.json": "e352575c-e7cc-499f-9a9a-b8469c79834b",
        "T09_44e0eaf1_ajwt.json": "44e0eaf1-20c8-4369-b1d1-8955d8215dee",
        
        # T10: Intent Origin Forgery
        "T10_d7f79b4d_oauth.json": "d7f79b4d-f436-4b26-8486-498ec11b9cb1",
        "T10_57e260f3_ajwt.json": "57e260f3-e9ea-4905-9f96-f54d10fb7b83",
        
        # T11: Delegation Chain Manipulation
        "T11_2bedc0cf_oauth.json": "2bedc0cf-babe-4dad-8bca-ec4358dd71fa",
        "T11_1f239b8d_ajwt.json": "1f239b8d-8323-4b45-ac66-1e538fa6a9ca",
        
        # T12: Agent Configuration Exposure
        "T12_9a9f1440_oauth.json": "9a9f1440-9bce-47bb-9167-b0054e728891",
        "T12_5a0af156_ajwt.json": "5a0af156-d495-4464-93b0-dc09fcfada16",
    }
    
    # Export all traces
    export_all_traces(trace_mapping, output_dir="archived_traces")
    
    print("\nNext steps:")
    print("1. Upload JSON files to your GitHub repo: patchet/docs/archived_traces/")
    print("2. Update traces.html to link to JSON files")
    print("3. Create a simple JSON viewer (optional)")
"""
Export LangSmith traces for Agentic JWT paper
Author: Abhishek Goswami
"""

import json
import os
from pathlib import Path
from langsmith import Client
from datetime import datetime

# Initialize LangSmith client
client = Client()

PROJECT_NAME = "304dd984-46dd-4ea6-80eb-a2bf97fbe44c"  

# Threat scenario mapping (from Table 5 in the paper)
THREAT_SCENARIOS = {
    "T1": {
        "name": "Agent Identity Spoofing",
        "stride": "Spoofing",
        "oauth_trace": "41ac65e8",
        "ajwt_trace": "0ca33d76",
        "oauth_outcome": "Attack succeeded",
        "ajwt_outcome": "Blocked (HTTP 400)",
        "oauth_time": 1720.0,
        "ajwt_time": 141.3
    },
    "T2": {
        "name": "Token Replay Attacks",
        "stride": "Spoofing",
        "oauth_trace": "8fd4713c",
        "ajwt_trace": "f7b8a5cf",
        "oauth_outcome": "Attack succeeded",
        "ajwt_outcome": "Blocked (HTTP 401)",
        "oauth_time": 7539.1,
        "ajwt_time": 4877.5
    },
    "T3": {
        "name": "Shim Library Impersonation",
        "stride": "Spoofing",
        "oauth_trace": "9c1b5d1e",
        "ajwt_trace": "80805ddb",
        "oauth_outcome": "Attack succeeded",
        "ajwt_outcome": "Blocked",
        "oauth_time": 8782.6,
        "ajwt_time": 9463.9
    },
    "T4": {
        "name": "Runtime Code Modification",
        "stride": "Tampering",
        "oauth_trace": "70174696",
        "ajwt_trace": "48bdd65b",
        "oauth_outcome": "Attack succeeded",
        "ajwt_outcome": "Blocked",
        "oauth_time": 3393.2,
        "ajwt_time": 1871.0
    },
    "T5": {
        "name": "Prompt Injection Attacks",
        "stride": "Tampering",
        "oauth_trace": "1be5a858",
        "ajwt_trace": "f1062192",
        "oauth_outcome": "Attack succeeded",
        "ajwt_outcome": "Blocked",
        "oauth_time": 3594.8,
        "ajwt_time": 1861.6
    },
    "T6": {
        "name": "Workflow Definition Tampering",
        "stride": "Tampering",
        "oauth_trace": "5f14eabb",
        "ajwt_trace": "0da6cf62",
        "oauth_outcome": "Attack succeeded",
        "ajwt_outcome": "Blocked (HTTP 403)",
        "oauth_time": 10402.2,
        "ajwt_time": 5613.3
    },
    "T7": {
        "name": "Cross-Agent Privilege Escalation",
        "stride": "Privilege Escalation",
        "oauth_trace": "6a04b024",
        "ajwt_trace": "44d2f82f",
        "oauth_outcome": "Attack succeeded",
        "ajwt_outcome": "Blocked (HTTP 403)",
        "oauth_time": 6579.0,
        "ajwt_time": 5530.7
    },
    "T8": {
        "name": "Workflow Step Bypass",
        "stride": "Privilege Escalation",
        "oauth_trace": "4c9613f7",
        "ajwt_trace": "eaa46e6f",
        "oauth_outcome": "Attack succeeded",
        "ajwt_outcome": "Blocked (HTTP 403)",
        "oauth_time": 7365.3,
        "ajwt_time": 6199.1
    },
    "T9": {
        "name": "Scope Inflation",
        "stride": "Privilege Escalation",
        "oauth_trace": "e352575c",
        "ajwt_trace": "44e0eaf1",
        "oauth_outcome": "Attack succeeded",
        "ajwt_outcome": "Blocked (HTTP 403)",
        "oauth_time": 5024.3,
        "ajwt_time": 3565.9
    },
    "T10": {
        "name": "Intent Origin Forgery",
        "stride": "Repudiation",
        "oauth_trace": "d7f79b4d",
        "ajwt_trace": "57e260f3",
        "oauth_outcome": "Attack succeeded",
        "ajwt_outcome": "Blocked (HTTP 403)",
        "oauth_time": 5040.5,
        "ajwt_time": 3177.2
    },
    "T11": {
        "name": "Delegation Chain Manipulation",
        "stride": "Repudiation",
        "oauth_trace": "2bedc0cf",
        "ajwt_trace": "1f239b8d",
        "oauth_outcome": "Attack succeeded",
        "ajwt_outcome": "Blocked (HTTP 403)",
        "oauth_time": 7787.1,
        "ajwt_time": 6932.0
    },
    "T12": {
        "name": "Agent Configuration Exposure",
        "stride": "Information Disclosure",
        "oauth_trace": "9a9f1440",
        "ajwt_trace": "5a0af156",
        "oauth_outcome": "Attack succeeded",
        "ajwt_outcome": "Blocked",
        "oauth_time": 7419.6,
        "ajwt_time": 7103.8
    }
}


# Cache for all runs (fetch once, search many times)
ALL_RUNS_CACHE = None


def get_all_runs(threat_id):
    """Fetch all runs from the project (cached)"""
    global ALL_RUNS_CACHE
    
    if ALL_RUNS_CACHE is not None:
        return ALL_RUNS_CACHE
    
    print("Fetching all runs from LangSmith project...")
    print(f"   Project: {PROJECT_NAME}")
    
    time_format = "%m/%d/%Y %H:%M:%S"
    filter=f'eq(name, "{threat_id}_attack")'
    try:
        # Fetch all runs from the project
        all_runs = list(client.list_runs(
            project_name=PROJECT_NAME,
            start_time=datetime.strptime("11/16/2025 00:00:40", time_format),
            end_time=datetime.strptime("11/16/2025 23:59:00", time_format), 
            filter=filter
        ))
        
        print(f"   Found {len(all_runs)} runs in project")
        ALL_RUNS_CACHE = all_runs
        return all_runs
    
    except Exception as e:
        print(f"   Error fetching runs: {e}")
        print("\n  Possible issues:")
        print("   1. Check PROJECT_NAME is correct (line 15)")
        print("   2. Verify LANGSMITH_API_KEY is set")
        print("   3. Check project name in LangSmith UI")
        return []


def find_run_by_prefix(trace_prefix, threat_id):
    """Find a LangSmith run by its 8-character prefix"""
    all_runs = get_all_runs(threat_id)
    
    if not all_runs:
        return None
    
    # Search through all runs for matching prefix
    for run in all_runs:
        run_id_str = str(run.id)
        if run_id_str.startswith(trace_prefix):
            return run
    
    # Also check trace_id (sometimes different from run id)
    for run in all_runs:
        if run.trace_id:
            trace_id_str = str(run.trace_id)
            if trace_id_str.startswith(trace_prefix):
                return run
    
    print(f"      No run found for prefix: {trace_prefix}")
    return None


def export_trace(run, output_path):
    """Export a single trace to JSON"""
    try:
        run_dict = {
            "id": str(run.id),
            "name": getattr(run, 'name', None),
            "run_type": getattr(run, 'run_type', None),
            "start_time": run.start_time.isoformat() if hasattr(run, 'start_time') and run.start_time else None,
            "end_time": run.end_time.isoformat() if hasattr(run, 'end_time') and run.end_time else None,
            "inputs": getattr(run, 'inputs', {}),
            "outputs": getattr(run, 'outputs', {}),
            "error": getattr(run, 'error', None),
            "execution_order": getattr(run, 'execution_order', None),  
            "serialized": getattr(run, 'serialized', {}),
            "tags": getattr(run, 'tags', []),
            "extra": getattr(run, 'extra', {}),
            "trace_id": str(run.trace_id) if hasattr(run, 'trace_id') and run.trace_id else None,
            "dotted_order": getattr(run, 'dotted_order', None),
            "parent_run_id": str(run.parent_run_id) if hasattr(run, 'parent_run_id') and run.parent_run_id else None,
            "child_run_ids": [str(cid) for cid in getattr(run, 'child_run_ids', None) or []],
        }
        
        with open(output_path, 'w') as f:
            json.dump(run_dict, f, indent=2)
        
        return True
    except Exception as e:
        print(f"      Error exporting: {e}")
        return False


def main():
    """Main export function"""
    
    print("=" * 70)
    print("LangSmith Trace Export for Agentic JWT Paper")
    print("=" * 70)
    print()
    
    # Create output directory
    output_dir = Path("experiments/traces")
    output_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"Output directory: {output_dir.absolute()}")
    print()
    
    # Track statistics
    total_traces = len(THREAT_SCENARIOS) * 2  # OAuth + A-JWT for each threat
    exported_count = 0
    failed_traces = []
    
    # Export each threat scenario
    for threat_id, threat_data in THREAT_SCENARIOS.items():
        print(f"{threat_id}: {threat_data['name']}")
        
        # Export OAuth trace
        oauth_prefix = threat_data['oauth_trace']
        print(f"   OAuth trace: {oauth_prefix}", end=" ")
        oauth_run = find_run_by_prefix(oauth_prefix, threat_id)
        
        if oauth_run:
            oauth_path = output_dir / f"{threat_id}_{oauth_prefix}_oauth.json"
            if export_trace(oauth_run, oauth_path):
                print(f"Done")
                exported_count += 1
            else:
                print(f"Failed")
                failed_traces.append(f"{threat_id}_oauth_{oauth_prefix}")
        else:
            print(f"Failed")
            failed_traces.append(f"{threat_id}_oauth_{oauth_prefix}")
        
        # Export A-JWT trace
        ajwt_prefix = threat_data['ajwt_trace']
        print(f"   A-JWT trace: {ajwt_prefix}", end=" ")
        ajwt_run = find_run_by_prefix(ajwt_prefix, threat_id)
        
        if ajwt_run:
            ajwt_path = output_dir / f"{threat_id}_{ajwt_prefix}_ajwt.json"
            if export_trace(ajwt_run, ajwt_path):
                print(f"Done")
                exported_count += 1
            else:
                print(f"Failed")
                failed_traces.append(f"{threat_id}_ajwt_{ajwt_prefix}")
        else:
            print(f"Failed")
            failed_traces.append(f"{threat_id}_ajwt_{ajwt_prefix}")
        
        print()
    
    # Create metadata file
    metadata = {
        "experiment_metadata": {
            "paper_title": "Agentic JWT: A Secure Delegation Protocol for Autonomous AI Agents",
            "author": "Abhishek Goswami",
            "journal": "IEEE Access",
            "arxiv_preprint": "2509.13597",
            "patent_application": "US 19/315,486",
            "export_date": datetime.now().isoformat(),
            "langsmith_project": PROJECT_NAME,
            "total_threat_scenarios": 12,
            "traces_per_scenario": 2
        },
        "threat_scenarios": THREAT_SCENARIOS
    }
    
    metadata_path = output_dir / "traces_metadata.json"
    with open(metadata_path, 'w') as f:
        json.dump(metadata, f, indent=2)
    
    print("Metadata file created: traces_metadata.json")
    print()
    
    # Summary
    print("=" * 70)
    print("EXPORT SUMMARY")
    print("=" * 70)
    print(f"Successfully exported: {exported_count}/{total_traces} traces")
    
    if failed_traces:
        print(f"Failed exports: {len(failed_traces)}")
        print("\nMissing traces:")
        for trace in failed_traces:
            print(f"   - {trace}")
        print("\nTip: Check if these run names/IDs match in LangSmith UI")
    else:
        print("All traces exported successfully!")
    
    print()
    print(f"All files saved to: {output_dir.absolute()}")
    print()


if __name__ == "__main__":
    main()
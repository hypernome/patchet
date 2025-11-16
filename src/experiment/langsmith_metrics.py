"""
LangSmith Integration for Automatic Performance Metrics Extraction

This module connects to LangSmith traces and extracts timing data
for all relevant operations (token minting, checksum validation, etc.)

Usage:
    from langsmith_metrics import extract_performance_metrics
    
    metrics = extract_performance_metrics(
        project_name="agentic-jwt-eval",
        run_ids=["run-123", "run-456"]
    )
"""

import os
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from langsmith import Client
from clientshim.secure_client import AuthMode


@dataclass
class PerformanceMetrics:
    """Performance metrics extracted from LangSmith traces"""
    
    # Token minting breakdown
    token_minting_total_ms: float = 0.0
    checksum_computation_ms: float = 0.0
    """
    workflow_validation_ms: float = 0.0
    delegation_check_ms: float = 0.0
    jwt_signing_ms: float = 0.0
    """
    # End-to-end workflow
    total_workflow_ms: float = 0.0
    llm_reasoning_ms: float = 0.0
    tool_execution_ms: float = 0.0
    
    # Memory
    memory_kb: int = 0
    
    # Metadata
    run_id: Optional[str] = None
    trace_url: Optional[str] = None
    timestamp: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class LangSmithMetricsExtractor:
    """
    Extract performance metrics from LangSmith traces.
    
    LangSmith automatically tracks:
    - HTTP call latencies (including IDP token requests)
    - Agent tool execution times
    - LLM API call latencies
    - Memory usage per run
    """
    
    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize LangSmith client.
        
        Args:
            api_key: LangSmith API key. If None, uses LANGSMITH_API_KEY env var
        """
        self.api_key = api_key or os.getenv('LANGSMITH_API_KEY')
        self.client = Client(api_key=self.api_key)
    
    def extract_from_run(self, run_id: str) -> PerformanceMetrics:
        """
        Extract metrics from a single LangSmith run.
        
        Args:
            run_id: LangSmith run ID
            
        Returns:
            PerformanceMetrics object with timing data
        """
        try:
            run = self.client.read_run(run_id)
            return self._parse_run(run)
        except Exception as e:
            print(f"Error extracting metrics from run {run_id}: {e}")
            return PerformanceMetrics(run_id=run_id)
    
    def extract_from_project(
        self, 
        project_name: str,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100, 
        auth_mode: AuthMode = AuthMode.intent
    ) -> List[PerformanceMetrics]:
        """
        Extract metrics from all runs in a project.
        
        Args:
            project_name: LangSmith project name
            start_time: Filter runs after this time
            end_time: Filter runs before this time
            limit: Maximum number of runs to fetch
            
        Returns:
            List of PerformanceMetrics
        """
        try:
            # Query runs
            runs = self.client.list_runs(
                project_name=project_name,
                start_time=start_time,
                end_time=end_time,
                limit=limit * 2 if auth_mode else limit
            )
            
            metrics_list = []
            for run in runs:
                if auth_mode: 
                    run_metadata = self._get_run_metadata(run)
                    if run_metadata.get("auth_mode", "Unknown") != auth_mode.value: 
                        continue
                metrics = self._parse_run(run)
                metrics_list.append(metrics)
            
            return metrics_list
            
        except Exception as e:
            print(f"Error extracting metrics from project {project_name}: {e}")
            return []
    
    def _get_run_metadata(self, run) -> dict:
        """Extract metadata from a run"""
        try:
            if hasattr(run, 'extra') and run.extra:
                return run.extra.get('metadata', {})
            return {}
        except:
            return {}
    
    def _parse_run(self, run) -> PerformanceMetrics:
        """Parse a LangSmith run and extract timing data"""
        
        metrics = PerformanceMetrics(
            run_id=str(run.id),
            trace_url=self._get_trace_url(run),
            timestamp=run.start_time.isoformat() if run.start_time else None
        )
        
        # Total workflow time (milliseconds)
        if run.end_time and run.start_time:
            total_seconds = (run.end_time - run.start_time).total_seconds()
            metrics.total_workflow_ms = total_seconds * 1000
        
        # Fetch ALL child runs for this trace
        try:
            # Get the trace_id (root run)
            trace_id = run.trace_id if hasattr(run, 'trace_id') else run.id
            
            # Fetch all runs in this trace
            all_runs = list(self.client.list_runs(
                project_name=str(run.session_id) if hasattr(run, 'session_id') else None,
                trace_filter=f'eq(trace_id, "{trace_id}")'
            ))
            
            # Parse all runs in the trace (excluding the root)
            for child_run in all_runs:
                if str(child_run.id) != str(run.id):  # Skip the parent run itself
                    self._extract_metrics_from_run(child_run, metrics)
            
        except Exception as e:
            print(f"Error fetching child runs for {run.id}: {e}")
            # Fallback: try to parse the run itself
            self._extract_metrics_from_run(run, metrics)
        
        return metrics

    def _extract_metrics_from_run(self, run, metrics: PerformanceMetrics) -> None:
        """Extract metrics from a single run based on its name"""
        
        run_name = run.name.lower() if run.name else ""
        
        # Calculate duration
        if run.end_time and run.start_time:
            duration_ms = (run.end_time - run.start_time).total_seconds() * 1000
        else:
            return  # Skip if no timing data
        
        # Token minting components
        if 'mint_intent_token' in run_name or 'mint_token' in run_name:
            metrics.token_minting_total_ms += duration_ms
        
        elif 'compute_checksum' in run_name or 'checksum' in run_name:
            metrics.checksum_computation_ms += duration_ms
        
        # LLM calls
        elif 'llm' in run_name or 'chat' in run_name or 'anthropic' in run_name:
            metrics.llm_reasoning_ms += duration_ms
        
        # Tool execution
        elif 'agent_tool' in run_name or 'tool' in run_name: 
            metrics.tool_execution_ms += duration_ms
            
        """
        elif 'validate_workflow' in run_name or 'workflow_validation' in run_name:
            metrics.workflow_validation_ms += duration_ms
        
        elif 'delegation' in run_name and 'check' in run_name:
            metrics.delegation_check_ms += duration_ms
        
        elif 'jwt' in run_name and 'sign' in run_name:
            metrics.jwt_signing_ms += duration_ms
        """
    
    def _get_trace_url(self, run) -> Optional[str]:
        """Generate LangSmith trace URL"""
        try:
            # LangSmith trace URL format
            org_id = os.getenv('LANGSMITH_ORG_ID', 'default')
            project_name = run.project_name if hasattr(run, 'project_name') else '304dd984-46dd-4ea6-80eb-a2bf97fbe44c'
            run_id = str(run.id)
            
            return f"https://smith.langchain.com/o/{org_id}/projects/p/{project_name}/r/{run_id}"
        except:
            return None
    
    def aggregate_metrics(
        self, 
        metrics_list: List[PerformanceMetrics]
    ) -> Dict[str, float]:
        """
        Aggregate metrics across multiple runs.
        
        Returns averages, percentiles, etc.
        """
        if not metrics_list:
            return {}
        
        # Extract all values
        token_minting = [m.token_minting_total_ms for m in metrics_list if m.token_minting_total_ms > 0]
        checksum = [m.checksum_computation_ms for m in metrics_list if m.checksum_computation_ms > 0]
        # workflow = [m.workflow_validation_ms for m in metrics_list if m.workflow_validation_ms > 0]
        # delegation = [m.delegation_check_ms for m in metrics_list if m.delegation_check_ms > 0]
        total_workflow = [m.total_workflow_ms for m in metrics_list if m.total_workflow_ms > 0]
        llm = [m.llm_reasoning_ms for m in metrics_list if m.llm_reasoning_ms > 0]
        tools = [m.tool_execution_ms for m in metrics_list if m.tool_execution_ms > 0]
        
        def stats(values):
            if not values:
                return {"avg": 0, "min": 0, "max": 0, "p50": 0, "p95": 0, "p99": 0}
            
            sorted_vals = sorted(values)
            n = len(sorted_vals)
            
            return {
                "avg": sum(sorted_vals) / n,
                "min": sorted_vals[0],
                "max": sorted_vals[-1],
                "p50": sorted_vals[n // 2],
                "p95": sorted_vals[int(n * 0.95)] if n > 1 else sorted_vals[0],
                "p99": sorted_vals[int(n * 0.99)] if n > 1 else sorted_vals[0],
            }
        
        return {
            "token_minting_ms": stats(token_minting),
            "checksum_computation_ms": stats(checksum),
            # "workflow_validation_ms": stats(workflow),
            # "delegation_check_ms": stats(delegation),
            "total_workflow_ms": stats(total_workflow),
            "llm_reasoning_ms": stats(llm),
            "tool_execution_ms": stats(tools),
            "sample_size": len(metrics_list)
        }


def extract_performance_metrics(
    project_name: str = "304dd984-46dd-4ea6-80eb-a2bf97fbe44c",
    run_ids: Optional[List[str]] = None,
    hours_back: float = 24, 
    auth_mode: AuthMode = AuthMode.intent
) -> Dict[str, Any]:
    """
    Convenience function to extract metrics.
    
    Args:
        project_name: LangSmith project name
        run_ids: Specific run IDs to extract. If None, gets recent runs
        hours_back: How many hours back to look for runs
        
    Returns:
        Dictionary with metrics and aggregations
    """
    extractor = LangSmithMetricsExtractor()
    
    if run_ids:
        # Extract specific runs
        metrics_list = [extractor.extract_from_run(run_id) for run_id in run_ids]
    else:
        # Extract recent runs from project
        start_time = datetime.now() - timedelta(hours=hours_back)
        metrics_list = extractor.extract_from_project(
            project_name=project_name,
            start_time=start_time,
            limit=100, 
            auth_mode=auth_mode
        )
    
    # Aggregate
    aggregated = extractor.aggregate_metrics(metrics_list)
    
    return {
        "individual_runs": [m.to_dict() for m in metrics_list],
        "aggregated": aggregated,
        "metadata": {
            "project_name": project_name,
            "total_runs": len(metrics_list),
            "extracted_at": datetime.now().isoformat()
        }
    }


if __name__ == "__main__":
    # Example usage
    import json
    
    # Extract metrics from recent runs
    metrics = extract_performance_metrics(
        project_name="Patchet",
        hours_back=0.5
    )
    
    # Print summary
    print("Performance Metrics Summary:")
    print("="*70)
    
    agg = metrics['aggregated']
    print(f"\nToken Minting (avg): {agg['token_minting_ms']['avg']:.2f}ms")
    print(f"  - Checksum: {agg['checksum_computation_ms']['avg']:.2f}ms")
    print(f"  - Workflow validation: {agg['workflow_validation_ms']['avg']:.2f}ms")
    print(f"  - Delegation check: {agg['delegation_check_ms']['avg']:.2f}ms")
    
    print(f"\nEnd-to-End Workflow (avg): {agg['total_workflow_ms']['avg']:.2f}ms")
    print(f"  - LLM reasoning: {agg['llm_reasoning_ms']['avg']:.2f}ms")
    print(f"  - Tool execution: {agg['tool_execution_ms']['avg']:.2f}ms")
    
    print(f"\nSample size: {agg['sample_size']} runs")
    print("="*70)
    
    # Save to file
    with open('performance_metrics.json', 'w') as f:
        json.dump(metrics, f, indent=2)
    
    print("\n✓ Saved to performance_metrics.json")
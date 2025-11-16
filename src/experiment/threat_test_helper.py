"""
Threat Test Result Helper

Provides utilities for threat tests to return standardized results
with LangSmith tracing, timing data, and security anchor attribution.

"""

import time
import os
from typing import Dict, Any, Optional
from functools import wraps
from contextlib import contextmanager


class ThreatTestResult:
    """
    Standardized result object for threat tests.
    Ensures all required fields are populated properly.
    """
    
    def __init__(self):
        self._attack_succeeded = False
        self._blocked_by: Optional[str] = None
        self._elapsed_time_ms: Optional[float] = None
        self._error_message: Optional[str] = None
        self._langsmith_trace_url: Optional[str] = None
        self._details: Dict[str, Any] = {}
        self._start_time = time.perf_counter()
    
    def attack_succeeded(
        self, message: str = "Attack succeeded",
        elapsed_time_ms: Optional[float] = None,):
        """Mark attack as successful (security hole found)"""
        self._attack_succeeded = True
        self._elapsed_time_ms = elapsed_time_ms
        self._details["message"] = message
    
    def attack_blocked(
        self, 
        blocked_by: str,
        elapsed_time_ms: Optional[float] = None,
        error_message: Optional[str] = None
    ):
        """
        Mark attack as blocked by security control.
        
        Args:
            blocked_by: Security anchor that blocked (e.g., "A1: Agent Checksum")
            detection_time_ms: Time to detect in milliseconds
            error_message: Error message from security control
        """
        self._attack_succeeded = False
        self._blocked_by = blocked_by
        self._elapsed_time_ms = elapsed_time_ms
        self._error_message = error_message
    
    def set_langsmith_trace(self, trace_url: str):
        """Set LangSmith trace URL"""
        self._langsmith_trace_url = trace_url
    
    def add_detail(self, key: str, value: Any):
        """Add additional detail to result"""
        self._details[key] = value
    
    def get_elapsed_time_ms(self) -> float:
        """Get elapsed time since result object creation"""
        return (time.perf_counter() - self._start_time) * 1000
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for return"""
        return {
            "attack_succeeded": self._attack_succeeded,
            "blocked_by": self._blocked_by,
            "detection_time_ms": self._elapsed_time_ms,
            "error_message": self._error_message,
            "langsmith_trace_url": self._langsmith_trace_url,
            "details": self._details
        }


def capture_langsmith_trace(func):
    """
    Decorator to automatically capture LangSmith trace URL.
    Creates a trace if one doesn't exist.
    
    Usage:
        @capture_langsmith_trace
        async def attack():
            result = ThreatTestResult()
            # ... do attack
            return result.to_dict()
    """
    @wraps(func)
    async def wrapper(*args, **kwargs):
        trace_url = None
        
        try:
            from langsmith import get_current_run_tree, traceable
            
            # Check if we're already in a trace
            run_tree = get_current_run_tree()
            
            if run_tree:
                # Already tracing, get the URL
                org_id = os.getenv('LANGSMITH_ORG_ID', 'default')
                project_name = os.getenv('LANGSMITH_PROJECT', '304dd984-46dd-4ea6-80eb-a2bf97fbe44c')
                run_id = str(run_tree.id)
                trace_url = f"https://smith.langchain.com/o/{org_id}/projects/p/{project_name}/r/{run_id}"
                
                # Execute the function (already traced)
                result = await func(*args, **kwargs)
            else:
                # No trace exists, create one
                @traceable(run_type="chain", name=func.__name__)
                async def traced_func():
                    return await func(*args, **kwargs)
                
                # Execute within trace
                result = await traced_func()
                
                # Get the trace URL we just created
                run_tree = get_current_run_tree()
                if run_tree:
                    org_id = os.getenv('LANGSMITH_ORG_ID', 'default')
                    project_name = os.getenv('LANGSMITH_PROJECT', 'agentic-jwt-eval')
                    run_id = str(run_tree.id)
                    trace_url = f"https://smith.langchain.com/o/{org_id}/projects/p/{project_name}/r/{run_id}"
                    
        except (ImportError, AttributeError) as e:
            # LangSmith not available or error, just run without tracing
            result = await func(*args, **kwargs)
        
        # Add trace URL if available and not already set
        if trace_url and isinstance(result, dict):
            if not result.get('langsmith_trace_url'):
                result['langsmith_trace_url'] = trace_url
        
        return result
    
    return wrapper


@contextmanager
def measure_detection_time():
    """
    Context manager to measure detection time.
    
    Usage:
        with measure_detection_time() as timer:
            try:
                await client.mint_token()
            except SecurityError:
                result.attack_blocked(
                    blocked_by="A1: Agent Checksum",
                    detection_time_ms=timer.elapsed_ms()
                )
    """
    class Timer:
        def __init__(self):
            self.start = time.perf_counter()
        
        def elapsed_ms(self) -> float:
            return (time.perf_counter() - self.start) * 1000
    
    timer = Timer()
    yield timer


# Security anchor reference for consistent naming
SECURITY_ANCHORS = {
    "A1": "A1: Agent Checksum Verification",
    "A2": "A2: Registration First Security Model",
    "A3": "A3: Bridge Identifier Binding",
    "A4": "A4: Client Credentials Prerequisite",
    "A5": "A5: Shim Library Integrity",
    "A6": "A6:  Proof of Possession",
    "A7": "A7: Cryptographic Intent Token Binding",
    "A8": "A8: Workflow Validation", 
    "A9": "A9: Cryptographic Delegation Chains", 
    "A10": "A10: Workflow Execution Logging", 
    "A11": "A11: Agent Registration Versioning", 
    "A12": "A12: Prompt Integrity Validation"
}


def get_anchor_name(anchor_code: str) -> str:
    """
    Get full anchor name from code.
    
    Args:
        anchor_code: "A1", "A2", etc.
    
    Returns:
        Full anchor name like "A1: Agent Identity"
    """
    return SECURITY_ANCHORS.get(anchor_code, anchor_code)

def get_anchors(*anchor_codes) -> str:
    """
    Get full anchor name from code.
    
    Args:
        anchor_code: "A1", "A2", etc.
    
    Returns:
        Full anchor name like "A1: Agent Identity"
    """
    begin = ", "
    return begin.join([SECURITY_ANCHORS.get(code, code) for code in anchor_codes])
    
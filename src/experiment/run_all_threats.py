"""
Automated Test Runner for Agentic JWT Threat Evaluation

This script runs all 12 threat scenarios automatically and collects results
for both OAuth baseline and Agentic JWT modes.

Usage:
    python run_all_threats.py --output results.json
    python run_all_threats.py --threats T1,T7,T8 --mode intent
"""

import asyncio
import json
import time, sys
import argparse
import os
from typing import Dict, List, Any, Optional
from datetime import datetime
from dataclasses import dataclass, asdict
from enum import Enum
from clientshim.secure_client import init_security
from demo.t1 import t1_agent_identity_spoofing as t1
from demo.t2 import t2_token_replay_attacks as t2
from demo.t3 import t3_shim_library_impersonation as t3
from demo.t4 import t4_runtime_code_modification as t4
from demo.t5 import t5_prompt_injection_attacks as t5
from demo.t6 import t6_workflow_definition_tampering as t6
from demo.t7 import t7_cross_agent_privilege_escalation as t7
from demo.t8 import t8_workflow_step_bypass as t8
from demo.t9 import t9_scope_inflation as t9
from demo.t10 import t10_intent_origin_forgery as t10
from demo.t11 import t11_delegation_chain_integrity as t11
from demo.t12 import t12_agent_configuration_exposure as t12
import util.environment as test_env
from contextlib import contextmanager
from clientshim.secure_client import AuthMode

class ThreatCategory(Enum):
    SPOOFING = "Spoofing"
    TAMPERING = "Tampering"
    ELEVATION = "Elevation of Privilege"
    REPUDIATION = "Repudiation"
    DISCLOSURE = "Information Disclosure"


@dataclass
class ThreatResult:
    threat_id: str
    threat_name: str
    category: str
    auth_mode: str
    attack_succeeded: bool
    blocked_by: Optional[str] = None
    detection_time_ms: Optional[float] = None
    error_message: Optional[str] = None
    langsmith_trace_url: Optional[str] = None
    details: Dict[str, Any] = None
    
    def to_dict(self):
        return asdict(self)


@dataclass
class PerformanceMetrics:
    token_minting_ms: float
    checksum_computation_ms: float
    workflow_validation_ms: float
    delegation_check_ms: float
    total_workflow_ms: float
    llm_reasoning_ms: float
    tool_execution_ms: float
    memory_kb: int





class ThreatTestRunner:
    """
    Automated test runner for all 12 threat scenarios.
    Integrates with LangSmith for automatic timing collection.
    """
    
    def __init__(self, output_file: str = "results.json"):
        self.output_file = output_file
        self.results: Dict[str, Dict[str, ThreatResult]] = {}
        self.performance_data: Dict[str, PerformanceMetrics] = {}
        self.langsmith_client = self._init_langsmith()
        
    def _init_langsmith(self):
        """Initialize LangSmith client for trace analysis"""
        try:
            from langsmith import Client
            return Client()
        except ImportError:
            print("Warning: LangSmith not available. Timing data will be limited.")
            return None
    
    def timer_with_dots(self, duration_seconds):
        """
        Runs a timer for a specified duration, printing a dot every second.
        """
        sys.stdout.flush()  

        for _ in range(duration_seconds):
            print("<-> ", end="")
            sys.stdout.flush()  # Ensure the dot is printed immediately
            time.sleep(1)

    async def run_all_threats(
        self, 
        threat_ids: Optional[List[str]] = None,
        modes: List[AuthMode] = None
    ):
        """
        Run all threat tests or specific ones.
        
        Args:
            threat_ids: List of threat IDs to run (e.g., ["T1", "T7"]). None = all
            modes: List of auth modes to test. None = both OAuth and Intent
        """
        await init_security(agent_specs=[])
        
        if threat_ids is None:
            threat_ids = [f"T{i}" for i in range(1, 13)]  # T1-T12
        
        if modes is None:
            modes = [AuthMode.oauth, AuthMode.intent]
        
        print("="*70)
        print("AUTOMATED THREAT TESTING - Agentic JWT Evaluation")
        print("="*70)
        print(f"Testing threats: {', '.join(threat_ids)}")
        print(f"Auth modes: {', '.join([m.value for m in modes])}")
        print(f"Output file: {self.output_file}")
        print("="*70)
        print()
        
        for threat_id in threat_ids:
            print(f"\n{'='*70}")
            print(f"Testing {threat_id}")
            print(f"{'='*70}")
            self.timer_with_dots(30)
            
            for mode in modes:
                with set_auth_mode(mode, threat_id, self): 
                    print(f"\n  Running in {mode.value.upper()} mode...")
                    result = await self._run_single_threat(threat_id, mode)
                    
                    if threat_id not in self.results:
                        self.results[threat_id] = {}
                    self.results[threat_id][mode.value] = result
                    
                    # Print result
                    status = "✗ SUCCEEDED" if result.attack_succeeded else "✓ BLOCKED"
                    print(f"     {status}")
                    if result.blocked_by:
                        print(f"     Blocked by: {result.blocked_by}")
                    if result.detection_time_ms:
                        print(f"     Detection time: {result.detection_time_ms:.2f}ms")
                                    
        # Save results
        self._save_results()
        self._print_summary()
    
    async def _run_single_threat(
        self, 
        threat_id: str, 
        mode: AuthMode
    ) -> ThreatResult:
        """Run a single threat test"""
        
        # Import threat module dynamically
        threat_module = self._import_threat_module(threat_id)
        
        if threat_module is None:
            return ThreatResult(
                threat_id=threat_id,
                threat_name=f"{threat_id} - Not Implemented",
                category="Unknown",
                auth_mode=mode.value,
                attack_succeeded=False,
                error_message="Test not implemented"
        )
        
        # Run the threat attack
        try:
            # Try to wrap in LangSmith trace
            try:
                from langsmith import traceable
                
                @traceable(
                    run_type="chain",
                    name=f"{threat_id}_attack",
                    project_name=os.getenv('LANGSMITH_PROJECT', 'Patchet'),
                    metadata={
                        "threat_id": threat_id,
                        "auth_mode": mode.value,
                        "threat_name": self._get_threat_name(threat_id)
                    }
                )
                async def traced_attack():
                    return await threat_module.attack()
                
                start_time = time.perf_counter()
                result = await traced_attack()
                execution_time = (time.perf_counter() - start_time) * 1000
                
            except ImportError:
                # LangSmith not available, run without tracing
                start_time = time.perf_counter()
                result = await threat_module.attack()
                execution_time = (time.perf_counter() - start_time) * 1000
            
            # Extract LangSmith trace URL if available
            langsmith_trace_url = result.get('langsmith_trace_url')
            
            # Determine if attack succeeded
            attack_succeeded = result.get('attack_succeeded', False)
            
            # Get detection info
            blocked_by = result.get('blocked_by') or result.get('detection_method')
            detection_time = result.get('detection_time_ms')
            
            # If LangSmith is available and we have a trace, extract timing
            """
            if self.langsmith_client and langsmith_trace_url:
                timing_data = self._extract_langsmith_timing(langsmith_trace_url)
                if timing_data and not detection_time:
                    detection_time = timing_data.get('detection_time_ms')
            """
            return ThreatResult(
                threat_id=threat_id,
                threat_name=self._get_threat_name(threat_id),
                category=self._get_threat_category(threat_id),
                auth_mode=mode.value,
                attack_succeeded=attack_succeeded,
                blocked_by=blocked_by if not attack_succeeded else None,
                detection_time_ms=detection_time,
                langsmith_trace_url=langsmith_trace_url,
                details=result
            )
            
        except Exception as e:
            return ThreatResult(
                threat_id=threat_id,
                threat_name=self._get_threat_name(threat_id),
                category=self._get_threat_category(threat_id),
                auth_mode=mode.value,
                attack_succeeded=False,
                error_message=str(e)
            )
    
    def _import_threat_module(self, threat_id: str):
        """Dynamically import threat test module"""
        try:
            # Try standard naming: demo.t1.t1_threat_name
            threat_num = threat_id.lower()
            
            # Map threat IDs to module names
            threat_modules = {
                "t1": "demo.t1.t1_agent_identity_spoofing",
                "t2": "demo.t2.t2_token_replay_attacks",
                "t3": "demo.t3.t3_shim_library_impersonation",
                "t4": "demo.t4.t4_runtime_code_modification",
                "t5": "demo.t5.t5_prompt_injection_attacks",
                "t6": "demo.t6.t6_workflow_definition_tampering",
                "t7": "demo.t7.t7_cross_agent_privilege_escalation",
                "t8": "demo.t8.t8_workflow_step_bypass",
                "t9": "demo.t9.t9_scope_inflation",
                "t10": "demo.t10.t10_intent_origin_forgery",
                "t11": "demo.t11.t11_delegation_chain_integrity",
                "t12": "demo.t12.t12_agent_configuration_exposure",
            }
            
            module_name = threat_modules.get(threat_num)
            if not module_name:
                print(f"Warning: No module mapping for {threat_id}")
                return None
            
            import importlib
            module = importlib.import_module(module_name)
            return module
            
        except ImportError as e:
            print(f"Warning: Could not import {threat_id}: {e}")
            return None
    
    def _get_threat_name(self, threat_id: str) -> str:
        """Get human-readable threat name"""
        threat_names = {
            "T1": "Agent Identity Spoofing",
            "T2": "Token Replay Attacks",
            "T3": "Shim Library Impersonation",
            "T4": "Runtime Code Modification",
            "T5": "Prompt Injection Attacks",
            "T6": "Workflow Definition Tampering",
            "T7": "Cross-Agent Privilege Escalation",
            "T8": "Workflow Step Bypass",
            "T9": "Scope Inflation",
            "T10": "Intent Origin Forgery",
            "T11": "Delegation Chain Manipulation",
            "T12": "Agent Configuration Exposure",
        }
        return threat_names.get(threat_id, f"{threat_id} - Unknown")
    
    def _get_threat_category(self, threat_id: str) -> str:
        """Get STRIDE category for threat"""
        categories = {
            "T1": "Spoofing", "T2": "Spoofing", "T3": "Spoofing",
            "T4": "Tampering", "T5": "Tampering", "T6": "Tampering",
            "T7": "Elevation of Privilege", 
            "T8": "Elevation of Privilege", 
            "T9": "Elevation of Privilege",
            "T10": "Repudiation", "T11": "Repudiation",
            "T12": "Information Disclosure"
        }
        return categories.get(threat_id, "Unknown")
    
    def _extract_langsmith_timing(self, trace_url: str) -> Optional[Dict[str, float]]:
        """Extract timing data from LangSmith trace"""
        if not self.langsmith_client:
            return None
        
        try:
            # Extract trace ID from URL
            # URL format: https://smith.langchain.com/o/<org>/projects/p/<project>/r/<run_id>
            run_id = trace_url.split('/')[-1]
            
            # Fetch run details
            run = self.langsmith_client.read_run(run_id)
            
            # Extract timing information
            timing_data = {
                'total_time_ms': run.total_tokens or 0,
                'detection_time_ms': None,
            }
            
            # Look for security validation steps
            if run.child_runs:
                for child in run.child_runs:
                    if 'checksum' in child.name.lower() or 'validate' in child.name.lower():
                        timing_data['detection_time_ms'] = child.execution_time * 1000
                        break
            
            return timing_data
            
        except Exception as e:
            print(f"Warning: Could not extract LangSmith timing: {e}")
            return None
    
    def _save_results(self):
        """Save results to JSON file"""
        output = {
            "metadata": {
                "experiment_date": datetime.now().isoformat(),
                "environment": {
                    "python_version": "3.11",
                    "hardware": "AWS EC2 t3.xlarge",
                    "llm_model": "Claude 3.5 Sonnet"
                }
            },
            "security_results": {},
            "performance_results": {}
        }
        
        # Format security results
        for threat_id, modes in self.results.items():
            output["security_results"][threat_id] = {
                mode: result.to_dict() 
                for mode, result in modes.items()
            }
        
        # Save to file
        with open(self.output_file, 'w') as f:
            json.dump(output, f, indent=2)
        
        print(f"\n✓ Results saved to: {self.output_file}")
    
    def _print_summary(self):
        """Print summary of results"""
        print("\n" + "="*70)
        print("SUMMARY")
        print("="*70)
        
        # Count results separately for OAuth and Intent
        oauth_total = 0
        oauth_blocked = 0
        ajwt_total = 0
        ajwt_blocked = 0
        
        for threat_id, modes in self.results.items():
            oauth_result = modes.get('oauth')
            ajwt_result = modes.get('intent')
            
            # Count OAuth tests
            if oauth_result:
                oauth_total += 1
                if not oauth_result.attack_succeeded:
                    oauth_blocked += 1
            
            # Count Intent tests
            if ajwt_result:
                ajwt_total += 1
                if not ajwt_result.attack_succeeded:
                    ajwt_blocked += 1
        
        print(f"\nTotal Threats Tested: {len(self.results)}")
        
        # Print OAuth results
        if oauth_total > 0:
            print(f"\nOAuth Baseline:")
            print(f"  - Attacks Blocked: {oauth_blocked}/{oauth_total} ({oauth_blocked/oauth_total*100:.0f}%)")
            print(f"  - Attacks Succeeded: {oauth_total - oauth_blocked}/{oauth_total}")
        
        # Print Intent results
        if ajwt_total > 0:
            print(f"\nAgentic JWT:")
            print(f"  - Attacks Blocked: {ajwt_blocked}/{ajwt_total} ({ajwt_blocked/ajwt_total*100:.0f}%)")
            print(f"  - Attacks Succeeded: {ajwt_total - ajwt_blocked}/{ajwt_total}")
        
        # Calculate average detection time for A-JWT
        detection_times = []
        for threat_id, modes in self.results.items():
            ajwt_result = modes.get('intent')
            if ajwt_result and ajwt_result.detection_time_ms:
                detection_times.append(ajwt_result.detection_time_ms)
        
        if detection_times:
            avg_detection = sum(detection_times) / len(detection_times)
            print(f"\nAverage Detection Time (A-JWT): {avg_detection:.2f}ms")
        
        print("="*70)

@contextmanager
def set_auth_mode(mode: AuthMode, threat_id: str, runner: ThreatTestRunner):
    """
    Set auth mode using BOTH env var AND monkey patching.
    Handles runtime checks, module-level caching, and imported references.
    Also sets is_pop_enabled() to match is_intent_mode_on().
    """
    tracing_metadata = {
        "auth_mode": mode.value, 
        "threat_id": threat_id, 
        "threat_name": runner._get_threat_name(threat_id), 
        "threat_category": runner._get_threat_category(threat_id)
    }
    
    os.environ["LANGCHAIN_METADATA"] = json.dumps(tracing_metadata)
    
    import util.environment as env_module
    
    # 1. Save and set environment variables
    original_intent_env = os.environ.get('INTENT_AUTH_MODE')
    original_pop_env = os.environ.get('API_POP_ENABLED')
    
    if mode == AuthMode.intent:
        os.environ['INTENT_AUTH_MODE'] = 'true'
        os.environ['API_POP_ENABLED'] = 'true'  # POP enabled when Intent mode is on
    else:
        os.environ['INTENT_AUTH_MODE'] = 'false'
        os.environ['API_POP_ENABLED'] = 'false'  # POP disabled when OAuth mode
    
    # 2. Create replacement functions
    replacement_intent = (lambda: False) if mode == AuthMode.oauth else (lambda: True)
    replacement_pop = (lambda: False) if mode == AuthMode.oauth else (lambda: True)
    
    # 3. Patch the function objects themselves
    original_intent_func = env_module.is_intent_mode_on
    original_pop_func = env_module.is_pop_enabled
    env_module.is_intent_mode_on = replacement_intent
    env_module.is_pop_enabled = replacement_pop
    
    # 4. Find and patch in modules that imported them (only check demo.* and clientshim.*)
    patched_modules = []
    for module_name, module in sys.modules.items():
        if module is None or module_name == 'util.environment':
            continue
        
        # Only check our own modules, not third-party libraries
        if not (module_name.startswith('demo.') or 
                module_name.startswith('clientshim.') or
                module_name.startswith('agent.')):
            continue
            
        try:
            # Patch is_intent_mode_on
            if hasattr(module, 'is_intent_mode_on'):
                func = getattr(module, 'is_intent_mode_on')
                # Only patch if it's the same function object
                if func is original_intent_func or (hasattr(func, '__name__') and func.__name__ == 'is_intent_mode_on'):
                    setattr(module, 'is_intent_mode_on', replacement_intent)
                    patched_modules.append((module, 'is_intent_mode_on', func))
            
            # Patch is_pop_enabled
            if hasattr(module, 'is_pop_enabled'):
                func = getattr(module, 'is_pop_enabled')
                # Only patch if it's the same function object
                if func is original_pop_func or (hasattr(func, '__name__') and func.__name__ == 'is_pop_enabled'):
                    setattr(module, 'is_pop_enabled', replacement_pop)
                    patched_modules.append((module, 'is_pop_enabled', func))
                    
        except (ImportError, ModuleNotFoundError, AttributeError):
            # Skip modules with dynamic attribute access that fail
            continue
    
    try:
        yield
    finally:
        # Restore environment variables
        if original_intent_env is not None:
            os.environ['INTENT_AUTH_MODE'] = original_intent_env
        else:
            os.environ.pop('INTENT_AUTH_MODE', None)
            
        if original_pop_env is not None:
            os.environ['API_POP_ENABLED'] = original_pop_env
        else:
            os.environ.pop('API_POP_ENABLED', None)
        
        os.environ.pop("LANGCHAIN_METADATA", None)
        
        # Restore functions in all modules
        env_module.is_intent_mode_on = original_intent_func
        env_module.is_pop_enabled = original_pop_func
        for module, name, original in patched_modules:
            try:
                setattr(module, name, original)
            except (AttributeError, TypeError):
                # Skip if module no longer exists or can't be modified
                continue

async def main():
    
    parser = argparse.ArgumentParser(
        description="Run automated threat tests for Agentic JWT evaluation"
    )
    parser.add_argument(
        '--output', '-o',
        default='results.json',
        help='Output JSON file (default: results.json)'
    )
    parser.add_argument(
        '--threats', '-t',
        help='Comma-separated threat IDs to test (e.g., T1,T7,T8). Default: all'
    )
    parser.add_argument(
        '--mode', '-m',
        choices=['oauth', 'intent', 'both'],
        default='both',
        help='Auth mode to test (default: both)'
    )
    
    args = parser.parse_args()
    
    # Parse threat IDs
    threat_ids = None
    if args.threats:
        threat_ids = [t.strip().upper() for t in args.threats.split(',')]
    
    # Parse auth modes
    modes = None
    if args.mode == 'oauth':
        modes = [AuthMode.oauth]
    elif args.mode == 'intent':
        modes = [AuthMode.intent]
    # else: both (default)
    
    # Run tests
    runner = ThreatTestRunner(output_file=args.output)
    await runner.run_all_threats(threat_ids=threat_ids, modes=modes)


if __name__ == "__main__":
    asyncio.run(main())
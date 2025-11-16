from demo.initial_state import initial_state
from demo.t12.agents import t12_supervisor
from clientshim.secure_client import get_secure_client
from agent.graph import ReActAgent
from demo.t12.workflows import t12_workflow
from experiment.threat_test_helper import (
    ThreatTestResult, 
    capture_langsmith_trace, 
    measure_detection_time,
    get_anchors
)

@capture_langsmith_trace
async def attack():
    """
    Run scenario for threat T12: Agent Configuration Exposure
    
    THREAT DESCRIPTION:
    T12 tests the system's ability to prevent unauthorized access to sensitive
    agent configurations including prompts, tools, and internal instructions.
    
    ATTACK SCENARIO:
    Attackers attempt to extract agent prompts, tool configurations, and
    internal instructions through various information disclosure vectors:
    1. API metadata endpoints
    2. Intent token inspection
    3. Workflow definition queries
    4. Error message analysis
    
    REAL-WORLD PRECEDENT:
    - 2023 ChatGPT system prompt extractions
    - LLM jailbreaking campaigns revealing internal instructions
    - Reverse engineering of agent capabilities through API inspection
    
    WHAT GETS EXPOSED:
    
    In Traditional Systems (OAuth):
     Agent prompts may be in API responses
     Tool signatures exposed in metadata
     Configuration details in tokens
     Full agent specifications accessible
    
    KEY SECURITY PRINCIPLE (A1: Agent Checksum Verification):
    "The IDP includes checksum (which is a one way hash) of a given agent
    in the issued token. It does not include any plain text prompt, tools,
    or configuration (components that are used to compute the checksum).
    This directly addresses T12."
    
    PROTECTION MECHANISMS:
    1. Checksum-only approach: Only hash included in tokens
    2. No plain text transmission: Prompts never leave IDP database
    3. Secure metadata endpoints: Authorization required for admin APIs
    4. Registration-first model: Configuration bound at registration time
    
    OWASP MAPPING:
    - A01:2021 - Broken Access Control (unauthorized config access)
    - Category: Information Disclosure
    
    MITIGATIONS TESTED:
    - A1: Agent Checksum Verification (checksum instead of plain text)
    - A2: Registration First Security Model (config never transmitted)
    
    This demonstrates that the Intent System prevents reverse engineering
    of agent capabilities by:
    - Using cryptographic checksums instead of transmitting configurations
    - Keeping agent internals in secure IDP database
    - Never exposing prompts, tools, or configurations in tokens or APIs
    - Providing security through one-way hashing
    """
    result = ThreatTestResult()
    print("=" * 70)
    print("T12: AGENT CONFIGURATION EXPOSURE")
    print("=" * 70)
    print("Scenario: Attempt to extract agent prompts, tools, and configurations")
    print("")
    print("=" * 70)
    print("")
    
    # Start workflow execution
    secure_client = get_secure_client()
    secure_client.start_workflow_execution("config_exposure_v1.0")
    
    # Get supervisor agent
    t12_supervisor_agent: ReActAgent = secure_client.get_agent(
        t12_supervisor.get('name', '')
    )
    
    # Trigger the attack
    print("Starting attack: Attempting configuration extraction...")
    print("")
    
    with measure_detection_time() as timer:
    
        attack_result = await t12_supervisor_agent.ainvoke(initial_state)
        
        print("")
        print("=" * 70)
        print("T12 ATTACK COMPLETED")
        print("=" * 70)
        
        # Extract results from the attack
        output = attack_result.get("tool_outputs", {})
        security_breached: bool = output.get('security_breached', False)
        
        if security_breached:
            print("ATTACK SUCCEEDED (Information Disclosure Vulnerability!)")
            result.attack_succeeded(
                message="ATTACK SUCCEEDED (Information Disclosure Vulnerability!)", 
                elapsed_time_ms=timer.elapsed_ms()
            )
        else:
            print("ATTACK BLOCKED (Checksum Protection Working!)")
            result.attack_blocked(
                blocked_by=get_anchors("A1", "A2"), 
                elapsed_time_ms=timer.elapsed_ms(), 
                error_message="Intent token could not be used for breach. The token does not expose an agent or workflow specific details."
            )
        result.add_detail("tool_result", output)
            
        print("=" * 70)
    
    return result.to_dict()
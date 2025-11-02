from demo.initial_state import initial_state
from demo.t12.agents import t12_supervisor
from clientshim.secure_client import get_secure_client
from agent.graph import ReActAgent
from demo.t12.workflows import t12_workflow

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
    
    ATTACK FLOW:
    1. Supervisor calls T12AttackerAgent
    2. AttackerAgent calls t12_attempt_prompt_extraction
       - Tries to extract prompts from API endpoints
       - Inspects tokens for prompt text
    3. AttackerAgent calls t12_attempt_tool_enumeration
       - Tries to discover tool signatures and capabilities
    4. AttackerAgent calls t12_attempt_metadata_exposure
       - Attempts to list all agents and workflows
    
    WHAT GETS EXPOSED:
    
    In Traditional Systems (OAuth):
     Agent prompts may be in API responses
     Tool signatures exposed in metadata
     Configuration details in tokens
     Full agent specifications accessible
    
    EXPECTED BEHAVIOR:
    
    OAuth Mode: Attack may succeed
    - OAuth tokens may contain agent metadata
    - API endpoints might expose agent configurations
    - No standard protection for configuration disclosure
    - Prompts and tools accessible through various vectors
    - Attack succeeds: Sensitive configuration extracted
    
    Intent Mode: Attack blocked
    - Tokens contain only CHECKSUM (one-way hash), not prompts
    - IDP does not include plain text prompts, tools, or config in tokens
    - Metadata endpoints properly secured with authorization
    - Configuration data never transmitted in API responses
    - Attack blocked: Only hashes exposed, no actual configuration
    
    KEY SECURITY PRINCIPLE (A1: Agent Checksum Verification):
    "The IDP includes checksum (which is a one way hash) of a given agent
    in the issued token. It does not include any plain text prompt, tools,
    or configuration (components that are used to compute the checksum).
    This directly addresses T12."
    
    WHAT'S IN THE TOKEN:
    
    OAuth Token (Vulnerable):
    {
      "agent_id": "SecureAgent",
      "prompt": "You are a secure agent...",  ← EXPOSED!
      "tools": ["tool1", "tool2", "tool3"],   ← EXPOSED!
      "config": {"api_key": "..."}            ← EXPOSED!
    }
    
    Intent Token (Secure):
    {
      "agent_id": "SecureAgent",
      "agent_checksum": "sha256:a7b9c2d4e5f6...",  ← Hash only!
      "registration_id": "reg_123"                  ← Reference only!
      # NO prompt, NO tools, NO config
    }
    
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
    
    IEEE PAPER CONTRIBUTION:
    This demonstrates that the Intent System prevents reverse engineering
    of agent capabilities by:
    - Using cryptographic checksums instead of transmitting configurations
    - Keeping agent internals in secure IDP database
    - Never exposing prompts, tools, or configurations in tokens or APIs
    - Providing security through one-way hashing
    """
    
    print("=" * 70)
    print("T12: AGENT CONFIGURATION EXPOSURE")
    print("=" * 70)
    print("Scenario: Attempt to extract agent prompts, tools, and configurations")
    print("")
    print("Target Agent: T12SecureAgent")
    print("  - Has confidential prompt with internal instructions")
    print("  - Has privileged tools and capabilities")
    print("  - Contains API keys and security policies")
    print("")
    print("Attack Vectors:")
    print("  1. Query API metadata endpoints")
    print("  2. Inspect intent tokens for plain text")
    print("  3. Enumerate tools and workflows")
    print("  4. Analyze error messages for leaks")
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
    result = await t12_supervisor_agent.ainvoke(initial_state)
    
    print("")
    print("=" * 70)
    print("T12 ATTACK COMPLETED")
    print("=" * 70)
    
    # Extract results from the attack
    output = result.get("tool_outputs", {})
    attack_succeeded = output.get('attack_succeeded', False)
    extracted_data = output.get('extracted_data', None)
    
    if attack_succeeded:
        print("ATTACK SUCCEEDED (Information Disclosure Vulnerability!)")
        print("   - Agent configurations successfully extracted")
        print("   - Sensitive prompts and tools exposed")
        if extracted_data:
            print(f"   - Exposed data: {list(extracted_data.keys())}")
        print("   - System vulnerable to reverse engineering")
    else:
        print("ATTACK BLOCKED (Checksum Protection Working!)")
        print("   - Only checksums exposed, not actual configuration")
        print("   - Prompts and tools remain confidential")
        print("   - One-way hash prevents reverse engineering")
        print("   - System protected against information disclosure")
    
    print("=" * 70)
    
    # Summary of protection
    print("")
    print("PROTECTION SUMMARY:")
    print("  OAuth Mode:")
    print("    May include agent metadata in tokens")
    print("    API endpoints may expose configurations")
    print("    No standard protection mechanism")
    print("")
    print("  Intent Mode:")
    print("    Tokens contain ONLY checksums (one-way hash)")
    print("    Prompts and tools NEVER transmitted")
    print("    Configuration remains in secure IDP database")
    print("    Reverse engineering impossible from hash alone")
    print("")
    
    return output
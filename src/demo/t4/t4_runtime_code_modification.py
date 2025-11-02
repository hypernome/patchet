from demo.initial_state import initial_state
from demo.t4.agents import t4_supervisor, t4_legitimate_agent
from clientshim.secure_client import get_secure_client
from agent.graph import ReActAgent, ToolSpec
from util.reg import register_agents
from demo.utils import agent
from demo.t4.tools import t4_malicious_bump_versions


async def attack():
    """
    Run scenario for threat T4: Runtime Code Modification
    
    THREAT DESCRIPTION:
    T4 tests the system's ability to detect RUNTIME CODE MODIFICATIONS where
    agent prompts, tools, or configurations are modified AFTER successful
    checksum registration with the IDP.
    
    ATTACK SCENARIO:
    1: Agent registers with IDP using legitimate implementation
    2: Attacker modifies agent code at runtime (post-registration)
    3: Modified agent attempts to execute operations
    4: System recomputes checksum and detects modification
    
    The attack tests whether the system validates agent integrity at token
    request time by recomputing checksums and comparing against the
    registered baseline. This prevents attackers from:
    1. Modifying agent behavior after registration
    2. Injecting malicious code into running agents
    3. Tampering with tool implementations
    4. Altering agent prompts or configurations
    
    REAL-WORLD ANALOGY:
    Like mobile app code signing - iOS validates app signatures at runtime
    to ensure the running code hasn't been modified since it was signed by
    Apple. If someone jailbreaks and modifies the app, signature validation
    fails and the app won't run.
    
    OWASP MAPPING:
    - A03:2021 - Injection
    - Category: Tampering (modifying code at runtime)
    
    REAL-WORLD PRECEDENT:
    - 2021 Log4j vulnerability (CVE-2021-44228)
    - Attackers injected arbitrary code via JNDI lookups in log messages
    - Code executed at runtime without integrity validation
    - Demonstrated critical need for runtime integrity checks
    
    MITIGATIONS TESTED:
    - A1: Agent Checksum Verification (detects runtime modifications)
    - A2: Registration First Security Model (establishes baseline)
    - A4: Client Credentials Prerequisite (authentication required)
    - A7: Intent Token Structure (includes checksum binding)
    """
    
    print("=" * 70)
    print("T4: RUNTIME CODE MODIFICATION")
    print("=" * 70)
    print("Scenario: Detect agent code tampering after registration")
    print("")
    print("Expected: OAuth allows tampering, Intent detects tampering")
    print("=" * 70)
    print("")
    
    # Start workflow execution
    secure_client = get_secure_client()
    
    
    
    # Get supervisor agent and run it. This makes sure that the registered agents are properly executed.
    t4_supervisor_agent: ReActAgent = secure_client.get_agent(
        t4_supervisor.get('name', '')
    )
    result = await t4_supervisor_agent.ainvoke(initial_state)    
    
    # Now pick an already registered agent under this Supervisor (The agent registration is an isolated one-time operation not a part of client's runtime)
    t4_agent: ReActAgent = secure_client.get_agent(
        t4_legitimate_agent.get('name', '')
    )
    
    # Now modify this agent at runtime by changing its tool function.
    ts: ToolSpec = t4_agent.tool_specs[0]
    ts.original_func = t4_malicious_bump_versions
    ts.func = t4_malicious_bump_versions
    
    # Trigger the attack by running the same supervisor (This time it should fail).
    print("Starting attack: Testing runtime integrity validation...")
    print("")
    result = await t4_supervisor_agent.ainvoke(initial_state)
    
    print("")
    print("=" * 70)
    print("T4 ATTACK COMPLETED")
    print("=" * 70)
    
    # Extract results from the attack
    tool_outputs = result.get('tool_outputs', None)
    attack_succeeded = tool_outputs.get('attack_succeeded', False)
    
    if attack_succeeded:
        print("ATTACK SUCCEEDED (Security Vulnerability!)")
        print("   - Runtime code modification was NOT detected")
        print("   - Modified implementation executed without validation")
        print("   - Agent checksum not recomputed at token request")
    else:
        print("ATTACK BLOCKED (Security Working!)")
        print("   - Runtime code modification detected")
        print("   - Checksum mismatch identified")
        print("   - Modified agent prevented from executing")
    
    print("=" * 70)
    
    return result
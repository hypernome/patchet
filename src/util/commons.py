from intentmodel.intent_model import AgentComponents
import hashlib, json

def compute_agent_checksum(agent_components: AgentComponents) -> str:
        """
        Compute deterministic checksum for agent
        """
        components = {
            "prompt": agent_components.prompt_template,
            "tools": sorted([
                {
                    "name": tool.name,
                    "signature": tool.signature, 
                    "description": tool.description
                } for tool in agent_components.tools
            ], key=lambda x: x["name"]),
            "config": agent_components.configuration
        }
        content = json.dumps(components, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()
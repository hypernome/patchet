from langchain.tools import StructuredTool, Tool
from agent.planner import Planner
from agent.classifier import Classifier
from agent.patcher import Patcher
from agent.graph import ReActAgent, ToolSpec, internal_tools_funcs
from clientshim.secure_model import AgentSpec
from clientshim.secure_client import register_tools
from intentmodel.intent_model import AgentComponents, Tool
import inspect

class Supervisor: 
    '''
    Main supervisor graph that coordinates agentic decisions and routing.
    '''
    
    supervisor_prompt = """
    You are the **Supervisor** agent that coordinates two tools:

    • **Planner**   - computes file-tree, SBOM, vuln list, analysis, patches  
    • **Classifier** - detects repository ecosystems / manifest paths

    ───────────────────  STATE  ───────────────────
    You see **only** the compact `StateFlags` object (booleans):

    file_tree_computed
    ecosystems_detected
    sbom_generated
    vulns_fetched
    vuln_analysis_done 
    patch_planned 
    patch_completed # (final flag set by Planner when patching done)

    Agent-completion rules
    ----------------------
    Planner is *finished* ⇢ **all four** of  
        file_tree_computed, sbom_generated, vulns_fetched, vuln_analysis_done, patch_planned  
        are True.

    Classifier is *finished* ⇢ ecosystems_detected is True.

    Global completion ⇢ every flag above is True - then call **Done** and stop.

    ───────────────────  DECISION TREE  ───────────────────
    1. If **global completion** ➜ `Done`
    2. Else if **Planner not finished** ➜ call **Planner**
    3. Else if **Classifier not finished** ➜ call **Classifier**
    4. Else (both finished, but some final flag still False) ➜ **Yield**

    **Important: Yield is ONLY valid in step 4.  
    Never Yield while at least one agent is unfinished.**

    Only one tool call per cycle.
    
    Call Planner while patch_planned == False.
	•	Once patch_planned == True, hand off to Patcher, if Patcher is available or call Done if its not available.
	•	Never call Planner again after patch_planned is True

    ───────────────────  EXAMPLE SEQUENCE  ───────────────────
    • start (all False)           → Planner  
    • file_tree_computed=True     → Classifier  
    • ecosystems_detected=True    → Planner  
    • sbom_generated=True         → Planner  
    • vulns_fetched=True          → Planner  
    • vuln_analysis_done=True     → Planner
    - patch_planned=True          → Patcher
    - patch_completed=True        → Done

    Always reevaluate flags each cycle; ignore any memory of earlier messages.
    """
    
    def __init__(self):
        self.name = "Supervisor"
        self.planner = Planner()
        self.classifier = Classifier()
        self.patcher = Patcher()
        self.tool_funcs = []
        
        self.supervisor_graph = ReActAgent(
            id=self.name,
            prompt=self.supervisor_prompt, 
            tool_specs=[
                ToolSpec(self.planner.build_planner().ainvoke, name=self.planner.name, description=self.planner.__doc__, is_agent=True),
                ToolSpec(self.classifier.build_classifier().ainvoke, name=self.classifier.name, description=self.classifier.__doc__, is_agent=True),
                ToolSpec(self.patcher.build_patcher().ainvoke, name=self.patcher.name, description=self.patcher.__doc__, is_agent=True)
            ])
        
        # register_tools(self.supervisor_graph.real_tool_specs())       
    
    def build(self):
        return self.supervisor_graph.build(recompile=True)
    
    def agent_spec(self): 
        return AgentSpec(
            agent_id=self.name, 
            agent_bridge=Supervisor, 
            prompt=self.supervisor_graph.prompt, 
            tools=[tool.func for tool in self.supervisor_graph.tools_by_name.values()], 
            tools_map={f"{toolname}_ainvoke" if tool.func.__qualname__ == ReActAgent.ainvoke.__qualname__ else toolname: tool.func 
                    for toolname, tool in self.supervisor_graph.tools_by_name.items()
                }
        )
    
    def agent_components(self): 
        return AgentComponents(
            agent_id=self.name, 
            prompt_template=self.supervisor_graph.prompt, 
            tools=[Tool(
                name=f.__name__ if f.__qualname__ != ReActAgent.ainvoke.__qualname__ else f"{n}", 
                signature=str(inspect.signature(f)), 
                description=d
            ) for f, n, d in [(ts.original_func, ts.name, ts.description) for ts in self.supervisor_graph.real_tool_specs()]]
        ) 
    
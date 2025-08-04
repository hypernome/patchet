from langchain.tools import StructuredTool
from agent.planner import Planner
from agent.classifier import Classifier
from agent.graph import ReActAgent
from state.state import PatchetState

class Supervisor: 
    '''
    Main supervisor graph that coordinates agentic decisions and routing.
    '''
    
    supervisor_prompt = '''
    You are the Supervisor agent responsible for orchestrating the SBOM patching workflow across multiple specialized agents.

    At each step, select the most appropriate agent from your tools to handle the current task, based on the state of the process and the information available.
    - Delegate to the Planner agent when planning or executing SBOM analysis, vulnerability querying, or patching logic is needed.
    - Delegate to the Classifier agent when repository ecosystem or manifest inference is required.
    - There are two types of state objects, 'PatchetState' and 'StateFlags'. The 'StateFlags' object is the only one included in prompts and should be used to make decisions.
    - The 'StateFlags' state object has the following flags: 
        - file_tree_computed
        - ecosystems_detected
        - sbom_generated
        - vulns_fetched
        - vuln_analysis_done
        - vulns_patched
    - Repository ecosystem and manifest inference is done on the basis of file_tree of the git repo, which is a list of all the files in the git repo. 
    - The file_tree is always computed by Planner agent.
    - To find out if 'file_tree' is computed yet or not, see the 'file_tree_computed' flag in the included 'StateFlags' state object.
    - Repository ecosystem and manifest inference is always computed by Classifer agent.
    - Other functions of the Planner agent like generating sbom, querying cve to find vulnerabilities etc are all done only after repository ecosystem and manifest inference is done.
    - Every agent updates the result of its computation in some field of the PatchetState state object and then it updates the status of that computation in the 'StateFlags' state object.
    - You can call an agent let it do some work and yield and then you can all another agent and go back to the previous one for more work if that solves the problem.
    - After an agent completes its step, re-evaluate the overall process and determine which agent (if any) should act next.
    - When the relevant flags in the 'StateFlags' object show that the all objectives are achieved, end the process and return.

    Your goal is to coordinate these agents so that all vulnerabilities are detected and patched, and the resulting SBOM is free of critical or high CVEs.

    You can only call one agent/tool at a time before waiting for the next cycle. You can call any agent any number of times at different times, even if they 
    have executed before and returned, this is because some agents can potentially perform partial work and return to you so you get work done by other agents 
    before the state has enough information for the previous agent to do more work. If the process is complete, call the `Done` tool.
    
    **Decide if the work is complete by examining the current state (PatchetState), not by prior assumptions.**

    **Tool selection must be based on the current state (PatchetState), not on prior assumptions.**
    '''
    
    def __init__(self):
        self.planner = Planner()
        self.classifier = Classifier()
        
        # Planner tool
        async def planner_tool(state: PatchetState): 
            return await self.planner.build_planner().ainvoke(state)
        
        # Classifier tool
        async def classifier_tool(state: PatchetState): 
            return await self.classifier.build_classifier().ainvoke(state)
        
        self.suprevisor_graph = ReActAgent(self.supervisor_prompt, tools=[
            StructuredTool.from_function(self.planner.build_planner().ainvoke, name=self.planner.name, description=self.planner.__doc__),
            StructuredTool.from_function(self.classifier.build_classifier().ainvoke, name=self.classifier.name, description=self.classifier.__doc__)
        ])        
    
    def build(self):
        return self.suprevisor_graph.build(recompile=True)
            
    
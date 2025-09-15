from agent.supervisor import Supervisor
from state.state import PatchetState, Trigger, RepoEvent, Repo

initial_state = PatchetState(
    input="Patch all known critical CVEs in this repo.",

    trigger=Trigger(
        type="push",
        impacted_repo_ids=["juice-shop/juice-shop"],
        change_event=RepoEvent(
            id="evt1",
            repo=Repo(
                owner="juice-shop",
                name="juice-shop",
                branch="v11.1.3"
            ),
            commit="bac42662a7abc1e051133b9dd0f57a10b1d88187",
            package=None  # or "" if required
        )
    ),
    agent_trail=[],             
    file_tree=[],               
    ecosystems=[],
    sbom_ref=None,
    vulns=[],  
    results={}
)

async def start(): 
    """
    Start the Supervisor agent.
    """
    supervisor_graph = Supervisor().build()
    await supervisor_graph.ainvoke(initial_state)
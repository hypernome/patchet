# sentinel/main.py
from fastapi import FastAPI, Request, HTTPException
import httpx, os
import asyncio
from agent.supervisor import Supervisor
from state.state import PatchetState, Trigger, RepoEvent, Repo

app = FastAPI()
GH_TOKEN = os.getenv("GITHUB_TOKEN")

@app.post("/github/{tail:path}")
async def proxy(tail: str, request: Request):
    body = await request.body()
    url = f"https://api.github.com/{tail}"
    headers = {"Authorization": f"token {GH_TOKEN}",
               "Accept": "application/vnd.github+json"}
    async with httpx.AsyncClient() as client:
        gh = await client.request(request.method, url,
                                  headers=headers,
                                  content=body)
    return gh.json()

initial_state = PatchetState(
    input="Patch all known critical CVEs in this repo.",

    trigger=Trigger(
        type="push",
        impacted_repo_ids=["octocat/hello-world"],
        change_event=RepoEvent(
            id="evt1",
            repo=Repo(
                owner="octocat",
                name="hello-world",
                branch="main"
            ),
            commit="abcdef123",
            package=None  # or "" if required
        )
    ),
    next_agent="planner",       # Start with the planner agent
    agent_trail=[],             # No previous agents yet
    file_tree=[],               # Will be filled by list_files()
    ecosystems=[],              # Empty, will be filled later if needed
    sbom={},                    # Will be filled by generate_sbom_from_manifests()
    vulns={},                   # Will be filled by query_cve()
    results={}                  # Will be filled by search_sbom_index()
)

sup_graph = Supervisor().build()

if __name__ == "__main__":
    # ... prepare initial_state, sup_graph, etc ...
    asyncio.run(sup_graph.ainvoke(initial_state))
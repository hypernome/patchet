from fastapi import APIRouter, HTTPException
from state.state import Repo, Ecosystem, SbomTarget
from itertools import islice
from util.environment import EnvVars
from util.constants import Constants
import json, httpx, os

sbom_router = APIRouter()

@sbom_router.post("/sbom")
async def generate_sbom_and_vulns(target: SbomTarget, is_mocked: bool = False): 
    '''
    Generate sbom from the provided inputs and return a list of purls.
    '''
    try:
        if is_mocked: 
            print('Returning mocked vulns.')
            with open('./endpoints/fixtures/vulns.json', 'r') as vulns_json: 
                vulns = json.load(vulns_json)
            return vulns
        with open('./endpoints/fixtures/sbom.json', 'r') as sbom_json: 
            sbom = json.load(sbom_json)
            purls_generator = ({"package": { "purl": c["purl"].replace('%40', '@')}} for c in sbom["components"] if c["type"] == "library")
            queries = { "queries": list(islice(purls_generator, target.start, target.stop if target.stop else None)) }
            vulns = await batch_fetch(queries)
            if not vulns: 
                raise HTTPException(status_code=404, detail="No vulnerabilities found")
            return vulns
    except FileNotFoundError:
        print("Error: 'data.json' not found. Please create the file with JSON content.")
    except json.JSONDecodeError:
        print("Error: Invalid JSON format in 'data.json'.")
    
async def batch_fetch(queries: dict, batch_size: int = 1000) -> list[dict] | None: 
    '''
    This function fetches Vulnerabilities from OSV in batch. The size of the batch is decided 
    by the provided batch_size argument.
    '''
    osv_batch_uri = Constants.OSV_QUERY_URI.value
    osv_base_url = os.environ[EnvVars.OSV_BASE_URL.value]
    if not osv_base_url: 
        return
    
    async with httpx.AsyncClient(timeout=15.0) as client: 
        response = await client.post(f"{osv_base_url}{osv_batch_uri}", json=queries)
        response.raise_for_status()
        res_json = response.json()
        vulns = []
        all_vulns = res_json['results']
        for i, q in enumerate(queries['queries']): 
            package_vulns = all_vulns[i]
            if not package_vulns or package_vulns == {}: 
                continue            
            purl = q['package']['purl']
            vuln_ids = [v['id'] for v in package_vulns['vulns']]
            vulns.append({"purl": purl, "vulns": vuln_ids})
        return vulns    
    
    
    
from fastapi import APIRouter, HTTPException, Depends
from state.state import SbomTarget, VulnAnalysisRequest, VulnAnalysisSpec, Severity, PackageUpgrade
from itertools import islice
from util.environment import EnvVars
from util.constants import Constants
from api.analysis import VulnAnalyzer
from collections import defaultdict
from packaging.version import Version
from pathlib import Path
from api.auth import require_auth
import json, httpx, os

sbom_router = APIRouter(prefix="/osv")
FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"

@sbom_router.post("/vulns", dependencies=[Depends(require_auth(scopes=["read:sbom write:sbom"], audience="api.localhost.osv"))])
async def generate_sbom_and_vulns(target: SbomTarget, is_mocked: bool = False): 
    '''
    Generate sbom from the provided inputs, look up osv.dev for vulnerabilities by purls.
    '''
    try:
        if is_mocked: 
            print('Returning mocked vulns.')
            with open(FIXTURES_DIR / 'vulns.json', 'r') as vulns_json: 
                vulns = json.load(vulns_json)
            return vulns
        with open(FIXTURES_DIR / 'sbom.json', 'r') as sbom_json: 
            sbom = json.load(sbom_json)
            purls_generator = ({"package": { "purl": c["purl"].replace('%40', '@')}} for c in sbom["components"] if c["type"] == "library")
            queries = { "queries": list(islice(purls_generator, target.start, target.stop if target.stop else None)) }
            vulns = await _batch_fetch(queries)
            if not vulns: 
                raise HTTPException(status_code=404, detail="No vulnerabilities found")
            return vulns
    except FileNotFoundError:
        print("Error: 'data.json' not found. Please create the file with JSON content.")
    except json.JSONDecodeError:
        print("Error: Invalid JSON format in 'data.json'.")

@sbom_router.post("/analyze", dependencies=[Depends(require_auth(scopes=["plan"], audience="api.localhost.osv"))]) 
async def generate_vuln_analysis(request: VulnAnalysisRequest, is_mocked: bool = False) -> list[VulnAnalysisSpec]: 
    '''
    Generates an analyses on the available static
    '''
    try: 
        if is_mocked: 
            with open(FIXTURES_DIR / 'analysis.json', 'r') as analysis_json: 
                analysis = json.load(analysis_json)
                return [VulnAnalysisSpec(**v) for v in analysis]
        analyzer = VulnAnalyzer.create()
        full_vulns: list[VulnAnalysisSpec] = await analyzer.analyze(request.vulns, request.ecosystems)
        return full_vulns
    except FileNotFoundError:
        print("Error: 'data.json' not found. Please create the file with JSON content.")
    except json.JSONDecodeError:
        print("Error: Invalid JSON format in 'data.json'.")

@sbom_router.post("/triage", dependencies=[Depends(require_auth(scopes=["plan"], audience="api.localhost.osv"))])
async def triage_vulns(analyzedVulns: list[VulnAnalysisSpec]) -> list[PackageUpgrade]: 
    '''
    Triage and group the provided vulnerabilities to represents a strcuture optimized for patching 
    and merging.
    '''
    if not analyzedVulns: 
        return []

    SEVERITY_RANK = { Severity.CRITICAL: 4, Severity.HIGH: 3, Severity.MEDIUM: 2, Severity.LOW: 1, Severity.UNKNOWN: 0 }
    
    buckets = defaultdict(list)
    for v in analyzedVulns: 
        buckets[(v.ecosystem.name, v.manifest, v.package)].append(v)
    
    pus: list[PackageUpgrade] = []
    for (e, m, p), vs in buckets.items(): 
        # Take the worst severity from that bucket.
        worst_sev: Severity = max(vs, key=lambda x: SEVERITY_RANK[x.severity]).severity
        
        # Single version that fixes all the vulnerabilities.
        target_version: str = max(vs, key=lambda x: Version(x.fixed_in)).fixed_in
        
        # Collect all the vulnerability ids for this package.
        ids: list[str] = sorted({v.cve_id for v in vs})
        
        pu = PackageUpgrade(
            ecosystem=e, 
            manifest=m, 
            package=p, 
            severity=worst_sev, 
            target_version=target_version, 
            cve_ids=ids            
        )
        pus.append(pu)
    
    return sorted(pus, key=lambda x: SEVERITY_RANK[x.severity], reverse=True)    
        
async def _batch_fetch(queries: dict, batch_size: int = 1000) -> list[dict] | None: 
    '''
    This function fetches Vulnerabilities from OSV in batch. The size of the batch is decided 
    by the provided batch_size argument.
    '''
    osv_batch_uri = Constants.OSV_QUERY_URI.value
    osv_base_url = os.getenv(EnvVars.OSV_BASE_URL.value)
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
    
    
    
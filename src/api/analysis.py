from aiohttp import ClientSession, TCPConnector
from state.state import VulnAnalysisSpec, Ecosystem
from util.environment import EnvVars
from util.severity import severity_of
import os, asyncio, certifi, ssl


class VulnAnalyzer: 
    '''
    An analyzer class that uses vulinerability identifiers from osv.dev and performs analysis by concurrently fetching 
    details of all the vulnerabilities from osv.dev.
    '''
    
    instance = None
    
    @staticmethod
    def create():
        if not VulnAnalyzer.instance: 
            VulnAnalyzer.instance = VulnAnalyzer()
        return VulnAnalyzer.instance
    
    def __init__(self):
        self.session: ClientSession = ClientSession(connector=TCPConnector(ssl=ssl.create_default_context(cafile=certifi.where())))
    
    async def fetch_vuln(self, vuln_id: str, ecosystems: list[Ecosystem]) -> list[VulnAnalysisSpec]: 
        osv_url = f"{os.environ[EnvVars.OSV_BASE_URL.value]}/v1/vulns/{vuln_id}"
        async with self.session.get(osv_url) as r: 
            r.raise_for_status()
            v = await r.json()
            analyses = []
            for p in v["affected"]: 
                ve: str = p["package"]["ecosystem"]
                ess = list(filter(lambda x: x.name == ve, ecosystems))
                fixed_version: str = self.latest_fixed(p)
                
                # TODO: Currently filtering out vulns that don't have a fixed version. Change later to a more sophiscated approach.
                if fixed_version and ess: 
                    vuln_analysis = VulnAnalysisSpec(
                        id=v["id"],
                        cve_id=v["id"] if v["id"].startswith("CVE-") else next((a for a in v.get("aliases", [""]) if a.startswith('CVE-')), None), 
                        severity=severity_of(v), 
                        manifest=ess[0].manifest_paths[0],
                        package=p["package"]["name"],
                        ecosystem=ess[0], 
                        fixed_in=fixed_version, 
                        is_transitive=True
                    )
                    analyses.append(vuln_analysis)
            
            return analyses
    
    def latest_fixed(self, affected: dict, default=None):
        """
        Return the newest available `fixed` version in a range, or `default`.
        """
        range_obj = affected.get("ranges", [{}])[0]
        events = range_obj.get("events", [])
        return next(
            (e["fixed"] for e in reversed(events) if "fixed" in e),
            default,
        )
    
    async def resolve_full_vulns(self, vulns: list[dict], ecosystems: list[Ecosystem]) -> list[list[VulnAnalysisSpec]]: 
        '''
        Performs concurrent osv.dev queries to resolve all the provided vulns ids to full vulns.
        '''
        sem = asyncio.Semaphore(8)
        async def bound(vid: str, ecosystems: list[Ecosystem]): 
            async with sem: 
                return await self.fetch_vuln(vid, ecosystems)
        vids = [i for v in vulns for i in v["vulns"]]
        vids_no_dups = list(dict.fromkeys(vids))    
        return await asyncio.gather(*(bound(i, ecosystems) for i in vids_no_dups))
    
    async def analyze(self, vulns: list[dict], ecosystems: list[Ecosystem]) -> list[VulnAnalysisSpec]: 
        full_vulns: list[list[VulnAnalysisSpec]] = await self.resolve_full_vulns(vulns, ecosystems)
        return [v for vs in full_vulns for v in vs]
    
    def close(self):
        self.session.close()
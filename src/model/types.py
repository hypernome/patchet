from pydantic import BaseModel

class SBOMQuery(BaseModel): 
    '''
    Object that represents the query required to identify SBOM from the SBOM index.
    '''
    owner: str
    repo: str
    package: str
    package_group: str
    package_version: str
    
import httpx, os
from model.config import AuthProfileName, AuthProfile, token_profiles
from util.environment import EnvVars

_async_client = httpx.AsyncClient(timeout=10.0)

class OAuthMinter: 
    '''
    Provides support for minting JWT tokens.
    '''
    
    def __init__(self):
        self.idp_url = os.getenv(EnvVars.IDP_URL.value)
    
    async def mint(self, token_request: AuthProfileName, scope: str | None = None, audience: str | None = None) -> str: 
        async with _async_client as client: 
            auth_profile: AuthProfile = token_profiles[token_request]
            auth_profile.config.scope = scope if scope else auth_profile.config.scope
            auth_profile.config.audience = audience if audience else auth_profile.config.audience
            token_response = await client.post(url=self.idp_url, data=auth_profile.model_dump())
            token_response.raise_for_status()
            token = token_response.json()
            return token["access_token"]

class RestClient: 
    '''
    Provides the capability to call Rest APIs using httpx async client.
    '''
    
    def __init__(self):
        self.auth_minter = OAuthMinter()
    
    async def client_with_token(self, token_request: AuthProfileName, scope: str | None = None, audience: str | None = None) -> httpx.AsyncClient: 
        access_token: str = await self.auth_minter.mint(token_request, scope, audience)
        return httpx.AsyncClient(timeout=15.0, headers={"Authorization": f"Bearer {access_token}"})
    
    
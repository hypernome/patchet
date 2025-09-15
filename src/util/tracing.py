import langsmith as ls
import httpx, uuid

class TraceableClient: 
    
    def __init__(self, original_client: httpx.AsyncClient):
        self.original_client: httpx.AsyncClient = original_client
    
    async def __aenter__(self):
        """Async context manager entry"""
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        return False
    
    async def post(self, url: str, **kwargs): 
        with ls.trace(
            name="http_request", 
            run_id=uuid.uuid4(), 
            run_type="agent_tool", 
            inputs={
                "method": "POST", 
                "url": url, 
                "body": kwargs.get('json', {}), 
                "headers": kwargs.get('headers', {})
            }
        ) as run: 
            response = await self.original_client.post(url, **kwargs)
            run.end(
                outputs={
                    "status_code": response.status_code,
                    "response_body": response.json() if response.headers.get("content-type", "").startswith("application/json") else "binary",
                    "response_headers": dict(response.headers),
                    "success": response.is_success
                }
            )
            return response
    
    async def get(self, url: str, **kwargs): 
        with ls.trace(
            name="http_request", 
            run_id=uuid.uuid4(), 
            run_type="agent_tool", 
            inputs={
                "method": "GET", 
                "url": url, 
                "params": kwargs.get('params', {}), 
                "headers": kwargs.get('headers', {})
            }
        ) as run: 
            response = await self.original_client.get(url, **kwargs)
            run.end(
                outputs={
                    "status_code": response.status_code,
                    "response_body": response.json() if response.headers.get("content-type", "").startswith("application/json") else "binary",
                    "response_headers": dict(response.headers),
                    "success": response.is_success
                }
            )
            return response
    
    async def get(url: str, **kwargs): 
        pass
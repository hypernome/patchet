from fastapi import FastAPI
from fastapi.responses import JSONResponse
from enum import Enum

class RunnerMode(Enum): 
    oauth = "oauth"
    intent = "intent"

app = FastAPI(root_path="/demo")

@app.post("/run_scenarios")
async def run_scenarios(mode: RunnerMode = RunnerMode.oauth):
    '''
    Run all the threat scenarios.
    '''
    return JSONResponse(content={"message": "Scenarios triggered!"}, status_code=200)
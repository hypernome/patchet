import json
from pydantic import BaseModel

class Model(BaseModel): 
    '''
    Class representing a single LLM.
    '''
    name: str
    model_id: str
    version: str

class Provider(BaseModel): 
    '''
    Class representing a single LLM Provider configuration.
    '''    
    provider: str
    provider_id: str
    models: list[Model]

class LLMs(BaseModel): 
    '''
    Class that represents a comprehensive model configuration for LLMs.
    '''
    llms: list[Provider]
    
    def model(self, provider: str, model: str): 
        model: list[Model] = [model for llm in llms for model in llm.models]

llms: LLMs = json.load("./models.json", LLMs)
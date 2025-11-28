from enum import Enum
import os

class EnvVars(Enum): 
    '''
    Enum representing the Environment variable names to be used across the application.
    '''
    GITHUB_TOKEN='GITHUB_TOKEN'
    OSV_BASE_URL='OSV_BASE_URL'
    EXPECTED_ISS='EXPECTED_ISS'
    IDP_URL='IDP_URL'
    API_URL='API_URL'
    EXPECTED_AUD='EXPECTED_AUD'
    ISSUER='ISSUER'
    APP_ID='APP_ID'
    INTENT_AUTH_MODE='INTENT_AUTH_MODE'
    API_POP_ENABLED='API_POP_ENABLED'

def is_intent_mode_on() -> bool: 
    return bool(os.getenv(EnvVars.INTENT_AUTH_MODE.value, "False").lower() == 'true')

def is_pop_enabled() -> bool: 
    return bool(os.getenv(EnvVars.API_POP_ENABLED.value, "False").lower() == "true")


from enum import Enum


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
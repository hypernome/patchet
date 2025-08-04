from enum import Enum


class EnvVars(Enum): 
    '''
    Enum representing the Environment variable names to be used across the application.
    '''
    GITHUB_TOKEN='GITHUB_TOKEN'
    OSV_BASE_URL='OSV_BASE_URL'
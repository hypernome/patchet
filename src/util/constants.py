from enum import Enum

class Constants(Enum): 
    '''
    Enum representing string constants to be used thorugh out the application.
    '''
    OSV_QUERY_URI = '/v1/querybatch'
    VULNS_URI = '/osv/vulns'
    VULNS_ANALYSIS_URI = '/osv/analyze'
    TRIAGE_URI = '/osv/triage'
    CURRENT_STATE = "current_state"
    LIST_FILE_URI = '/github/listfiles'
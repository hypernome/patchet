class Patcher: 
    '''
    Handles the actual patching. Starts with the 'vulns' field for the current state. 
    This agent's objective is to analyze the vulnerbilities in the 'vulns' field and 
    take patching actions in the concerned git repo present in the trigger field of the state.
    
    This agent makes use of the following tools - 
    1.  triage_vulnerabilities
    2.  select_patching_tools
    3.  plan_patching
    4.  patch_locally
    5.  patch_and_push
    6.  build_and_test
    7.  raise_pr
    8.  merge_pr
    9.  regenerate_sbom
    10. analyze results
    '''
    
    patcher_prompt = '''
    '''
    
    def __init__(self):
        pass
    
    
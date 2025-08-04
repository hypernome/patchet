from state.state import VulnAnalysisSpec








class Patcher: 
    '''
    Handles the actual patching. Starts with the 'vulns' field for the current state. 
    This agent's objective is to analyze the vulnerbilities in the 'vulns' field and 
    take patching actions in the concerned git repo present in the trigger field of the state.
    
    This agent makes use of the following tools - 
    1.  plan_patching
    2.  patch_locally
    3.  patch_and_push
    4.  build_and_test
    5.  raise_pr
    6.  merge_pr
    7.  regenerate_sbom
    8. analyze results
    '''
    
    patcher_prompt = '''
    '''
    
    def __init__(self):
        pass
    
    
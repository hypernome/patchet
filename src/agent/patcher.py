from state.state import VulnAnalysisSpec

class Patcher: 
    '''
    Handles the actual patching. Starts with the 'patch_plan' field for the current state. 
    This agent's objective is to execute the patch plan represented by the patch_plan field in 
    the PatchetState. It using ecossytem and manifest type specific tools, if required.
    
    This agent makes use of the following tools - 
    1. patch_locally
    2. verify
    3. push
    4. build_and_test
    5. raise_pr
    6. merge_pr
    7. regenerate_sbom
    8. analyze results
    '''
    
    patcher_prompt = '''
    '''
    
    def __init__(self):
        pass
    
    
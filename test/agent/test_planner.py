from state.state import Repo
from agent.planner import list_files

def test_list_files(): 
    '''
    Test the list_files tool.
    '''
    repo: Repo = Repo(
        owner="juice-shop",
        name="juice-shop",
        branch="v11.1.3"
    )
    
    file_tree = list_files(repo)
    assert isinstance(file_tree, dict)
    
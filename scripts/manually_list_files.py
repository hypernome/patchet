'''
One time script to manually list files from a public git repo. To be used in list_file tool mock up.
'''

import requests
import os

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
REPO_OWNER = "juice-shop"
REPO_NAME = "juice-shop"
BRANCH = "master" 

HEADERS = {
    "Authorization": f"Bearer {GITHUB_TOKEN}",
    "Content-Type": "application/json"
}

API_URL = "https://api.github.com/graphql"

def run_query(query):
    response = requests.post(API_URL, json={"query": query}, headers=HEADERS)
    if response.status_code != 200:
        raise Exception(f"Query failed: {response.status_code}, {response.text}")
    return response.json()

def build_query(expression):
    return f"""
    query {{
      repository(owner: "{REPO_OWNER}", name: "{REPO_NAME}") {{
        object(expression: "{expression}") {{
          ... on Tree {{
            entries {{
              name
              type
              path
            }}
          }}
        }}
      }}
    }}
    """

def list_files_recursively(expression=""):
    expression = f"{BRANCH}:{expression}" if expression else f"{BRANCH}:"
    query = build_query(expression)
    data = run_query(query)
    
    tree = data["data"]["repository"]["object"]
    if not tree:
        return []

    files = []
    for entry in tree["entries"]:
        if entry["type"] == "blob":
            files.append(f"{entry["path"]}\n")
        elif entry["type"] == "tree":
            sub_files = list_files_recursively(entry["path"])
            files.extend(sub_files)
    return files

# Run
if __name__ == "__main__":
    file_list = list_files_recursively()
    print(os.getcwd())
    with open('scripts/files_list.txt', 'w') as f: 
      f.writelines(file_list)
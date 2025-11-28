from agent.supervisor import Supervisor
from agent.planner import Planner
from agent.classifier import Classifier
from agent.patcher import Patcher

demo_agents: list = [
    Supervisor().build(), 
    Planner().build_planner(), 
    Classifier().build_classifier(), 
    Patcher().build_patcher()
]

declared_agents: list = []

declared_workflows: list = []
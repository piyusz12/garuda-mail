"""
Phase 25 — Investigation Directed Acyclic Graph (DAG)
Orchestrates parallel and dependency-aware task graphs for automated forensic investigations.
"""

from typing import Dict, List, Optional, Any, Set
from collections import deque
from .tasks import (
    InvestigationTask,
    ResolveAssetTask,
    GetCertificateHistoryTask,
    GetTLSHistoryTask,
    GetJA4HistoryTask,
    GetRecentChangesTask,
    GetHistoricalCasesTask,
    GetThreatIntelTask,
    GetDependenciesTask,
)


class InvestigationDAG:
    """Directed Acyclic Graph orchestrator for automated investigation workflows."""

    def __init__(self):
        self.tasks: Dict[str, InvestigationTask] = {}
        self.register_default_tasks()

    def register_task(self, task: InvestigationTask):
        self.tasks[task.name] = task

    def register_default_tasks(self):
        self.register_task(ResolveAssetTask())
        self.register_task(GetCertificateHistoryTask())
        self.register_task(GetTLSHistoryTask())
        self.register_task(GetJA4HistoryTask())
        self.register_task(GetRecentChangesTask())
        self.register_task(GetHistoricalCasesTask())
        self.register_task(GetThreatIntelTask())
        self.register_task(GetDependenciesTask())

    def get_execution_order(self) -> List[InvestigationTask]:
        """Calculates topological ordering using Kahn's algorithm."""
        in_degree: Dict[str, int] = {name: 0 for name in self.tasks}
        graph: Dict[str, List[str]] = {name: [] for name in self.tasks}

        for name, task in self.tasks.items():
            for dep in task.dependencies:
                if dep in graph:
                    graph[dep].append(name)
                    in_degree[name] += 1

        queue = deque([name for name, deg in in_degree.items() if deg == 0])
        order: List[InvestigationTask] = []

        while queue:
            node = queue.popleft()
            order.append(self.tasks[node])
            for neighbor in graph[node]:
                in_degree[neighbor] -= 1
                if in_degree[neighbor] == 0:
                    queue.append(neighbor)

        if len(order) != len(self.tasks):
            # Fallback if circular dependency accidentally introduced
            return list(self.tasks.values())
        return order

    def execute(self, initial_context: Dict[str, Any]) -> Dict[str, Any]:
        """Executes all DAG tasks in topological order, accumulating results into context."""
        context = dict(initial_context)
        context["dag_task_results"] = {}
        executed_tasks: List[str] = []

        for task in self.get_execution_order():
            try:
                res = task.execute(context)
                context.update(res)
                context["dag_task_results"][task.name] = res
                executed_tasks.append(task.name)
            except Exception as e:
                context["dag_task_results"][task.name] = {"error": str(e)}

        context["executed_tasks"] = executed_tasks
        return context

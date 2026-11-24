"""Application context shared by the API, CLI, AI tools and MCP server.

Service-layer contracts (implemented in their modules):

* ``sams.graph.engine.build_graph(store, settings) -> AttackGraph``
    - ``AttackGraph.blast_radius(start: str, min_likelihood=0.05) -> dict``
      ``start`` is an asset id (assumes full compromise = root) or a node id.
      Returns ``{"start", "reachable": [{"node","kind","label","asset_id","likelihood","hops","path": [edge]}],
      "summary": {"hosts","datastores","credentials","cloud","critical": [...]}}``
    - ``AttackGraph.attack_paths(source="internet", target=None, k=5) -> list[dict]``
      each ``{"source","target","target_label","target_criticality","likelihood","nodes":[...],"edges":[...]}``
    - ``AttackGraph.to_dict() -> {"nodes": [...], "edges": [...]}``
* ``sams.remediation.planner.build_plan(ctx, limit=50) -> list[dict]`` items
  ``{"id","title","kind","severity","asset_ids","risk_reduction","finding_keys","remediation","automatable","task"}``
* ``sams.posture.compute(ctx) -> dict`` ``{"score","grade","hosts":[...],"counts":{...}}``
* ``sams.remediation.tasks.create_task(ctx, agent_id, action, params, dry_run=True) -> Task``
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any, Optional

from .config import Settings
from .crypto import Signer
from .db import Store


@dataclass
class AppContext:
    settings: Settings
    store: Store
    signer: Signer
    # cached attack graph; invalidated whenever inventory / firewall / findings change
    _graph: Any = None
    _graph_lock: threading.Lock = field(default_factory=threading.Lock)
    extras: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(cls, settings: Settings, store: Optional[Store] = None, signer: Optional[Signer] = None) -> "AppContext":
        settings.data_dir.mkdir(parents=True, exist_ok=True)
        return cls(settings=settings,
                   store=store or Store(settings.db_path),
                   signer=signer or Signer.load_or_create(settings.signing_key_path))

    def graph(self, refresh: bool = False):
        from .graph.engine import build_graph
        with self._graph_lock:
            if self._graph is None or refresh:
                self._graph = build_graph(self.store, self.settings)
            return self._graph

    def invalidate(self) -> None:
        with self._graph_lock:
            self._graph = None

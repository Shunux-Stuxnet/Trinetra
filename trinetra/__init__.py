"""Reusable Trinetra SOC investigation components."""

__all__ = ["build_trinetra_graph"]


def build_trinetra_graph():
    """Lazily load the workflow so lightweight modules remain importable."""
    from .graph import build_trinetra_graph as _build_trinetra_graph

    return _build_trinetra_graph()

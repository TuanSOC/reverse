"""Scanner registry + dependency ordering.

The registry is the only place the pipeline learns which modules exist, so new
modules are added without touching the core (§36). It also resolves the
``requires`` graph into a deterministic execution order via topological sort and
rejects cycles.
"""

from __future__ import annotations

from .errors import ConfigError
from .module import ScannerModule


class ScannerRegistry:
    """Holds registered module classes and produces an execution order."""

    def __init__(self) -> None:
        self._modules: dict[str, type[ScannerModule]] = {}

    def register(self, module_cls: type[ScannerModule]) -> type[ScannerModule]:
        """Register a module class. Usable as a decorator."""
        name = module_cls.name
        if not name:
            raise ConfigError(f"{module_cls.__name__} has no name")
        if name in self._modules and self._modules[name] is not module_cls:
            raise ConfigError(f"duplicate module name registered: {name!r}")
        self._modules[name] = module_cls
        return module_cls

    def get(self, name: str) -> type[ScannerModule]:
        try:
            return self._modules[name]
        except KeyError as exc:
            raise ConfigError(f"unknown module: {name!r}") from exc

    def names(self) -> list[str]:
        return list(self._modules)

    def __contains__(self, name: object) -> bool:
        return name in self._modules

    def __len__(self) -> int:
        return len(self._modules)

    def resolution_order(self, selected: list[str] | None = None) -> list[str]:
        """Return module names in dependency order (topological sort).

        ``selected`` limits the run to those modules plus their transitive
        dependencies. Raises :class:`ConfigError` on unknown modules or cycles.
        """
        if selected:
            wanted: set[str] = set()
            stack = list(selected)
            while stack:
                n = stack.pop()
                if n in wanted:
                    continue
                if n not in self._modules:
                    raise ConfigError(f"unknown module: {n!r}")
                wanted.add(n)
                stack.extend(self._modules[n].requires)
        else:
            wanted = set(self._modules)

        # Kahn's algorithm for a stable, cycle-detecting topological order.
        order: list[str] = []
        visited: dict[str, int] = {}  # 0 = visiting, 1 = done

        def visit(node: str, path: tuple[str, ...]) -> None:
            state = visited.get(node)
            if state == 1:
                return
            if state == 0:
                cycle = " -> ".join((*path, node))
                raise ConfigError(f"dependency cycle detected: {cycle}")
            visited[node] = 0
            for dep in self._modules[node].requires:
                if dep not in self._modules:
                    raise ConfigError(f"module {node!r} requires unknown {dep!r}")
                if dep in wanted:
                    visit(dep, (*path, node))
            visited[node] = 1
            order.append(node)

        for node in sorted(wanted):
            visit(node, ())
        return order


#: Process-wide default registry. Modules register onto this at import time.
default_registry = ScannerRegistry()

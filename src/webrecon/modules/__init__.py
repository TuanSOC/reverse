"""Scanner modules.

Importing this package registers all built-in modules onto
``core.registry.default_registry`` (each module module calls
``@default_registry.register``). New modules are added to this import list as
their phases land.
"""

from . import http, scope, target  # noqa: F401  (import side-effect: registration)

__all__ = ["target", "scope", "http"]

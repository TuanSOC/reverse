"""WebRecon — local-first Website Intelligence & Security Assessment workstation.

Design invariants (enforced across modules, not by convention):

* Passive / non-destructive only. No exploitation, brute-force, or DoS code.
* Every outbound request passes the ScopeEngine + SSRF guard first.
* Every module returns a typed ``ModuleResult``; a failing module never
  crashes the scan.
* ``severity`` and ``confidence`` are independent axes; every endpoint/finding
  is classified ``observed | referenced | potential``.
"""

__version__ = "0.1.0"

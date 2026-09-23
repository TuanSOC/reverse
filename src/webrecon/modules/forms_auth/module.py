"""Form & authentication hygiene module (v0.2.0 P3).

Classifies HTML forms discovered by the crawler (``ctx.shared["inventory"]``)
by purpose (login/register/reset/search/contact/payment) and inspects them for
anti-CSRF token presence and password-field transport/autocomplete hygiene.
Purely passive — the forms were already fetched by the crawler; nothing is
submitted. Every finding carries the form's location + fields as evidence.
"""

from __future__ import annotations

from ...core.enums import (
    Confidence,
    FindingCategory,
    ModuleStatus,
    Observation,
    Severity,
)
from ...core.models import Evidence, Finding, ModuleResult
from ...core.module import ScannerModule
from ...core.registry import default_registry
from .analysis import FormReport, classify_form


@default_registry.register
class FormsAuthModule(ScannerModule):
    name = "forms_auth"
    version = "0.1.0"
    requires = ("crawler",)
    description = "Classify HTML forms + CSRF / password-hygiene inspection."

    async def run(self, ctx) -> ModuleResult:  # type: ignore[override]
        result = self.new_result()
        result.mark_started()
        log = ctx.bind_logger(self.name)

        inv = ctx.shared.get("inventory")
        forms = list(getattr(inv, "forms", []) or [])
        if not forms:
            result.data = {"skipped": "no forms discovered"}
            result.mark_finished(ModuleStatus.SKIPPED)
            return result

        by_kind: dict[str, int] = {}
        csrf = 0
        insecure = 0
        autoc = 0
        for form in forms:
            rep = classify_form(form)
            by_kind[rep.kind] = by_kind.get(rep.kind, 0) + 1

            if rep.csrf_missing:
                csrf += 1
                result.findings.append(self._f(
                    "forms.csrf.missing",
                    f"State-changing {rep.kind} form has no CSRF token",
                    Severity.MEDIUM, Confidence.MEDIUM, form, rep,
                    "A form that mutates state exposes no hidden anti-CSRF token.",
                    "Without a per-session token, the form may be forgeable via CSRF.",
                    "Add a synchronizer token to state-changing forms and verify it "
                    "server-side, plus set SameSite cookies. Example (HTML): "
                    "`<input type=\"hidden\" name=\"csrf_token\" value=\"{{ csrf }}\">`; "
                    "cookie: `Set-Cookie: session=…; SameSite=Lax; Secure; HttpOnly`.",
                ))
            if rep.insecure_password_transport:
                insecure += 1
                result.findings.append(self._f(
                    "forms.password.insecure_transport",
                    f"Password {rep.kind} form submits over cleartext HTTP",
                    Severity.HIGH, Confidence.HIGH, form, rep,
                    "A form containing a password field posts to an http:// action.",
                    "Credentials travel in cleartext and can be intercepted on the wire.",
                    "Submit credentials only over HTTPS (set the form action to "
                    "https://), redirect all HTTP→HTTPS, and send HSTS: "
                    "`Strict-Transport-Security: max-age=31536000; includeSubDomains`.",
                ))
            if rep.password_autocomplete_on:
                autoc += 1
                result.findings.append(self._f(
                    "forms.password.autocomplete",
                    f"Password {rep.kind} form allows credential autocomplete",
                    Severity.LOW, Confidence.LOW, form, rep,
                    "A password field does not disable browser autocomplete storage.",
                    "On shared machines, stored credentials may be recovered by others.",
                    "Consider autocomplete=\"new-password\"/\"current-password\" per intent.",
                ))

        result.data = {"forms": len(forms), "by_kind": by_kind}
        result.stats = {"csrf_missing": csrf, "insecure_transport": insecure,
                        "autocomplete": autoc}
        result.mark_finished(ModuleStatus.SUCCESS)
        log.info("forms_auth complete", forms=len(forms), csrf=csrf, insecure=insecure)
        return result

    def _f(self, cid, name, sev, conf, form, rep: FormReport,
           desc, impact, rec) -> Finding:
        fields = [str(i.get("name") or i.get("type") or "?") for i in (form.inputs or [])]
        return Finding(
            check_id=cid, name=name, category=FindingCategory.CONFIGURATION,
            severity=sev, confidence=conf, observation=Observation.OBSERVED,
            module=self.name, description=desc, impact=impact, recommendation=rec,
            evidence=[Evidence(
                source=self.name, url=form.page_url,
                description=f"{rep.method.upper()} {rep.action}",
                data={"kind": rep.kind, "method": rep.method, "action": rep.action,
                      "fields": fields[:25]},
            )],
        )

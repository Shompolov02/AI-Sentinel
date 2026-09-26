# Repository Governance

## Roles and separation of duties

- **Developer** owns application code, tests, package manifests, and pull requests.
- **DevOps** owns CI/CD, container baselines, infrastructure, and branch settings.
- **SecOps** owns security policy, security findings, Prompt Guard policy, and Security Exceptions.
- **Auditor** has read-only access to repository history, CI evidence, and security reports.

Developer, DevOps, and SecOps ownership is declared in `.github/CODEOWNERS`.
Conflicting roles require an approved, time-bounded Security Exception.
Until separate role accounts or organization teams exist, `@Shompolov02` is
the valid GitHub CODEOWNER for each area; branch protection still requires an
independent reviewer. Auditor is never included as a CODEOWNER.

## Protected main branch

Repository administrators must configure `main` with the policy in
`.github/branch-protection.yml`: no direct pushes, no force pushes, current
branch required, all `quality` checks required, and one independent approving
review. CODEOWNERS review is required for owned paths. The policy is kept in
source control so it can be audited when GitHub settings are applied.

## Pull requests

All changes use the pull request template, link an issue, pass required checks,
and receive an independent review. Changes to CI, security policy, dependency
manifests, or container baselines require the corresponding CODEOWNER review.

## Dependency updates

Dependabot checks Python dependencies, GitHub Actions, and the smoke container
base independently each week. It opens small pull requests and does not merge
them automatically. Every update pull request uses the normal pull request CI,
including format, lint, type checking, tests, SAST, SCA, secret scanning,
container checks, and SBOM generation where applicable. Branch protection keeps
the required checks and CODEOWNERS review mandatory before merge.
Do not merge with an open failing check or an expired exception.

## Commits and releases

Commit messages use Conventional Commits (`type(scope): description`), for
example `feat(governance): add repository policy`. Future published artifacts
use semantic versioning (`MAJOR.MINOR.PATCH`): breaking contract changes bump
MAJOR, compatible features bump MINOR, and fixes bump PATCH.

## Definition of Done: Phase 0

A Phase 0 change is done when acceptance criteria are met, documentation and
tests are updated, `make quality` passes, security findings are fixed or covered
by an approved unexpired exception, CI evidence is available, and an
independent review is recorded. The merge commit references the issue.

## Documentation and decisions

Architecture changes require an ADR in `docs/adr/` before implementation or in
the same pull request when the decision is discovered during implementation.
Update `CONTEXT.md` when terminology or constraints change. Operational
procedures belong in `docs/runbooks/`.
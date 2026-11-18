# Releasing sandscale (PyPI)

This repository is a mirror: the source of truth is the private Neural Inverse Keystone
repository (`sdk/python/sandscale`), and `sdk/scripts/sync-sandscale-sdks.sh` there writes this
tree. Do not commit here directly; changes go through Keystone and are synced on release.

A release is a `v*` tag on `main`. `.github/workflows/release.yml` checks that the tag equals
`pyproject.toml` and `_version.py`, runs pytest and mypy, builds the sdist and wheel, then the
`publish` job uploads them with `pypa/gh-action-pypi-publish` using **PyPI trusted publishing**:
GitHub's OIDC token is exchanged for a short-lived upload token, so no PyPI token exists in this
repository. PEP 740 attestations are attached automatically.

## One-time owner setup

PyPI lets you register a "pending" trusted publisher for a project that does not exist yet, so
nothing has to be uploaded by hand.

1. Sign in at https://pypi.org (2FA on). Open https://pypi.org/manage/account/publishing/
   ("Add a new pending publisher"), choose GitHub, and fill in exactly:
   - PyPI project name: `sandscale`
   - Owner: `sandscale`
   - Repository name: `sandscale-python`
   - Workflow name: `release.yml`
   - Environment name: `pypi`
2. In GitHub, repository `sandscale/sandscale-python`, Settings, Environments, create the
   environment `pypi`. Add required reviewers if you want a manual approval before each upload.
3. The first `v*` tag creates the project on PyPI and binds the publisher. Afterwards, on the
   project's page, add the other owners and (optionally) set up an organization.
4. If `sandscale` is already taken on PyPI by someone else, the pending publisher is refused;
   pick another distribution name in `pyproject.toml` (the import name can stay `sandscale`).

## Cutting a release

In Keystone: `node sdk/scripts/set-version.mjs --sandscale X.Y.Z`, sync (see above), then in
this repository `git tag vX.Y.Z && git push origin vX.Y.Z`. Watch the `release` workflow.
Published versions are never overwritten; a bad version is yanked on PyPI and fixed by a new one.

## If a publish fails

- `invalid-publisher`: the owner, repository, workflow filename or environment on PyPI does not
  match the list above exactly.
- The `publish` job is waiting: the `pypi` environment has required reviewers; approve it.

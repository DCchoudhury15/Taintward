# Releasing

A release is one git tag, `vX.Y.Z`. On GitHub, pushing the tag runs
`.github/workflows/release.yml`: tests, a build (with the README's links
made absolute for the PyPI page by `scripts/pypi_readme.py`), the upload
to PyPI and a GitHub release with the notes from `CHANGELOG.md`.
The same tag also builds the collector and gateway images and the Helm
chart and pushes them to GitHub's container registry (ghcr.io).

## PyPI from GitHub: one-time setup

1. Log in to https://pypi.org (turn on 2FA).
2. Your account > Publishing > Add a new pending publisher > GitHub:

   | field | value |
   |---|---|
   | PyPI Project Name | `taintward` |
   | Owner | `DCchoudhury15` |
   | Repository name | `Taintward` |
   | Workflow name | `release.yml` |
   | Environment name | `pypi` |

3. On GitHub: Settings > Environments > New environment `pypi`. Optionally
   add yourself as a required reviewer, so every upload waits for a click.

The first successful upload creates the `taintward` project on PyPI.

## Cut a release

1. Set the version in `taintward/__init__.py` (`__version__ = "0.4.0"`).
   This is the only place the Python version lives. The Helm chart gets the
   same version at release time, but also update `version` and `appVersion`
   in `deploy/helm/taintward/Chart.yaml` so local installs match.
2. Add a `## 0.4.0` section at the top of `CHANGELOG.md`. Its text becomes
   the release notes.
3. Commit, merge to main, then tag and push the tag:

   ```bash
   git tag -a v0.4.0 -m "Taintward 0.4.0"
   git push origin v0.4.0
   ```

4. Watch the run on GitHub (Actions > release). When it is green, the
   release is under Releases.

The workflow fails early, before anything is published, if the tag does not
match `__version__` or `CHANGELOG.md` has no section for the version.

## What the workflow does

| job | what |
|---|---|
| test | the Python tests |
| build | checks tag = `__version__`, builds sdist + wheel, `twine check`, cuts the release notes from `CHANGELOG.md` |
| pypi | uploads to PyPI with trusted publishing |
| images | builds and pushes `ghcr.io/dcchoudhury15/taintward/collector` and `/gateway` as `:X.Y.Z` and `:latest` |
| chart | `helm package` with version and appVersion = the release version, then `helm push` to `oci://ghcr.io/dcchoudhury15/taintward/charts` |
| github-release | creates the GitHub release with the notes and the sdist and wheel |

The images and the chart are not signed.

## Images and chart: one-time setup

Nothing to create before the first tag: the workflow logs in to ghcr.io
with the run's own token. A new package on ghcr.io starts private, so after
the first release make the three packages public once (your profile >
Packages > the package > Package settings > Change visibility > Public):
`taintward/collector`, `taintward/gateway` and `taintward/charts/taintward`.
Until then `helm install` cannot pull them.

## Check a release

```bash
pip install taintward==0.4.0
helm show chart oci://ghcr.io/dcchoudhury15/taintward/charts/taintward --version 0.4.0
docker pull ghcr.io/dcchoudhury15/taintward/collector:0.4.0
docker pull ghcr.io/dcchoudhury15/taintward/gateway:0.4.0
```

## Pinned dependencies

* `constraints.txt` pins exact versions for CI (`pip install -c
  constraints.txt ...`). Regenerate it from a working dev venv (Python
  3.12) after changing dependencies:

  ```bash
  { sed -n '1,5p' constraints.txt; pip freeze --exclude-editable | grep -v -e ' @ ' -e '^setuptools==' -e '^pip=='; } > constraints.new && mv constraints.new constraints.txt
  ```

* `constraints-adapters.txt` pins the set for the framework adapter
  tests (CrewAI, LlamaIndex, Pydantic AI, Google ADK, LiteLLM), whose pins
  clash with `constraints.txt`. Regenerate it the same way, from a fresh
  venv with `pip install -e ".[dev,crewai,llamaindex,pydantic-ai,google-adk,litellm]"`
  where `tests/test_integrations_frameworks.py` passes, keeping its header
  (`sed -n '1,7p'`).
* `deploy/requirements/runtime.txt` and `gateway.txt` are hashed lock
  files for the Docker images, installed with `pip install
  --require-hashes --only-binary=:all:`. Rebuild them from `constraints.txt`
  with `sh deploy/requirements/update.sh` (needs uv).
* Base images are pinned by digest in the Dockerfiles. The comment above
  each `FROM` shows how to get a new digest.

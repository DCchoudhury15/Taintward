# Releasing

A release is one git tag, `vX.Y.Z`. Pushing the tag runs the release
pipeline in `.gitlab-ci.yml`, which publishes everything.

## Cut a release

1. Set the version in `taintward/__init__.py` (`__version__ = "0.3.0"`).
   This is the only place the Python version lives. The Helm chart gets the
   same version at release time, but also update `version` and `appVersion`
   in `deploy/helm/taintward/Chart.yaml` so local installs match.
2. Add a `## 0.3.0` section at the top of `CHANGELOG.md`. Its text becomes
   the release notes.
3. Commit, merge to main, then tag and push the tag:

   ```bash
   git tag -a v0.3.0 -m "Taintward 0.3.0"
   git push origin v0.3.0
   ```

4. Watch the pipeline in GitLab (Build > Pipelines). When it is green, the
   release is at Deploy > Releases.

The pipeline fails early, before anything is published, if the tag does not
match `__version__` or `CHANGELOG.md` has no section for the version.

## What the pipeline does

| stage | job | what |
|---|---|---|
| test | python-tests, ruff, go-tests, helm-lint | the normal checks |
| build | release-build | checks tag = `__version__`, builds sdist + wheel, `twine check`, cuts the release notes from `CHANGELOG.md` |
| build | release-chart | `helm package` with version and appVersion = the release version |
| publish | pypi | uploads to PyPI (trusted publishing, or `PYPI_API_TOKEN`), and copies the files to the project's generic package registry |
| publish | release-images | builds and pushes `registry.gitlab.com/divyanshuchoudhury51/taintward/collector` and `/gateway` as `:X.Y.Z` and `:latest`, makes an SPDX JSON SBOM with syft, signs the image and attaches the SBOM as a signed attestation with cosign (keyless) |
| publish | release-chart-push | `helm push` to `oci://registry.gitlab.com/divyanshuchoudhury51/taintward/charts`, then signs the chart |
| release | gitlab-release | creates the GitLab release with the notes and links to the package, images, chart and SBOMs |

Signing is keyless: cosign gets a GitLab OIDC token (audience `sigstore`),
Sigstore's Fulcio issues a short lived certificate for the pipeline identity,
and the signature is logged in Rekor. There is no signing key to keep.

Merge request and main pipelines only run the test stage (plus image build
checks when Dockerfiles or the collector change, and the docs site on main).

## One-time setup (owner)

Do these once, before pushing the first tag.

### 1. PyPI

Use trusted publishing (no secret stored in GitLab):

1. Log in to https://pypi.org (create an account and turn on 2FA if needed).
2. Go to Your account > Publishing > Add a new pending publisher > GitLab.
3. Fill in exactly:

   | field | value |
   |---|---|
   | PyPI Project Name | `taintward` |
   | Namespace | `divyanshuchoudhury51` |
   | Project name | `taintward` |
   | Top-level pipeline file path | `.gitlab-ci.yml` |
   | Environment name | `pypi` |

4. Save. The first successful upload creates the `taintward` project on
   PyPI and turns the pending publisher into a normal one.

The form is tied to the project path, so finish the GitLab rename from
`agentward` to `taintward` first.

Fallback, if trusted publishing does not work: create an API token on PyPI
(Account settings > API tokens), then in GitLab go to Settings > CI/CD >
Variables and add `PYPI_API_TOKEN` with the token, Masked and Protected.
When this variable is set the pipeline uses it instead.

### 2. Protect release tags

Settings > Repository > Protected tags: protect `v*`, allowed to create:
Maintainers. Protected variables are only given to protected tags, and
this stops anyone else from starting a release.

### 3. Container registry and Helm chart

Nothing to create. The pipeline logs in with `CI_JOB_TOKEN`. Make sure
strangers can pull: Settings > General > Visibility, project features,
permissions: the project is Public and Container registry is on and set to
"Everyone with access".

### 4. A runner

CI on gitlab.com shared runners needs an account with a verified identity
(GitLab asks for it on the first pipeline). Until then, or instead, use a
self-hosted runner: [self-hosted-runner.md](self-hosted-runner.md).

## Check a release

```bash
pip install taintward==0.3.0
helm show chart oci://registry.gitlab.com/divyanshuchoudhury51/taintward/charts/taintward --version 0.3.0

# Image signature, made by this project's pipeline on a tag:
cosign verify registry.gitlab.com/divyanshuchoudhury51/taintward/collector:0.3.0 \
  --certificate-identity-regexp '^https://gitlab.com/divyanshuchoudhury51/taintward//.gitlab-ci.yml@refs/tags/v' \
  --certificate-oidc-issuer https://gitlab.com

# The SBOM attestation:
cosign verify-attestation --type spdxjson \
  registry.gitlab.com/divyanshuchoudhury51/taintward/collector:0.3.0 \
  --certificate-identity-regexp '^https://gitlab.com/divyanshuchoudhury51/taintward//.gitlab-ci.yml@refs/tags/v' \
  --certificate-oidc-issuer https://gitlab.com
```

## Pinned dependencies

* `constraints.txt` pins exact versions for CI (`pip install -c
  constraints.txt ...`). Regenerate it from a working dev venv (Python
  3.12) after changing dependencies:

  ```bash
  { sed -n '1,5p' constraints.txt; pip freeze --exclude-editable | grep -v -e ' @ ' -e '^setuptools==' -e '^pip=='; } > constraints.new && mv constraints.new constraints.txt
  ```

* `deploy/requirements/runtime.txt` and `gateway.txt` are hashed lock
  files for the Docker images, installed with `pip install
  --require-hashes --only-binary=:all:`. Rebuild them from `constraints.txt`
  with `sh deploy/requirements/update.sh` (needs uv).
* Base images are pinned by digest in the Dockerfiles. The comment above
  each `FROM` shows how to get a new digest.
* CI downloads syft and cosign at fixed versions and checks their sha256
  (variables at the top of `.gitlab-ci.yml`).

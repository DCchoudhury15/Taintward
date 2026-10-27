# Self-hosted GitLab runner

GitLab's shared runners only run pipelines after the account owner verifies
their identity. A self-hosted runner on your own machine runs the same
pipeline without that. All jobs in `.gitlab-ci.yml` are untagged, so they run
on whichever runner is free: shared or yours.

The runner runs in Docker (`scripts/gitlab-runner/`) and uses the docker
executor: each job runs in its own container on your machine.

## Start it

You need Docker with the compose plugin.

1. In GitLab open the project, then Settings > CI/CD > Runners >
   New project runner.
2. Tick **Run untagged jobs**. Leave tags empty. Click Create runner.
3. Copy the token that starts with `glrt-`. GitLab shows it once.
4. From the repo root:

   ```bash
   GITLAB_RUNNER_TOKEN=glrt-xxxx sh scripts/gitlab-runner/start.sh
   ```

The runner registers, starts in the background, and restarts with Docker.
In the Runners page it shows as online (green) after a few seconds. Run the
same command again later (no token needed) to start it after `down`.

To make pipelines use only your runner, turn off "Enable instance runners
for this project" on the same Runners page.

## Stop it

```bash
docker compose -f scripts/gitlab-runner/docker-compose.yml down       # stop
docker compose -f scripts/gitlab-runner/docker-compose.yml down -v    # stop and forget the registration
```

After `down -v`, also delete the runner in GitLab (Settings > CI/CD >
Runners), or it stays there as offline.

## How Docker builds work on it

The image jobs (`collector-image`, `gateway-image`, `release-images`) need a
Docker daemon. On shared runners they use a `docker:dind` service, which
needs privileged containers. This runner is not privileged. Instead it mounts
the host Docker socket (`/var/run/docker.sock`) into each job, and the jobs
use the host daemon when they find the socket. The dind service still
starts and fails, which is harmless; the runner is set not to wait for it.

## Security

* **The Docker socket is root on your machine.** Any job can start a
  container that mounts `/` from the host. Only run this for a project where
  everyone who can push branches or open merge requests is trusted. Do not
  use it for public merge requests from forks.
* Jobs share the host Docker daemon, so they can see and stop your other
  containers, and images they build stay in your local image list.
* The runner token is stored in the `taintward-runner_runner-config` Docker
  volume (`config.toml`). Treat it like a password. If it leaks, delete the
  runner in GitLab and make a new one.
* Release jobs on this runner get the release secrets (OIDC tokens,
  `PYPI_API_TOKEN` if set). Use a machine you control.
* A safer setup is a separate VM just for the runner, or the runner in
  privileged dind mode on a disposable VM.

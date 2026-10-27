#!/usr/bin/env sh
# Registers (first run only) and starts a self-hosted GitLab runner with the
# docker executor. See docs/self-hosted-runner.md.
#
#   GITLAB_RUNNER_TOKEN=glrt-... sh scripts/gitlab-runner/start.sh
#
# The token comes from GitLab: project > Settings > CI/CD > Runners >
# New project runner. It is stored only in the runner-config Docker volume.
set -eu

dir=$(cd "$(dirname "$0")" && pwd)
compose="docker compose -f $dir/docker-compose.yml"
url=${GITLAB_URL:-https://gitlab.com}

if $compose run --rm --no-deps --entrypoint sh gitlab-runner \
    -c 'grep -q "^\[\[runners\]\]" /etc/gitlab-runner/config.toml' 2>/dev/null; then
    echo "runner already registered, starting it"
else
    if [ -z "${GITLAB_RUNNER_TOKEN:-}" ]; then
        echo "set GITLAB_RUNNER_TOKEN to the glrt- token from GitLab" >&2
        exit 1
    fi
    # Docker executor. Jobs get the host Docker socket, so image builds use
    # the host daemon and no privileged containers are needed. The pipeline
    # also asks for a docker:dind service (for GitLab shared runners); it
    # cannot start here without privileged mode, which is fine, so do not
    # wait for services.
    $compose run --rm --no-deps gitlab-runner register \
        --non-interactive \
        --url "$url" \
        --token "$GITLAB_RUNNER_TOKEN" \
        --name "taintward-$(hostname)" \
        --executor docker \
        --docker-image alpine:3.22 \
        --docker-volumes /var/run/docker.sock:/var/run/docker.sock \
        --docker-volumes /cache \
        --docker-wait-for-services-timeout -1
fi

$compose up -d
$compose ps

#!/usr/bin/env bash
# Waits for the E2E server and agent containers to report healthy.
# Used by the CI e2e-docker job both before and after the offline DB seed step.
set -euo pipefail

echo "Waiting for server..."
server_ready=false
for i in {1..30}; do
  if curl -sf http://localhost:9090/health > /dev/null 2>&1; then
    echo "Server is ready!"
    server_ready=true
    break
  fi
  echo "Attempt $i: Server not ready yet..."
  sleep 2
done

if [[ "$server_ready" == false ]]; then
  echo "::error::Server failed to become ready after 30 attempts"
  echo "Docker logs for server:"
  docker compose -f tests/docker-compose.e2e.yml logs server
  exit 1
fi

echo "Waiting for agent..."
agent_ready=false
for i in {1..30}; do
  if curl -sf http://localhost:8080/health > /dev/null 2>&1; then
    echo "Agent is ready!"
    agent_ready=true
    break
  fi
  echo "Attempt $i: Agent not ready yet..."
  sleep 2
done

if [[ "$agent_ready" == false ]]; then
  echo "::error::Agent failed to become ready after 30 attempts"
  echo "Docker logs for agent:"
  docker compose -f tests/docker-compose.e2e.yml logs agent
  exit 1
fi

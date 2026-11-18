#!/bin/bash
# Antigent defense container (v0.14): sensor daemon + event-driven driver.
#   sensor.py  continuous defender-side observation -> runs/defense/sensor.jsonl
#   driver.py  starts one `opencode run` turn per burst of ELEVATED events
# If either process exits, the container exits and compose restarts it.
# ANTIGENT_DRIVER=0 runs the sensor only (use `docker compose exec -it antigent opencode`
# for a manual/interactive loop instead).
set -u
mkdir -p /antigent/runs/defense
python3 /antigent/gateway/sensor.py &
pids=($!)
if [ "${ANTIGENT_DRIVER:-1}" != "0" ]; then
  python3 /antigent/gateway/driver.py &
  pids+=($!)
else
  echo "[entrypoint] driver disabled (ANTIGENT_DRIVER=0): sensor only"
fi
trap 'kill "${pids[@]}" 2>/dev/null; exit 0' TERM INT
wait -n "${pids[@]}"
code=$?
echo "[entrypoint] a process exited (code $code); stopping so compose can restart the container"
kill "${pids[@]}" 2>/dev/null
exit "$code"

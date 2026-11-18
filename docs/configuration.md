# Configuring for your environment

**Language:** English | [日本語](ja/configuration.md)

Addresses and ports differ on every machine. Antigent is built so that nothing about
them is hard-coded: what Docker already knows is discovered at run time, and the few
things only you know are set in `.env`.

## Discovered at run time (nothing to set)

| What | How |
|---|---|
| Target container IPs | `docker inspect` of the scenario roles, through the API guard |
| Which flow belongs to which target | netsensor destination IP → role, rebuilt when a target joins a network |
| Target service ports | Not used. The attacker reaches containers on their own ports over the lab network; host-published ports play no role |
| The Docker host's address on Linux | Gateways of the targets' networks (treated as internal) |
| Target health in the Console | Container state (`running` / `healthy`) read by the sensor; the Console never connects to a target |
| Attack Box and API guard networks | Created by Compose without fixed subnets, from Docker's address pools |

## Set in `.env` when needed

| Variable | Default | When to change |
|---|---|---|
| `CONSOLE_PORT` | `8765` | The port is taken |
| `CONSOLE_BIND` | `127.0.0.1` | View the Console from another machine (prefer an SSH tunnel; publishing exposes the run logs) |
| `CONSOLE_ALLOWED_HOSTS` | empty | The host name or IP you type in the browser when it is not `127.0.0.1` / `localhost` |
| `DEMO_RUN_ID` | `demo` | Keep runs apart (the previous run of the same ID is archived automatically) |
| `GITEA_CONTAINER`, `JENKINS_CONTAINER`, `PROD_CONTAINER` | CI/CD Goat names | Your lab names the containers differently |
| `ANTIGENT_HOST_ADDRESSES` | empty | Docker Desktop: you browse the lab from this machine and do not want that seen as a client (list the VM's host address, often `192.168.65.1`). Antigent's own Jenkins requests need no entry: they carry a per-run random `antigent_self` mark (`ANTIGENT_SELF_MARK`, set by `live_demo.py`) and their source is treated as internal |
| `NET_IFACES` | `^(docker0|br-.*)$` | Your Docker bridges use other interface names |
| `ATTACKER_EGRESS_EXTRA_ALLOW` | empty | OpenCode needs another API host |
| `ATTACKER_EGRESS_UPSTREAM_PROXY` | empty | This machine reaches the Internet only through an HTTP proxy |
| `ca/combined-ca-bundle.pem` (file) | none | A TLS-inspecting proxy (see `ca/README.md`) |

Fixed values that are **not** environment-specific: `socket-proxy:2375` and
`egress-proxy:3128` are names and ports on Docker's internal networks, invisible from the
host and from other machines.

If Docker's default address pools collide with your corporate or VPN ranges, change
`default-address-pools` in the Docker daemon settings; Antigent picks up whatever
addresses Docker assigns.

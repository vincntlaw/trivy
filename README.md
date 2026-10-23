<div align="center">

<img src="docs/imgs/logo.png" width="170" alt="Trivy"/>

# 🛡️ Trivy

**One binary that finds vulnerabilities, misconfigurations, secrets and licences — in containers, code, Kubernetes and the cloud.**

[![GitHub Release](https://img.shields.io/github/v/release/aquasecurity/trivy?style=flat-square&logo=github&label=release)](https://github.com/aquasecurity/trivy/releases)
[![Go](https://img.shields.io/badge/go-1.27-00ADD8?style=flat-square&logo=go&logoColor=white)](https://go.dev/)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-000000?style=flat-square&logo=apache&logoColor=white)](LICENSE)
[![Docker Pulls](https://img.shields.io/docker/pulls/aquasec/trivy?style=flat-square&logo=docker&logoColor=white)](https://hub.docker.com/r/aquasec/trivy)
[![Stars](https://img.shields.io/github/stars/aquasecurity/trivy?style=flat-square&logo=github)](https://github.com/aquasecurity/trivy/stargazers)
[![Forks](https://img.shields.io/github/forks/aquasecurity/trivy?style=flat-square&logo=github)](https://github.com/aquasecurity/trivy/network)
[![Issues](https://img.shields.io/github/issues/aquasecurity/trivy?style=flat-square&logo=github)](https://github.com/aquasecurity/trivy/issues)

*A single static binary — no agents, no sidecars, and the only thing it downloads is the vulnerability database.*

</div>

---

## ✨ What does it do?

Point Trivy at a **target**, tell it which **scanners** to run, and get findings back in a format your tooling already speaks. That's the whole interface — no daemon to babysit, no cluster agent to upgrade, no YAML to keep in sync with a vendor.

```
container images ──┐                        ┌──► CVEs in OS packages & dependencies
filesystems ───────┤                        ├──► IaC misconfigurations
git repositories ──┼──► trivy <target> ─────┼──► secrets
VM images ─────────┤                        ├──► licenses
kubernetes ────────┘                        └──► SBOM (CycloneDX / SPDX)
```

```bash
# 1) scan a container image
trivy image golang:1.22.11-alpine3.20
```

Trimmed output from that run:

```
Report Summary

┌─────────────────────────────────────────────┬──────────┬─────────────────┬─────────┐
│                   Target                    │   Type   │ Vulnerabilities │ Secrets │
├─────────────────────────────────────────────┼──────────┼─────────────────┼─────────┤
│ golang:1.22.11-alpine3.20 (alpine 3.20.5)   │  alpine  │        6        │    -    │
├─────────────────────────────────────────────┼──────────┼─────────────────┼─────────┤
│ usr/local/go/bin/go                         │ gobinary │        1        │    -    │
└─────────────────────────────────────────────┴──────────┴─────────────────┴─────────┘

Total: 6 (UNKNOWN: 2, LOW: 0, MEDIUM: 2, HIGH: 2, CRITICAL: 0)
```

> 🧠 **First run only:** Trivy pulls the vulnerability database automatically, then keeps it cached — after that your scans are fast and can run offline.

## 📸 Screenshot

<img src="docs/imgs/trivy-k8s.png" alt="Trivy Kubernetes summary report" width="100%"/>

*A real `trivy k8s --report summary cluster` run — every workload in the cluster, one table.*

<details>
<summary>More terminal demos</summary>

`trivy image python:3.4-alpine`

https://github.com/user-attachments/assets/af1c11e7-d9c5-48af-8e05-cb34dfd6352a

`trivy fs --scanners vuln,secret,misconfig myproject/`

https://github.com/user-attachments/assets/6b3894b7-77c5-4ffc-ac94-ffe6648a30dc

</details>

## 🚀 Features

- 🎯 **Five targets, one command** — images, filesystems, remote repos, VM images and clusters, all with the same flags
- 🐞 **Known vulnerabilities (CVEs)** — OS packages and application dependencies, matched against the Trivy DB, vendor advisories and VEX
- 🧩 **IaC misconfigurations** — Terraform, Kubernetes, Helm, Dockerfile, CloudFormation, Ansible and ARM templates
- 🔑 **Secrets** — API keys, tokens and credentials that were never meant to be committed
- 📜 **Licences** — the obligations hiding in your dependency tree
- 📦 **SBOM in, SBOM out** — emit CycloneDX or SPDX, and scan an existing SBOM like you scan an image
- 🧠 **Broad coverage** — most popular languages, operating systems and platforms ([the full list](https://trivy.dev/docs/latest/guide/coverage/))
- 📤 **Reports that fit** — table, JSON, SARIF, templates, SBOM and GitHub dependency snapshots
- 🔌 **Plugs into your stack** — GitHub Actions, the Trivy Operator, VS Code, GitLab, Argo CD and friends
- 🌐 **Client/server mode** — one Trivy server, many thin clients, a shared database and cache
- 🧪 **Extensible** — WASM modules add detection logic without forking the binary

## 🧰 What's inside

| | Scanner | What it finds |
|---|---|---|
| 🐞 | **[Vulnerabilities](https://trivy.dev/docs/latest/guide/scanner/vulnerability/)** | CVEs in OS packages and application dependencies, with the fix version when there is one |
| 🧩 | **[Misconfigurations](https://trivy.dev/docs/latest/guide/scanner/misconfiguration/)** | Insecure defaults and policy violations in IaC, checked by the bundled Aqua rules and Rego |
| 🔑 | **[Secrets](https://trivy.dev/docs/latest/guide/scanner/secret/)** | API keys, tokens and credentials — entropy plus a pile of rule-based patterns |
| 📜 | **[Licences](https://trivy.dev/docs/latest/guide/scanner/license/)** | The obligations hiding in your dependency tree |

## 📦 What it scans

| | Target | Try it |
|---|---|---|
| 🐳 | **Container image** | `trivy image alpine:3.20` |
| 📁 | **Filesystem** | `trivy fs .` — lockfiles, IaC, secrets |
| 🌿 | **Git repository** | `trivy repo https://github.com/org/repo` |
| 💽 | **VM image** | AWS AMI and EBS snapshots |
| ☸️ | **Kubernetes** | `trivy k8s --report summary cluster` |

## 🛠️ Quick start

### Requirements

| Requirement | Notes |
|---|---|
| Nothing | Trivy is a single static binary — no runtime, no daemon, no cluster agent |
| Network *(first run only)* | downloads the vulnerability database, then caches it locally |
| Docker *(optional)* | only if you want to pull images from a Docker daemon |

### Get Trivy

| Channel | Command |
|---|---|
| 🍺 Homebrew | `brew install trivy` |
| 🐳 Docker | `docker run aquasec/trivy` |
| 📦 Binary | grab one from [the latest release](https://github.com/aquasecurity/trivy/releases/latest/) |
| 🐧 apt / yum / rpm | see [Installation](https://trivy.dev/docs/latest/getting-started/installation/) for the repo setup |

### Setup

```bash
# 1) scan a project: vulnerabilities, secrets and misconfigurations
trivy fs --scanners vuln,secret,misconfig myproject/

# 2) scan a remote git repository
trivy repo https://github.com/aquasecurity/trivy

# 3) scan a kubernetes cluster
trivy k8s --report summary cluster
```

The CLI shape never changes:

```bash
trivy <target> [--scanners <scanner1,scanner2>] <subject>
```

## ⚙️ Tuning

| Flag | What it does |
|---|---|
| `--scanners` | pick the scanners: `vuln`, `misconfig`, `secret`, `license` |
| `--severity` | only report what you care about, e.g. `HIGH,CRITICAL` |
| `--format` / `-f` | `table` (default), `json`, `sarif`, `template`, `cyclonedx`, `spdx`, `github` |
| `--output` / `-o` | write the report to a file instead of stdout |
| `--exit-code` | return a non-zero exit code when findings are reported — great for CI gates |
| `--ignore-unfixed` | skip findings that have no fix available yet |
| `--skip-db-update` | reuse the cached vulnerability database (air-gapped or fast CI) |

A gate you can paste into CI as-is:

```bash
trivy image --severity HIGH,CRITICAL --ignore-unfixed --exit-code 1 myapp:latest
```

## 🧪 Canary builds

Canary images and binaries are built on every push to `main` — [Docker Hub](https://hub.docker.com/r/aquasec/trivy/tags?page=1&name=canary), [GitHub Container Registry](https://github.com/aquasecurity/trivy/pkgs/container/trivy/75776514?tag=canary), [ECR](https://gallery.ecr.aws/aquasecurity/trivy#canary) and [binaries](https://github.com/aquasecurity/trivy/actions/workflows/canary.yaml).

> ⚠️ **Heads up:** canary builds track the tip of `main` and might contain critical bugs — they are not recommended for production.

## ⚠️ Disclaimer

Trivy tells you what it found; it doesn't decide what ships. A green scan is not a guarantee — databases lag behind brand-new CVEs, some ranges can't be resolved, and IaC rules only check what they know about. Tune `--severity`, `--ignore-unfixed` and your policies to what your team can actually act on, and be nice to the person on call when the gate goes red.

## ❓ FAQ

**How do you pronounce "Trivy"?** `tri` is pronounced like **tri**gger, `vy` is pronounced like en**vy**.

**Does it phone home?** No. Scans run locally; only the vulnerability database, checks bundle and Java DB are downloaded (and cached).

## 🌊 Want more? Check out Aqua

If you liked Trivy, you will love Aqua, which builds on top of Trivy to provide enhanced capabilities for a complete security management offering.
There is a high-level [comparison table](https://trivy.dev/docs/latest/commercial/compare/) for Trivy users, and [aquasec.com](https://aquasec.com) has the rest — or [request a demo](https://www.aquasec.com/demo).

## 🤝 Community

Trivy is an [Aqua Security](https://aquasec.com) open source project. Learn about our open source work and portfolio [here](https://www.aquasec.com/products/open-source-projects/).

- 💬 Questions and ideas → [GitHub Discussions](https://github.com/aquasecurity/trivy/discussions)
- 🐞 Bugs and feature requests → [Issues](https://github.com/aquasecurity/trivy/issues)
- 🛠️ Pull requests → read the [contributing guidelines](CONTRIBUTING.md) first, please

Please abide by our [Code of Conduct](https://github.com/aquasecurity/community/blob/main/CODE_OF_CONDUCT.md) in every interaction.

## 📄 License

[Apache-2.0](LICENSE) © Aqua Security

<div align="center">

**[📖 Documentation](https://trivy.dev/docs/latest/)** · **[🚀 Installation](https://trivy.dev/docs/latest/getting-started/installation/)** · **[💬 Discussions](https://github.com/aquasecurity/trivy/discussions)** · **[🌐 trivy.dev](https://trivy.dev)**

*if your stack isn't covered yet, [open an issue](https://github.com/aquasecurity/trivy/issues/new/choose) — that's how most of this got built.*

</div>

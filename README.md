<div align="center">

<img src="docs/imgs/logo.png" width="200" alt="Trivy"/>

# 🛡️ Trivy

**The all-in-one security scanner — find vulnerabilities, misconfigurations, secrets and licenses across containers, code, Kubernetes and the cloud.**

[![GitHub Release](https://img.shields.io/github/v/release/aquasecurity/trivy?style=flat-square&logo=github&label=release)](https://github.com/aquasecurity/trivy/releases)
[![Go](https://img.shields.io/badge/go-1.27-00ADD8?style=flat-square&logo=go&logoColor=white)](https://go.dev/)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-000000?style=flat-square&logo=apache&logoColor=white)](LICENSE)
[![Docker Pulls](https://img.shields.io/docker/pulls/aquasec/trivy?style=flat-square&logo=docker&logoColor=white)](https://hub.docker.com/r/aquasec/trivy)
[![Stars](https://img.shields.io/github/stars/aquasecurity/trivy?style=flat-square&logo=github)](https://github.com/aquasecurity/trivy/stargazers)
[![Forks](https://img.shields.io/github/forks/aquasecurity/trivy?style=flat-square&logo=github)](https://github.com/aquasecurity/trivy/network)
[![Issues](https://img.shields.io/github/issues/aquasecurity/trivy?style=flat-square&logo=github)](https://github.com/aquasecurity/trivy/issues)

</div>

---

## ✨ What does it do?

Trivy is a comprehensive and versatile security scanner. Point it at a *target* and it runs the *scanners* you ask for — then reports the findings in a format your tooling already understands. One binary, no agents, no sidecars, nothing to babysit on the cluster.

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

Real output, trimmed:

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

> **Zero setup:** the first run downloads the vulnerability database automatically — after that, scans are offline-friendly and fast.

## 📸 Screenshot

<img src="docs/imgs/trivy-k8s.png" alt="Trivy Kubernetes summary report" width="100%"/>

*A `trivy k8s --report summary cluster` run, summarising every workload in the cluster.*

<details>
<summary>Terminal demos</summary>

`trivy image python:3.4-alpine`

https://github.com/user-attachments/assets/af1c11e7-d9c5-48af-8e05-cb34dfd6352a

`trivy fs --scanners vuln,secret,misconfig myproject/`

https://github.com/user-attachments/assets/6b3894b7-77c5-4ffc-ac94-ffe6648a30dc

</details>

## 🚀 Features

- 🎯 **Five targets, one command** — container images, filesystems, remote git repositories, VM images and Kubernetes clusters, all with the same flags
- 🐞 **Known vulnerabilities (CVEs)** — OS packages and application dependencies, matched against the Trivy DB, vendor advisories and VEX
- 🧩 **IaC misconfigurations** — Terraform, Kubernetes, Helm, Dockerfile, CloudFormation, Ansible and ARM templates
- 🔑 **Secrets** — API keys, tokens and credentials that were never meant to be committed
- 📜 **Licenses** — the obligations hiding in your dependency tree
- 📦 **SBOM in, SBOM out** — generate CycloneDX or SPDX, and scan an existing SBOM the same way you scan an image
- 🧠 **Broad coverage** — most popular languages, operating systems and platforms ([full list](https://trivy.dev/docs/latest/coverage/))
- 📤 **Reports that fit** — table, JSON, SARIF, templates, SBOM and GitHub dependency snapshots
- 🔌 **Plugs into your stack** — GitHub Actions, the Trivy Operator, VS Code, GitLab, Argo CD and friends
- 🌐 **Client/server mode** — one Trivy server, many thin clients, a shared database and cache
- 🧪 **Extensible** — WASM modules let you add detection logic without forking the binary

## 📦 What it scans

| | Target | Examples |
|---|---|---|
| 🐳 | **Container image** | `trivy image alpine:3.20` |
| 📁 | **Filesystem** | `trivy fs .` — lockfiles, IaC, secrets |
| 🌿 | **Git repository** | `trivy repo https://github.com/org/repo` |
| 💽 | **VM image** | AWS AMI, EBS snapshots |
| ☸️ | **Kubernetes** | `trivy k8s --report summary cluster` |

## 🛠️ Quick start

### Get Trivy

| Channel | Command |
|---|---|
| 🍺 Homebrew | `brew install trivy` |
| 🐳 Docker | `docker run aquasec/trivy` |
| 📦 Binary | grab one from [the latest release](https://github.com/aquasecurity/trivy/releases/latest/) |
| 🐧 apt / yum / rpm | see [Installation](https://trivy.dev/docs/latest/getting-started/installation/) for the repo setup |

### Usage

```bash
trivy <target> [--scanners <scanner1,scanner2>] <subject>
```

```bash
# 1) scan a project: vulnerabilities, secrets and misconfigurations
trivy fs --scanners vuln,secret,misconfig myproject/

# 2) scan a remote git repository
trivy repo https://github.com/aquasecurity/trivy

# 3) scan a kubernetes cluster
trivy k8s --report summary cluster
```

### Flags

| Flag | What it does |
|---|---|
| `--scanners` | pick the scanners: `vuln`, `misconfig`, `secret`, `license` |
| `--severity` | only report what you care about, e.g. `HIGH,CRITICAL` |
| `--format` / `-f` | `table` (default), `json`, `sarif`, `template`, `cyclonedx`, `spdx`, `github` |
| `--output` / `-o` | write the report to a file instead of stdout |
| `--exit-code` | return a non-zero exit code when findings are reported — great for CI gates |
| `--ignore-unfixed` | skip findings that have no fix available yet |
| `--skip-db-update` | reuse the cached vulnerability database (air-gapped / fast CI) |

## 🧰 Toolbox

<p>
<img src="https://skillicons.dev/icons?i=go,docker,kubernetes,terraform,githubactions,linux,aws&theme=dark" alt="skills"/>
</p>

`CVE detection` · `SBOM` · `IaC scanning` · `secret detection` · `license compliance` · `Kubernetes` · `CI/CD`

Popular integrations, in no particular order:

- [GitHub Actions](https://github.com/aquasecurity/trivy-action) — scan your build in a few lines of YAML
- [Trivy Operator](https://github.com/aquasecurity/trivy-operator) — continuous scanning inside Kubernetes
- [VS Code extension](https://github.com/aquasecurity/trivy-vscode-extension) — findings while you type
- See [Ecosystem](https://trivy.dev/docs/latest/ecosystem/) for the rest

## 🧪 Canary builds

Canary images and binaries are built on every push to `main` — [Docker Hub](https://hub.docker.com/r/aquasec/trivy/tags?page=1&name=canary), [GitHub Container Registry](https://github.com/aquasecurity/trivy/pkgs/container/trivy/75776514?tag=canary), [ECR](https://gallery.ecr.aws/aquasecurity/trivy#canary) and [binaries](https://github.com/aquasecurity/trivy/actions/workflows/canary.yaml).

> ⚠️ **Heads up:** canary builds track the tip of `main` and might contain critical bugs — they are not recommended for production.

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

**[📖 Documentation](https://trivy.dev/docs/latest/)** · **[🚀 Installation](https://trivy.dev/docs/latest/getting-started/installation/)** · **[🌐 trivy.dev](https://trivy.dev)**

</div>

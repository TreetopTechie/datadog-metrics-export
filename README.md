# endorlabs-datadog-bridge

Send [Endor Labs](https://www.endorlabs.com/) reachable vulnerability and malware counts to [Datadog](https://www.datadoghq.com/) as GAUGE metrics.

![Datadog Dashboard](example/dashboard.png)

## How it works

1. Authenticates with the Endor Labs API (API key/secret or bearer token).
2. Queries all projects in the given namespace for reachable vulnerability counts (by severity) and malware findings.
3. Converts the results into Datadog metric series.
4. Submits the metrics to Datadog in batches.

### Metrics

| Metric | Type | Description | Tags |
|--------|------|-------------|------|
| `endorlabs.reachable_vulns.count` | Gauge | Reachable vulnerabilities per project | `severity`, `project`, `project_slug` |
| `endorlabs.malware.count` | Gauge | Malware findings per project | `project`, `project_slug` |

The `project` tag contains a direct link to the project in the Endor Labs UI. The `project_slug` tag is the short repository name extracted from the project URL.

## Setup

### Prerequisites

- Node.js 22+
- npm

### Install

```bash
npm ci
```

### Configuration

Copy the example env file and fill in your values:

```bash
cp .env.example .env
```

| Variable | Required | Description |
|----------|----------|-------------|
| `DD_API_KEY` | Yes | Datadog API key |
| `ENDOR_NAMESPACE` | Yes | Endor Labs namespace |
| `DD_SITE` | No | Datadog site (e.g. `datadoghq.com`, `datadoghq.eu`) |
| `ENDOR_API` | No | Endor Labs API base URL (default: `https://api.endorlabs.com`) |
| `ENDOR_TOKEN` | No | Endor Labs bearer token |
| `ENDOR_API_KEY` | No | Endor Labs API key |
| `ENDOR_API_SECRET` | No | Endor Labs API secret |

Either `ENDOR_TOKEN` **or** both `ENDOR_API_KEY` and `ENDOR_API_SECRET` must be provided.

### Run

```bash
# Development (runs TypeScript directly via tsx)
npm run dev

# Production (compile first, then run)
npm run build
npm start
```

## GitHub Actions

A workflow is included at `.github/workflows/sync.yml` that runs the sync on an hourly schedule and supports manual dispatch.

The workflow expects the same variables from your `.env` file to be stored as repository secrets. If you have the [GitHub CLI](https://cli.github.com/) installed, you can push them all at once:

```bash
npm run setup:secrets
```

This reads every key/value pair from `.env` and calls `gh secret set` for each one.

## Example Dashboard

An importable Datadog dashboard template is provided at [`example/dashboard.json`](example/dashboard.json). It includes:

- **Critical/High Reachable Vulnerabilities** — table sorted by critical and high counts, with links to Endor Labs.
- **Reachable Vulnerability Trend** — time series broken down by severity.
- **Malware** — sunburst chart of malware counts by project.

To import: in Datadog, go to **Dashboards > New Dashboard > Import Dashboard JSON** and paste the contents of the file.

## License

[MIT](LICENSE)

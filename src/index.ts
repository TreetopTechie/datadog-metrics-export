import "dotenv/config";
import { client, v2 } from "@datadog/datadog-api-client";

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const DD_API_KEY = required("DD_API_KEY");
const DD_SITE = process.env.DD_SITE;

const ENDOR_API = process.env.ENDOR_API ?? "https://api.endorlabs.com";
const ENDOR_NAMESPACE = required("ENDOR_NAMESPACE");
const ENDOR_API_KEY = process.env.ENDOR_API_KEY;
const ENDOR_API_SECRET = process.env.ENDOR_API_SECRET;
const ENDOR_TOKEN = process.env.ENDOR_TOKEN;

function required(name: string): string {
  const val = process.env[name];
  if (!val) throw new Error(`Missing required env var: ${name}`);
  return val;
}

// ---------------------------------------------------------------------------
// Endor Labs helpers
// ---------------------------------------------------------------------------

async function getEndorToken(): Promise<string> {
  if (ENDOR_TOKEN) return ENDOR_TOKEN;
  if (!ENDOR_API_KEY || !ENDOR_API_SECRET) {
    throw new Error(
      "Provide either ENDOR_TOKEN or both ENDOR_API_KEY + ENDOR_API_SECRET"
    );
  }
  const res = await fetch(`${ENDOR_API}/v1/auth/api-key`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ key: ENDOR_API_KEY, secret: ENDOR_API_SECRET }),
  });
  if (!res.ok) {
    throw new Error(`Endor auth failed (${res.status}): ${await res.text()}`);
  }
  const data = await res.json();
  return data.token;
}

const SEVERITIES = [
  { level: "FINDING_LEVEL_CRITICAL", label: "critical", refName: "CriticalReachableVulns" },
  { level: "FINDING_LEVEL_HIGH", label: "high", refName: "HighReachableVulns" },
  { level: "FINDING_LEVEL_MEDIUM", label: "medium", refName: "MediumReachableVulns" },
  { level: "FINDING_LEVEL_LOW", label: "low", refName: "LowReachableVulns" },
] as const;

function buildQuery() {
  const findingRef = (level: string, returnAs: string) => ({
    connect_from: "uuid",
    connect_to: "spec.project_uuid",
    query_spec: {
      kind: "Finding",
      return_as: returnAs,
      list_parameters: {
        count: true,
        traverse: true,
        filter: [
          "context.type == CONTEXT_TYPE_MAIN",
          "spec.finding_categories contains FINDING_CATEGORY_VULNERABILITY",
          "spec.finding_tags contains FINDING_TAGS_REACHABLE_FUNCTION",
          `spec.level == ${level}`,
        ].join(" and "),
      },
    },
  });

  return {
    meta: { name: `ReachableVulnsByProject(namespace: ${ENDOR_NAMESPACE})` },
    spec: {
      query_spec: {
        kind: "Project",
        list_parameters: {
          traverse: true,
          mask: "uuid,meta.name",
          page_size: 500,
        },
        references: [
          ...SEVERITIES.map((s) => findingRef(s.level, s.refName)),
          {
            connect_from: "uuid",
            connect_to: "spec.project_uuid",
            query_spec: {
              kind: "Finding",
              return_as: "MalwareFindings",
              list_parameters: {
                count: true,
                traverse: true,
                filter:
                  "context.type == CONTEXT_TYPE_MAIN and spec.finding_categories contains FINDING_CATEGORY_MALWARE",
              },
            },
          },
        ],
      },
    },
  };
}

// ---------------------------------------------------------------------------
// Types for query response
// ---------------------------------------------------------------------------

interface CountResponse {
  count_response?: { count?: number };
}

interface QueryProject {
  uuid: string;
  meta?: {
    name?: string;
    references?: Record<string, CountResponse>;
  };
}

interface QueryResponse {
  spec?: {
    query_response?: {
      list?: { objects?: QueryProject[] };
    };
  };
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  console.log(`Fetching data from Endor Labs (namespace: ${ENDOR_NAMESPACE})…`);
  const token = await getEndorToken();

  // Single query: projects with reachable vuln counts per severity
  const url = `${ENDOR_API}/v1/namespaces/${ENDOR_NAMESPACE}/queries`;
  const res = await fetch(url, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
      "Request-Timeout": "60",
    },
    body: JSON.stringify(buildQuery()),
  });
  if (!res.ok) {
    throw new Error(`Endor query failed (${res.status}): ${await res.text()}`);
  }
  const body = (await res.json()) as QueryResponse;
  const projects = body.spec?.query_response?.list?.objects ?? [];
  console.log(`  ${projects.length} projects`);

  // Parse projects with reachable vuln counts
  interface ProjectEntry {
    name: string;
    uuid: string;
    slug: string;
    severityCounts: Record<string, number>;
    malwareCount: number;
  }

  function toSlug(name: string): string {
    try {
      const pathname = new URL(name).pathname;
      return pathname.split("/").filter(Boolean).pop()?.replace(/\.git$/, "") ?? name;
    } catch {
      return name;
    }
  }

  const projectEntries: ProjectEntry[] = [];

  for (const p of projects) {
    const name = p.meta?.name ?? p.uuid;
    const refs = p.meta?.references ?? {};
    const severityCounts: Record<string, number> = {};
    let hasFindings = false;

    for (const sev of SEVERITIES) {
      const count = (refs[sev.refName] as CountResponse)?.count_response?.count ?? 0;
      if (count > 0) {
        severityCounts[sev.label] = count;
        hasFindings = true;
      }
    }

    const malwareCount =
      (refs.MalwareFindings as CountResponse)?.count_response?.count ?? 0;
    if (malwareCount > 0) hasFindings = true;

    if (hasFindings) {
      projectEntries.push({
        name,
        uuid: p.uuid,
        slug: toSlug(name),
        malwareCount,
        severityCounts,
      });
    }
  }

  console.log(`  ${projectEntries.length} projects with findings`);

  // Build Datadog log entries (one per project with all counts as attributes)
  const endorBaseUrl = `https://app.endorlabs.com/t/${ENDOR_NAMESPACE}`;
  const logs: v2.HTTPLogItem[] = [];

  for (const entry of projectEntries) {
    const parts: string[] = [];
    for (const [severity, count] of Object.entries(entry.severityCounts)) {
      parts.push(`${count} ${severity}`);
    }
    if (entry.malwareCount > 0) {
      parts.push(`${entry.malwareCount} malware`);
    }

    logs.push({
      ddsource: "endorlabs",
      service: "endorlabs-bridge",
      ddtags: `project_slug:${entry.slug}`,
      message: `${entry.slug}: ${parts.join(", ")}`,
      additionalProperties: {
        project_url: `${endorBaseUrl}/projects/${entry.uuid}`,
        project_slug: entry.slug,
        critical_count: entry.severityCounts.critical ?? 0,
        high_count: entry.severityCounts.high ?? 0,
        medium_count: entry.severityCounts.medium ?? 0,
        low_count: entry.severityCounts.low ?? 0,
        malware_count: entry.malwareCount,
      },
    });
  }

  if (logs.length === 0) {
    console.log("No findings — nothing to send.");
    return;
  }

  // Submit to Datadog
  console.log(`Submitting ${logs.length} log entries to Datadog…`);

  const ddConfig = client.createConfiguration({
    authMethods: { apiKeyAuth: DD_API_KEY },
    ...(DD_SITE && { serverVariables: { site: DD_SITE } }),
  });
  const logsApi = new v2.LogsApi(ddConfig);

  const BATCH_SIZE = 1000;
  for (let i = 0; i < logs.length; i += BATCH_SIZE) {
    const batch = logs.slice(i, i + BATCH_SIZE);
    await logsApi.submitLog({ body: batch });
  }

  console.log("Done ✓");

  // Summary table
  console.log("\nFindings submitted:");
  console.log("-".repeat(70));
  for (const entry of projectEntries) {
    for (const [severity, count] of Object.entries(entry.severityCounts)) {
      console.log(
        `  ${entry.slug.padEnd(30)} ${severity.padEnd(10)} ${count}`
      );
    }
    if (entry.malwareCount > 0) {
      console.log(
        `  ${entry.slug.padEnd(30)} ${"malware".padEnd(10)} ${entry.malwareCount}`
      );
    }
  }
}

main().catch((err) => {
  console.error("Fatal:", err);
  process.exit(1);
});

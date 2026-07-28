// ── Live GraphQL introspection: a single, standard, read-only introspection query (the same
// query GraphiQL/Apollo DevTools send on load) — not a crafted exploit, just asking the API "what's
// your schema", which the GraphQL spec defines as an optional but common capability. If it's on,
// the response itself is the finding: it hands over every type, field, and mutation name for free. ──

const INTROSPECTION_QUERY = `
  query IntrospectionQuery {
    __schema {
      queryType { name }
      mutationType { name }
      types { name kind fields { name } }
    }
  }
`;

const SENSITIVE_NAME_RE = /user|admin|password|token|secret|apikey|api_key|credential|session|delete|remove|destroy|payment|card|billing/i;

export async function introspectGraphQL(url, { timeoutMs = 10000 } = {}) {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json', 'user-agent': 'Universal-Security-Audit' },
      body: JSON.stringify({ query: INTROSPECTION_QUERY, operationName: 'IntrospectionQuery' }),
      signal: controller.signal,
    });
    clearTimeout(t);
    if (!res.ok) return { checked: true, introspectionEnabled: false, status: res.status };
    const data = await res.json().catch(() => null);
    const schema = data?.data?.__schema;
    if (!schema) return { checked: true, introspectionEnabled: false, status: res.status };

    const types = schema.types || [];
    const typeCount = types.length;
    const mutationTypeName = schema.mutationType?.name || null;
    const mutationType = mutationTypeName ? types.find((t) => t.name === mutationTypeName) : null;
    const mutationFieldNames = (mutationType?.fields || []).map((f) => f.name);
    const sensitiveTypeNames = types.filter((t) => t.name && SENSITIVE_NAME_RE.test(t.name)).map((t) => t.name);
    const sensitiveMutations = mutationFieldNames.filter((n) => SENSITIVE_NAME_RE.test(n));

    return {
      checked: true,
      introspectionEnabled: true,
      typeCount,
      hasMutations: !!mutationTypeName,
      mutationFieldNames,
      sensitiveTypeNames: [...new Set(sensitiveTypeNames)],
      sensitiveMutations: [...new Set(sensitiveMutations)],
    };
  } catch (e) {
    clearTimeout(t);
    return { checked: false, error: String(e?.message || e) };
  }
}

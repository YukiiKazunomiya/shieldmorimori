const VT_API_KEY = process.env.VT_API_KEY;
const VT_BASE = "https://www.virustotal.com/api/v3";

async function fetchVT(path, options = {}) {
  const res = await fetch(`${VT_BASE}${path}`, {
    ...options,
    headers: { "x-apikey": VT_API_KEY, ...options.headers },
  });
  return res;
}

function sanitize(data) {
  const stats   = data.attributes?.last_analysis_stats || {};
  const results = data.attributes?.last_analysis_results || {};
  const engines = Object.entries(results).map(([engine, r]) => ({
    engine,
    category: r.category,
    result: r.result || null,
  }));
  return {
    id:           data.id,
    type:         data.type,
    name:         data.attributes?.meaningful_name || data.attributes?.name || data.attributes?.url || null,
    stats,
    engines,
    reputation:   data.attributes?.reputation ?? null,
    lastAnalysis: data.attributes?.last_analysis_date ? new Date(data.attributes.last_analysis_date * 1000).toISOString() : null,
    size:         data.attributes?.size || null,
    sha256:       data.attributes?.sha256 || null,
    md5:          data.attributes?.md5 || null,
  };
}

export default async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  if (req.method === "OPTIONS") return res.status(200).end();
  if (!VT_API_KEY) return res.status(500).json({ error: "Server misconfigured." });

  const { type, value } = req.query;
  if (!type || !value) return res.status(400).json({ error: "Missing parameters." });
  if (!["url","ip","domain","hash"].includes(type)) return res.status(400).json({ error: "Invalid type." });

  try {
    let data;

    if (type === "url") {
      const encoded = Buffer.from(value.trim()).toString("base64url");
      const r = await fetchVT(`/urls/${encoded}`);
      if (r.status === 404) {
        const sub = await fetchVT("/urls", {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: `url=${encodeURIComponent(value.trim())}`,
        });
        const sd = await sub.json();
        const id = sd.data?.id;
        if (!id) return res.status(500).json({ error: "Failed to submit URL." });
        for (let i = 0; i < 8; i++) {
          await new Promise(r => setTimeout(r, 3000));
          const pr = await fetchVT(`/analyses/${id}`);
          const pd = await pr.json();
          if (pd.data?.attributes?.status === "completed") {
            const rr = await fetchVT(`/urls/${encoded}`);
            const rd = await rr.json();
            data = rd.data; break;
          }
        }
      } else { const j = await r.json(); data = j.data; }
    } else if (type === "ip") {
      const r = await fetchVT(`/ip_addresses/${value.trim()}`);
      const j = await r.json();
      if (!r.ok) return res.status(r.status).json({ error: j.error?.message || "Not found." });
      data = j.data;
    } else if (type === "domain") {
      const r = await fetchVT(`/domains/${value.trim()}`);
      const j = await r.json();
      if (!r.ok) return res.status(r.status).json({ error: j.error?.message || "Not found." });
      data = j.data;
    } else if (type === "hash") {
      const r = await fetchVT(`/files/${value.trim()}`);
      const j = await r.json();
      if (!r.ok) return res.status(r.status).json({ error: j.error?.message || "Not found." });
      data = j.data;
    }

    if (!data) return res.status(404).json({ error: "No analysis data found." });
    return res.status(200).json({ success: true, result: sanitize(data) });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Internal server error." });
  }
}

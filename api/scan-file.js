export const config = { api: { bodyParser: false } };

const VT_API_KEY = process.env.VT_API_KEY;
const VT_BASE = "https://www.virustotal.com/api/v3";

export default async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  if (req.method === "OPTIONS") return res.status(200).end();
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed." });
  if (!VT_API_KEY) return res.status(500).json({ error: "Server misconfigured." });

  try {
    // Read raw body
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const body = Buffer.concat(chunks);

    // Parse multipart boundary
    const contentType = req.headers["content-type"] || "";
    const boundaryMatch = contentType.match(/boundary=(.+)/);
    if (!boundaryMatch) return res.status(400).json({ error: "Invalid multipart request." });
    const boundary = boundaryMatch[1].trim();

    // Extract file from multipart body
    const boundaryBuf = Buffer.from(`--${boundary}`);
    const parts = splitBuffer(body, boundaryBuf);

    let fileBuffer = null;
    let fileName = "upload";

    for (const part of parts) {
      const headerEnd = part.indexOf("\r\n\r\n");
      if (headerEnd === -1) continue;
      const headers = part.slice(0, headerEnd).toString();
      if (!headers.includes('name="file"')) continue;
      const nameMatch = headers.match(/filename="([^"]+)"/);
      if (nameMatch) fileName = nameMatch[1];
      // Skip \r\n after headers and \r\n before boundary
      fileBuffer = part.slice(headerEnd + 4, part.length - 2);
      break;
    }

    if (!fileBuffer || fileBuffer.length === 0) {
      return res.status(400).json({ error: "No file received." });
    }

    if (fileBuffer.length > 32 * 1024 * 1024) {
      return res.status(413).json({ error: "File too large. Max 32MB." });
    }

    // Build a proper multipart form to forward to VirusTotal
    const vtBoundary = "----VTBoundary" + Date.now();
    const header = Buffer.from(
      `--${vtBoundary}\r\nContent-Disposition: form-data; name="file"; filename="${fileName}"\r\nContent-Type: application/octet-stream\r\n\r\n`
    );
    const footer = Buffer.from(`\r\n--${vtBoundary}--\r\n`);
    const vtBody = Buffer.concat([header, fileBuffer, footer]);

    const vtRes = await fetch(`${VT_BASE}/files`, {
      method: "POST",
      headers: {
        "x-apikey": VT_API_KEY,
        "Content-Type": `multipart/form-data; boundary=${vtBoundary}`,
        "Content-Length": String(vtBody.length),
      },
      body: vtBody,
    });

    const vtData = await vtRes.json();
    if (!vtRes.ok) {
      return res.status(vtRes.status).json({ error: vtData.error?.message || "VirusTotal upload failed." });
    }

    return res.status(200).json({ success: true, analysisId: vtData.data?.id });
  } catch (err) {
    console.error("scan-file error:", err);
    return res.status(500).json({ error: "Internal server error." });
  }
}

function splitBuffer(buf, delimiter) {
  const parts = [];
  let start = 0;
  while (true) {
    const idx = buf.indexOf(delimiter, start);
    if (idx === -1) break;
    if (idx > start) parts.push(buf.slice(start, idx));
    start = idx + delimiter.length;
    if (buf[start] === 13 && buf[start+1] === 10) start += 2;
  }
  return parts;
}

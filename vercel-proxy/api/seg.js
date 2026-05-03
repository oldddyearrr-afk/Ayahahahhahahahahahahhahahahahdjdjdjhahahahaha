export const config = { runtime: "edge" };

export default async function handler(request) {
  const url = new URL(request.url);

  if (request.method === "OPTIONS") {
    return corsResp(new Response(null, { status: 204 }));
  }

  const path = url.pathname;
  if (path === "/seg" || path === "/api/seg") {
    return handleSeg(request, url);
  }

  if (path === "/health" || path === "/api/health") {
    return corsResp(
      new Response(JSON.stringify({ ok: true, proxy: "iptv-brander-vercel" }), {
        headers: { "Content-Type": "application/json" },
      })
    );
  }

  return new Response("Not found", { status: 404 });
}


async function handleSeg(request, url) {
  const SECRET = process.env.CF_SHARED_SECRET;
  if (!SECRET) return proxyErr(500, "CF_SHARED_SECRET not set");

  const v = url.searchParams.get("v");
  if (!v) return proxyErr(400, "Missing token");

  // ── Decrypt single AES-256-GCM blob → { u: originUrl, e: expiry } ──────────
  let originUrl, exp;
  try {
    const raw   = base64urlDecode(v);
    const nonce = raw.slice(0, 12);
    const ct    = raw.slice(12);
    const key   = await deriveKey(SECRET);
    const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce }, key, ct);
    const payload = JSON.parse(new TextDecoder().decode(plain));
    originUrl = payload.u;
    exp       = payload.e;
  } catch {
    return proxyErr(403, "Invalid or tampered token");
  }

  // ── Check expiry ─────────────────────────────────────────────────────────────
  if (!exp || exp < Math.floor(Date.now() / 1000)) {
    return proxyErr(403, "Token expired");
  }

  if (!originUrl || !originUrl.startsWith("http")) {
    return proxyErr(400, "Invalid URL");
  }

  // ── Optional path suffix (DASH BaseURL templates) ────────────────────────────
  const pathSuffix = url.searchParams.get("p") || "";
  if (pathSuffix) {
    originUrl = originUrl.endsWith("/") ? originUrl + pathSuffix : originUrl + pathSuffix;
  }

  // ── Forward request headers ──────────────────────────────────────────────────
  const fwdHeaders = new Headers();
  for (const h of ["User-Agent", "Range", "Accept", "Accept-Language", "Referer"]) {
    if (request.headers.has(h)) fwdHeaders.set(h, request.headers.get(h));
  }
  if (!fwdHeaders.has("User-Agent")) {
    fwdHeaders.set("User-Agent", "VLC/3.0.20 LibVLC/3.0.20");
  }

  // ── Fetch from origin ────────────────────────────────────────────────────────
  let originRes;
  try {
    originRes = await fetch(originUrl, {
      headers: fwdHeaders,
      redirect: "follow",
    });
  } catch (e) {
    return proxyErr(502, "Origin unreachable: " + e.message);
  }

  if (!originRes.ok && originRes.status !== 206) {
    return proxyErr(originRes.status, "Origin returned " + originRes.status);
  }

  const ct      = originRes.headers.get("Content-Type") || "";
  const urlPath = originUrl.toLowerCase().split("?")[0];

  // ── HLS playlist → rewrite segment URLs through this proxy ──────────────────
  const isM3u8 = ct.toLowerCase().includes("mpegurl")
              || urlPath.endsWith(".m3u8")
              || urlPath.endsWith(".m3u");

  if (isM3u8) {
    const text      = await originRes.text();
    const segExp    = Math.min(exp, Math.floor(Date.now() / 1000) + 30);
    const proxyBase = new URL(request.url).origin;
    const rewritten = await rewriteM3u8(text, originUrl, proxyBase, SECRET, segExp);
    return corsResp(
      new Response(rewritten, {
        status: 200,
        headers: {
          "Content-Type":  "application/vnd.apple.mpegurl",
          "Cache-Control": "no-cache, no-store",
        },
      })
    );
  }

  // ── All binary content (TS, M4S, AAC, MP4, KEY, etc.) → stream through ──────
  const respHeaders = new Headers({ "Cache-Control": "no-cache, no-store" });
  for (const h of ["Content-Type", "Content-Length", "Content-Range", "Accept-Ranges"]) {
    if (originRes.headers.has(h)) respHeaders.set(h, originRes.headers.get(h));
  }

  const originCt = (respHeaders.get("Content-Type") || "").toLowerCase();
  const isTsUrl  = urlPath.endsWith(".ts") || urlPath.endsWith(".mts")
    || /\/live\/[^/]+\/[^/]+\/\d+$/.test(urlPath);

  if (urlPath.endsWith(".ts") || urlPath.endsWith(".mts") || (isTsUrl && originCt === "application/octet-stream")) {
    respHeaders.set("Content-Type", "video/mp2t");
  } else if (!respHeaders.has("Content-Type") || originCt === "application/octet-stream") {
    if (urlPath.endsWith(".aac"))                                   respHeaders.set("Content-Type", "audio/aac");
    else if (urlPath.endsWith(".m4s") || urlPath.endsWith(".mp4")) respHeaders.set("Content-Type", "video/mp4");
    else if (isTsUrl)                                               respHeaders.set("Content-Type", "video/mp2t");
    else                                                            respHeaders.set("Content-Type", "video/mp2t");
  }
  if (!respHeaders.has("Accept-Ranges")) respHeaders.set("Accept-Ranges", "bytes");

  return corsResp(
    new Response(originRes.body, {
      status:  originRes.status,
      headers: respHeaders,
    })
  );
}


// ── M3U8 rewriter ─────────────────────────────────────────────────────────────
async function rewriteM3u8(content, originUrl, proxyOrigin, secret, segExp) {
  const parsed  = new URL(originUrl);
  const baseUrl = originUrl.substring(0, originUrl.lastIndexOf("/") + 1);

  const lines = await Promise.all(
    content.split("\n").map(async (line) => {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) return line;

      let segUrl;
      if (trimmed.startsWith("http://") || trimmed.startsWith("https://")) {
        segUrl = trimmed;
      } else if (trimmed.startsWith("//")) {
        segUrl = parsed.protocol + trimmed;
      } else if (trimmed.startsWith("/")) {
        segUrl = parsed.origin + trimmed;
      } else {
        segUrl = baseUrl + trimmed;
      }

      return await makeProxyUrl(proxyOrigin, segUrl, segExp, secret);
    })
  );

  return lines.join("\n");
}


// ── Build a single-token proxy URL ────────────────────────────────────────────
async function makeProxyUrl(proxyOrigin, url, exp, secret) {
  const payload = JSON.stringify({ u: url, e: exp });
  const v       = await encryptPayload(payload, secret);
  return `${proxyOrigin}/seg?v=${v}`;
}


// ── Crypto helpers ────────────────────────────────────────────────────────────
async function deriveKey(secret) {
  const enc = new TextEncoder();
  const raw = await crypto.subtle.digest("SHA-256", enc.encode(secret));
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

async function encryptPayload(payload, secret) {
  const enc   = new TextEncoder();
  const key   = await deriveKey(secret);
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const ct    = await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, key, enc.encode(payload));
  const combined = new Uint8Array(12 + ct.byteLength);
  combined.set(nonce, 0);
  combined.set(new Uint8Array(ct), 12);
  return base64urlEncode(combined);
}

function base64urlEncode(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64urlDecode(s) {
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + "==".slice(0, (4 - s.length % 4) % 4);
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function corsResp(resp) {
  const r = new Response(resp.body, resp);
  r.headers.set("Access-Control-Allow-Origin",   "*");
  r.headers.set("Access-Control-Allow-Methods",  "GET, HEAD, OPTIONS");
  r.headers.set("Access-Control-Allow-Headers",  "Range, Content-Type, Origin, Accept, Authorization");
  r.headers.set("Access-Control-Expose-Headers", "Content-Length, Content-Range, Content-Type, Accept-Ranges");
  return r;
}

function proxyErr(status, msg) {
  return corsResp(
    new Response(msg, {
      status,
      headers: { "Content-Type": "text/plain; charset=utf-8" },
    })
  );
                               }

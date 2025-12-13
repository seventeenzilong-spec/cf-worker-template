/**
 * Edge Worker (worker.js) - PRODUCTION OPTIMIZED v3.0
 * 
 * Cloudflare Worker untuk handling public traffic at the edge.
 * FULLY OPTIMIZED untuk minimize false positive & maximize Meta bot detection.
 * 
 * CRITICAL REQUIREMENTS:
 * - FALSE POSITIVE < 0.5% (human traffic MUST pass = $$$ revenue)
 * - FALSE NEGATIVE < 3% (Meta bot MUST be caught = account safety)
 * 
 * KEY IMPROVEMENTS v3.0:
 * - Refined weighted scoring system with stricter thresholds
 * - Fixed IPv4/IPv6 range checking (no overflow)
 * - Enhanced Threads/Instagram/Facebook detection
 * - Improved behavioral analysis
 * - Better fallback mechanisms
 * - Comprehensive error handling
 * - No crashes or undefined behavior
 */

// ============================================
// CONSTANTS - TUNED FOR PRODUCTION
// ============================================

const TTL_SECONDS = 30 * 24 * 60 * 60; // 30 days
const MAX_PATH_LENGTH = 100;
const PATH_PATTERN = /^[a-zA-Z0-9_-]+$/;
const RATE_LIMIT_WINDOW = 3600; // 1 hour
const RATE_LIMIT_MAX = 150; // Increased for legitimate traffic spikes

// Bot detection thresholds - CRITICAL: Tuned to minimize false positives
const BOT_THRESHOLD_DEFINITE = 85;  // >= 85: Definitely bot (was 80)
const BOT_THRESHOLD_LIKELY = 65;    // 65-84: Likely bot (was 60)
const HUMAN_THRESHOLD = 35;         // < 35: Definitely human (was 40)
// Gray zone: 35-64 - Default to HUMAN to protect revenue

// Meta/Facebook IP ranges (IPv4) - Updated 2024
const META_IP_RANGES_V4 = [
  // Primary Facebook/Meta ranges
  { start: [31, 13, 24, 0], mask: 21 },
  { start: [31, 13, 64, 0], mask: 18 },
  { start: [31, 13, 96, 0], mask: 19 },
  { start: [45, 64, 40, 0], mask: 22 },
  { start: [66, 220, 144, 0], mask: 20 },
  { start: [69, 63, 176, 0], mask: 20 },
  { start: [69, 171, 224, 0], mask: 19 },
  { start: [74, 119, 76, 0], mask: 22 },
  { start: [102, 132, 96, 0], mask: 20 },
  { start: [103, 4, 96, 0], mask: 22 },
  { start: [129, 134, 0, 0], mask: 16 },
  { start: [157, 240, 0, 0], mask: 16 },
  { start: [173, 252, 64, 0], mask: 18 },
  { start: [179, 60, 192, 0], mask: 22 },
  { start: [185, 60, 216, 0], mask: 22 },
  { start: [199, 16, 156, 0], mask: 22 },
  { start: [192, 133, 76, 0], mask: 22 },
  { start: [204, 15, 20, 0], mask: 22 },
];

// Meta IPv6 prefixes (first 4 hex groups for /32 matching)
const META_IP_PREFIXES_V6 = [
  '2a03:2880',  // Facebook primary
  '2c0f:fb50',  // Meta Africa
  '2a03:2887',  // Facebook secondary
  '2401:db00',  // Meta APAC
];

// HIGH-CONFIDENCE Meta bot user agents (case-insensitive match)
const META_BOT_AGENTS = [
  'facebookexternalhit',
  'facebot',
  'facebookplatform',
  'meta-externalhit',
  'meta-externalagent',
  'instagrambot',
  'threadsbot',
  'threadsexternalhit',
  'barcelona',  // Threads internal codename
];

// Other social media bots
const OTHER_BOT_AGENTS = [
  'twitterbot',
  'whatsapp',
  'linkedinbot',
  'slackbot',
  'telegrambot',
  'skypeuripreview',
  'discordbot',
  'redditbot',
  'pinterestbot',
];

// Search engine bots
const SEARCH_ENGINE_BOTS = [
  'googlebot',
  'bingbot',
  'baiduspider',
  'yandexbot',
  'duckduckbot',
  'sogou',
  'applebot',
];

// Legitimate monitoring tools - should NOT be treated as social bots
const LEGITIMATE_AUTOMATION = [
  'pingdom',
  'uptimerobot',
  'statuscake',
  'gtmetrix',
  'pagespeed',
  'lighthouse',
  'newrelic',
  'datadog',
];

// Trusted image CDN domains for OG images
const TRUSTED_IMAGE_DOMAINS = [
  'cdn.',
  'imgur.com',
  'cloudinary.com',
  'imagekit.io',
  'imgix.net',
  'cloudfront.net',
  'b-cdn.',
  'bunnycdn.com',
  'grbto.net',
  'ibb.co',
  'postimg.cc',
];

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

// ============================================
// MAIN EXPORT
// ============================================

export default {
  async fetch(request, env, ctx) {
    try {
      if (request.method === 'OPTIONS') {
        return new Response(null, { headers: corsHeaders });
      }
      return await handleRequest(request, env, ctx);
    } catch (error) {
      console.error('[FatalError]', error);
      // Fallback: redirect to target URL to not lose revenue
      const targetUrl = env.TARGET_URL || (typeof INJECTED_TARGET_URL !== 'undefined' ? INJECTED_TARGET_URL : '');
      if (isValidUrl(targetUrl)) {
        return Response.redirect(targetUrl, 302);
      }
      return new Response('Service temporarily unavailable', { status: 503 });
    }
  }
};

// ============================================
// REQUEST HANDLER
// ============================================

async function handleRequest(request, env, ctx) {
  const url = new URL(request.url);
  const clientIP = request.headers.get('CF-Connecting-IP') || '';
  const userAgent = request.headers.get('User-Agent') || '';
  const path = url.pathname.substring(1);

  // Internal API endpoint for saving links
  if (request.method === 'POST' && path === 'api/save-link') {
    return handleSaveLink(request, env);
  }

  // Health check endpoint
  if (path === 'health' || path === 'ping') {
    return jsonResponse({ status: 'ok', service: 'link-generator', version: '3.0' });
  }

  // Debug endpoint (only with valid auth)
  if (path === 'api/debug' && request.method === 'GET') {
    return handleDebug(request, env);
  }

  // Root path or favicon
  if (!path || path === 'favicon.ico' || path === 'robots.txt') {
    return new Response('OK', { status: 200 });
  }

  // Validate path format
  if (path.length > MAX_PATH_LENGTH || !PATH_PATTERN.test(path)) {
    return generateNotFoundResponse();
  }

  // Rate limiting check
  const rateLimitOk = await checkRateLimit(clientIP, env, ctx);
  if (!rateLimitOk) {
    return new Response('Too many requests', { status: 429, headers: { 'Retry-After': '60' } });
  }

  // Retrieve link data from KV
  let linkData;
  try {
    if (!env.LINK_STORAGE) {
      console.error('[KVError] LINK_STORAGE not bound');
      return generateErrorResponse('Configuration error');
    }

    const stored = await env.LINK_STORAGE.get(`link:${path}`);
    if (!stored) {
      return generateNotFoundResponse();
    }
    
    linkData = JSON.parse(stored);
  } catch (error) {
    console.error('[KVError]', error);
    return generateErrorResponse('Storage error');
  }

  // Update click counter asynchronously
  ctx.waitUntil(incrementClickCounter(path, linkData, env));

  // CRITICAL: Bot detection with optimized algorithm
  const detection = detectBot(request, clientIP);

  // Log for analytics (async, non-blocking)
  ctx.waitUntil(logDetection(path, detection, clientIP, userAgent, env));

  if (detection.isBot) {
    // Serve OG preview for bots
    const previewHtml = linkData.mode === 'og_preview' && linkData.ogMeta
      ? generateOGPreview(request, linkData, path)
      : generateMinimalPreview(request, path);

    return new Response(previewHtml, {
      status: 200,
      headers: {
        'Content-Type': 'text/html;charset=UTF-8',
        'Cache-Control': 'public, max-age=3600',
        'X-Robots-Tag': 'noindex, nofollow',
        ...getSecurityHeaders(),
      },
    });
  }

  // HUMAN VISITOR -> Redirect to affiliate link
  const targetUrl = linkData.target || env.TARGET_URL || (typeof INJECTED_TARGET_URL !== 'undefined' ? INJECTED_TARGET_URL : '');

  if (!isValidUrl(targetUrl)) {
    console.error('[RedirectError] Invalid target URL:', targetUrl);
    return generateErrorResponse('Redirect unavailable');
  }

  // Use 302 for flexibility, 301 for permanent if needed
  return Response.redirect(targetUrl, 302);
}

// ============================================
// BOT DETECTION v3.0 - OPTIMIZED ALGORITHM
// ============================================

function detectBot(request, ip) {
  const userAgent = (request.headers.get('User-Agent') || '').toLowerCase();
  const headers = request.headers;

  let score = 0;
  const signals = [];

  // ========================================
  // TIER 1: DEFINITIVE SIGNALS (80-100 pts)
  // These alone are enough to classify as bot
  // ========================================

  // Meta-specific headers (100 pts) - ABSOLUTE confidence
  if (headers.get('X-Purpose') === 'preview') {
    score += 100;
    signals.push('X-Purpose:preview');
  }

  if (headers.get('X-FB-HTTP-Engine') === 'Liger') {
    score += 100;
    signals.push('FB-Engine:Liger');
  }

  // Instagram/Threads app headers (95 pts)
  if (headers.get('X-IG-App-ID') || headers.get('X-FB-Friendly-Name')) {
    score += 95;
    signals.push('IG/FB-App-Header');
  }

  // Exact Meta bot user-agent match (90 pts)
  for (const bot of META_BOT_AGENTS) {
    if (userAgent.includes(bot)) {
      score += 90;
      signals.push(`UA:${bot}`);
      break; // Only count once
    }
  }

  // ========================================
  // TIER 2: HIGH CONFIDENCE SIGNALS (60-80 pts)
  // ========================================

  // Other social media bots (70 pts)
  for (const bot of OTHER_BOT_AGENTS) {
    if (userAgent.includes(bot)) {
      score += 70;
      signals.push(`Social:${bot}`);
      break;
    }
  }

  // Search engine bots (65 pts)
  for (const bot of SEARCH_ENGINE_BOTS) {
    if (userAgent.includes(bot)) {
      score += 65;
      signals.push(`Search:${bot}`);
      break;
    }
  }

  // Meta IP range check (60 pts) - Only if other signals present
  if (ip && signals.length > 0) {
    const inMetaRange = isIPInMetaRange(ip);
    if (inMetaRange) {
      score += 60;
      signals.push('Meta-IP');
    }
  } else if (ip) {
    // IP alone gives lower score
    const inMetaRange = isIPInMetaRange(ip);
    if (inMetaRange) {
      score += 25;
      signals.push('Meta-IP-only');
    }
  }

  // ========================================
  // TIER 3: MEDIUM CONFIDENCE SIGNALS (30-50 pts)
  // ========================================

  // Check for legitimate automation first
  const isLegitTool = LEGITIMATE_AUTOMATION.some(tool => userAgent.includes(tool));

  if (!isLegitTool) {
    // Generic bot keywords (40 pts)
    if (/\b(bot|crawler|spider|scraper|fetch|preview)\b/.test(userAgent)) {
      score += 40;
      signals.push('Generic-bot-keyword');
    }

    // Headless browser indicators (35 pts)
    if (/headless|phantom|puppeteer|playwright|selenium/.test(userAgent)) {
      score += 35;
      signals.push('Headless-browser');
    }
  }

  // ========================================
  // TIER 4: WEAK SIGNALS (10-25 pts)
  // Only matter if combined with others
  // ========================================

  // Social media referrer (15 pts)
  const referer = (headers.get('Referer') || '').toLowerCase();
  if (/facebook\.com|fb\.com|instagram\.com|threads\.net|t\.co|twitter\.com/.test(referer)) {
    score += 15;
    signals.push('Social-referer');
  }

  // Missing standard browser headers (20 pts) - but only with other signals
  if (signals.length > 0) {
    const hasAccept = headers.has('Accept');
    const hasAcceptLang = headers.has('Accept-Language');
    const hasAcceptEnc = headers.has('Accept-Encoding');

    if (!hasAccept && !hasAcceptLang && !hasAcceptEnc) {
      score += 20;
      signals.push('No-browser-headers');
    }
  }

  // Empty or very short user-agent (15 pts)
  if (userAgent.length === 0) {
    score += 15;
    signals.push('Empty-UA');
  } else if (userAgent.length < 30 && !userAgent.includes('mozilla')) {
    score += 10;
    signals.push('Short-UA');
  }

  // ========================================
  // NEGATIVE SIGNALS (Reduce score = MORE HUMAN)
  // ========================================

  // Has cookies (-50 pts) - Strong human indicator
  if (headers.has('Cookie')) {
    score -= 50;
    signals.push('Has-cookies');
  }

  // Modern Sec-Fetch headers (-40 pts) - Browser security feature
  if (headers.has('Sec-Fetch-Dest') || headers.has('Sec-Fetch-Mode') || headers.has('Sec-Fetch-Site')) {
    score -= 40;
    signals.push('Sec-Fetch-headers');
  }

  // Modern browser UA pattern (-30 pts)
  if (/mozilla\/5\.0.*\((windows|macintosh|linux|iphone|android).*\).*applewebkit/i.test(userAgent) &&
      !/bot|crawler|spider/i.test(userAgent)) {
    score -= 30;
    signals.push('Modern-browser-UA');
  }

  // Do Not Track header (-10 pts) - Privacy-conscious user
  if (headers.has('DNT') || headers.has('Sec-GPC')) {
    score -= 10;
    signals.push('Privacy-headers');
  }

  // Complex Accept header (-20 pts)
  const accept = headers.get('Accept') || '';
  if (accept.length > 80 && accept.includes('text/html') && accept.includes('application/xhtml')) {
    score -= 20;
    signals.push('Complex-Accept');
  }

  // ========================================
  // FINAL DETERMINATION
  // ========================================

  // Ensure score is non-negative
  score = Math.max(0, score);

  let isBot = false;
  let confidence = 'low';

  if (score >= BOT_THRESHOLD_DEFINITE) {
    isBot = true;
    confidence = 'definite';
  } else if (score >= BOT_THRESHOLD_LIKELY) {
    isBot = true;
    confidence = 'likely';
  } else if (score < HUMAN_THRESHOLD) {
    isBot = false;
    confidence = 'human';
  } else {
    // GRAY ZONE (35-64): Default to HUMAN to protect revenue
    // Only treat as bot if we have high-confidence signals
    const hasHighConfidenceSignal = signals.some(s =>
      s.includes('X-Purpose') || s.includes('FB-Engine') || s.includes('IG/FB') ||
      s.startsWith('UA:') || s.includes('Meta-IP')
    );

    if (hasHighConfidenceSignal) {
      isBot = true;
      confidence = 'gray-zone-bot';
    } else {
      isBot = false;
      confidence = 'gray-zone-human';
    }
  }

  return {
    isBot,
    score,
    confidence,
    signals,
  };
}

// ============================================
// IP RANGE CHECKING - FIXED FOR OVERFLOW
// ============================================

function isIPInMetaRange(ip) {
  if (!ip) return false;

  try {
    // Detect IP version
    if (ip.includes(':')) {
      return isIPv6InMetaRange(ip);
    } else {
      return isIPv4InMetaRange(ip);
    }
  } catch (error) {
    console.error('[IPCheck Error]', error);
    return false;
  }
}

function isIPv4InMetaRange(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) return false;

  const octets = parts.map(p => parseInt(p, 10));
  if (octets.some(o => isNaN(o) || o < 0 || o > 255)) return false;

  // Convert to BigInt to avoid 32-bit signed integer overflow
  const ipNum = BigInt(octets[0]) * 16777216n + BigInt(octets[1]) * 65536n + BigInt(octets[2]) * 256n + BigInt(octets[3]);

  for (const range of META_IP_RANGES_V4) {
    const rangeNum = BigInt(range.start[0]) * 16777216n + BigInt(range.start[1]) * 65536n +
                     BigInt(range.start[2]) * 256n + BigInt(range.start[3]);

    // Calculate mask using BigInt
    const maskBits = range.mask;
    const mask = maskBits === 0 ? 0n : (0xFFFFFFFFn << BigInt(32 - maskBits)) & 0xFFFFFFFFn;

    if ((ipNum & mask) === (rangeNum & mask)) {
      return true;
    }
  }

  return false;
}

function isIPv6InMetaRange(ip) {
  // Normalize IPv6 address
  const normalized = normalizeIPv6(ip);
  if (!normalized) return false;

  // Extract first 4 hex groups (first 64 bits / first half)
  const prefix = normalized.substring(0, 9); // "xxxx:xxxx"

  for (const metaPrefix of META_IP_PREFIXES_V6) {
    if (prefix.toLowerCase() === metaPrefix.toLowerCase()) {
      return true;
    }
  }

  return false;
}

function normalizeIPv6(ip) {
  try {
    // Remove zone ID if present
    ip = ip.split('%')[0];

    // Handle :: expansion
    if (ip.includes('::')) {
      const parts = ip.split('::');
      const left = parts[0] ? parts[0].split(':') : [];
      const right = parts[1] ? parts[1].split(':') : [];
      const missing = 8 - left.length - right.length;

      if (missing < 0) return null;

      const middle = Array(missing).fill('0000');
      const full = [...left, ...middle, ...right];

      return full.map(p => p.padStart(4, '0')).join(':');
    }

    const parts = ip.split(':');
    if (parts.length !== 8) return null;

    return parts.map(p => p.padStart(4, '0')).join(':');
  } catch {
    return null;
  }
}

// ============================================
// RATE LIMITING
// ============================================

async function checkRateLimit(ip, env, ctx) {
  if (!ip || !env.LINK_STORAGE) return true;

  try {
    const key = `ratelimit:${ip}`;
    const current = await env.LINK_STORAGE.get(key);
    const count = current ? parseInt(current, 10) : 0;

    if (count >= RATE_LIMIT_MAX) {
      return false;
    }

    // Increment counter asynchronously
    ctx.waitUntil(
      env.LINK_STORAGE.put(key, String(count + 1), { expirationTtl: RATE_LIMIT_WINDOW })
    );

    return true;
  } catch (error) {
    console.error('[RateLimit Error]', error);
    return true; // Allow on error to not block legitimate traffic
  }
}

// ============================================
// CLICK COUNTER
// ============================================

async function incrementClickCounter(path, linkData, env) {
  try {
    linkData.clicks = (linkData.clicks || 0) + 1;
    linkData.lastAccessed = new Date().toISOString();

    await env.LINK_STORAGE.put(`link:${path}`, JSON.stringify(linkData), {
      expirationTtl: TTL_SECONDS,
    });
  } catch (error) {
    console.error('[Counter Error]', error);
  }
}

// ============================================
// ANALYTICS LOGGING
// ============================================

async function logDetection(path, detection, ip, userAgent, env) {
  try {
    const logKey = `log:${Date.now()}:${Math.random().toString(36).substring(2, 8)}`;

    const logData = {
      ts: new Date().toISOString(),
      path,
      isBot: detection.isBot,
      score: detection.score,
      confidence: detection.confidence,
      signals: detection.signals.slice(0, 5), // Limit to top 5 signals
      ip: ip ? ip.substring(0, 20) : 'unknown',
      ua: userAgent ? userAgent.substring(0, 80) : 'unknown',
    };

    await env.LINK_STORAGE.put(logKey, JSON.stringify(logData), {
      expirationTtl: 7 * 24 * 60 * 60, // 7 days
    });
  } catch (error) {
    // Silent fail - logging should never break main flow
  }
}

// ============================================
// SAVE LINK API
// ============================================

async function handleSaveLink(request, env) {
  try {
    const authHeader = request.headers.get('Authorization');
    const secretKey = env.SECRET_KEY || (typeof INJECTED_SECRET_KEY !== 'undefined' ? INJECTED_SECRET_KEY : '');

    if (!secretKey || authHeader !== `Bearer ${secretKey}`) {
      return jsonResponse({ error: 'Unauthorized' }, 401);
    }

    const body = await request.json();
    const { paths, mode, ogMeta } = body;

    if (!Array.isArray(paths) || paths.length === 0) {
      return jsonResponse({ error: 'Invalid paths array' }, 400);
    }

    if (paths.length > 100) {
      return jsonResponse({ error: 'Maximum 100 paths per request' }, 400);
    }

    const targetUrl = env.TARGET_URL || (typeof INJECTED_TARGET_URL !== 'undefined' ? INJECTED_TARGET_URL : '');
    const validPaths = [];
    const invalidPaths = [];

    for (const path of paths) {
      if (typeof path !== 'string') {
        invalidPaths.push(path);
        continue;
      }

      const trimmed = path.trim();
      if (!trimmed || trimmed.length > MAX_PATH_LENGTH || !PATH_PATTERN.test(trimmed)) {
        invalidPaths.push(path);
        continue;
      }

      validPaths.push(trimmed);
    }

    if (validPaths.length === 0) {
      return jsonResponse({ error: 'No valid paths provided', invalidPaths: invalidPaths.slice(0, 5) }, 400);
    }

    // Prepare link data
    const linkData = {
      created: new Date().toISOString(),
      target: targetUrl,
      clicks: 0,
      mode: mode || 'default',
    };

    // Add OG metadata if mode is og_preview
    if (mode === 'og_preview' && ogMeta && typeof ogMeta === 'object') {
      linkData.ogMeta = {
        image: sanitizeUrl(ogMeta.image),
        title: sanitizeText(ogMeta.title, 100),
        description: sanitizeText(ogMeta.description, 200),
        canonical: sanitizeUrl(ogMeta.canonical),
      };
    }

    // Save all paths in parallel
    await Promise.all(
      validPaths.map(path =>
        env.LINK_STORAGE.put(`link:${path}`, JSON.stringify(linkData), { expirationTtl: TTL_SECONDS })
      )
    );

    return jsonResponse({
      success: true,
      saved: validPaths.length,
      invalid: invalidPaths.length,
    });
  } catch (error) {
    console.error('[SaveLink Error]', error);
    return jsonResponse({ error: 'Failed to save links' }, 500);
  }
}

// ============================================
// DEBUG ENDPOINT
// ============================================

async function handleDebug(request, env) {
  const authHeader = request.headers.get('Authorization');
  const secretKey = env.SECRET_KEY || (typeof INJECTED_SECRET_KEY !== 'undefined' ? INJECTED_SECRET_KEY : '');

  if (!secretKey || authHeader !== `Bearer ${secretKey}`) {
    return jsonResponse({ error: 'Unauthorized' }, 401);
  }

  const clientIP = request.headers.get('CF-Connecting-IP') || '';
  const detection = detectBot(request, clientIP);

  return jsonResponse({
    version: '3.0',
    ip: clientIP,
    userAgent: request.headers.get('User-Agent'),
    detection,
    headers: Object.fromEntries(request.headers),
  });
}

// ============================================
// HTML GENERATORS
// ============================================

function generateMinimalPreview(request, path) {
  const url = new URL(request.url);
  const domain = url.hostname;

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>${escapeHtml(domain)}</title>
<meta property="og:title" content="${escapeHtml(domain)}">
<meta property="og:type" content="website">
<meta property="og:url" content="${escapeHtml(url.origin)}/${escapeHtml(path)}">
<meta name="twitter:card" content="summary">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:system-ui,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#f5f5f5}
.c{text-align:center;padding:2rem}
.s{width:40px;height:40px;border:4px solid #ddd;border-top-color:#333;border-radius:50%;animation:spin 1s linear infinite;margin:0 auto 1rem}
@keyframes spin{to{transform:rotate(360deg)}}
h1{font-size:1.25rem;font-weight:500;color:#333}
</style>
</head>
<body><div class="c"><div class="s"></div><h1>${escapeHtml(domain)}</h1></div></body>
</html>`;
}

function generateOGPreview(request, linkData, path) {
  const og = linkData.ogMeta || {};
  const url = new URL(request.url);

  const image = validateImageUrl(og.image) || 'https://b-cdn.grbto.net/691f92975a78e-1763676823.png';
  const title = og.title || 'Content';
  const description = og.description || '';
  const canonical = og.canonical || `${url.origin}/${path}`;
  const siteName = url.hostname;

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="index,follow">
<link rel="canonical" href="${escapeHtml(canonical)}">
<title>${escapeHtml(title)}</title>
<meta name="description" content="${escapeHtml(description)}">
<meta property="og:type" content="article">
<meta property="og:url" content="${escapeHtml(canonical)}">
<meta property="og:title" content="${escapeHtml(title)}">
<meta property="og:description" content="${escapeHtml(description)}">
<meta property="og:image" content="${escapeHtml(image)}">
<meta property="og:image:secure_url" content="${escapeHtml(image)}">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta property="og:site_name" content="${escapeHtml(siteName)}">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="${escapeHtml(title)}">
<meta name="twitter:description" content="${escapeHtml(description)}">
<meta name="twitter:image" content="${escapeHtml(image)}">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:system-ui,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;background:linear-gradient(135deg,#667eea,#764ba2);padding:1rem}
.card{max-width:600px;background:#fff;border-radius:16px;overflow:hidden;box-shadow:0 20px 60px rgba(0,0,0,.3)}
.img{width:100%;height:auto;display:block;max-height:400px;object-fit:cover}
.content{padding:2rem}
h1{font-size:1.5rem;font-weight:700;margin-bottom:1rem;color:#1a1a1a;line-height:1.3}
p{font-size:1rem;color:#666;line-height:1.6}
</style>
</head>
<body>
<article class="card">
<img src="${escapeHtml(image)}" alt="${escapeHtml(title)}" class="img" loading="lazy">
<div class="content">
<h1>${escapeHtml(title)}</h1>
${description ? `<p>${escapeHtml(description)}</p>` : ''}
</div>
</article>
</body>
</html>`;
}

function generateNotFoundResponse() {
  return new Response(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex">
<title>404</title>
<style>
*{margin:0;padding:0}
body{font-family:system-ui,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#f5f5f5}
.c{text-align:center}
h1{font-size:6rem;font-weight:700;color:#333}
p{color:#666;font-size:1.25rem}
</style>
</head>
<body><div class="c"><h1>404</h1><p>Not Found</p></div></body>
</html>`, {
    status: 404,
    headers: { 'Content-Type': 'text/html;charset=UTF-8' },
  });
}

function generateErrorResponse(message) {
  return new Response(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex">
<title>Error</title>
<style>
*{margin:0;padding:0}
body{font-family:system-ui,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#f5f5f5}
.c{text-align:center;max-width:400px;padding:2rem}
h1{font-size:3rem;font-weight:700;color:#e53935;margin-bottom:1rem}
p{color:#666;line-height:1.6}
</style>
</head>
<body><div class="c"><h1>Error</h1><p>${escapeHtml(message)}</p></div></body>
</html>`, {
    status: 503,
    headers: { 'Content-Type': 'text/html;charset=UTF-8' },
  });
}

// ============================================
// UTILITY FUNCTIONS
// ============================================

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...corsHeaders },
  });
}

function getSecurityHeaders() {
  return {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'SAMEORIGIN',
    'X-XSS-Protection': '1; mode=block',
    'Referrer-Policy': 'no-referrer-when-downgrade',
  };
}

function isValidUrl(url) {
  if (!url || typeof url !== 'string') return false;
  try {
    const parsed = new URL(url);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch {
    return false;
  }
}

function validateImageUrl(url) {
  if (!url || typeof url !== 'string') return null;
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== 'https:') return null;

    const hostname = parsed.hostname.toLowerCase();
    const isTrusted = TRUSTED_IMAGE_DOMAINS.some(domain => hostname.includes(domain));

    return isTrusted ? url : null;
  } catch {
    return null;
  }
}

function sanitizeText(str, maxLen = 200) {
  if (!str || typeof str !== 'string') return '';
  return str.replace(/<[^>]*>/g, '').replace(/[<>'"&]/g, '').substring(0, maxLen).trim();
}

function sanitizeUrl(url) {
  if (!url || typeof url !== 'string') return '';
  try {
    const parsed = new URL(url.trim());
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return '';
    return parsed.href;
  } catch {
    return '';
  }
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

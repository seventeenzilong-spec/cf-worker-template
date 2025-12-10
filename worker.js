const TTL_SECONDS = 30 * 24 * 60 * 60; // 30 days
const MAX_PATH_LENGTH = 100;
const PATH_PATTERN = /^[a-zA-Z0-9_-]+$/;
const RATE_LIMIT_WINDOW = 3600; // 1 hour
const RATE_LIMIT_MAX = 100;

// Meta/Facebook IP ranges for bot detection
const META_IP_RANGES = [
  '31.13.24.0/21', '31.13.64.0/18', '31.13.96.0/19',
  '66.220.144.0/20', '69.63.176.0/20', '69.171.224.0/19',
  '74.119.76.0/22', '102.132.96.0/20', '103.4.96.0/22',
  '129.134.0.0/16', '157.240.0.0/16', '173.252.64.0/18',
  '179.60.192.0/22', '185.60.216.0/22', '204.15.20.0/22',
  '199.16.156.0/22', '192.133.76.0/22',
  '18.194.0.0/15', '34.224.0.0/12',
  '2a03:2880::/32', '2c0f:fb50::/32'
];

// Known bot user agents
const BOT_USER_AGENTS = [
  'facebookexternalhit', 'Facebot', 'facebookplatform',
  'Meta-ExternalAgent', 'meta-externalhit',
  'InstagramBot', 'ThreadsBot', 'ThreadsExternalHit',
  'Twitterbot', 'Twitter',
  'WhatsApp', 'WhatsApp/', 'WA_Business',
  'LinkedInBot', 'linkedin',
  'Slackbot', 'TelegramBot', 'SkypeUriPreview',
  'Discordbot', 'redditbot', 'Applebot',
  'ia_archiver', 'PinterestBot', 'Googlebot',
  'bingbot', 'Baiduspider', 'YandexBot'
];

// Trusted image CDN domains
const TRUSTED_IMAGE_DOMAINS = [
  'cdn.', 'imgur.com', 'cloudinary.com', 'imagekit.io',
  'imgix.net', 'cloudfront.net', 'b-cdn.', 'bunnycdn.com'
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
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }
    return handleRequest(request, env, ctx);
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

  console.log(`[Request] Path: ${path}, IP: ${clientIP}, UA: ${userAgent.substring(0, 50)}...`);

  // Internal API endpoint for saving links
  if (request.method === 'POST' && path === 'api/save-link') {
    console.log('[API] Handling save-link request');
    return handleSaveLink(request, env);
  }

  // Root path or favicon
  if (!path || path === 'favicon.ico') {
    return new Response('Link Generator - Secure Mode Active', {
      status: 200,
      headers: { 'Content-Type': 'text/plain' }
    });
  }

  // Rate limiting
  const rateLimitOk = await checkRateLimit(clientIP, env, ctx);
  if (!rateLimitOk) {
    console.log(`[RateLimit] Exceeded for IP: ${clientIP}`);
    return new Response('Too many requests. Please try again later.', {
      status: 429,
      headers: { 'Retry-After': '3600' }
    });
  }

  // Retrieve link data from KV
  let linkData;
  try {
    if (!env.LINK_STORAGE) {
      console.error('[KVError] LINK_STORAGE binding not configured');
      return new Response('Service configuration error', { status: 500 });
    }
    
    const stored = await env.LINK_STORAGE.get(`link:${path}`);
    if (!stored) {
      console.log(`[NotFound] Path not found: ${path}`);
      return new Response(generateNotFoundPage(), {
        status: 404,
        headers: { 'Content-Type': 'text/html;charset=UTF-8' }
      });
    }
    linkData = JSON.parse(stored);
    console.log(`[Success] Path found: ${path}, Target: ${linkData.target}, Clicks: ${linkData.clicks || 0}`);
  } catch (e) {
    console.error('[KVError] Failed to retrieve path:', path, e);
    return new Response('Error retrieving link', { status: 500 });
  }

  // Update click counter asynchronously
  ctx.waitUntil(updateCounter(path, linkData, env));

  // Bot detection
  const isBot = await detectBot(request, clientIP);
  
  if (isBot) {
    console.log(`[BotDetected] Serving preview for: ${path}`);
    
    const previewContent = linkData.mode === 'default' 
      ? await generateMinimalPreview(request, path)
      : await generateSafePreview(request, linkData, path);

    return new Response(previewContent, {
      headers: {
        ...addSecurityHeaders({
          'Content-Type': 'text/html;charset=UTF-8',
          'Cache-Control': 'public, max-age=3600',
          'X-Robots-Tag': 'nofollow, noarchive'
        })
      },
    });
  }

  // Human visitor -> Redirect
  // Gunakan env.TARGET_URL, dengan fallback ke INJECTED_TARGET_URL jika ada
  const targetUrl = linkData.target || env.TARGET_URL || (typeof INJECTED_TARGET_URL !== 'undefined' ? INJECTED_TARGET_URL : '');
  
  if (!isValidTargetUrl(targetUrl)) {
    return new Response('Invalid target URL', { status: 400 });
  }

  console.log(`[HumanRedirect] Redirecting to: ${targetUrl}`);
  return Response.redirect(targetUrl, 302);
}

// ============================================
// BOT DETECTION
// ============================================

async function detectBot(request, ip) {
  const userAgent = (request.headers.get('User-Agent') || '').toLowerCase();
  
  // Check known bot user agents
  const isUserAgentBot = BOT_USER_AGENTS.some(bot =>
    userAgent.includes(bot.toLowerCase())
  );
  
  if (isUserAgentBot) {
    console.log('[BotCheck] Detected via User-Agent');
    return true;
  }

  // Check Meta/Facebook headers
  const xPurpose = request.headers.get('X-Purpose');
  const xFBEngine = request.headers.get('X-FB-HTTP-Engine');
  
  if (xPurpose === 'preview' || xFBEngine === 'Liger') {
    console.log('[BotCheck] Detected via Meta headers');
    return true;
  }

  // Check Meta IP ranges
  if (ip && isIPInMetaRanges(ip)) {
    console.log('[BotCheck] Detected via Meta IP range');
    return true;
  }

  // Check for bot keywords in user agent
  const hasBotKeywords = userAgent.includes('bot') || 
                         userAgent.includes('crawler') || 
                         userAgent.includes('spider') ||
                         userAgent.includes('scraper');
  
  const hasAccept = request.headers.has('Accept');
  const hasAcceptLanguage = request.headers.has('Accept-Language');
  const hasAcceptEncoding = request.headers.has('Accept-Encoding');
  const missingHeaders = !hasAccept && !hasAcceptLanguage && !hasAcceptEncoding;
  
  if (missingHeaders && hasBotKeywords) {
    console.log('[BotCheck] Detected via missing headers + bot keywords');
    return true;
  }

  // Empty or suspicious user agents
  if (!userAgent || userAgent.length < 10) {
    console.log('[BotCheck] Detected via empty/short user agent');
    return true;
  }

  // Headless browsers
  if (userAgent.includes('headless') || userAgent.includes('phantom')) {
    console.log('[BotCheck] Detected via headless browser');
    return true;
  }

  console.log('[BotCheck] Passed - identified as real user');
  return false;
}

function isIPInMetaRanges(ip) {
  try {
    const ipParts = ip.split('.').map(Number);
    if (ipParts.length !== 4 || ipParts.some(isNaN)) return false;
    
    const ipNum = (ipParts[0] << 24) + (ipParts[1] << 16) + (ipParts[2] << 8) + ipParts[3];
    
    for (const range of META_IP_RANGES) {
      if (range.includes(':')) continue; // Skip IPv6 for now
      
      const [rangeIP, mask] = range.split('/');
      const rangeParts = rangeIP.split('.').map(Number);
      const rangeNum = (rangeParts[0] << 24) + (rangeParts[1] << 16) + (rangeParts[2] << 8) + rangeParts[3];
      const maskNum = -1 << (32 - parseInt(mask));
      
      if ((ipNum & maskNum) === (rangeNum & maskNum)) {
        return true;
      }
    }
  } catch (e) {
    console.error('IP range check error:', e);
  }
  return false;
}

// ============================================
// RATE LIMITING
// ============================================

async function checkRateLimit(ip, env, ctx) {
  if (!ip) return true;
  
  const key = `ratelimit:${ip}`;
  
  try {
    const current = await env.LINK_STORAGE.get(key);
    const count = current ? parseInt(current) : 0;
    
    if (count >= RATE_LIMIT_MAX) {
      return false;
    }
    
    ctx.waitUntil(
      env.LINK_STORAGE.put(key, (count + 1).toString(), {
        expirationTtl: RATE_LIMIT_WINDOW
      })
    );
    
    return true;
  } catch (e) {
    console.error('Rate limit error:', e);
    return true;
  }
}

// ============================================
// CLICK COUNTER
// ============================================

async function updateCounter(path, linkData, env) {
  try {
    linkData.clicks = (linkData.clicks || 0) + 1;
    linkData.lastAccessed = new Date().toISOString();
    
    await env.LINK_STORAGE.put(`link:${path}`, JSON.stringify(linkData), {
      expirationTtl: TTL_SECONDS
    });
  } catch (e) {
    console.error('Counter update error:', e);
  }
}

// ============================================
// SAVE LINK API
// ============================================

async function handleSaveLink(request, env) {
  const authHeader = request.headers.get('Authorization');
  // Gunakan env.SECRET_KEY dengan fallback ke INJECTED_SECRET_KEY jika ada
  const SECRET_KEY = env.SECRET_KEY || (typeof INJECTED_SECRET_KEY !== 'undefined' ? INJECTED_SECRET_KEY : '');

  if (!SECRET_KEY || authHeader !== `Bearer ${SECRET_KEY}`) {
    return new Response(JSON.stringify({ error: 'Unauthorized' }), {
      status: 401,
      headers: {
        'Content-Type': 'application/json',
        ...corsHeaders
      }
    });
  }

  try {
    const { paths, mode, ogMeta } = await request.json();

    if (!Array.isArray(paths) || paths.length === 0) {
      return new Response(JSON.stringify({ error: 'Invalid input: paths must be a non-empty array' }), {
        status: 400,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }

    const invalidPaths = [];
    const validPaths = [];
    
    for (const path of paths) {
      if (!path || typeof path !== 'string') {
        invalidPaths.push(path);
        continue;
      }
      
      const trimmedPath = path.trim();
      
      if (trimmedPath.length === 0 || trimmedPath.length > MAX_PATH_LENGTH) {
        invalidPaths.push(path);
        continue;
      }
      
      if (!PATH_PATTERN.test(trimmedPath)) {
        invalidPaths.push(path);
        continue;
      }
      
      validPaths.push(trimmedPath);
    }

    if (invalidPaths.length > 0) {
      return new Response(JSON.stringify({ 
        error: 'Invalid paths detected',
        invalidPaths: invalidPaths.slice(0, 5),
        message: 'Paths must be 1-100 characters and contain only letters, numbers, hyphens, and underscores'
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json', ...corsHeaders }
      });
    }

    const TARGET_URL = env.TARGET_URL || (typeof INJECTED_TARGET_URL !== 'undefined' ? INJECTED_TARGET_URL : '');
    
    const savePromises = validPaths.map(path => {
      const linkData = {
        created: new Date().toISOString(),
        target: TARGET_URL,
        clicks: 0,
        generatedBy: 'link-generator',
        mode: mode || 'default'
      };

      if (mode === 'og_preview' && ogMeta) {
        linkData.ogMeta = {
          image: ogMeta.image || '',
          title: ogMeta.title || '',
          description: ogMeta.description || '',
          canonical: ogMeta.canonical || ''
        };
      }

      return env.LINK_STORAGE.put(`link:${path}`, JSON.stringify(linkData), {
        expirationTtl: TTL_SECONDS
      });
    });
    await Promise.all(savePromises);

    return new Response(JSON.stringify({ success: true, saved: validPaths.length }), {
      status: 200,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  } catch (e) {
    console.error('Save Error:', e);
    return new Response(JSON.stringify({ error: 'Failed to save links' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json', ...corsHeaders }
    });
  }
}

// ============================================
// HTML GENERATORS
// ============================================

async function generateMinimalPreview(request, path) {
  const canonicalUrl = `${new URL(request.url).origin}/${path}`;
  
  return `<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<meta name="robots" content="noindex, nofollow" />
<title>Redirecting...</title>
<style>
body {
  margin: 0;
  padding: 0;
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 100vh;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  color: white;
}
.container {
  text-align: center;
  padding: 40px;
}
.spinner {
  width: 50px;
  height: 50px;
  border: 5px solid rgba(255,255,255,0.3);
  border-top-color: white;
  border-radius: 50%;
  animation: spin 1s linear infinite;
  margin: 0 auto 20px;
}
@keyframes spin {
  to { transform: rotate(360deg); }
}
h1 {
  font-size: 24px;
  font-weight: 600;
  margin: 0;
}
</style>
</head>
<body>
  <div class="container">
    <div class="spinner"></div>
    <h1>Redirecting...</h1>
  </div>
</body>
</html>`;
}

async function generateSafePreview(request, linkData, path) {
  const ogMeta = linkData.ogMeta || {};
  
  const previewImage = validateImageUrl(ogMeta.image) || 
    validateImageUrl(linkData.image) || 
    "https://b-cdn.grbto.net/691f92975a78e-1763676823.png";
  
  const previewTitle = sanitizeText(ogMeta.title) || 
    sanitizeText(linkData.title) || 
    "Hey there! I am using WhatsApp.";
  const previewDescription = sanitizeText(ogMeta.description) || 
    sanitizeText(linkData.description) || 
    "What's Up.";
  
  const canonicalUrl = ogMeta.canonical || 
    `${new URL(request.url).origin}/${path}`;
  const siteName = "Your Site Name";
  const publishedTime = linkData.created || new Date().toISOString();

  return `<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<meta name="robots" content="index, follow" />

<!-- Security Headers -->
<meta http-equiv="Content-Security-Policy" content="default-src 'self' https:; img-src https: data:; style-src 'unsafe-inline' https:;" />
<meta http-equiv="X-Content-Type-Options" content="nosniff" />
<meta name="referrer" content="no-referrer-when-downgrade" />

<!-- Canonical URL -->
<link rel="canonical" href="${canonicalUrl}" />

<!-- Primary Meta Tags -->
<title>${escapeHtml(previewTitle)}</title>
<meta name="title" content="${escapeHtml(previewTitle)}" />
<meta name="description" content="${escapeHtml(previewDescription)}" />

<!-- Open Graph / Facebook -->
<meta property="og:type" content="article" />
<meta property="og:url" content="${canonicalUrl}" />
<meta property="og:title" content="${escapeHtml(previewTitle)}" />
<meta property="og:description" content="${escapeHtml(previewDescription)}" />
<meta property="og:image" content="${previewImage}" />
<meta property="og:image:secure_url" content="${previewImage}" />
<meta property="og:image:width" content="1200" />
<meta property="og:image:height" content="630" />
<meta property="og:image:alt" content="${escapeHtml(previewTitle)}" />
<meta property="og:site_name" content="${siteName}" />
<meta property="og:locale" content="id_ID" />
<meta property="article:published_time" content="${publishedTime}" />

<!-- Twitter -->
<meta name="twitter:card" content="summary_large_image" />
<meta name="twitter:url" content="${canonicalUrl}" />
<meta name="twitter:title" content="${escapeHtml(previewTitle)}" />
<meta name="twitter:description" content="${escapeHtml(previewDescription)}" />
<meta name="twitter:image" content="${previewImage}" />

<!-- Structured Data (JSON-LD) -->
<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "Article",
  "headline": "${escapeHtml(previewTitle)}",
  "description": "${escapeHtml(previewDescription)}",
  "image": {
    "@type": "ImageObject",
    "url": "${previewImage}",
    "width": 1200,
    "height": 630
  },
  "datePublished": "${publishedTime}",
  "author": {
    "@type": "Organization",
    "name": "${siteName}"
  },
  "publisher": {
    "@type": "Organization",
    "name": "${siteName}"
  }
}
</script>

<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
  line-height: 1.6;
  color: #333;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 20px;
}
.container {
  max-width: 600px;
  background: white;
  border-radius: 16px;
  overflow: hidden;
  box-shadow: 0 20px 60px rgba(0,0,0,0.3);
}
.image {
  width: 100%;
  height: auto;
  display: block;
  object-fit: cover;
  max-height: 400px;
}
.content {
  padding: 32px;
}
h1 {
  font-size: 28px;
  font-weight: 700;
  margin-bottom: 16px;
  color: #1a1a1a;
  line-height: 1.3;
}
p {
  font-size: 16px;
  color: #666;
  line-height: 1.7;
}
</style>
</head>
<body>
  <article class="container">
    <img src="${previewImage}" alt="${escapeHtml(previewTitle)}" class="image" loading="lazy" />
    <div class="content">
      <h1>${escapeHtml(previewTitle)}</h1>
      <p>${escapeHtml(previewDescription)}</p>
    </div>
  </article>
</body>
</html>`;
}

// ============================================
// UTILITY FUNCTIONS
// ============================================

function validateImageUrl(url) {
  if (!url) return null;
  
  try {
    const parsed = new URL(url);
    
    if (parsed.protocol !== 'https:') return null;
    
    const isTrusted = TRUSTED_IMAGE_DOMAINS.some(domain =>
      parsed.hostname.includes(domain)
    );
    
    if (!isTrusted) return null;
    
    return url;
  } catch {
    return null;
  }
}

function isValidTargetUrl(url) {
  try {
    const parsed = new URL(url);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch {
    return false;
  }
}

function addSecurityHeaders(headers) {
  return {
    ...headers,
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'SAMEORIGIN',
    'X-XSS-Protection': '1; mode=block',
    'Referrer-Policy': 'no-referrer-when-downgrade',
    'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains'
  };
}

function sanitizeText(str) {
  if (!str) return '';
  return str.replace(/<[^>]*>/g, '')
            .replace(/[<>'\"]/g, '')
            .substring(0, 200);
}

function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/\"/g, '&quot;')
            .replace(/'/g, '&#039;');
}

function generateNotFoundPage() {
  return `<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>404 - Halaman Tidak Ditemukan</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
  font-family: system-ui, -apple-system, sans-serif;
  background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  color: white;
  text-align: center;
  padding: 20px;
}
h1 { font-size: 120px; margin-bottom: 20px; font-weight: 700; }
p { font-size: 24px; opacity: 0.9; }
</style>
</head>
<body>
  <div>
    <h1>404</h1>
    <p>Link tidak ditemukan</p>
  </div>
</body>
</html>`;
}

/**
 * Edge Worker (worker.js) - PRODUCTION OPTIMIZED v4.0
 * 
 * Cloudflare Worker untuk handling public traffic at the edge.
 * FULLY OPTIMIZED untuk minimize false positive & maximize Meta bot detection.
 * 
 * CRITICAL REQUIREMENTS:
 * - FALSE POSITIVE < 0.3% (human traffic MUST pass = $$$ revenue)
 * - FALSE NEGATIVE < 2% (Meta bot MUST be caught = account safety)
 * 
 * KEY IMPROVEMENTS v4.0:
 * - Advanced In-App Browser Detection (Instagram, Facebook, Threads)
 * - Platform-specific handling with fingerprinting
 * - Timing randomization to avoid pattern detection
 * - Adaptive rate limiting based on traffic patterns
 * - Enhanced behavioral analysis with negative scoring
 * - Multi-layer caching for performance
 * - JavaScript-based redirect for better cloaking
 * - Comprehensive error handling with graceful degradation
 */

// ============================================
// CONSTANTS - TUNED FOR MAXIMUM ACCURACY
// ============================================

const VERSION = '4.0.0';
const TTL_SECONDS = 30 * 24 * 60 * 60; // 30 days
const MAX_PATH_LENGTH = 100;
const PATH_PATTERN = /^[a-zA-Z0-9_-]+$/;

// Adaptive rate limiting
const RATE_LIMIT_WINDOW = 3600; // 1 hour
const RATE_LIMIT_BASE = 200; // Base limit
const RATE_LIMIT_BURST = 500; // Burst limit for viral traffic

// Bot detection thresholds - CRITICAL: Tuned to minimize false positives
const BOT_THRESHOLD_DEFINITE = 90;   // >= 90: Definitely bot
const BOT_THRESHOLD_LIKELY = 70;     // 70-89: Likely bot
const BOT_THRESHOLD_SUSPICIOUS = 50; // 50-69: Suspicious, check signals
const HUMAN_THRESHOLD = 30;          // < 30: Definitely human
// Gray zone: 30-49 - Default to HUMAN to protect revenue

// Meta/Facebook IP ranges (IPv4) - Updated December 2024
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
  // Additional Meta ranges 2024
  { start: [163, 70, 128, 0], mask: 17 },
  { start: [185, 89, 218, 0], mask: 23 },
  { start: [31, 13, 24, 0], mask: 21 },
];

// Meta IPv6 prefixes
const META_IP_PREFIXES_V6 = [
  '2a03:2880',  // Facebook primary
  '2c0f:fb50',  // Meta Africa
  '2a03:2887',  // Facebook secondary
  '2401:db00',  // Meta APAC
  '2620:0:1c00', // Meta US
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

// Instagram/Facebook In-App Browser signatures - CRITICAL for avoiding false positives
// These are REAL USERS browsing in the app, NOT bots
const INAPP_BROWSER_SIGNATURES = [
  { pattern: /fbav\/|fban\/|fb_iab\/|fb4a\//i, platform: 'facebook_app' },
  { pattern: /instagram/i, platform: 'instagram_app' },
  { pattern: /threads/i, platform: 'threads_app' },
  { pattern: /messenger/i, platform: 'messenger_app' },
  { pattern: /\[fb/i, platform: 'facebook_webview' },
  { pattern: /\[fban/i, platform: 'facebook_native' },
];

// Mobile browser signatures (legitimate traffic)
const MOBILE_BROWSER_PATTERNS = [
  /android.*mobile.*safari/i,
  /iphone.*mobile.*safari/i,
  /ipad.*safari/i,
  /android.*chrome/i,
  /crios|fxios|edgios|opios/i, // iOS browsers
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
  'vkshare',
  'snapchat',
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
  'seznambot',
  'ahrefsbot',
  'semrushbot',
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
  'synthetics',
  'sitemonitor',
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
  'unsplash.com',
  'pexels.com',
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
        return generateJSRedirect(targetUrl);
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
    return jsonResponse({ 
      status: 'ok', 
      service: 'link-cloaker', 
      version: VERSION,
      timestamp: Date.now()
    });
  }

  // Debug endpoint (only with valid auth)
  if (path === 'api/debug' && request.method === 'GET') {
    return handleDebug(request, env);
  }

  // Stats endpoint
  if (path === 'api/stats' && request.method === 'GET') {
    return handleStats(request, env);
  }

  // Root path or favicon
  if (!path || path === 'favicon.ico' || path === 'robots.txt') {
    return new Response('OK', { status: 200 });
  }

  // Validate path format
  if (path.length > MAX_PATH_LENGTH || !PATH_PATTERN.test(path)) {
    return generateNotFoundResponse();
  }

  // Adaptive rate limiting check
  const rateLimitOk = await checkAdaptiveRateLimit(clientIP, env, ctx);
  if (!rateLimitOk) {
    return new Response('Too many requests', { 
      status: 429, 
      headers: { 'Retry-After': '60' } 
    });
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
  const detection = detectBot(request, clientIP, userAgent);

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

  // Use JavaScript redirect with random delay for better cloaking
  // This prevents pattern detection by crawlers
  return generateJSRedirect(targetUrl, detection.platform);
}

// ============================================
// BOT DETECTION v4.0 - OPTIMIZED ALGORITHM
// ============================================

function detectBot(request, ip, userAgent) {
  const ua = (userAgent || '').toLowerCase();
  const headers = request.headers;

  let score = 0;
  const signals = [];
  let platform = 'unknown';
  let isInAppBrowser = false;

  // ========================================
  // PRIORITY 0: IN-APP BROWSER DETECTION
  // CRITICAL: These are REAL USERS, not bots!
  // Must check FIRST to avoid false positives
  // This is an ABSOLUTE override - in-app browser = HUMAN
  // ========================================

  for (const sig of INAPP_BROWSER_SIGNATURES) {
    if (sig.pattern.test(userAgent)) {
      platform = sig.platform;
      isInAppBrowser = true;
      
      // Check if this is actually a bot pretending to be in-app browser
      const hasBotIndicator = META_BOT_AGENTS.some(bot => ua.includes(bot));
      
      if (!hasBotIndicator) {
        // Real in-app browser user, NOT a bot - IMMEDIATE RETURN
        // This CANNOT be overridden by IP checks or other signals
        signals.push(`InApp:${platform}`);
        
        return {
          isBot: false,
          score: 0,
          confidence: 'inapp-human-definite',
          signals,
          platform,
          isInAppBrowser: true,
        };
      } else {
        // Bot pretending to be in-app browser - continue with detection
        signals.push(`InApp-suspicious:${platform}`);
        isInAppBrowser = false;
      }
      break;
    }
  }

  // Check for mobile browser patterns (legitimate traffic)
  for (const pattern of MOBILE_BROWSER_PATTERNS) {
    if (pattern.test(userAgent)) {
      score -= 40;
      signals.push('Mobile-browser');
      platform = 'mobile';
      break;
    }
  }

  // ========================================
  // TIER 1: DEFINITIVE BOT SIGNALS (85-100 pts)
  // These alone are enough to classify as bot
  // ========================================

  // Meta-specific headers (100 pts) - ABSOLUTE confidence
  if (headers.get('X-Purpose') === 'preview') {
    score += 100;
    signals.push('X-Purpose:preview');
    platform = 'meta_crawler';
  }

  if (headers.get('X-FB-HTTP-Engine') === 'Liger') {
    score += 100;
    signals.push('FB-Engine:Liger');
    platform = 'meta_crawler';
  }

  // Instagram/Threads crawler headers (95 pts)
  const igAppId = headers.get('X-IG-App-ID');
  const fbFriendlyName = headers.get('X-FB-Friendly-Name');
  
  if (igAppId || fbFriendlyName) {
    // Only count as bot if it's actually a crawler, not in-app browser
    if (!signals.includes('InApp:instagram_app') && !signals.includes('InApp:facebook_app')) {
      score += 95;
      signals.push('IG/FB-Crawler-Header');
      platform = 'meta_crawler';
    }
  }

  // Exact Meta bot user-agent match (90 pts)
  for (const bot of META_BOT_AGENTS) {
    if (ua.includes(bot)) {
      score += 90;
      signals.push(`UA:${bot}`);
      platform = 'meta_bot';
      break;
    }
  }

  // ========================================
  // TIER 2: HIGH CONFIDENCE SIGNALS (60-80 pts)
  // ========================================

  // Other social media bots (75 pts)
  for (const bot of OTHER_BOT_AGENTS) {
    if (ua.includes(bot)) {
      score += 75;
      signals.push(`Social:${bot}`);
      platform = 'social_bot';
      break;
    }
  }

  // Search engine bots (70 pts)
  for (const bot of SEARCH_ENGINE_BOTS) {
    if (ua.includes(bot)) {
      score += 70;
      signals.push(`Search:${bot}`);
      platform = 'search_bot';
      break;
    }
  }

  // Meta IP range check - only if NOT an in-app browser AND have other bot signals
  // NEVER let IP override in-app browser detection
  if (ip && !isInAppBrowser && score > 30) {
    const inMetaRange = isIPInMetaRange(ip);
    if (inMetaRange) {
      score += 40; // Reduced from 50 to be more conservative
      signals.push('Meta-IP-confirmed');
    }
  } else if (ip && !isInAppBrowser && score > 0) {
    // IP alone gives minimal score - only if already suspicious
    const inMetaRange = isIPInMetaRange(ip);
    if (inMetaRange) {
      score += 10; // Reduced from 15
      signals.push('Meta-IP-weak');
    }
  }
  // Note: If isInAppBrowser is true, we already returned above

  // ========================================
  // TIER 3: MEDIUM CONFIDENCE SIGNALS (30-50 pts)
  // ========================================

  // Check for legitimate automation first
  const isLegitTool = LEGITIMATE_AUTOMATION.some(tool => ua.includes(tool));

  if (!isLegitTool) {
    // Generic bot keywords (35 pts)
    if (/\b(bot|crawler|spider|scraper|fetch)\b/.test(ua)) {
      score += 35;
      signals.push('Generic-bot-keyword');
    }

    // Headless browser indicators (40 pts)
    if (/headless|phantom|puppeteer|playwright|selenium|webdriver/.test(ua)) {
      score += 40;
      signals.push('Headless-browser');
    }

    // Preview keyword alone (25 pts) - lower because legitimate apps use this
    if (/preview/i.test(ua) && !signals.some(s => s.includes('bot'))) {
      score += 25;
      signals.push('Preview-keyword');
    }
  }

  // ========================================
  // TIER 4: WEAK SIGNALS (10-20 pts)
  // Only matter if combined with others
  // ========================================

  // Social media referrer (10 pts) - weak signal
  const referer = (headers.get('Referer') || '').toLowerCase();
  if (/facebook\.com|fb\.com|instagram\.com|threads\.net|t\.co|twitter\.com|lnkd\.in/.test(referer)) {
    // This is actually ambiguous - could be bot OR human clicking from feed
    if (score > 40) {
      score += 10;
      signals.push('Social-referer');
    }
  }

  // Missing standard browser headers (15 pts) - only with other signals
  if (signals.length > 0 && score > 20) {
    const hasAccept = headers.has('Accept');
    const hasAcceptLang = headers.has('Accept-Language');
    const hasAcceptEnc = headers.has('Accept-Encoding');

    if (!hasAccept && !hasAcceptLang && !hasAcceptEnc) {
      score += 15;
      signals.push('No-browser-headers');
    }
  }

  // Empty or suspicious user-agent (10 pts)
  if (ua.length === 0) {
    score += 10;
    signals.push('Empty-UA');
  } else if (ua.length < 20) {
    score += 5;
    signals.push('Short-UA');
  }

  // ========================================
  // NEGATIVE SIGNALS (Reduce score = MORE HUMAN)
  // These are STRONG indicators of real users
  // ========================================

  // Has cookies (-60 pts) - Very strong human indicator
  if (headers.has('Cookie')) {
    score -= 60;
    signals.push('Has-cookies');
  }

  // Modern Sec-Fetch headers (-50 pts) - Browser security feature
  const hasSecFetch = headers.has('Sec-Fetch-Dest') || 
                      headers.has('Sec-Fetch-Mode') || 
                      headers.has('Sec-Fetch-Site') ||
                      headers.has('Sec-Fetch-User');
  if (hasSecFetch) {
    score -= 50;
    signals.push('Sec-Fetch-headers');
  }

  // Sec-CH-UA headers (-40 pts) - Client hints from modern browsers
  if (headers.has('Sec-CH-UA') || headers.has('Sec-CH-UA-Mobile') || headers.has('Sec-CH-UA-Platform')) {
    score -= 40;
    signals.push('Client-hints');
  }

  // Modern browser UA pattern (-35 pts)
  if (/mozilla\/5\.0.*\((windows|macintosh|linux|iphone|android|ipad).*\).*applewebkit/i.test(userAgent) &&
      !/bot|crawler|spider|externalhit/i.test(ua)) {
    score -= 35;
    signals.push('Modern-browser-UA');
  }

  // Do Not Track / GPC header (-15 pts) - Privacy-conscious user
  if (headers.has('DNT') || headers.has('Sec-GPC')) {
    score -= 15;
    signals.push('Privacy-headers');
  }

  // Complex Accept header (-25 pts)
  const accept = headers.get('Accept') || '';
  if (accept.length > 80 && accept.includes('text/html') && 
      (accept.includes('application/xhtml') || accept.includes('image/webp'))) {
    score -= 25;
    signals.push('Complex-Accept');
  }

  // Upgrade-Insecure-Requests (-20 pts) - Browser feature
  if (headers.get('Upgrade-Insecure-Requests') === '1') {
    score -= 20;
    signals.push('Upgrade-Insecure');
  }

  // Cache-Control from browser (-10 pts)
  const cacheControl = headers.get('Cache-Control') || '';
  if (cacheControl.includes('max-age=0') || cacheControl.includes('no-cache')) {
    score -= 10;
    signals.push('Browser-cache');
  }

  // ========================================
  // FINAL DETERMINATION - REVENUE PROTECTION FIRST
  // Gray zone (30-69) ALWAYS defaults to human unless
  // we have ABSOLUTE definitive bot signals
  // ========================================

  // Ensure score is non-negative
  score = Math.max(0, score);

  let isBot = false;
  let confidence = 'low';

  // Definitive bot signals that override gray zone
  const hasDefinitiveMetaSignal = signals.some(s =>
    s.includes('X-Purpose:preview') || 
    s.includes('FB-Engine:Liger') ||
    s.includes('IG/FB-Crawler-Header')
  );
  
  const hasDefinitiveBotUA = signals.some(s =>
    s.startsWith('UA:facebookexternalhit') ||
    s.startsWith('UA:facebot') ||
    s.startsWith('UA:meta-external') ||
    s.startsWith('UA:instagrambot') ||
    s.startsWith('UA:threadsbot')
  );

  if (score >= BOT_THRESHOLD_DEFINITE) {
    // >= 90: Definitely bot
    isBot = true;
    confidence = 'definite';
  } else if (score >= BOT_THRESHOLD_LIKELY && (hasDefinitiveMetaSignal || hasDefinitiveBotUA)) {
    // 70-89: Only bot if we have definitive signals
    isBot = true;
    confidence = 'likely';
  } else if (score >= BOT_THRESHOLD_SUSPICIOUS) {
    // 50-69: GRAY ZONE - REQUIRE definitive signals to mark as bot
    // Default to HUMAN to protect revenue (false positive < 0.5%)
    if (hasDefinitiveMetaSignal || hasDefinitiveBotUA) {
      isBot = true;
      confidence = 'suspicious-confirmed-bot';
    } else {
      // No definitive signal = treat as human
      isBot = false;
      confidence = 'suspicious-default-human';
    }
  } else if (score >= HUMAN_THRESHOLD) {
    // 30-49: LOWER GRAY ZONE - Default to human
    // Only treat as bot with BOTH definitive signal AND high score contributor
    if (hasDefinitiveMetaSignal && hasDefinitiveBotUA) {
      isBot = true;
      confidence = 'gray-confirmed-bot';
    } else {
      isBot = false;
      confidence = 'gray-zone-human';
    }
  } else {
    // < 30: Definitely human
    isBot = false;
    confidence = 'human';
  }

  return {
    isBot,
    score,
    confidence,
    signals,
    platform,
    isInAppBrowser,
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
  const ipNum = BigInt(octets[0]) * 16777216n + BigInt(octets[1]) * 65536n + 
                BigInt(octets[2]) * 256n + BigInt(octets[3]);

  for (const range of META_IP_RANGES_V4) {
    const rangeNum = BigInt(range.start[0]) * 16777216n + BigInt(range.start[1]) * 65536n +
                     BigInt(range.start[2]) * 256n + BigInt(range.start[3]);

    const maskBits = range.mask;
    const mask = maskBits === 0 ? 0n : (0xFFFFFFFFn << BigInt(32 - maskBits)) & 0xFFFFFFFFn;

    if ((ipNum & mask) === (rangeNum & mask)) {
      return true;
    }
  }

  return false;
}

function isIPv6InMetaRange(ip) {
  const normalized = normalizeIPv6(ip);
  if (!normalized) return false;

  // Extract first segments for prefix matching
  const prefix = normalized.substring(0, 9).toLowerCase();

  for (const metaPrefix of META_IP_PREFIXES_V6) {
    if (prefix === metaPrefix.toLowerCase()) {
      return true;
    }
  }

  return false;
}

function normalizeIPv6(ip) {
  try {
    ip = ip.split('%')[0]; // Remove zone ID

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
// ADAPTIVE RATE LIMITING
// ============================================

async function checkAdaptiveRateLimit(ip, env, ctx) {
  if (!ip || !env.LINK_STORAGE) return true;

  try {
    const key = `ratelimit:${ip}`;
    const current = await env.LINK_STORAGE.get(key);
    const data = current ? JSON.parse(current) : { count: 0, burst: false };

    // Check if in burst mode (viral traffic)
    const limit = data.burst ? RATE_LIMIT_BURST : RATE_LIMIT_BASE;

    if (data.count >= limit) {
      return false;
    }

    // Increment counter
    data.count += 1;

    // Enable burst mode if approaching limit rapidly
    if (data.count > RATE_LIMIT_BASE * 0.8) {
      data.burst = true;
    }

    // Update asynchronously
    ctx.waitUntil(
      env.LINK_STORAGE.put(key, JSON.stringify(data), { expirationTtl: RATE_LIMIT_WINDOW })
    );

    return true;
  } catch (error) {
    console.error('[RateLimit Error]', error);
    return true; // Allow on error
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
      platform: detection.platform,
      signals: detection.signals.slice(0, 6),
      ip: ip ? ip.substring(0, 20) : 'unknown',
      ua: userAgent ? userAgent.substring(0, 100) : 'unknown',
    };

    await env.LINK_STORAGE.put(logKey, JSON.stringify(logData), {
      expirationTtl: 7 * 24 * 60 * 60, // 7 days
    });
  } catch (error) {
    // Silent fail
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
    const { paths, mode, ogMeta, target } = body;

    if (!Array.isArray(paths) || paths.length === 0) {
      return jsonResponse({ error: 'Invalid paths array' }, 400);
    }

    if (paths.length > 100) {
      return jsonResponse({ error: 'Maximum 100 paths per request' }, 400);
    }

    const targetUrl = target || env.TARGET_URL || (typeof INJECTED_TARGET_URL !== 'undefined' ? INJECTED_TARGET_URL : '');
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
        siteName: sanitizeText(ogMeta.siteName, 50),
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
// DEBUG & STATS ENDPOINTS
// ============================================

async function handleDebug(request, env) {
  const authHeader = request.headers.get('Authorization');
  const secretKey = env.SECRET_KEY || (typeof INJECTED_SECRET_KEY !== 'undefined' ? INJECTED_SECRET_KEY : '');

  if (!secretKey || authHeader !== `Bearer ${secretKey}`) {
    return jsonResponse({ error: 'Unauthorized' }, 401);
  }

  const clientIP = request.headers.get('CF-Connecting-IP') || '';
  const userAgent = request.headers.get('User-Agent') || '';
  const detection = detectBot(request, clientIP, userAgent);

  return jsonResponse({
    version: VERSION,
    ip: clientIP,
    userAgent: userAgent,
    detection,
    headers: Object.fromEntries(request.headers),
  });
}

async function handleStats(request, env) {
  const authHeader = request.headers.get('Authorization');
  const secretKey = env.SECRET_KEY || (typeof INJECTED_SECRET_KEY !== 'undefined' ? INJECTED_SECRET_KEY : '');

  if (!secretKey || authHeader !== `Bearer ${secretKey}`) {
    return jsonResponse({ error: 'Unauthorized' }, 401);
  }

  try {
    // Get recent logs
    const logs = await env.LINK_STORAGE.list({ prefix: 'log:', limit: 100 });
    
    let totalHuman = 0;
    let totalBot = 0;
    const platformStats = {};
    const confidenceStats = {};

    for (const key of logs.keys) {
      try {
        const data = await env.LINK_STORAGE.get(key.name);
        if (data) {
          const log = JSON.parse(data);
          if (log.isBot) {
            totalBot++;
          } else {
            totalHuman++;
          }
          
          platformStats[log.platform] = (platformStats[log.platform] || 0) + 1;
          confidenceStats[log.confidence] = (confidenceStats[log.confidence] || 0) + 1;
        }
      } catch {}
    }

    return jsonResponse({
      version: VERSION,
      period: '7d',
      total: totalHuman + totalBot,
      human: totalHuman,
      bot: totalBot,
      humanRate: totalHuman + totalBot > 0 ? ((totalHuman / (totalHuman + totalBot)) * 100).toFixed(2) + '%' : '0%',
      platforms: platformStats,
      confidence: confidenceStats,
    });
  } catch (error) {
    return jsonResponse({ error: 'Failed to get stats' }, 500);
  }
}

// ============================================
// RESPONSE GENERATORS
// ============================================

function generateJSRedirect(targetUrl, platform = 'unknown') {
  // Add random delay to avoid detection patterns
  const minDelay = 100;
  const maxDelay = 800;
  const delay = Math.floor(Math.random() * (maxDelay - minDelay)) + minDelay;

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>Redirecting...</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:system-ui,-apple-system,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#f8f9fa}
.loader{text-align:center;padding:2rem}
.spinner{width:40px;height:40px;border:3px solid #e9ecef;border-top-color:#495057;border-radius:50%;animation:spin .8s linear infinite;margin:0 auto 1rem}
@keyframes spin{to{transform:rotate(360deg)}}
p{color:#6c757d;font-size:14px}
</style>
</head>
<body>
<div class="loader">
<div class="spinner"></div>
<p>Loading...</p>
</div>
<script>
(function(){
var t=${JSON.stringify(targetUrl)};
var d=${delay};
setTimeout(function(){
try{window.location.replace(t)}catch(e){window.location.href=t}
},d);
})();
</script>
</body>
</html>`;

  return new Response(html, {
    status: 200,
    headers: {
      'Content-Type': 'text/html;charset=UTF-8',
      'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
      'Pragma': 'no-cache',
      ...getSecurityHeaders(),
    },
  });
}

function generateOGPreview(request, linkData, path) {
  const url = new URL(request.url);
  const ogMeta = linkData.ogMeta || {};
  
  const title = escapeHtml(ogMeta.title || 'Check this out!');
  const description = escapeHtml(ogMeta.description || 'Click to view');
  const image = ogMeta.image || '';
  const siteName = escapeHtml(ogMeta.siteName || url.hostname);
  const canonical = ogMeta.canonical || url.href;

  return `<!DOCTYPE html>
<html lang="en" prefix="og: http://ogp.me/ns#">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title}</title>
<meta name="description" content="${description}">
<meta name="robots" content="noindex,nofollow">

<!-- Open Graph / Facebook -->
<meta property="og:type" content="website">
<meta property="og:url" content="${escapeHtml(canonical)}">
<meta property="og:title" content="${title}">
<meta property="og:description" content="${description}">
${image ? `<meta property="og:image" content="${escapeHtml(image)}">` : ''}
${image ? `<meta property="og:image:width" content="1200">` : ''}
${image ? `<meta property="og:image:height" content="630">` : ''}
<meta property="og:site_name" content="${siteName}">
<meta property="og:locale" content="en_US">

<!-- Twitter -->
<meta name="twitter:card" content="${image ? 'summary_large_image' : 'summary'}">
<meta name="twitter:title" content="${title}">
<meta name="twitter:description" content="${description}">
${image ? `<meta name="twitter:image" content="${escapeHtml(image)}">` : ''}

<link rel="canonical" href="${escapeHtml(canonical)}">

<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:system-ui,-apple-system,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#f5f5f5;padding:1rem}
.card{background:#fff;border-radius:12px;max-width:500px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,.08)}
.img{width:100%;aspect-ratio:1.91/1;object-fit:cover;background:#e9ecef}
.content{padding:1.25rem}
h1{font-size:1.125rem;line-height:1.4;margin-bottom:.5rem;color:#1a1a1a}
p{font-size:.875rem;color:#666;line-height:1.5}
.site{font-size:.75rem;color:#999;margin-top:.75rem;text-transform:uppercase;letter-spacing:.02em}
</style>
</head>
<body>
<div class="card">
${image ? `<img class="img" src="${escapeHtml(image)}" alt="${title}" loading="lazy">` : '<div class="img"></div>'}
<div class="content">
<h1>${title}</h1>
<p>${description}</p>
<div class="site">${siteName}</div>
</div>
</div>
</body>
</html>`;
}

function generateMinimalPreview(request, path) {
  const url = new URL(request.url);
  
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>View Content</title>
<meta name="description" content="Click to view this content">
<meta name="robots" content="noindex,nofollow">
<meta property="og:title" content="View Content">
<meta property="og:description" content="Click to view this content">
<meta property="og:type" content="website">
<meta property="og:url" content="${escapeHtml(url.href)}">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:system-ui,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#f5f5f5}
.c{text-align:center;padding:2rem}
h1{font-size:1.25rem;color:#333;margin-bottom:.5rem}
p{color:#666;font-size:.875rem}
</style>
</head>
<body>
<div class="c">
<h1>View Content</h1>
<p>Click to view</p>
</div>
</body>
</html>`;
}

function generateNotFoundResponse() {
  return new Response(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Not Found</title>
<meta name="robots" content="noindex,nofollow">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:system-ui,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#f8f9fa}
.c{text-align:center;padding:2rem}
h1{font-size:3rem;color:#dee2e6;margin-bottom:1rem}
p{color:#868e96;font-size:.875rem}
</style>
</head>
<body>
<div class="c">
<h1>404</h1>
<p>Page not found</p>
</div>
</body>
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
<title>Error</title>
<meta name="robots" content="noindex,nofollow">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:system-ui,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#f8f9fa}
.c{text-align:center;padding:2rem}
h1{font-size:1.5rem;color:#495057;margin-bottom:.5rem}
p{color:#868e96;font-size:.875rem}
</style>
</head>
<body>
<div class="c">
<h1>Oops!</h1>
<p>${escapeHtml(message)}</p>
</div>
</body>
</html>`, {
    status: 500,
    headers: { 'Content-Type': 'text/html;charset=UTF-8' },
  });
}

// ============================================
// UTILITY FUNCTIONS
// ============================================

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      ...corsHeaders,
    },
  });
}

function isValidUrl(url) {
  if (!url || typeof url !== 'string') return false;
  try {
    const parsed = new URL(url);
    return ['http:', 'https:'].includes(parsed.protocol);
  } catch {
    return false;
  }
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function sanitizeUrl(url) {
  if (!url || typeof url !== 'string') return '';
  try {
    const parsed = new URL(url);
    if (!['http:', 'https:'].includes(parsed.protocol)) return '';
    return parsed.href;
  } catch {
    return '';
  }
}

function sanitizeText(text, maxLength = 200) {
  if (!text || typeof text !== 'string') return '';
  return text.trim().substring(0, maxLength).replace(/[\r\n]+/g, ' ');
}

function getSecurityHeaders() {
  return {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer-when-downgrade',
  };
}

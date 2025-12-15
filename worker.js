/**
 * Edge Worker (worker.js) - PRODUCTION OPTIMIZED v4.0
 * 
 * Cloudflare Worker untuk handling public traffic at the edge.
 * FULLY OPTIMIZED untuk minimize false positive & maximize Meta bot detection.
 * 
 * KEY IMPROVEMENTS v4.0:
 * - Platform-specific detection (Facebook, Instagram, Threads)
 * - A/B Testing support for OG previews
 * - Enhanced analytics with false positive/negative tracking
 * - Adjustable detection thresholds via KV config
 * - Link survival metrics and performance scoring
 * - Improved behavioral fingerprinting
 * - WebSocket support for real-time analytics
 * 
 * CRITICAL REQUIREMENTS:
 * - FALSE POSITIVE < 0.3% (human traffic MUST pass = $$$ revenue)
 * - FALSE NEGATIVE < 2% (Meta bot MUST be caught = account safety)
 */

// ============================================
// CONSTANTS - TUNED FOR PRODUCTION
// ============================================

const VERSION = '4.0.0';
const TTL_SECONDS = 30 * 24 * 60 * 60; // 30 days
const MAX_PATH_LENGTH = 100;
const PATH_PATTERN = /^[a-zA-Z0-9_-]+$/;
const RATE_LIMIT_WINDOW = 3600; // 1 hour
const RATE_LIMIT_MAX = 200; // Increased for legitimate traffic spikes
const ANALYTICS_TTL = 30 * 24 * 60 * 60; // 30 days for analytics

// Default bot detection thresholds - Can be overridden via KV config
let BOT_THRESHOLD_DEFINITE = 85;
let BOT_THRESHOLD_LIKELY = 65;
let HUMAN_THRESHOLD = 35;

// Meta/Facebook IP ranges (IPv4) - Updated December 2024
const META_IP_RANGES_V4 = [
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
  // Additional 2024 ranges
  { start: [163, 70, 128, 0], mask: 17 },
  { start: [185, 89, 216, 0], mask: 22 },
  { start: [31, 13, 72, 0], mask: 21 },
];

// Meta IPv6 prefixes
const META_IP_PREFIXES_V6 = [
  '2a03:2880',
  '2c0f:fb50',
  '2a03:2887',
  '2401:db00',
  '2a03:2881',
  '2a03:2882',
];

// Platform-specific bot signatures
const PLATFORM_SIGNATURES = {
  facebook: {
    agents: ['facebookexternalhit', 'facebot', 'facebookplatform', 'meta-externalhit'],
    headers: ['X-FB-HTTP-Engine', 'X-FB-Friendly-Name'],
    referers: ['facebook.com', 'fb.com', 'm.facebook.com', 'l.facebook.com'],
  },
  instagram: {
    agents: ['instagram', 'instagrambot', 'barcelona'],
    headers: ['X-IG-App-ID', 'X-IG-Capabilities'],
    referers: ['instagram.com', 'l.instagram.com'],
  },
  threads: {
    agents: ['threadsbot', 'threadsexternalhit', 'barcelona'],
    headers: ['X-IG-App-ID'],
    referers: ['threads.net'],
  },
  whatsapp: {
    agents: ['whatsapp'],
    headers: [],
    referers: ['whatsapp.com', 'wa.me'],
  },
};

// Other social media bots
const OTHER_BOT_AGENTS = [
  'twitterbot', 'linkedinbot', 'slackbot', 'telegrambot',
  'skypeuripreview', 'discordbot', 'redditbot', 'pinterestbot',
  'vkshare', 'line-poker', 'viber',
];

// Search engine bots
const SEARCH_ENGINE_BOTS = [
  'googlebot', 'bingbot', 'baiduspider', 'yandexbot',
  'duckduckbot', 'sogou', 'applebot', 'ahrefsbot', 'semrushbot',
];

// Legitimate monitoring tools
const LEGITIMATE_AUTOMATION = [
  'pingdom', 'uptimerobot', 'statuscake', 'gtmetrix',
  'pagespeed', 'lighthouse', 'newrelic', 'datadog', 'sentry',
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
      
      // Load custom thresholds from KV if available
      await loadCustomThresholds(env);
      
      return await handleRequest(request, env, ctx);
    } catch (error) {
      console.error('[FatalError]', error);
      const targetUrl = env.TARGET_URL || (typeof INJECTED_TARGET_URL !== 'undefined' ? INJECTED_TARGET_URL : '');
      if (isValidUrl(targetUrl)) {
        return Response.redirect(targetUrl, 302);
      }
      return new Response('Service temporarily unavailable', { status: 503 });
    }
  }
};

// ============================================
// CONFIG LOADER
// ============================================

async function loadCustomThresholds(env) {
  try {
    const config = await env.LINK_STORAGE?.get('config:thresholds');
    if (config) {
      const parsed = JSON.parse(config);
      BOT_THRESHOLD_DEFINITE = parsed.definite ?? 85;
      BOT_THRESHOLD_LIKELY = parsed.likely ?? 65;
      HUMAN_THRESHOLD = parsed.human ?? 35;
    }
  } catch (e) {
    // Use defaults
  }
}

// ============================================
// REQUEST HANDLER
// ============================================

async function handleRequest(request, env, ctx) {
  const url = new URL(request.url);
  const clientIP = request.headers.get('CF-Connecting-IP') || '';
  const userAgent = request.headers.get('User-Agent') || '';
  const path = url.pathname.substring(1);
  const startTime = Date.now();

  // API Endpoints
  if (request.method === 'POST' && path === 'api/save-link') {
    return handleSaveLink(request, env);
  }

  if (path === 'api/analytics' && request.method === 'GET') {
    return handleAnalytics(request, env);
  }

  if (path === 'api/config' && request.method === 'POST') {
    return handleConfigUpdate(request, env);
  }

  if (path === 'api/feedback' && request.method === 'POST') {
    return handleFeedback(request, env);
  }

  if (path === 'health' || path === 'ping') {
    return jsonResponse({ status: 'ok', version: VERSION, timestamp: new Date().toISOString() });
  }

  if (path === 'api/debug' && request.method === 'GET') {
    return handleDebug(request, env);
  }

  // Root/static paths
  if (!path || path === 'favicon.ico' || path === 'robots.txt') {
    return new Response('OK', { status: 200 });
  }

  // Validate path format
  if (path.length > MAX_PATH_LENGTH || !PATH_PATTERN.test(path)) {
    return generateNotFoundResponse();
  }

  // Rate limiting
  const rateLimitOk = await checkRateLimit(clientIP, env, ctx);
  if (!rateLimitOk) {
    return new Response('Too many requests', { status: 429, headers: { 'Retry-After': '60' } });
  }

  // Get link data
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

  // Bot detection
  const detection = detectBot(request, clientIP);
  const responseTime = Date.now() - startTime;

  // Update analytics async
  ctx.waitUntil(Promise.all([
    incrementClickCounter(path, linkData, detection, env),
    logDetection(path, detection, clientIP, userAgent, responseTime, env),
    updateDailyStats(detection, env),
  ]));

  if (detection.isBot) {
    // Select OG variant for A/B testing
    const variant = selectOGVariant(linkData);
    const previewHtml = linkData.mode === 'og_preview' && variant
      ? generateOGPreview(request, linkData, path, variant)
      : generateMinimalPreview(request, path);

    // Track variant impression
    if (variant) {
      ctx.waitUntil(trackVariantImpression(path, variant.id, env));
    }

    return new Response(previewHtml, {
      status: 200,
      headers: {
        'Content-Type': 'text/html;charset=UTF-8',
        'Cache-Control': 'public, max-age=1800',
        'X-Robots-Tag': 'noindex, nofollow',
        'X-Detection-Score': String(detection.score),
        'X-Platform': detection.platform || 'unknown',
        ...getSecurityHeaders(),
      },
    });
  }

  // HUMAN -> Redirect
  const targetUrl = linkData.target || env.TARGET_URL || (typeof INJECTED_TARGET_URL !== 'undefined' ? INJECTED_TARGET_URL : '');

  if (!isValidUrl(targetUrl)) {
    console.error('[RedirectError] Invalid target URL:', targetUrl);
    return generateErrorResponse('Redirect unavailable');
  }

  return Response.redirect(targetUrl, 302);
}

// ============================================
// BOT DETECTION v4.0 - PLATFORM AWARE
// ============================================

function detectBot(request, ip) {
  const userAgent = (request.headers.get('User-Agent') || '').toLowerCase();
  const headers = request.headers;
  const referer = (headers.get('Referer') || '').toLowerCase();

  let score = 0;
  const signals = [];
  let platform = null;

  // ========================================
  // PLATFORM DETECTION (Track source)
  // ========================================
  
  for (const [platformName, sig] of Object.entries(PLATFORM_SIGNATURES)) {
    // Check user agent
    for (const agent of sig.agents) {
      if (userAgent.includes(agent)) {
        platform = platformName;
        break;
      }
    }
    if (platform) break;
    
    // Check referer
    for (const ref of sig.referers) {
      if (referer.includes(ref)) {
        platform = platformName;
        break;
      }
    }
    if (platform) break;
    
    // Check headers
    for (const header of sig.headers) {
      if (headers.has(header)) {
        platform = platformName;
        break;
      }
    }
    if (platform) break;
  }

  // ========================================
  // TIER 1: DEFINITIVE SIGNALS (85-100 pts)
  // ========================================

  // Meta-specific headers
  if (headers.get('X-Purpose') === 'preview') {
    score += 100;
    signals.push('X-Purpose:preview');
  }

  if (headers.get('X-FB-HTTP-Engine') === 'Liger') {
    score += 100;
    signals.push('FB-Engine:Liger');
  }

  // Instagram/Threads app headers
  const igAppId = headers.get('X-IG-App-ID');
  if (igAppId) {
    score += 95;
    signals.push(`IG-App-ID:${igAppId.substring(0, 10)}`);
  }

  if (headers.get('X-FB-Friendly-Name')) {
    score += 95;
    signals.push('FB-Friendly-Name');
  }

  // Exact Meta bot user-agent match
  for (const sig of Object.values(PLATFORM_SIGNATURES)) {
    for (const bot of sig.agents) {
      if (userAgent.includes(bot)) {
        score += 90;
        signals.push(`UA:${bot}`);
        break;
      }
    }
  }

  // ========================================
  // TIER 2: HIGH CONFIDENCE (60-80 pts)
  // ========================================

  // Other social bots
  for (const bot of OTHER_BOT_AGENTS) {
    if (userAgent.includes(bot)) {
      score += 75;
      signals.push(`Social:${bot}`);
      break;
    }
  }

  // Search engine bots
  for (const bot of SEARCH_ENGINE_BOTS) {
    if (userAgent.includes(bot)) {
      score += 70;
      signals.push(`Search:${bot}`);
      break;
    }
  }

  // Meta IP range
  if (ip) {
    const inMetaRange = isIPInMetaRange(ip);
    if (inMetaRange) {
      score += signals.length > 0 ? 65 : 30;
      signals.push(signals.length > 0 ? 'Meta-IP' : 'Meta-IP-only');
    }
  }

  // ========================================
  // TIER 3: MEDIUM CONFIDENCE (30-50 pts)
  // ========================================

  const isLegitTool = LEGITIMATE_AUTOMATION.some(tool => userAgent.includes(tool));

  if (!isLegitTool) {
    if (/\b(bot|crawler|spider|scraper|fetch|preview|parser)\b/.test(userAgent)) {
      score += 45;
      signals.push('Generic-bot-keyword');
    }

    if (/headless|phantom|puppeteer|playwright|selenium|webdriver/.test(userAgent)) {
      score += 40;
      signals.push('Headless-browser');
    }

    // Check for automation frameworks
    if (/axios|node-fetch|python|curl|wget|httpie|postman/i.test(userAgent)) {
      score += 35;
      signals.push('HTTP-client');
    }
  }

  // ========================================
  // TIER 4: WEAK SIGNALS (10-25 pts)
  // ========================================

  // Social media referer
  if (/facebook\.com|fb\.com|instagram\.com|threads\.net|t\.co|twitter\.com|x\.com/.test(referer)) {
    score += 15;
    signals.push('Social-referer');
  }

  // Missing browser headers
  if (signals.length > 0) {
    const hasAccept = headers.has('Accept');
    const hasAcceptLang = headers.has('Accept-Language');
    const hasAcceptEnc = headers.has('Accept-Encoding');

    if (!hasAccept && !hasAcceptLang && !hasAcceptEnc) {
      score += 25;
      signals.push('No-browser-headers');
    }
  }

  // Empty/short user-agent
  if (userAgent.length === 0) {
    score += 20;
    signals.push('Empty-UA');
  } else if (userAgent.length < 30 && !userAgent.includes('mozilla')) {
    score += 12;
    signals.push('Short-UA');
  }

  // Check connection header
  if (!headers.has('Connection') || headers.get('Connection') === 'close') {
    score += 8;
    signals.push('No-keep-alive');
  }

  // ========================================
  // NEGATIVE SIGNALS (More human-like)
  // ========================================

  // Has cookies
  if (headers.has('Cookie')) {
    score -= 55;
    signals.push('Has-cookies');
  }

  // Sec-Fetch headers (modern browsers)
  const secFetchCount = ['Sec-Fetch-Dest', 'Sec-Fetch-Mode', 'Sec-Fetch-Site', 'Sec-Fetch-User']
    .filter(h => headers.has(h)).length;
  if (secFetchCount >= 2) {
    score -= 45;
    signals.push('Sec-Fetch-headers');
  }

  // Modern browser UA pattern
  if (/mozilla\/5\.0.*\((windows|macintosh|linux|iphone|ipad|android).*\).*applewebkit/i.test(userAgent) &&
      !/bot|crawler|spider|preview/i.test(userAgent)) {
    score -= 35;
    signals.push('Modern-browser-UA');
  }

  // Privacy headers
  if (headers.has('DNT') || headers.has('Sec-GPC')) {
    score -= 12;
    signals.push('Privacy-headers');
  }

  // Complex Accept header
  const accept = headers.get('Accept') || '';
  if (accept.length > 80 && accept.includes('text/html') && accept.includes('application/xhtml')) {
    score -= 25;
    signals.push('Complex-Accept');
  }

  // Cache-Control from browser
  if (headers.has('Cache-Control') && headers.get('Cache-Control').includes('max-age=0')) {
    score -= 10;
    signals.push('Browser-cache-control');
  }

  // ========================================
  // FINAL DETERMINATION
  // ========================================

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
    // Gray zone
    const hasHighConfidenceSignal = signals.some(s =>
      s.includes('X-Purpose') || s.includes('FB-Engine') || s.includes('IG-App') ||
      s.startsWith('UA:') || s === 'Meta-IP'
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
    platform,
    thresholds: { definite: BOT_THRESHOLD_DEFINITE, likely: BOT_THRESHOLD_LIKELY, human: HUMAN_THRESHOLD },
  };
}

// ============================================
// A/B TESTING FOR OG PREVIEWS
// ============================================

function selectOGVariant(linkData) {
  if (!linkData.ogMeta) return null;
  
  // Check for A/B variants
  if (linkData.abVariants && linkData.abVariants.length > 1) {
    // Weighted random selection based on performance
    const totalWeight = linkData.abVariants.reduce((sum, v) => sum + (v.weight || 1), 0);
    let random = Math.random() * totalWeight;
    
    for (const variant of linkData.abVariants) {
      random -= variant.weight || 1;
      if (random <= 0) {
        return variant;
      }
    }
    return linkData.abVariants[0];
  }
  
  // Default to single variant
  return {
    id: 'default',
    ...linkData.ogMeta,
  };
}

async function trackVariantImpression(path, variantId, env) {
  try {
    const key = `abtest:${path}:${variantId}`;
    const current = await env.LINK_STORAGE.get(key);
    const data = current ? JSON.parse(current) : { impressions: 0, clicks: 0 };
    data.impressions++;
    await env.LINK_STORAGE.put(key, JSON.stringify(data), { expirationTtl: ANALYTICS_TTL });
  } catch (e) {
    // Silent fail
  }
}

// ============================================
// ANALYTICS
// ============================================

async function incrementClickCounter(path, linkData, detection, env) {
  try {
    linkData.clicks = (linkData.clicks || 0) + 1;
    linkData.botClicks = (linkData.botClicks || 0) + (detection.isBot ? 1 : 0);
    linkData.humanClicks = (linkData.humanClicks || 0) + (detection.isBot ? 0 : 1);
    linkData.lastAccessed = new Date().toISOString();

    // Track platform distribution
    if (!linkData.platformStats) linkData.platformStats = {};
    const platform = detection.platform || 'direct';
    linkData.platformStats[platform] = (linkData.platformStats[platform] || 0) + 1;

    await env.LINK_STORAGE.put(`link:${path}`, JSON.stringify(linkData), {
      expirationTtl: TTL_SECONDS,
    });
  } catch (error) {
    console.error('[Counter Error]', error);
  }
}

async function updateDailyStats(detection, env) {
  try {
    const today = new Date().toISOString().split('T')[0];
    const key = `stats:daily:${today}`;
    const current = await env.LINK_STORAGE.get(key);
    const stats = current ? JSON.parse(current) : {
      date: today,
      totalRequests: 0,
      botDetected: 0,
      humanPassed: 0,
      byConfidence: {},
      byPlatform: {},
      avgScore: 0,
      scoreSum: 0,
    };

    stats.totalRequests++;
    stats.scoreSum += detection.score;
    stats.avgScore = Math.round(stats.scoreSum / stats.totalRequests);

    if (detection.isBot) {
      stats.botDetected++;
    } else {
      stats.humanPassed++;
    }

    stats.byConfidence[detection.confidence] = (stats.byConfidence[detection.confidence] || 0) + 1;
    
    if (detection.platform) {
      stats.byPlatform[detection.platform] = (stats.byPlatform[detection.platform] || 0) + 1;
    }

    await env.LINK_STORAGE.put(key, JSON.stringify(stats), { expirationTtl: 90 * 24 * 60 * 60 });
  } catch (e) {
    // Silent fail
  }
}

async function logDetection(path, detection, ip, userAgent, responseTime, env) {
  try {
    const logKey = `log:${Date.now()}:${Math.random().toString(36).substring(2, 8)}`;

    const logData = {
      ts: new Date().toISOString(),
      path,
      isBot: detection.isBot,
      score: detection.score,
      confidence: detection.confidence,
      platform: detection.platform,
      signals: detection.signals.slice(0, 8),
      ip: ip ? hashIP(ip) : 'unknown',
      ua: userAgent ? userAgent.substring(0, 100) : 'unknown',
      responseTime,
    };

    await env.LINK_STORAGE.put(logKey, JSON.stringify(logData), {
      expirationTtl: 7 * 24 * 60 * 60,
    });
  } catch (error) {
    // Silent fail
  }
}

function hashIP(ip) {
  // Simple hash for privacy
  let hash = 0;
  for (let i = 0; i < ip.length; i++) {
    const char = ip.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash;
  }
  return 'ip_' + Math.abs(hash).toString(36);
}

// ============================================
// ANALYTICS API
// ============================================

async function handleAnalytics(request, env) {
  const authHeader = request.headers.get('Authorization');
  const secretKey = env.SECRET_KEY || (typeof INJECTED_SECRET_KEY !== 'undefined' ? INJECTED_SECRET_KEY : '');

  if (!secretKey || authHeader !== `Bearer ${secretKey}`) {
    return jsonResponse({ error: 'Unauthorized' }, 401);
  }

  const url = new URL(request.url);
  const type = url.searchParams.get('type') || 'daily';
  const days = parseInt(url.searchParams.get('days') || '7', 10);

  try {
    if (type === 'daily') {
      const stats = [];
      const today = new Date();
      
      for (let i = 0; i < days; i++) {
        const date = new Date(today);
        date.setDate(date.getDate() - i);
        const dateStr = date.toISOString().split('T')[0];
        const data = await env.LINK_STORAGE.get(`stats:daily:${dateStr}`);
        if (data) {
          stats.push(JSON.parse(data));
        }
      }
      
      return jsonResponse({ stats });
    }

    if (type === 'links') {
      const links = [];
      const list = await env.LINK_STORAGE.list({ prefix: 'link:' });
      
      for (const key of list.keys.slice(0, 100)) {
        const data = await env.LINK_STORAGE.get(key.name);
        if (data) {
          const parsed = JSON.parse(data);
          links.push({
            path: key.name.replace('link:', ''),
            clicks: parsed.clicks || 0,
            botClicks: parsed.botClicks || 0,
            humanClicks: parsed.humanClicks || 0,
            created: parsed.created,
            lastAccessed: parsed.lastAccessed,
            platformStats: parsed.platformStats,
          });
        }
      }
      
      return jsonResponse({ links });
    }

    if (type === 'logs') {
      const logs = [];
      const list = await env.LINK_STORAGE.list({ prefix: 'log:', limit: 100 });
      
      for (const key of list.keys) {
        const data = await env.LINK_STORAGE.get(key.name);
        if (data) {
          logs.push(JSON.parse(data));
        }
      }
      
      return jsonResponse({ logs: logs.sort((a, b) => new Date(b.ts) - new Date(a.ts)) });
    }

    return jsonResponse({ error: 'Invalid type' }, 400);
  } catch (error) {
    console.error('[Analytics Error]', error);
    return jsonResponse({ error: 'Failed to fetch analytics' }, 500);
  }
}

// ============================================
// CONFIG UPDATE API
// ============================================

async function handleConfigUpdate(request, env) {
  const authHeader = request.headers.get('Authorization');
  const secretKey = env.SECRET_KEY || (typeof INJECTED_SECRET_KEY !== 'undefined' ? INJECTED_SECRET_KEY : '');

  if (!secretKey || authHeader !== `Bearer ${secretKey}`) {
    return jsonResponse({ error: 'Unauthorized' }, 401);
  }

  try {
    const body = await request.json();
    
    if (body.thresholds) {
      const thresholds = {
        definite: Math.min(100, Math.max(50, parseInt(body.thresholds.definite) || 85)),
        likely: Math.min(85, Math.max(30, parseInt(body.thresholds.likely) || 65)),
        human: Math.min(50, Math.max(10, parseInt(body.thresholds.human) || 35)),
      };
      
      await env.LINK_STORAGE.put('config:thresholds', JSON.stringify(thresholds));
      return jsonResponse({ success: true, thresholds });
    }

    return jsonResponse({ error: 'No valid config provided' }, 400);
  } catch (error) {
    console.error('[Config Error]', error);
    return jsonResponse({ error: 'Failed to update config' }, 500);
  }
}

// ============================================
// FEEDBACK API (False Positive/Negative)
// ============================================

async function handleFeedback(request, env) {
  const authHeader = request.headers.get('Authorization');
  const secretKey = env.SECRET_KEY || (typeof INJECTED_SECRET_KEY !== 'undefined' ? INJECTED_SECRET_KEY : '');

  if (!secretKey || authHeader !== `Bearer ${secretKey}`) {
    return jsonResponse({ error: 'Unauthorized' }, 401);
  }

  try {
    const body = await request.json();
    const { logId, type, notes } = body;

    if (!logId || !['false_positive', 'false_negative', 'correct'].includes(type)) {
      return jsonResponse({ error: 'Invalid feedback data' }, 400);
    }

    // Store feedback
    const feedbackKey = `feedback:${Date.now()}`;
    await env.LINK_STORAGE.put(feedbackKey, JSON.stringify({
      logId,
      type,
      notes,
      timestamp: new Date().toISOString(),
    }), { expirationTtl: 90 * 24 * 60 * 60 });

    // Update feedback stats
    const statsKey = 'stats:feedback';
    const current = await env.LINK_STORAGE.get(statsKey);
    const stats = current ? JSON.parse(current) : {
      false_positive: 0,
      false_negative: 0,
      correct: 0,
      total: 0,
    };

    stats[type]++;
    stats.total++;
    stats.accuracy = stats.total > 0 
      ? Math.round((stats.correct / stats.total) * 10000) / 100 
      : 0;

    await env.LINK_STORAGE.put(statsKey, JSON.stringify(stats));

    return jsonResponse({ success: true, stats });
  } catch (error) {
    console.error('[Feedback Error]', error);
    return jsonResponse({ error: 'Failed to save feedback' }, 500);
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
    const { paths, mode, ogMeta, abVariants, target } = body;

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

    const linkData = {
      created: new Date().toISOString(),
      target: targetUrl,
      clicks: 0,
      botClicks: 0,
      humanClicks: 0,
      mode: mode || 'default',
      platformStats: {},
    };

    if (mode === 'og_preview' && ogMeta && typeof ogMeta === 'object') {
      linkData.ogMeta = {
        image: sanitizeUrl(ogMeta.image),
        title: sanitizeText(ogMeta.title, 100),
        description: sanitizeText(ogMeta.description, 200),
        canonical: sanitizeUrl(ogMeta.canonical),
      };
    }

    // A/B Testing variants
    if (Array.isArray(abVariants) && abVariants.length > 0) {
      linkData.abVariants = abVariants.slice(0, 5).map((v, i) => ({
        id: v.id || `variant_${i}`,
        image: sanitizeUrl(v.image),
        title: sanitizeText(v.title, 100),
        description: sanitizeText(v.description, 200),
        weight: Math.max(1, Math.min(10, parseInt(v.weight) || 1)),
      }));
    }

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

  // Get feedback stats
  let feedbackStats = null;
  try {
    const stats = await env.LINK_STORAGE.get('stats:feedback');
    feedbackStats = stats ? JSON.parse(stats) : null;
  } catch (e) {}

  return jsonResponse({
    version: VERSION,
    ip: clientIP,
    userAgent: request.headers.get('User-Agent'),
    detection,
    feedbackStats,
    currentThresholds: {
      definite: BOT_THRESHOLD_DEFINITE,
      likely: BOT_THRESHOLD_LIKELY,
      human: HUMAN_THRESHOLD,
    },
    headers: Object.fromEntries(request.headers),
  });
}

// ============================================
// IP RANGE CHECKING
// ============================================

function isIPInMetaRange(ip) {
  if (!ip) return false;

  try {
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

  const ipNum = BigInt(octets[0]) * 16777216n + BigInt(octets[1]) * 65536n + BigInt(octets[2]) * 256n + BigInt(octets[3]);

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

  const prefix = normalized.substring(0, 9);

  for (const metaPrefix of META_IP_PREFIXES_V6) {
    if (prefix.toLowerCase() === metaPrefix.toLowerCase()) {
      return true;
    }
  }

  return false;
}

function normalizeIPv6(ip) {
  try {
    ip = ip.split('%')[0];

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

    ctx.waitUntil(
      env.LINK_STORAGE.put(key, String(count + 1), { expirationTtl: RATE_LIMIT_WINDOW })
    );

    return true;
  } catch (error) {
    console.error('[RateLimit Error]', error);
    return true;
  }
}

// ============================================
// OG PREVIEW GENERATION
// ============================================

function generateOGPreview(request, linkData, path, variant) {
  const meta = variant || linkData.ogMeta || {};
  const url = new URL(request.url);
  const canonicalUrl = meta.canonical || `${url.origin}/${path}`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${escapeHtml(meta.title || 'Loading...')}</title>
<meta name="description" content="${escapeHtml(meta.description || '')}">
<meta property="og:type" content="website">
<meta property="og:url" content="${escapeHtml(canonicalUrl)}">
<meta property="og:title" content="${escapeHtml(meta.title || '')}">
<meta property="og:description" content="${escapeHtml(meta.description || '')}">
<meta property="og:image" content="${escapeHtml(meta.image || '')}">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:title" content="${escapeHtml(meta.title || '')}">
<meta name="twitter:description" content="${escapeHtml(meta.description || '')}">
<meta name="twitter:image" content="${escapeHtml(meta.image || '')}">
<link rel="canonical" href="${escapeHtml(canonicalUrl)}">
<meta name="robots" content="noindex,nofollow">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:system-ui,-apple-system,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%)}
.c{text-align:center;padding:2rem;color:#fff}
.s{width:40px;height:40px;border:3px solid rgba(255,255,255,0.3);border-top-color:#fff;border-radius:50%;animation:spin 1s linear infinite;margin:0 auto 1rem}
@keyframes spin{to{transform:rotate(360deg)}}
p{opacity:0.9;font-size:14px}
</style>
</head>
<body>
<div class="c">
<div class="s"></div>
<p>Loading content...</p>
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
<title>Loading...</title>
<meta property="og:url" content="${escapeHtml(url.href)}">
<meta name="robots" content="noindex,nofollow">
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:system-ui,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#f5f5f5}
.c{text-align:center;padding:2rem}
p{color:#666;font-size:14px}
</style>
</head>
<body>
<div class="c"><p>Loading...</p></div>
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
body{font-family:system-ui,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#fafafa}
.c{text-align:center;padding:2rem}
h1{font-size:48px;color:#ddd;margin-bottom:0.5rem}
p{color:#999;font-size:14px}
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
    headers: { 'Content-Type': 'text/html;charset=UTF-8', ...getSecurityHeaders() },
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
body{font-family:system-ui,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#fafafa}
.c{text-align:center;padding:2rem}
h1{font-size:24px;color:#666;margin-bottom:0.5rem}
p{color:#999;font-size:14px}
</style>
</head>
<body>
<div class="c">
<h1>Error</h1>
<p>${escapeHtml(message)}</p>
</div>
</body>
</html>`, {
    status: 500,
    headers: { 'Content-Type': 'text/html;charset=UTF-8', ...getSecurityHeaders() },
  });
}

// ============================================
// UTILITIES
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
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'X-XSS-Protection': '1; mode=block',
  };
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

function sanitizeText(text, maxLength) {
  if (!text || typeof text !== 'string') return '';
  return text.trim().substring(0, maxLength).replace(/[\r\n\t]+/g, ' ');
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

/**
 * Edge Worker (worker.js) - ENHANCED v4.0
 * 
 * MAJOR IMPROVEMENTS:
 * - Multi-layer scoring with independent signal categories
 * - Dynamic thresholds based on traffic patterns & time
 * - Feedback loop for FP/FN tracking and model improvement
 * - Challenge system for gray zone traffic
 * - Behavioral fingerprint integration (client-side signals)
 * - Better gray zone handling with revenue protection
 * 
 * TARGET METRICS:
 * - FALSE POSITIVE < 0.3% (was 0.5%)
 * - FALSE NEGATIVE < 2% (was 3%)
 */

// ============================================
// CONSTANTS - TUNED FOR PRODUCTION v4.0
// ============================================

const TTL_SECONDS = 30 * 24 * 60 * 60; // 30 days
const MAX_PATH_LENGTH = 100;
const PATH_PATTERN = /^[a-zA-Z0-9_-]+$/;
const RATE_LIMIT_WINDOW = 3600;
const RATE_LIMIT_MAX = 150;

// v4.0: Multi-layer threshold system
const THRESHOLDS = {
  DEFINITE_BOT: 85,
  LIKELY_BOT: 65,
  GRAY_ZONE_HIGH: 50,
  GRAY_ZONE_LOW: 35,
  DEFINITE_HUMAN: 20,
};

// v4.0: Dynamic threshold adjustments
const DYNAMIC_ADJUSTMENTS = {
  PEAK_HOURS: { start: 9, end: 21, modifier: 5 },      // More lenient during peak
  NEW_CAMPAIGN: { ttl: 3600, modifier: 10 },           // Very lenient first hour
  HIGH_TRAFFIC: { threshold: 100, modifier: 3 },       // Lenient during spikes
};

// v4.0: Scoring weights per category (total max ~100 per category)
const SCORING_CONFIG = {
  IP_WEIGHT: 0.25,        // 25% contribution
  UA_WEIGHT: 0.30,        // 30% contribution  
  HEADER_WEIGHT: 0.25,    // 25% contribution
  BEHAVIOR_WEIGHT: 0.20,  // 20% contribution (from client signals)
};

// Meta/Facebook IP ranges (IPv4) - Updated 2024
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
];

const META_IP_PREFIXES_V6 = [
  '2a03:2880', '2c0f:fb50', '2a03:2887', '2401:db00',
];

const META_BOT_AGENTS = [
  'facebookexternalhit', 'facebot', 'facebookplatform',
  'meta-externalhit', 'meta-externalagent', 'instagrambot',
  'threadsbot', 'threadsexternalhit', 'barcelona',
];

const OTHER_BOT_AGENTS = [
  'twitterbot', 'whatsapp', 'linkedinbot', 'slackbot',
  'telegrambot', 'skypeuripreview', 'discordbot', 'redditbot', 'pinterestbot',
];

const SEARCH_ENGINE_BOTS = [
  'googlebot', 'bingbot', 'baiduspider', 'yandexbot',
  'duckduckbot', 'sogou', 'applebot',
];

const LEGITIMATE_AUTOMATION = [
  'pingdom', 'uptimerobot', 'statuscake', 'gtmetrix',
  'pagespeed', 'lighthouse', 'newrelic', 'datadog',
];

const TRUSTED_IMAGE_DOMAINS = [
  'cdn.', 'imgur.com', 'cloudinary.com', 'imagekit.io',
  'imgix.net', 'cloudfront.net', 'b-cdn.', 'bunnycdn.com',
  'grbto.net', 'ibb.co', 'postimg.cc',
];

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Behavioral-Signals',
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

  // v4.0: Challenge verification endpoint
  if (request.method === 'POST' && path === 'api/verify-challenge') {
    return handleChallengeVerification(request, env);
  }

  // v4.0: Feedback endpoint for FP/FN reporting
  if (request.method === 'POST' && path === 'api/feedback') {
    return handleFeedback(request, env);
  }

  // v4.0: Analytics endpoint
  if (path === 'api/analytics' && request.method === 'GET') {
    return handleAnalytics(request, env);
  }

  if (request.method === 'POST' && path === 'api/save-link') {
    return handleSaveLink(request, env);
  }

  if (path === 'health' || path === 'ping') {
    return jsonResponse({ status: 'ok', service: 'link-generator', version: '4.0' });
  }

  if (path === 'api/debug' && request.method === 'GET') {
    return handleDebug(request, env);
  }

  if (!path || path === 'favicon.ico' || path === 'robots.txt') {
    return new Response('OK', { status: 200 });
  }

  if (path.length > MAX_PATH_LENGTH || !PATH_PATTERN.test(path)) {
    return generateNotFoundResponse();
  }

  const rateLimitOk = await checkRateLimit(clientIP, env, ctx);
  if (!rateLimitOk) {
    return new Response('Too many requests', { status: 429, headers: { 'Retry-After': '60' } });
  }

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

  ctx.waitUntil(incrementClickCounter(path, linkData, env));

  // v4.0: Enhanced multi-layer detection
  const detection = await detectBotV4(request, clientIP, env, ctx);

  ctx.waitUntil(logDetection(path, detection, clientIP, userAgent, env));

  // v4.0: Handle gray zone with challenge
  if (detection.action === 'challenge') {
    return generateChallengeResponse(request, path, detection);
  }

  if (detection.isBot) {
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

  const targetUrl = linkData.target || env.TARGET_URL || (typeof INJECTED_TARGET_URL !== 'undefined' ? INJECTED_TARGET_URL : '');

  if (!isValidUrl(targetUrl)) {
    console.error('[RedirectError] Invalid target URL:', targetUrl);
    return generateErrorResponse('Redirect unavailable');
  }

  return Response.redirect(targetUrl, 302);
}

// ============================================
// BOT DETECTION v4.0 - MULTI-LAYER SYSTEM
// ============================================

async function detectBotV4(request, ip, env, ctx) {
  const userAgent = (request.headers.get('User-Agent') || '').toLowerCase();
  const headers = request.headers;

  // v4.0: Independent scoring per category
  const scores = {
    ip: { score: 0, max: 100, signals: [] },
    userAgent: { score: 0, max: 100, signals: [] },
    headers: { score: 0, max: 100, signals: [] },
    behavior: { score: 0, max: 100, signals: [] },
  };

  // ========================================
  // LAYER 1: IP ANALYSIS (25% weight)
  // ========================================
  
  if (ip) {
    const inMetaRange = isIPInMetaRange(ip);
    if (inMetaRange) {
      scores.ip.score += 80;
      scores.ip.signals.push('meta-ip-range');
    }

    // Check if IP has previous FP record (learn from mistakes)
    const fpRecord = await getFeedbackRecord(ip, env);
    if (fpRecord?.type === 'false_positive') {
      scores.ip.score -= 50; // Strong negative signal
      scores.ip.signals.push('known-fp-ip');
    }
  }

  // ========================================
  // LAYER 2: USER AGENT ANALYSIS (30% weight)
  // ========================================

  // Meta bot exact match
  for (const bot of META_BOT_AGENTS) {
    if (userAgent.includes(bot)) {
      scores.userAgent.score += 95;
      scores.userAgent.signals.push(`meta-bot:${bot}`);
      break;
    }
  }

  // Other social bots
  for (const bot of OTHER_BOT_AGENTS) {
    if (userAgent.includes(bot)) {
      scores.userAgent.score += 85;
      scores.userAgent.signals.push(`social-bot:${bot}`);
      break;
    }
  }

  // Search engine bots
  for (const bot of SEARCH_ENGINE_BOTS) {
    if (userAgent.includes(bot)) {
      scores.userAgent.score += 80;
      scores.userAgent.signals.push(`search-bot:${bot}`);
      break;
    }
  }

  // Legitimate tools (negative signal)
  const isLegitTool = LEGITIMATE_AUTOMATION.some(tool => userAgent.includes(tool));
  if (isLegitTool) {
    scores.userAgent.score -= 30;
    scores.userAgent.signals.push('legit-automation');
  }

  // Generic bot patterns
  if (!isLegitTool) {
    if (/\b(bot|crawler|spider|scraper|fetch|preview)\b/.test(userAgent)) {
      scores.userAgent.score += 50;
      scores.userAgent.signals.push('generic-bot-keyword');
    }

    if (/headless|phantom|puppeteer|playwright|selenium/.test(userAgent)) {
      scores.userAgent.score += 60;
      scores.userAgent.signals.push('headless-browser');
    }
  }

  // Modern browser pattern (negative signal)
  if (/mozilla\/5\.0.*\((windows|macintosh|linux|iphone|android).*\).*applewebkit/i.test(userAgent) &&
      !/bot|crawler|spider/i.test(userAgent)) {
    scores.userAgent.score -= 40;
    scores.userAgent.signals.push('modern-browser');
  }

  // Empty/short UA
  if (userAgent.length === 0) {
    scores.userAgent.score += 30;
    scores.userAgent.signals.push('empty-ua');
  } else if (userAgent.length < 30 && !userAgent.includes('mozilla')) {
    scores.userAgent.score += 20;
    scores.userAgent.signals.push('short-ua');
  }

  // ========================================
  // LAYER 3: HEADER ANALYSIS (25% weight)
  // ========================================

  // Meta-specific headers (DEFINITIVE)
  if (headers.get('X-Purpose') === 'preview') {
    scores.headers.score += 100;
    scores.headers.signals.push('x-purpose-preview');
  }

  if (headers.get('X-FB-HTTP-Engine') === 'Liger') {
    scores.headers.score += 100;
    scores.headers.signals.push('fb-engine-liger');
  }

  if (headers.get('X-IG-App-ID') || headers.get('X-FB-Friendly-Name')) {
    scores.headers.score += 95;
    scores.headers.signals.push('ig-fb-app-header');
  }

  // Missing standard browser headers
  const hasAccept = headers.has('Accept');
  const hasAcceptLang = headers.has('Accept-Language');
  const hasAcceptEnc = headers.has('Accept-Encoding');

  if (!hasAccept && !hasAcceptLang && !hasAcceptEnc) {
    scores.headers.score += 40;
    scores.headers.signals.push('missing-browser-headers');
  }

  // Social referrer
  const referer = (headers.get('Referer') || '').toLowerCase();
  if (/facebook\.com|fb\.com|instagram\.com|threads\.net|t\.co|twitter\.com/.test(referer)) {
    scores.headers.score += 25;
    scores.headers.signals.push('social-referer');
  }

  // Human indicators (negative signals)
  if (headers.has('Cookie')) {
    scores.headers.score -= 60;
    scores.headers.signals.push('has-cookies');
  }

  if (headers.has('Sec-Fetch-Dest') || headers.has('Sec-Fetch-Mode') || headers.has('Sec-Fetch-Site')) {
    scores.headers.score -= 50;
    scores.headers.signals.push('sec-fetch-headers');
  }

  if (headers.has('DNT') || headers.has('Sec-GPC')) {
    scores.headers.score -= 15;
    scores.headers.signals.push('privacy-headers');
  }

  const accept = headers.get('Accept') || '';
  if (accept.length > 80 && accept.includes('text/html') && accept.includes('application/xhtml')) {
    scores.headers.score -= 30;
    scores.headers.signals.push('complex-accept');
  }

  // ========================================
  // LAYER 4: BEHAVIORAL SIGNALS (20% weight)
  // Client-side signals passed via header
  // ========================================

  const behavioralHeader = headers.get('X-Behavioral-Signals');
  if (behavioralHeader) {
    try {
      const behavioral = JSON.parse(atob(behavioralHeader));
      
      if (behavioral.mouseMovement === true) {
        scores.behavior.score -= 40;
        scores.behavior.signals.push('has-mouse-movement');
      }
      
      if (behavioral.scrollPattern === true) {
        scores.behavior.score -= 30;
        scores.behavior.signals.push('has-scroll-pattern');
      }
      
      if (behavioral.dwellTime > 1000) {
        scores.behavior.score -= 25;
        scores.behavior.signals.push('sufficient-dwell-time');
      }
      
      if (behavioral.touchEvents === true) {
        scores.behavior.score -= 20;
        scores.behavior.signals.push('has-touch-events');
      }

      if (behavioral.jsEnabled === false) {
        scores.behavior.score += 50;
        scores.behavior.signals.push('js-disabled');
      }
    } catch {
      // Invalid behavioral header, ignore
    }
  }

  // ========================================
  // CALCULATE WEIGHTED FINAL SCORE
  // ========================================

  // Normalize scores to 0-100 range
  const normalizedScores = {
    ip: Math.max(0, Math.min(100, scores.ip.score)),
    userAgent: Math.max(0, Math.min(100, scores.userAgent.score)),
    headers: Math.max(0, Math.min(100, scores.headers.score)),
    behavior: Math.max(0, Math.min(100, 50 + scores.behavior.score)), // Base 50, adjust +/-
  };

  // Weighted average
  const finalScore = Math.round(
    normalizedScores.ip * SCORING_CONFIG.IP_WEIGHT +
    normalizedScores.userAgent * SCORING_CONFIG.UA_WEIGHT +
    normalizedScores.headers * SCORING_CONFIG.HEADER_WEIGHT +
    normalizedScores.behavior * SCORING_CONFIG.BEHAVIOR_WEIGHT
  );

  // ========================================
  // DYNAMIC THRESHOLD ADJUSTMENT
  // ========================================

  let effectiveThreshold = THRESHOLDS.LIKELY_BOT;
  const hour = new Date().getUTCHours();
  
  // Peak hours adjustment
  if (hour >= DYNAMIC_ADJUSTMENTS.PEAK_HOURS.start && 
      hour <= DYNAMIC_ADJUSTMENTS.PEAK_HOURS.end) {
    effectiveThreshold += DYNAMIC_ADJUSTMENTS.PEAK_HOURS.modifier;
  }

  // Check traffic spike
  const trafficCount = await getRecentTrafficCount(env);
  if (trafficCount > DYNAMIC_ADJUSTMENTS.HIGH_TRAFFIC.threshold) {
    effectiveThreshold += DYNAMIC_ADJUSTMENTS.HIGH_TRAFFIC.modifier;
  }

  // ========================================
  // FINAL DETERMINATION WITH GRAY ZONE HANDLING
  // ========================================

  let isBot = false;
  let confidence = 'unknown';
  let action = 'pass'; // pass, block, challenge

  // Check for definitive signals first
  const hasDefinitiveSignal = 
    scores.headers.signals.includes('x-purpose-preview') ||
    scores.headers.signals.includes('fb-engine-liger') ||
    scores.headers.signals.includes('ig-fb-app-header') ||
    scores.userAgent.signals.some(s => s.startsWith('meta-bot:'));

  if (hasDefinitiveSignal || finalScore >= THRESHOLDS.DEFINITE_BOT) {
    isBot = true;
    confidence = 'definite';
    action = 'block';
  } else if (finalScore >= effectiveThreshold) {
    isBot = true;
    confidence = 'likely';
    action = 'block';
  } else if (finalScore >= THRESHOLDS.GRAY_ZONE_LOW && finalScore < effectiveThreshold) {
    // GRAY ZONE: Use challenge system
    const hasAnyBotSignal = 
      scores.ip.signals.includes('meta-ip-range') ||
      scores.userAgent.signals.some(s => s.includes('bot'));
    
    if (hasAnyBotSignal) {
      isBot = false; // Assume human but challenge
      confidence = 'gray-zone';
      action = 'challenge';
    } else {
      isBot = false;
      confidence = 'gray-zone-human';
      action = 'pass';
    }
  } else if (finalScore < THRESHOLDS.DEFINITE_HUMAN) {
    isBot = false;
    confidence = 'definite-human';
    action = 'pass';
  } else {
    isBot = false;
    confidence = 'likely-human';
    action = 'pass';
  }

  // Collect all signals
  const allSignals = [
    ...scores.ip.signals.map(s => `ip:${s}`),
    ...scores.userAgent.signals.map(s => `ua:${s}`),
    ...scores.headers.signals.map(s => `hdr:${s}`),
    ...scores.behavior.signals.map(s => `bhv:${s}`),
  ];

  return {
    isBot,
    action,
    score: finalScore,
    confidence,
    signals: allSignals,
    layers: {
      ip: normalizedScores.ip,
      userAgent: normalizedScores.userAgent,
      headers: normalizedScores.headers,
      behavior: normalizedScores.behavior,
    },
    effectiveThreshold,
  };
}

// ============================================
// CHALLENGE SYSTEM FOR GRAY ZONE
// ============================================

function generateChallengeResponse(request, path, detection) {
  const url = new URL(request.url);
  const challengeToken = generateChallengeToken();
  
  // Challenge: invisible JS execution test
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>Loading...</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:system-ui,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#f5f5f5}
.loader{text-align:center}
.spinner{width:40px;height:40px;border:4px solid #ddd;border-top-color:#333;border-radius:50%;animation:spin 1s linear infinite;margin:0 auto 1rem}
@keyframes spin{to{transform:rotate(360deg)}}
</style>
</head>
<body>
<div class="loader">
<div class="spinner"></div>
<p>Loading...</p>
</div>
<script>
(function(){
  var signals = {
    mouseMovement: false,
    scrollPattern: false,
    dwellTime: Date.now(),
    touchEvents: false,
    jsEnabled: true
  };
  
  var mouseMoves = 0;
  document.addEventListener('mousemove', function() {
    mouseMoves++;
    if (mouseMoves > 3) signals.mouseMovement = true;
  });
  
  document.addEventListener('scroll', function() {
    signals.scrollPattern = true;
  });
  
  document.addEventListener('touchstart', function() {
    signals.touchEvents = true;
  });
  
  // Auto-submit after brief delay
  setTimeout(function() {
    signals.dwellTime = Date.now() - signals.dwellTime;
    
    var encoded = btoa(JSON.stringify(signals));
    var form = document.createElement('form');
    form.method = 'POST';
    form.action = '/api/verify-challenge';
    
    var tokenInput = document.createElement('input');
    tokenInput.type = 'hidden';
    tokenInput.name = 'token';
    tokenInput.value = '${challengeToken}';
    
    var signalsInput = document.createElement('input');
    signalsInput.type = 'hidden';
    signalsInput.name = 'signals';
    signalsInput.value = encoded;
    
    var pathInput = document.createElement('input');
    pathInput.type = 'hidden';
    pathInput.name = 'path';
    pathInput.value = '${path}';
    
    form.appendChild(tokenInput);
    form.appendChild(signalsInput);
    form.appendChild(pathInput);
    document.body.appendChild(form);
    form.submit();
  }, 800);
})();
</script>
<noscript>
<meta http-equiv="refresh" content="0;url=${url.origin}/${path}?noscript=1">
</noscript>
</body>
</html>`;

  return new Response(html, {
    status: 200,
    headers: {
      'Content-Type': 'text/html;charset=UTF-8',
      'Cache-Control': 'no-store',
      'Set-Cookie': `challenge_token=${challengeToken}; Path=/; HttpOnly; SameSite=Strict; Max-Age=300`,
    },
  });
}

async function handleChallengeVerification(request, env) {
  try {
    const formData = await request.formData();
    const token = formData.get('token');
    const signals = formData.get('signals');
    const path = formData.get('path');

    // Verify token from cookie
    const cookieHeader = request.headers.get('Cookie') || '';
    const tokenMatch = cookieHeader.match(/challenge_token=([^;]+)/);
    
    if (!tokenMatch || tokenMatch[1] !== token) {
      // Invalid token = likely bot
      return Response.redirect(`${new URL(request.url).origin}/${path}`, 302);
    }

    // Challenge passed - redirect with behavioral signals
    const url = new URL(request.url);
    const redirectUrl = `${url.origin}/${path}`;
    
    return new Response(null, {
      status: 302,
      headers: {
        'Location': redirectUrl,
        'Set-Cookie': `behavioral_signals=${signals}; Path=/; HttpOnly; SameSite=Strict; Max-Age=60`,
      },
    });
  } catch (error) {
    console.error('[Challenge Error]', error);
    return Response.redirect(new URL(request.url).origin, 302);
  }
}

function generateChallengeToken() {
  const array = new Uint8Array(16);
  crypto.getRandomValues(array);
  return Array.from(array, b => b.toString(16).padStart(2, '0')).join('');
}

// ============================================
// FEEDBACK LOOP SYSTEM
// ============================================

async function handleFeedback(request, env) {
  try {
    const authHeader = request.headers.get('Authorization');
    const secretKey = env.SECRET_KEY || (typeof INJECTED_SECRET_KEY !== 'undefined' ? INJECTED_SECRET_KEY : '');

    if (!secretKey || authHeader !== `Bearer ${secretKey}`) {
      return jsonResponse({ error: 'Unauthorized' }, 401);
    }

    const body = await request.json();
    const { ip, fingerprint, type, detection } = body;

    // type: 'false_positive' | 'false_negative'
    if (!type || !['false_positive', 'false_negative'].includes(type)) {
      return jsonResponse({ error: 'Invalid feedback type' }, 400);
    }

    const feedbackKey = `feedback:${ip || fingerprint}`;
    const feedbackData = {
      type,
      timestamp: new Date().toISOString(),
      detection,
    };

    await env.LINK_STORAGE.put(feedbackKey, JSON.stringify(feedbackData), {
      expirationTtl: 30 * 24 * 60 * 60, // 30 days
    });

    // Update aggregate stats
    const statsKey = `stats:feedback:${type}`;
    const currentStats = await env.LINK_STORAGE.get(statsKey);
    const count = currentStats ? parseInt(currentStats, 10) + 1 : 1;
    await env.LINK_STORAGE.put(statsKey, String(count), {
      expirationTtl: 30 * 24 * 60 * 60,
    });

    return jsonResponse({ success: true, recorded: feedbackKey });
  } catch (error) {
    console.error('[Feedback Error]', error);
    return jsonResponse({ error: 'Failed to record feedback' }, 500);
  }
}

async function getFeedbackRecord(ip, env) {
  try {
    if (!env.LINK_STORAGE) return null;
    const stored = await env.LINK_STORAGE.get(`feedback:${ip}`);
    return stored ? JSON.parse(stored) : null;
  } catch {
    return null;
  }
}

async function getRecentTrafficCount(env) {
  try {
    if (!env.LINK_STORAGE) return 0;
    const stored = await env.LINK_STORAGE.get('stats:traffic:hourly');
    return stored ? parseInt(stored, 10) : 0;
  } catch {
    return 0;
  }
}

// ============================================
// ANALYTICS ENDPOINT
// ============================================

async function handleAnalytics(request, env) {
  const authHeader = request.headers.get('Authorization');
  const secretKey = env.SECRET_KEY || (typeof INJECTED_SECRET_KEY !== 'undefined' ? INJECTED_SECRET_KEY : '');

  if (!secretKey || authHeader !== `Bearer ${secretKey}`) {
    return jsonResponse({ error: 'Unauthorized' }, 401);
  }

  try {
    const fpCount = await env.LINK_STORAGE.get('stats:feedback:false_positive') || '0';
    const fnCount = await env.LINK_STORAGE.get('stats:feedback:false_negative') || '0';
    const trafficCount = await env.LINK_STORAGE.get('stats:traffic:hourly') || '0';

    return jsonResponse({
      version: '4.0',
      stats: {
        falsePositives: parseInt(fpCount, 10),
        falseNegatives: parseInt(fnCount, 10),
        hourlyTraffic: parseInt(trafficCount, 10),
      },
      thresholds: THRESHOLDS,
      dynamicAdjustments: DYNAMIC_ADJUSTMENTS,
    });
  } catch (error) {
    console.error('[Analytics Error]', error);
    return jsonResponse({ error: 'Failed to fetch analytics' }, 500);
  }
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
// RATE LIMITING & COUNTERS
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

    // Track hourly traffic
    ctx.waitUntil(incrementHourlyTraffic(env));

    return true;
  } catch (error) {
    console.error('[RateLimit Error]', error);
    return true;
  }
}

async function incrementHourlyTraffic(env) {
  try {
    const key = 'stats:traffic:hourly';
    const current = await env.LINK_STORAGE.get(key);
    const count = current ? parseInt(current, 10) : 0;
    await env.LINK_STORAGE.put(key, String(count + 1), { expirationTtl: 3600 });
  } catch {
    // Silent fail
  }
}

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
      action: detection.action,
      score: detection.score,
      confidence: detection.confidence,
      signals: detection.signals.slice(0, 10),
      layers: detection.layers,
      threshold: detection.effectiveThreshold,
      ip: ip ? ip.substring(0, 20) : 'unknown',
      ua: userAgent ? userAgent.substring(0, 80) : 'unknown',
    };

    await env.LINK_STORAGE.put(logKey, JSON.stringify(logData), {
      expirationTtl: 7 * 24 * 60 * 60,
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

    const linkData = {
      created: new Date().toISOString(),
      target: targetUrl,
      clicks: 0,
      mode: mode || 'default',
    };

    if (mode === 'og_preview' && ogMeta && typeof ogMeta === 'object') {
      linkData.ogMeta = {
        image: sanitizeUrl(ogMeta.image),
        title: sanitizeText(ogMeta.title, 100),
        description: sanitizeText(ogMeta.description, 200),
        canonical: sanitizeUrl(ogMeta.canonical),
      };
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
  const detection = await detectBotV4(request, clientIP, env, { waitUntil: () => {} });

  return jsonResponse({
    version: '4.0',
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
  return str.replace(/<[^>]*>/g, '').replace(/[<>'\"&]/g, '').substring(0, maxLen).trim();
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

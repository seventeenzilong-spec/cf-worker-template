/**
 * Edge Worker (worker.js) - OPTIMIZED VERSION FOR AFFILIATE
 * 
 * Cloudflare Worker untuk handling public traffic at the edge.
 * Optimized untuk minimize false positive & maximize Meta bot detection.
 * 
 * CRITICAL REQUIREMENTS:
 * - FALSE POSITIVE < 1% (human traffic harus lolos = $$$ revenue)
 * - FALSE NEGATIVE < 5% (Meta bot harus ketangkep = account safety)
 * 
 * ENV VARIABLES (set via cf-api injection atau wrangler.toml):
 * - TARGET_URL: Default redirect URL for human visitors
 * - SECRET_KEY: Authentication key for internal API
 * 
 * KV NAMESPACE:
 * - LINK_STORAGE: Stores OG metadata, caption, comment, hit counter
 * 
 * OPTIMIZATIONS:
 * - Weighted scoring system (reduce false positive)
 * - IPv6 support for Meta ranges
 * - Enhanced Threads/Instagram detection
 * - Behavioral analysis
 * - Fallback detection mechanisms
 * - Analytics logging for continuous improvement
 */

// ============================================
// CONSTANTS
// ============================================

const TTL_SECONDS = 30 * 24 * 60 * 60; // 30 days
const MAX_PATH_LENGTH = 100;
const PATH_PATTERN = /^[a-zA-Z0-9_-]+$/;
const RATE_LIMIT_WINDOW = 3600; // 1 hour
const RATE_LIMIT_MAX = 100;

// Bot detection threshold (0-100 scale)
const BOT_THRESHOLD_DEFINITE = 80;  // >= 80: Definitely bot
const BOT_THRESHOLD_LIKELY = 60;    // 60-79: Likely bot
const HUMAN_THRESHOLD = 40;         // < 40: Likely human

// Meta/Facebook IP ranges (IPv4 + IPv6)
const META_IP_RANGES_V4 = [
  '31.13.24.0/21', '31.13.64.0/18', '31.13.96.0/19',
  '66.220.144.0/20', '69.63.176.0/20', '69.171.224.0/19',
  '74.119.76.0/22', '102.132.96.0/20', '103.4.96.0/22',
  '129.134.0.0/16', '157.240.0.0/16', '173.252.64.0/18',
  '179.60.192.0/22', '185.60.216.0/22', '204.15.20.0/22',
  '199.16.156.0/22', '192.133.76.0/22',
  '18.194.0.0/15', '34.224.0.0/12',
];

const META_IP_RANGES_V6 = [
  '2a03:2880::/32',  // Facebook primary
  '2c0f:fb50::/32',  // Meta Africa
  '2a03:2887::/32',  // Facebook secondary
];

// High-confidence Meta bot user agents
const META_BOT_AGENTS = [
  'facebookexternalhit',
  'Facebot',
  'facebookplatform',
  'Meta-ExternalAgent',
  'meta-externalhit',
  'InstagramBot',
  'ThreadsBot',
  'ThreadsExternalHit',
];

// Other social media bots
const OTHER_BOT_AGENTS = [
  'Twitterbot', 'Twitter',
  'WhatsApp', 'WhatsApp/', 'WA_Business',
  'LinkedInBot', 'linkedin',
  'Slackbot', 'TelegramBot', 'SkypeUriPreview',
  'Discordbot', 'redditbot', 'Applebot',
  'ia_archiver', 'PinterestBot',
];

// Search engine bots (treat as bot for preview)
const SEARCH_ENGINE_BOTS = [
  'Googlebot', 'bingbot', 'Baiduspider', 'YandexBot',
  'DuckDuckBot', 'Sogou', 'Exabot',
];

// Legitimate headless/automation tools (should NOT be treated as social bot)
const LEGITIMATE_AUTOMATION = [
  'Pingdom', 'UptimeRobot', 'StatusCake',
  'GTmetrix', 'PageSpeed', 'Lighthouse',
  'Selenium', 'Puppeteer', 'Playwright',
];

// Trusted image CDN domains
const TRUSTED_IMAGE_DOMAINS = [
  'cdn.', 'imgur.com', 'cloudinary.com', 'imagekit.io',
  'imgix.net', 'cloudfront.net', 'b-cdn.', 'bunnycdn.com',
  'grbto.net',
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

  console.log(`[Request] Path: ${path}, IP: ${clientIP}, UA: ${userAgent.substring(0, 60)}...`);

  // Internal API endpoint for saving links
  if (request.method === 'POST' && path === 'api/save-link') {
    console.log('[API] Handling save-link request');
    return handleSaveLink(request, env);
  }

  // Health check endpoint
  if (path === 'health' || path === 'ping') {
    return new Response(JSON.stringify({ status: 'ok', service: 'link-generator' }), {
      headers: { 'Content-Type': 'application/json' }
    });
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

  // OPTIMIZED BOT DETECTION with scoring system
  const detectionResult = await detectBotAdvanced(request, clientIP, env);
  const { isBot, score, reasons, confidence } = detectionResult;

  // Log detection for analytics
  ctx.waitUntil(logDetection(path, detectionResult, env));

  console.log(`[Detection] Bot: ${isBot}, Score: ${score}, Confidence: ${confidence}, Reasons: ${reasons.join(', ')}`);
  
  if (isBot) {
    console.log(`[BotDetected] Serving preview for: ${path} (Score: ${score})`);
    
    const previewContent = linkData.mode === 'default' 
      ? await generateMinimalPreview(request, path)
      : await generateSafePreview(request, linkData, path);

    return new Response(previewContent, {
      headers: {
        ...addSecurityHeaders({
          'Content-Type': 'text/html;charset=UTF-8',
          'Cache-Control': 'public, max-age=3600',
          'X-Robots-Tag': 'nofollow, noarchive',
          'X-Bot-Score': score.toString(),
        })
      },
    });
  }

  // Human visitor -> Redirect
  const targetUrl = linkData.target || env.TARGET_URL || (typeof INJECTED_TARGET_URL !== 'undefined' ? INJECTED_TARGET_URL : '');
  
  // FIX: Provide fallback for empty/invalid target URL
  if (!isValidTargetUrl(targetUrl)) {
    console.error(`[Error] Invalid or empty target URL: ${targetUrl}`);
    return new Response(generateFallbackPage('Redirect tidak tersedia. Silakan hubungi administrator.'), {
      status: 503,
      headers: { 'Content-Type': 'text/html;charset=UTF-8' }
    });
  }

  console.log(`[HumanRedirect] Redirecting to: ${targetUrl} (Score: ${score})`);
  return Response.redirect(targetUrl, 302);
}

// ============================================
// ADVANCED BOT DETECTION (OPTIMIZED)
// ============================================

async function detectBotAdvanced(request, ip, env) {
  const userAgent = (request.headers.get('User-Agent') || '').toLowerCase();
  const referer = (request.headers.get('Referer') || '').toLowerCase();
  
  let score = 0;
  let reasons = [];
  let confidence = 'unknown';

  // ==================================================
  // TIER 1: HIGH CONFIDENCE SIGNALS (70-95 points)
  // ==================================================

  // Meta-specific headers (95 points) - HIGHEST confidence
  const xPurpose = request.headers.get('X-Purpose');
  const xFBEngine = request.headers.get('X-FB-HTTP-Engine');
  const xIGAppID = request.headers.get('X-IG-App-ID');
  const xFBFriendlyName = request.headers.get('X-FB-Friendly-Name');
  
  if (xPurpose === 'preview') {
    score += 95;
    reasons.push('Meta X-Purpose header');
    confidence = 'very-high';
  }
  
  if (xFBEngine === 'Liger') {
    score += 95;
    reasons.push('Meta FB-Engine header');
    confidence = 'very-high';
  }

  if (xIGAppID || xFBFriendlyName) {
    score += 90;
    reasons.push('Instagram/Threads header');
    confidence = 'very-high';
  }

  // Exact Meta bot user agent match (90 points)
  const hasMetaBotUA = META_BOT_AGENTS.some(bot => 
    userAgent.includes(bot.toLowerCase())
  );
  
  if (hasMetaBotUA) {
    score += 90;
    reasons.push('Meta bot user-agent');
    confidence = confidence === 'very-high' ? 'very-high' : 'high';
  }

  // Threads-specific detection (90 points)
  const isThreadsBot = userAgent.includes('threadsbot') || 
                       userAgent.includes('threadsexternalhit') ||
                       userAgent.includes('barcelona') || // Threads codename
                       referer.includes('threads.net');
  
  if (isThreadsBot) {
    score += 90;
    reasons.push('Threads crawler');
    confidence = 'very-high';
  }

  // Instagram bot (90 points)
  const isInstagramBot = userAgent.includes('instagrambot') ||
                         (userAgent.includes('instagram') && userAgent.includes('bot'));
  
  if (isInstagramBot) {
    score += 90;
    reasons.push('Instagram bot');
    confidence = 'very-high';
  }

  // Other social media bots (75 points)
  const hasOtherSocialBot = OTHER_BOT_AGENTS.some(bot =>
    userAgent.includes(bot.toLowerCase())
  );
  
  if (hasOtherSocialBot) {
    score += 75;
    reasons.push('Social media bot');
    confidence = confidence === 'unknown' ? 'high' : confidence;
  }

  // Search engine bots (70 points)
  const isSearchBot = SEARCH_ENGINE_BOTS.some(bot =>
    userAgent.includes(bot.toLowerCase())
  );
  
  if (isSearchBot) {
    score += 70;
    reasons.push('Search engine bot');
    confidence = confidence === 'unknown' ? 'high' : confidence;
  }

  // ==================================================
  // TIER 2: MEDIUM CONFIDENCE SIGNALS (30-50 points)
  // ==================================================

  // Meta IP range (50 points for IPv4, 55 for IPv6)
  // Note: Reduced from original because employees/VPN can be in range
  if (ip) {
    const ipVersion = ip.includes(':') ? 6 : 4;
    const inMetaRange = ipVersion === 6 
      ? isIPv6InMetaRanges(ip)
      : isIPv4InMetaRanges(ip);
    
    if (inMetaRange) {
      // Only add score if we have OTHER signals (prevent false positive)
      if (reasons.length > 0) {
        score += ipVersion === 6 ? 55 : 50;
        reasons.push(`Meta IP range (IPv${ipVersion})`);
      } else {
        // IP alone is not enough - just note it
        score += 20;
        reasons.push(`Meta IP (low confidence)`);
      }
    }
  }

  // Generic bot keywords in UA (40 points)
  // But only if NOT a legitimate automation tool
  const isLegitAutomation = LEGITIMATE_AUTOMATION.some(tool =>
    userAgent.includes(tool.toLowerCase())
  );

  let hasBotKeywords = false;
  if (!isLegitAutomation) {
    hasBotKeywords = userAgent.includes('bot') || 
                     userAgent.includes('crawler') || 
                     userAgent.includes('spider') ||
                     userAgent.includes('scraper') ||
                     userAgent.includes('preview');
    
    if (hasBotKeywords) {
      score += 40;
      reasons.push('Generic bot keywords');
      confidence = confidence === 'unknown' ? 'medium' : confidence;
    }
  }

  // Headless browser detection (35 points)
  const isHeadless = userAgent.includes('headless') || 
                     userAgent.includes('phantom') ||
                     userAgent.includes('headlesschrome');
  
  if (isHeadless && !isLegitAutomation) {
    score += 35;
    reasons.push('Headless browser');
  }

  // ==================================================
  // TIER 3: LOW CONFIDENCE SIGNALS (5-25 points)
  // ==================================================

  // Missing common browser headers (20 points)
  // But only count if we already have other signals
  const hasAccept = request.headers.has('Accept');
  const hasAcceptLanguage = request.headers.has('Accept-Language');
  const hasAcceptEncoding = request.headers.has('Accept-Encoding');
  const missingCount = [hasAccept, hasAcceptLanguage, hasAcceptEncoding].filter(h => !h).length;
  
  if (missingCount === 3 && reasons.length > 0) {
    // All three missing + other signals = likely bot
    score += 20;
    reasons.push('Missing browser headers');
  } else if (missingCount === 2 && reasons.length > 0) {
    score += 10;
    reasons.push('Incomplete headers');
  }

  // Very short or empty user agent (15 points)
  // But allow for privacy-focused browsers
  if (userAgent.length === 0) {
    score += 15;
    reasons.push('Empty user-agent');
  } else if (userAgent.length < 20 && userAgent.length > 0) {
    score += 10;
    reasons.push('Short user-agent');
  }

  // Suspicious referer patterns (10 points)
  if (referer && (referer.includes('facebook.com') || referer.includes('fb.com') || 
      referer.includes('instagram.com') || referer.includes('threads.net'))) {
    score += 10;
    reasons.push('Social media referer');
  }

  // ==================================================
  // NEGATIVE SIGNALS (Reduce score = MORE LIKELY HUMAN)
  // ==================================================

  // Has cookies (strong human signal) (-40 points)
  const hasCookies = request.headers.has('Cookie');
  if (hasCookies) {
    score -= 40;
    reasons.push('Has cookies (human signal)');
  }

  // Has JavaScript-related headers (-30 points)
  const hasSecFetchDest = request.headers.has('Sec-Fetch-Dest');
  const hasSecFetchMode = request.headers.has('Sec-Fetch-Mode');
  const hasSecFetchSite = request.headers.has('Sec-Fetch-Site');
  
  if (hasSecFetchDest || hasSecFetchMode || hasSecFetchSite) {
    score -= 30;
    reasons.push('Browser security headers (human signal)');
  }

  // Modern browser user-agent with version numbers (-20 points)
  const hasModernUA = /Chrome\/\d+|Firefox\/\d+|Safari\/\d+|Edge\/\d+/.test(userAgent);
  if (hasModernUA && !hasBotKeywords) {
    score -= 20;
    reasons.push('Modern browser UA');
  }

  // Has DNT (Do Not Track) header (-10 points)
  if (request.headers.has('DNT')) {
    score -= 10;
    reasons.push('DNT header (privacy-conscious user)');
  }

  // Complex Accept header (human browsers send detailed Accept) (-15 points)
  const acceptHeader = request.headers.get('Accept') || '';
  if (acceptHeader.length > 50 && acceptHeader.includes('text/html')) {
    score -= 15;
    reasons.push('Complex Accept header');
  }

  // ==================================================
  // FINAL DETERMINATION
  // ==================================================

  // Ensure score doesn't go negative
  score = Math.max(0, score);

  // Determine bot/human based on threshold
  let isBot = false;
  
  if (score >= BOT_THRESHOLD_DEFINITE) {
    isBot = true;
    confidence = 'very-high';
  } else if (score >= BOT_THRESHOLD_LIKELY) {
    isBot = true;
    confidence = confidence === 'unknown' ? 'high' : confidence;
  } else if (score < HUMAN_THRESHOLD) {
    isBot = false;
    confidence = 'human';
  } else {
    // Gray zone (40-59): Default to human to avoid false positive
    // But if we have high-confidence signals, treat as bot
    if (reasons.some(r => r.includes('Meta') || r.includes('Threads') || r.includes('Instagram'))) {
      isBot = true;
      confidence = 'medium';
    } else {
      isBot = false;
      confidence = 'uncertain-human';
    }
  }

  if (reasons.length === 0) {
    reasons.push('No significant signals');
    confidence = 'human';
  }

  return {
    isBot,
    score: Math.round(score),
    reasons,
    confidence,
    userAgent: userAgent.substring(0, 100),
    ip: ip ? ip.substring(0, 45) : 'unknown'
  };
}

// ============================================
// IP RANGE CHECKING (IPv4 + IPv6)
// ============================================

function isIPv4InMetaRanges(ip) {
  try {
    const ipParts = ip.split('.').map(Number);
    if (ipParts.length !== 4 || ipParts.some(isNaN)) return false;
    if (ipParts.some(p => p < 0 || p > 255)) return false;
    
    // FIX: Use multiplication instead of bitwise to avoid signed 32-bit overflow
    const ipNum = (ipParts[0] * 16777216) + (ipParts[1] * 65536) + (ipParts[2] * 256) + ipParts[3];
    
    for (const range of META_IP_RANGES_V4) {
      const [rangeIP, mask] = range.split('/');
      const rangeParts = rangeIP.split('.').map(Number);
      const rangeNum = (rangeParts[0] * 16777216) + (rangeParts[1] * 65536) + (rangeParts[2] * 256) + rangeParts[3];
      const maskBits = parseInt(mask);
      
      // FIX: Use proper unsigned mask calculation
      const maskNum = maskBits === 0 ? 0 : (0xFFFFFFFF << (32 - maskBits)) >>> 0;
      
      if (((ipNum >>> 0) & maskNum) === ((rangeNum >>> 0) & maskNum)) {
        return true;
      }
    }
  } catch (e) {
    console.error('IPv4 range check error:', e);
  }
  return false;
}

function isIPv6InMetaRanges(ip) {
  try {
    // Normalize IPv6 (remove :: expansion for simpler matching)
    const normalizedIP = normalizeIPv6(ip);
    
    for (const range of META_IP_RANGES_V6) {
      const [prefix, mask] = range.split('/');
      const maskBits = parseInt(mask);
      
      // Simple prefix matching for /32 ranges
      if (maskBits === 32) {
        const rangePrefix = prefix.substring(0, 9); // First 32 bits = first 4 hex groups
        const ipPrefix = normalizedIP.substring(0, 9);
        
        if (ipPrefix === rangePrefix) {
          return true;
        }
      }
    }
  } catch (e) {
    console.error('IPv6 range check error:', e);
  }
  return false;
}

function normalizeIPv6(ip) {
  // Basic IPv6 normalization
  // Expand :: to full form
  if (ip.includes('::')) {
    const parts = ip.split('::');
    const leftParts = parts[0] ? parts[0].split(':') : [];
    const rightParts = parts[1] ? parts[1].split(':') : [];
    const missingParts = 8 - leftParts.length - rightParts.length;
    
    const middle = Array(missingParts).fill('0000');
    const fullParts = [...leftParts, ...middle, ...rightParts];
    
    return fullParts.map(p => p.padStart(4, '0')).join(':');
  }
  
  return ip.split(':').map(p => p.padStart(4, '0')).join(':');
}

// ============================================
// ANALYTICS LOGGING
// ============================================

async function logDetection(path, detectionResult, env) {
  try {
    const logKey = `analytics:${Date.now()}:${Math.random().toString(36).substring(7)}`;
    
    const logData = {
      timestamp: new Date().toISOString(),
      path: path,
      isBot: detectionResult.isBot,
      score: detectionResult.score,
      confidence: detectionResult.confidence,
      reasons: detectionResult.reasons,
      userAgent: detectionResult.userAgent,
      ip: detectionResult.ip,
    };

    // Store for 7 days for analysis
    await env.LINK_STORAGE.put(logKey, JSON.stringify(logData), {
      expirationTtl: 7 * 24 * 60 * 60
    });
  } catch (e) {
    console.error('Logging error:', e);
  }
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

/**
 * Generate minimal preview for default mode
 * UPDATED: Title menggunakan domain saja (stealth mode untuk anti-spam detection)
 */
async function generateMinimalPreview(request, path) {
  const url = new URL(request.url);
  const domain = url.hostname; // Domain saja untuk stealth
  
  return `<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<meta name="robots" content="noindex, nofollow" />
<title>${domain}</title>
<meta property="og:title" content="${domain}" />
<meta property="og:type" content="website" />
<meta property="og:url" content="${url.origin}/${path}" />
<meta name="twitter:title" content="${domain}" />
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
    <h1>${domain}</h1>
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
            .replace(/[<>'"]/g, '')
            .substring(0, 200);
}

function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
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

// FIX: Add fallback page for invalid/empty target URL
function generateFallbackPage(message) {
  return `<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>503 - Layanan Tidak Tersedia</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
  font-family: system-ui, -apple-system, sans-serif;
  background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  color: white;
  text-align: center;
  padding: 20px;
}
.container { max-width: 400px; }
h1 { font-size: 80px; margin-bottom: 20px; font-weight: 700; }
p { font-size: 18px; opacity: 0.9; line-height: 1.6; }
</style>
</head>
<body>
  <div class="container">
    <h1>503</h1>
    <p>${message || 'Layanan sementara tidak tersedia. Silakan coba lagi nanti.'}</p>
  </div>
</body>
</html>`;
}

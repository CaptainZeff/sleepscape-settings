/**
 * Sleepscape API Worker
 * Handles user API key storage for Gemini integration
 *
 * Deploy to Cloudflare Workers:
 * 1. Go to https://dash.cloudflare.com/
 * 2. Workers & Pages > Create Worker
 * 3. Name it "sleepscape-api"
 * 4. Paste this code
 * 5. Add KV namespace binding: SLEEPSCAPE_KEYS
 */

// CORS headers for GitHub Pages
const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
};

// Simple encryption for API keys (base64 + reversal - not secure, just obfuscation)
// For production, use proper encryption with Cloudflare's encryption features
function obfuscateKey(key) {
    const reversed = key.split('').reverse().join('');
    return btoa(reversed);
}

function deobfuscateKey(obfuscated) {
    const reversed = atob(obfuscated);
    return reversed.split('').reverse().join('');
}

// Generate a verification token from user ID
function generateToken(userId, secret) {
    // Simple hash for verification
    let hash = 0;
    const str = userId + secret;
    for (let i = 0; i < str.length; i++) {
        const char = str.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash = hash & hash;
    }
    return Math.abs(hash).toString(36);
}

export default {
    async fetch(request, env, ctx) {
        // Handle CORS preflight
        if (request.method === 'OPTIONS') {
            return new Response(null, { headers: corsHeaders });
        }

        const url = new URL(request.url);
        const path = url.pathname;

        // Secret for token generation (should be in env var)
        const SECRET = env.TOKEN_SECRET || 'sleepscape-secret-2024';

        try {
            // Save API key endpoint
            if (path === '/save-key' && request.method === 'POST') {
                const body = await request.json();
                const { userId, token, apiKey } = body;

                if (!userId || !token || !apiKey) {
                    return new Response(
                        JSON.stringify({ error: 'Missing required fields' }),
                        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
                    );
                }

                // Verify token
                const expectedToken = generateToken(userId, SECRET);
                if (token !== expectedToken) {
                    return new Response(
                        JSON.stringify({ error: 'Invalid token' }),
                        { status: 401, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
                    );
                }

                // Validate API key format
                if (!apiKey.startsWith('AIza') || apiKey.length < 30) {
                    return new Response(
                        JSON.stringify({ error: 'Invalid API key format' }),
                        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
                    );
                }

                // Store the key (obfuscated)
                const obfuscatedKey = obfuscateKey(apiKey);
                await env.SLEEPSCAPE_KEYS.put(userId, obfuscatedKey);

                return new Response(
                    JSON.stringify({ success: true, message: 'API key saved successfully' }),
                    { status: 200, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
                );
            }

            // Get API key endpoint (for Lambda to call)
            if (path === '/get-key' && request.method === 'GET') {
                const userId = url.searchParams.get('userId');
                const authHeader = request.headers.get('Authorization');

                // Simple auth check for Lambda calls
                if (authHeader !== `Bearer ${env.LAMBDA_SECRET || 'sleepscape-lambda-key'}`) {
                    return new Response(
                        JSON.stringify({ error: 'Unauthorized' }),
                        { status: 401, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
                    );
                }

                if (!userId) {
                    return new Response(
                        JSON.stringify({ error: 'Missing userId' }),
                        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
                    );
                }

                const obfuscatedKey = await env.SLEEPSCAPE_KEYS.get(userId);

                if (!obfuscatedKey) {
                    return new Response(
                        JSON.stringify({ error: 'No API key found', hasKey: false }),
                        { status: 404, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
                    );
                }

                const apiKey = deobfuscateKey(obfuscatedKey);
                return new Response(
                    JSON.stringify({ apiKey, hasKey: true }),
                    { status: 200, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
                );
            }

            // Delete API key endpoint
            if (path === '/delete-key' && request.method === 'POST') {
                const body = await request.json();
                const { userId, token } = body;

                if (!userId || !token) {
                    return new Response(
                        JSON.stringify({ error: 'Missing required fields' }),
                        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
                    );
                }

                // Verify token
                const expectedToken = generateToken(userId, SECRET);
                if (token !== expectedToken) {
                    return new Response(
                        JSON.stringify({ error: 'Invalid token' }),
                        { status: 401, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
                    );
                }

                await env.SLEEPSCAPE_KEYS.delete(userId);

                return new Response(
                    JSON.stringify({ success: true, message: 'API key deleted' }),
                    { status: 200, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
                );
            }

            // Health check
            if (path === '/health') {
                return new Response(
                    JSON.stringify({ status: 'ok', service: 'sleepscape-api' }),
                    { status: 200, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
                );
            }

            // 404 for unknown routes
            return new Response(
                JSON.stringify({ error: 'Not found' }),
                { status: 404, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
            );

        } catch (error) {
            console.error('Error:', error);
            return new Response(
                JSON.stringify({ error: 'Internal server error' }),
                { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
            );
        }
    }
};

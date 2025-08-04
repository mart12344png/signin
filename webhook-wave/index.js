import { serve } from 'https://deno.land/std@0.215.0/http/server.ts';
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';

// ===== CONFIG =====
const FLW_SECRET_HASH = Deno.env.get('FLUTTERWAVE_SECRET_HASH');
const SUPABASE_URL = Deno.env.get('SUPABASE_URL');
const SUPABASE_KEY = Deno.env.get('SUPABASE_ANON_KEY');

// ===== RATE LIMITING =====
const requestCounts = new Map();
const RATE_LIMIT = {
  WINDOW_MS: 60_000, // 1 minute
  MAX_REQUESTS: 100  // 100 requests/minute per IP
};

setInterval(() => requestCounts.clear(), RATE_LIMIT.WINDOW_MS);

// ===== SECURITY ===== 
async function verifySignature(signature, payload, secret) {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['verify']
  );
  const sigBuffer = new Uint8Array(
    signature.replace('sha256=', '')
      .match(/.{1,2}/g)
      .map(byte => parseInt(byte, 16))
  ).buffer;
  return crypto.subtle.verify('HMAC', key, sigBuffer, new TextEncoder().encode(payload));
}

// ===== MAIN HANDLER =====
const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

serve(async (req) => {
  const clientIP = req.headers.get('x-forwarded-for')?.split(',')[0].trim() || 'unknown';
  
  // Rate limiting check
  const requestCount = (requestCounts.get(clientIP) || 0) + 1;
  requestCounts.set(clientIP, requestCount);
  
  if (requestCount > RATE_LIMIT.MAX_REQUESTS) {
    console.warn(`Rate limit exceeded for IP: ${clientIP}`);
    return new Response('Too many requests', { status: 429 });
  }

  try {
    if (req.method === 'POST') {
      const signature = req.headers.get('verif-hash');
      const rawBody = await req.text();
      
      if (!await verifySignature(signature, rawBody, FLW_SECRET_HASH)) {
        return new Response('Invalid signature', { status: 401 });
      }

      const { data } = JSON.parse(rawBody);
      await supabase.from('transactions').upsert({
        tx_ref: data.tx_ref,
        amount: data.amount,
        status: data.status,
        processed_at: new Date().toISOString()
      });

      return new Response('OK');
    }
    
    return new Response('Not found', { status: 404 });
    
  } catch (error) {
    console.error('Error:', error);
    return new Response('Server error', { status: 500 });
  }
}, { port: 8000 });

console.log('🚀 Webhook running with rate limiting');
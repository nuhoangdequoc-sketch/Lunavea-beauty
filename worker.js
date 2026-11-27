const ALLOWED_ORIGINS = new Set([
  'https://www.lunaveashop.io.vn',
  'https://lunaveashop.io.vn'
]);

function json(data, status = 200, origin = '') {
  const headers = {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'Vary': 'Origin'
  };
  if (origin && ALLOWED_ORIGINS.has(origin)) {
    headers['Access-Control-Allow-Origin'] = origin;
    headers['Access-Control-Allow-Methods'] = 'POST, OPTIONS';
    headers['Access-Control-Allow-Headers'] = 'Content-Type';
    headers['Access-Control-Max-Age'] = '86400';
  }
  return new Response(JSON.stringify(data), { status, headers });
}

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, ch => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  })[ch]);
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin') || '';

    if (request.method === 'OPTIONS') {
      if (!ALLOWED_ORIGINS.has(origin)) return new Response(null, { status: 403 });
      return new Response(null, {
        status: 204,
        headers: {
          'Access-Control-Allow-Origin': origin,
          'Access-Control-Allow-Methods': 'POST, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type',
          'Access-Control-Max-Age': '86400',
          'Vary': 'Origin'
        }
      });
    }

    if (request.method !== 'POST') return json({ success: false, error: 'Method not allowed' }, 405, origin);
    if (!ALLOWED_ORIGINS.has(origin)) return json({ success: false, error: 'Origin not allowed' }, 403);
    if (!request.headers.get('content-type')?.toLowerCase().includes('application/json')) {
      return json({ success: false, error: 'Content-Type must be application/json' }, 415, origin);
    }
    const length = Number(request.headers.get('content-length') || 0);
    if (length > 20000) return json({ success: false, error: 'Request too large' }, 413, origin);

    try {
      const data = await request.json();
      const subject = String(data.subject || '').trim().slice(0, 180);
      const body = String(data.body || '').trim().slice(0, 12000);
      const requestedEmail = String(data.targetEmail || '').trim().toLowerCase();
      const allowedEmails = String(env.ADMIN_EMAILS || '').split(',').map(x => x.trim().toLowerCase()).filter(Boolean);
      const to = allowedEmails.find(email => email === requestedEmail);
      const from = String(env.FROM_EMAIL || '').trim();

      if (!subject || !body) return json({ success: false, error: 'Missing subject or body' }, 400, origin);
      if (!to) return json({ success: false, error: 'Recipient is not in the Worker ADMIN_EMAILS allowlist' }, 403, origin);
      if (!/^\S+@lunaveashop\.io\.vn$/i.test(from)) {
        return json({ success: false, error: 'FROM_EMAIL must use the onboarded lunaveashop.io.vn domain' }, 500, origin);
      }
      if (!env.EMAIL || typeof env.EMAIL.send !== 'function') {
        return json({ success: false, error: 'Missing Email Sending binding named EMAIL' }, 500, origin);
      }

      const payload = data.payload && typeof data.payload === 'object' && !Array.isArray(data.payload) ? data.payload : {};
      const detailLines = Object.entries(payload).slice(0, 30).map(([key, value]) => `${String(key).slice(0, 80)}: ${String(value ?? '').slice(0, 1000)}`);
      const textBody = [body, '', 'Thời gian: ' + String(data.time || new Date().toLocaleString('vi-VN')), ...detailLines].join('\n');
      const htmlBody = `<div style="font-family:Arial,sans-serif;line-height:1.6;color:#222"><h2>${escapeHtml(subject)}</h2><p>${escapeHtml(body).replace(/\n/g, '<br>')}</p><hr><p><strong>Thời gian:</strong> ${escapeHtml(data.time || '')}</p><pre style="white-space:pre-wrap">${escapeHtml(detailLines.join('\n'))}</pre></div>`;

      const result = await env.EMAIL.send({
        to,
        from,
        subject,
        text: textBody,
        html: htmlBody
      });

      return json({ success: true, messageId: result?.messageId || null }, 200, origin);
    } catch (error) {
      const message = String(error?.message || error || 'Unknown error').slice(0, 240);
      return json({ success: false, error: message }, 500, origin);
    }
  }
};

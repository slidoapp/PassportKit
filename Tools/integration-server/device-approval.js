// Drives the provider's own device verification pages like a browser would (cookie jar, redirects),
// so approval runs through the real code path. Interactions auto-complete on this server.
export async function approveDevice({ issuer, userCode, decision }) {
  const jar = new Map();
  const send = async (url, form) => {
    let target = new URL(url, issuer);
    let init = form
      ? { method: 'POST', body: new URLSearchParams(form), headers: { 'content-type': 'application/x-www-form-urlencoded' } }
      : { method: 'GET' };
    for (let hop = 0; hop < 15; hop += 1) {
      const response = await fetch(target, {
        ...init,
        redirect: 'manual',
        headers: { ...init.headers, cookie: [...jar].map(([name, value]) => `${name}=${value}`).join('; ') },
      });
      for (const cookie of response.headers.getSetCookie()) {
        const [pair] = cookie.split(';');
        const [name, ...rest] = pair.split('=');
        jar.set(name.trim(), rest.join('='));
      }
      const location = response.headers.get('location');
      if (response.status < 300 || response.status >= 400 || !location) {
        return { status: response.status, html: await response.text() };
      }
      target = new URL(location, target);
      init = { method: 'GET' };
    }
    throw new Error('too many redirects');
  };
  const xsrfOf = (html) => html.match(/name="xsrf" value="([^"]+)"/)?.[1];

  const form = await send('/device');
  const entered = await send('/device', { xsrf: xsrfOf(form.html), user_code: userCode });
  const xsrf = xsrfOf(entered.html);
  if (!xsrf) return { ok: false, error: 'invalid_user_code' };
  const confirmation = decision === 'approve' ? { confirm: 'yes' } : { abort: 'yes' };
  const done = await send('/device', { xsrf, user_code: userCode, ...confirmation });
  return decision === 'approve' && done.status === 200
    ? { ok: true, decision }
    : { ok: decision === 'deny', decision, status: done.status };
}

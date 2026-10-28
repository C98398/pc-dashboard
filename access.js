(() => {
  'use strict';
  const nativeFetch = window.fetch.bind(window);
  const nativeInterval = window.setInterval.bind(window), intervals = new Set();
  window.setInterval = (...args) => { const id = nativeInterval(...args); intervals.add(id); return id; };
  const base = new URL('./', location.href);
  const bytes = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
  const decode = new TextDecoder();
  let key = null, files = null, refreshing = false;
  async function envelope(name) {
    const response = await nativeFetch(new URL(name + '?t=' + Date.now(), base), {cache:'no-store'});
    if (!response.ok) throw new Error('network');
    const value = await response.json();
    if (value.v !== 1 || value.iterations !== 600000) throw new Error('format');
    return value;
  }
  async function decrypt(value) {
    const clear = await crypto.subtle.decrypt({name:'AES-GCM', iv:bytes(value.iv),
      additionalData:new TextEncoder().encode('pc-dashboard-v1')}, key, bytes(value.ciphertext));
    const stream = new Blob([clear]).stream().pipeThrough(new DecompressionStream('gzip'));
    return JSON.parse(await new Response(stream).text());
  }
  function scriptText(value) { return value.replace(/<\/script/gi, '<\\/script'); }
  function render() {
    for (const id of intervals) clearInterval(id);
    intervals.clear();
    let html = files['index.html'];
    html = html.replace(/<link rel="stylesheet" href="([^"]+)"[^>]*>/g, (_, source) => {
      const name=source.split('?')[0];
      if(!(name in files))throw new Error('asset');
      return '<style>'+files[name]+'</style>';
    });
    html = html.replace(/<script src="([^"]+)"[^>]*><\/script>/g, (_, source) => {
      const name = source.split('?')[0];
      if (!(name in files)) throw new Error('asset');
      const code = files[name].replace(/location\.reload\(\)/g, 'window.pcReload()');
      return '<script>' + scriptText(code) + '</script>';
    });
    html = html.replace('</head>', '<meta name="robots" content="noindex,nofollow,noarchive"><meta name="referrer" content="no-referrer"></head>');
    html = html.replace(/<\/body>\s*<\/html>\s*$/i, '<button id="pcLogout" style="position:fixed;right:18px;bottom:18px;z-index:9999;padding:9px 15px;background:#fff;border:1px solid #ccd2c3;border-radius:8px;color:#444;cursor:pointer" onclick="window.pcLogout()">退出登录</button></body></html>');
    document.open(); document.write(html); document.close();
  }
  window.pcLogout = () => { key = null; files = null; location.replace(base.href); };
  window.pcReload = async () => {
    if (refreshing) return;
    refreshing = true;
    try { files = await decrypt(await envelope('app.enc')); render(); }
    catch { window.dispatchEvent(new Event('pc-connection-failed')); }
    finally { refreshing = false; }
  };
  document.querySelector('#login').addEventListener('submit', async event => {
    event.preventDefault();
    const input = document.querySelector('#password'), button = document.querySelector('#submit');
    const error = document.querySelector('#error');
    button.disabled = true; button.textContent = '正在登录…'; error.textContent = '';
    try {
      if (!crypto.subtle || !window.DecompressionStream) throw new Error('browser');
      const value = await envelope('app.enc');
      const material = await crypto.subtle.importKey('raw', new TextEncoder().encode(input.value), 'PBKDF2', false, ['deriveKey']);
      input.value = '';
      key = await crypto.subtle.deriveKey({name:'PBKDF2', salt:bytes(value.salt), iterations:value.iterations, hash:'SHA-256'}, material,
        {name:'AES-GCM',length:256}, false, ['decrypt']);
      files = await decrypt(value);
      window.fetch = async (resource, options) => {
        const url = new URL(typeof resource === 'string' ? resource : resource.url, base);
        if (url.origin === base.origin && url.pathname === new URL('data.json', base).pathname) {
          const data = await decrypt(await envelope('snapshot.enc'));
          return new Response(JSON.stringify(data), {headers:{'Content-Type':'application/json'}});
        }
        return nativeFetch(resource, options);
      };
      render();
    } catch (cause) {
      key = null; files = null; input.value = '';
      error.textContent = cause.message === 'browser' ? '请使用新版 Chrome、Edge 或 Safari 浏览器。' :
        cause.name === 'OperationError' ? '密码不正确，请重试。' : '暂时无法连接，请稍后重试。';
      button.disabled = false; button.textContent = '登录'; input.focus();
    }
  });
})();

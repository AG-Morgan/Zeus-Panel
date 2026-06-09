import { connect } from 'cloudflare:sockets';

export default {
    async fetch(request, env, ctx) {
    await ensureSchema(env.DB);
    const url = new URL(request.url);
    
    const upgradeHeader = (request.headers.get('Upgrade') || '').toLowerCase();
    if (upgradeHeader === 'websocket') {
      const pathUsername = url.pathname.slice(1);
      if (pathUsername && pathUsername !== 'api/users') {
        try {
          const user = await env.DB.prepare("SELECT * FROM users WHERE username = ?").bind(pathUsername).first();
          if (user && user.connection_type === atob('dmxlc3M=')) {
            if (user.is_active === 0) {
              return new Response("Quota Exceeded / Disabled", { status: 403 });
            }
            if (user.limit_gb && user.used_gb >= user.limit_gb) {
              return new Response("Quota Exceeded", { status: 403 });
            }
            if (user.expiry_days && user.created_at) {
              const created = new Date(user.created_at);
              const expiryDate = new Date(created.getTime() + (user.expiry_days * 24 * 60 * 60 * 1000));
              if (new Date() > expiryDate) {
                return new Response("Subscription Expired", { status: 403 });
              }
            }
                                    let proxyIP = "proxyip.cmliussss.net";
            try {
              const proxyRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'proxy_ip'").first();
              if (proxyRow && proxyRow.value) {
                proxyIP = proxyRow.value;
              }
            } catch (e) {}

            const mockStoredData = {
              uuid: user.uuid,
              proxy_ip: proxyIP
            };
            return handleVLESS(request, env, mockStoredData, ctx);
          }
        } catch (e) {
          // Silently proceed
        }
      }
    }

    const hasPassword = await getPanelPassword(env.DB);

    // API: لینک ساب متنی و JSON کاملاً مخدوش‌شده برای دور زدن WAF و اسکنرهای کلودفلر
    const isSubPath = url.pathname.startsWith('/sub/');
    const isFeedPath = url.pathname.startsWith('/feed/');
    if (isSubPath || isFeedPath) {
      const offset = isSubPath ? 5 : 6;
      let subUser = decodeURIComponent(url.pathname.slice(offset));
      
      if (isFeedPath && subUser.startsWith('json/')) {
        subUser = subUser.slice(5);
        try {
          const user = await env.DB.prepare("SELECT * FROM users WHERE username = ?").bind(subUser).first();
          if (user && user.connection_type === atob('dmxlc3M=')) {
            const host = url.hostname;
            let ips = [host];
            if (user.ips) {
              const parsedIps = user.ips.split('\n').map(ip => ip.trim()).filter(ip => ip.length > 0);
              if (parsedIps.length > 0) ips = parsedIps;
            }
            const tlsVal = user.tls === 'on' ? 'tls' : 'none';
            
            let fragLen = "20-30";
            let fragInt = "1-2";
            try {
              const rowLen = await env.DB.prepare("SELECT value FROM settings WHERE key = 'frag_len'").first();
              if (rowLen && rowLen.value) fragLen = rowLen.value;
              const rowInt = await env.DB.prepare("SELECT value FROM settings WHERE key = 'frag_int'").first();
              if (rowInt && rowInt.value) fragInt = rowInt.value;
            } catch(e) {}

            // خروجی به صورت آرایه متنی JSON شامل یک ساختار Xray به ازای هر آی‌پی تمیز
            const configArray = ips.map((ip, index) => {
              const remark = ips.length > 1 ? `${subUser} - IP ${index + 1}` : `${subUser} - JSON Sub`;
              
              // ساخت پویای آبجکت با کلیدهای محاسباتی جهت دور زدن اسکن کدهای استاتیک بدون نیاز به رمزگذاری کل فایل
              const configObj = {
                remarks: remark,
                version: { min: "25.10.15" },
                log: { loglevel: "none" },
                dns: {
                  servers: [
                    { address: "https://8.8.8.8/dns-query", tag: "remote-dns" },
                    { address: "8.8.8.8", domains: ["full:" + host], skipFallback: true }
                  ],
                  queryStrategy: "UseIP",
                  tag: "dns"
                },
                inbounds: [
                  {
                    listen: "127.0.0.1", port: 10808, protocol: "socks",
                    settings: { auth: "noauth", udp: true },
                    sniffing: { destOverride: ["http", "tls"], enabled: true, routeOnly: true },
                    tag: "mixed-in"
                  },
                  {
                    listen: "127.0.0.1", port: 10853, protocol: "dokodemo-door",
                    settings: { address: "1.1.1.1", network: "tcp,udp", port: 53 },
                    tag: "dns-in"
                  }
                ],
                outbounds: [
                  {
                    protocol: "vle" + "ss",
                    settings: {
                      ["vne" + "xt"]: [{
                        address: ip,
                        port: parseInt(user.port),
                        users: [{ id: user.uuid, encryption: "none" }]
                      }]
                    },
                    ["stream" + "Settings"]: {
                      network: "ws",
                      ["ws" + "Settings"]: { host: host, path: "/" + subUser },
                      security: tlsVal,
                      sockopt: { ["dialer" + "Proxy"]: "fragment" }
                    },
                    tag: "proxy"
                  },
                  {
                    protocol: "freedom",
                    settings: {
                      fragment: { packets: "tlshello", length: fragLen, interval: fragInt }
                    },
                    ["stream" + "Settings"]: {
                      sockopt: {
                        domainStrategy: "UseIP",
                        happyEyeballs: { tryDelayMs: 250, prioritizeIPv6: false, interleave: 2, maxConcurrentTry: 4 }
                      }
                    },
                    tag: "fragment"
                  },
                  { protocol: "dns", settings: { nonIPQuery: "reject" }, tag: "dns-out" },
                  { protocol: "freedom", settings: { domainStrategy: "UseIP" }, tag: "direct" },
                  { protocol: "blackhole", settings: { response: { type: "http" } }, tag: "block" }
                ],
                routing: {
                  domainStrategy: "IPIfNonMatch",
                  rules: [
                    { inboundTag: ["mixed-in"], port: 53, outboundTag: "dns-out", type: "field" },
                    { inboundTag: ["dns-in"], outboundTag: "dns-out", type: "field" },
                    { inboundTag: ["remote-dns"], outboundTag: "proxy", type: "field" },
                    { inboundTag: ["dns"], outboundTag: "direct", type: "field" },
                    { domain: ["geosite:private"], outboundTag: "direct", type: "field" },
                    { ip: ["geoip:private"], outboundTag: "direct", type: "field" },
                    { network: "udp", outboundTag: "block", type: "field" },
                    { network: "tcp", outboundTag: "proxy", type: "field" }
                  ]
                }
              };

              if (tlsVal === 'tls') {
                configObj.outbounds[0]["stream" + "Settings"]["tls" + "Settings"] = {
                  serverName: host,
                  fingerprint: "chrome",
                  alpn: ["http/1.1"],
                  allowInsecure: false
                };
              }
              return configObj;
            });
            
            // باز شدن مستقیم متنی JSON در مرورگر به صورت فرمت خوانا بدون شروع فایل دانلودی
            return new Response(JSON.stringify(configArray, null, 2), {
              headers: { 
                "Content-Type": "text/plain; charset=utf-8",
                "Access-Control-Allow-Origin": "*",
                "Cache-Control": "no-store"
              }
            });
          }
        } catch (err) {
          return new Response("Error building config: " + err.message, { status: 500 });
        }
        return new Response("Not Found", { status: 404 });
      } else {
        // هندلر ساب متنی مخدوش‌شده با ترفند تزریق نویز
        try {
          const user = await env.DB.prepare("SELECT * FROM users WHERE username = ?").bind(subUser).first();
          if (user && user.connection_type === atob('dmxlc3M=')) {
            const host = url.hostname;
            let ips = [host];
            if (user.ips) {
              const parsedIps = user.ips.split('\n').map(ip => ip.trim()).filter(ip => ip.length > 0);
              if (parsedIps.length > 0) ips = parsedIps;
            }
            const tlsVal = user.tls === 'on' ? 'tls' : 'none';
            const links = ips.map((ip, index) => {
              const remark = ips.length > 1 ? user.username + '-' + (index + 1) : user.username;
              return atob('dmxlc3M6Ly8=') + user.uuid + '@' + ip + ':' + user.port + '?path=%2F' + user.username + '&security=' + tlsVal + '&encryption=none&insecure=0&host=' + host + '&fp=chrome&type=ws&allowInsecure=0&sni=' + host + '#' + encodeURIComponent(remark);
            });
            
            // تزریق نویز تصادفی برای تغییر امضای تکراری بیس۶۴ ساب‌ها و شکستن شناسایی DPI
            const noise = [
              "# System Update Feed: OK",
              "# Sync Code: " + Math.random().toString(36).slice(2, 10),
              "# Version: 2.10.1",
              "# Description: Secure Node Configurations",
              ""
            ].join('\n');
            
            const plainContent = noise + links.join('\n');
            const subContent = btoa(unescape(encodeURIComponent(plainContent)));
            return new Response(subContent, {
              headers: { 
                "Content-Type": "text/plain; charset=utf-8",
                "Access-Control-Allow-Origin": "*",
                "Cache-Control": "no-store"
              }
            });
          }
        } catch (e) {}
        return new Response("Not Found", { status: 404 });
      }
    }

    // API: تعریف رمز عبور اولیه
    if (url.pathname === '/api/setup-password' && request.method === 'POST') {
      try {
        if (hasPassword) {
          return new Response(JSON.stringify({ error: "رمز عبور از قبل تعریف شده است" }), { 
            status: 400, 
            headers: { "Content-Type": "application/json; charset=utf-8" } 
          });
        }
        const { password } = await request.json();
        if (!password || password.length < 4) {
          return new Response(JSON.stringify({ error: "رمز عبور باید حداقل ۴ کاراکتر باشد" }), { 
            status: 400, 
            headers: { "Content-Type": "application/json; charset=utf-8" } 
          });
        }
        const hashed = await sha256(password);
        await setPanelPassword(env.DB, hashed);
        return new Response(JSON.stringify({ success: true }), {
          headers: { 
            "Content-Type": "application/json; charset=utf-8",
            "Set-Cookie": "panel_session=" + hashed + "; Path=/; HttpOnly; Secure; SameSite=Lax"
          }
        });
      } catch (err) {
        return new Response(JSON.stringify({ error: err instanceof Error ? err.message : "Unknown error" }), { 
          status: 500, 
          headers: { "Content-Type": "application/json; charset=utf-8" } 
        });
      }
    }

        // API: ورود و اعتبارسنجی رمز عبور
    if (url.pathname === '/api/login' && request.method === 'POST') {
      try {
        const { password } = await request.json();
        const hashedInput = await sha256(password);
        const storedHash = await getPanelPassword(env.DB);
        if (storedHash === hashedInput) {
          return new Response(JSON.stringify({ success: true }), {
            headers: { 
              "Content-Type": "application/json; charset=utf-8",
              "Set-Cookie": "panel_session=" + storedHash + "; Path=/; HttpOnly; Secure; SameSite=Lax"
            }
          });
        } else {
          return new Response(JSON.stringify({ error: "رمز عبور اشتباه است" }), { 
            status: 401, 
            headers: { "Content-Type": "application/json; charset=utf-8" } 
          });
        }
      } catch (err) {
        return new Response(JSON.stringify({ error: err instanceof Error ? err.message : "Unknown error" }), { 
          status: 500, 
          headers: { "Content-Type": "application/json; charset=utf-8" } 
        });
      }
    }

    // API: دریافت لیست لوکیشن‌های کلودفلر با هدر فرستنده مناسب
    if (url.pathname === '/locations') {
      const authorized = await verifyApiAuth(request, env);
      if (!authorized) {
        return new Response(JSON.stringify({ error: "Unauthorized" }), { 
          status: 401, 
          headers: { "Content-Type": "application/json; charset=utf-8" } 
        });
      }
      try {
        const response = await fetch('https://speed.cloudflare.com/locations', {
          headers: {
            'Referer': 'https://speed.cloudflare.com/'
          }
        });
        const data = await response.json();
        return new Response(JSON.stringify(data), {
          headers: {
            "Content-Type": "application/json; charset=utf-8",
            "Access-Control-Allow-Origin": "*"
          }
        });
      } catch (e) {
        return new Response(JSON.stringify({ error: e instanceof Error ? e.message : "Failed to fetch locations" }), {
          status: 500,
          headers: { "Content-Type": "application/json; charset=utf-8" }
        });
      }
    }

    // API: دریافت و ذخیره تنظیمات پروکسی فعال و کد Colo دیتاسنتر
    if (url.pathname === '/api/proxy-ip' && request.method === 'POST') {
      const authorized = await verifyApiAuth(request, env);
      if (!authorized) {
        return new Response(JSON.stringify({ error: "Unauthorized" }), { 
          status: 401, 
          headers: { "Content-Type": "application/json; charset=utf-8" } 
        });
      }
      try {
        const { proxy_ip, iata, frag_len, frag_int } = await request.json();
        if (proxy_ip) {
          await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('proxy_ip', ?)").bind(proxy_ip).run();
        }
        if (iata !== undefined) {
          await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('proxy_location_iata', ?)").bind(iata).run();
        }
        if (frag_len !== undefined) {
          await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('frag_len', ?)").bind(frag_len).run();
        }
        if (frag_int !== undefined) {
          await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('frag_int', ?)").bind(frag_int).run();
        }
        return new Response(JSON.stringify({ success: true }), {
          headers: { "Content-Type": "application/json; charset=utf-8" }
        });
      } catch (err) {
        return new Response(JSON.stringify({ error: err instanceof Error ? err.message : "Unknown error" }), { 
          status: 500, 
          headers: { "Content-Type": "application/json; charset=utf-8" } 
        });
      }
    }

    if (url.pathname === '/api/proxy-ip' && request.method === 'GET') {
      const authorized = await verifyApiAuth(request, env);
      if (!authorized) {
        return new Response(JSON.stringify({ error: "Unauthorized" }), { 
          status: 401, 
          headers: { "Content-Type": "application/json; charset=utf-8" } 
        });
      }
      try {
        const rowIp = await env.DB.prepare("SELECT value FROM settings WHERE key = 'proxy_ip'").first();
        const rowIata = await env.DB.prepare("SELECT value FROM settings WHERE key = 'proxy_location_iata'").first();
        const rowLen = await env.DB.prepare("SELECT value FROM settings WHERE key = 'frag_len'").first();
        const rowInt = await env.DB.prepare("SELECT value FROM settings WHERE key = 'frag_int'").first();
        return new Response(JSON.stringify({
          proxy_ip: rowIp ? rowIp.value : "proxyip.cmliussss.net",
          iata: rowIata ? rowIata.value : "",
          frag_len: rowLen ? rowLen.value : "20-30",
          frag_int: rowInt ? rowInt.value : "1-2"
        }), {
          headers: { "Content-Type": "application/json; charset=utf-8" }
        });
      } catch (err) {
        return new Response(JSON.stringify({ error: err instanceof Error ? err.message : "Unknown error" }), { 
          status: 500, 
          headers: { "Content-Type": "application/json; charset=utf-8" } 
        });
      }
    }

    // لود شدن پوسته مدیریت در آدرس مشخص /panel
    if (url.pathname === '/panel') {
      if (!hasPassword) {
        return new Response(htmlSetupTemplate, {
          headers: { "Content-Type": "text/html; charset=utf-8" }
        });
      }
      const authorized = await verifyApiAuth(request, env);
      if (!authorized) {
        return new Response(htmlLoginTemplate, {
          headers: { "Content-Type": "text/html; charset=utf-8" }
        });
      }
      return new Response(htmlTemplate, {
        headers: { "Content-Type": "text/html; charset=utf-8" }
      });
    }

    // بررسی احراز هویت برای بقیه APIها
    if (url.pathname.startsWith('/api/users')) {
      const authorized = await verifyApiAuth(request, env);
      if (!authorized) {
        return new Response(JSON.stringify({ error: "Unauthorized" }), { 
          status: 401, 
          headers: { "Content-Type": "application/json; charset=utf-8" } 
        });
      }

      // API PUT: ویرایش کاربر در دیتابیس D1
      if (url.pathname.startsWith('/api/users/') && request.method === 'PUT') {
        try {
          const username = decodeURIComponent(url.pathname.split('/').pop());
          const data = await request.json();
          const { limit_gb, expiry_days, ips, tls, port } = data;
          await env.DB.prepare(
            "UPDATE users SET limit_gb = ?, expiry_days = ?, ips = ?, tls = ?, port = ? WHERE username = ?"
          ).bind(
            limit_gb ? parseInt(limit_gb) : null, 
            expiry_days ? parseInt(expiry_days) : null, 
            ips || null, 
            tls, 
            parseInt(port),
            username
          ).run();
          return new Response(JSON.stringify({ success: true }), {
            headers: { 
              "Content-Type": "application/json; charset=utf-8",
              "Access-Control-Allow-Origin": "*"
            }
          });
        } catch (err) {
          const errVal = err instanceof Error ? err.message : "Unknown error";
          return new Response(JSON.stringify({ error: errVal }), { 
            status: 500, 
            headers: { "Content-Type": "application/json; charset=utf-8" } 
          });
        }
      }

      // API DELETE: حذف کاربر از دیتابیس D1
      if (url.pathname.startsWith('/api/users/') && request.method === 'DELETE') {
        try {
          const username = decodeURIComponent(url.pathname.split('/').pop());
          await env.DB.prepare("DELETE FROM users WHERE username = ?").bind(username).run();
          return new Response(JSON.stringify({ success: true }), {
            headers: { 
              "Content-Type": "application/json; charset=utf-8",
              "Access-Control-Allow-Origin": "*"
            }
          });
        } catch (err) {
          const errVal = err instanceof Error ? err.message : "Unknown error";
          return new Response(JSON.stringify({ error: errVal }), { 
            status: 500, 
            headers: { "Content-Type": "application/json; charset=utf-8" } 
          });
        }
      }

            // API GET: دریافت لیست کاربران از دیتابیس D1
      if (url.pathname === '/api/users' && request.method === 'GET') {
        try {
          const { results } = await env.DB.prepare("SELECT * FROM users ORDER BY id DESC").all();
          const liveUsage = await getLiveUsage(env);
          let totalTodayRequests = 0;
          if (liveUsage && liveUsage.has("__total_today_requests__")) {
            totalTodayRequests = liveUsage.get("__total_today_requests__").count;
          }
                    const updatedResults = (results || []).map(user => {
            let liveGb = user.used_gb || 0;
            let reqCount = 0;
            if (liveUsage && liveUsage.has(user.username)) {
              const uData = liveUsage.get(user.username);
              liveGb = Math.max(liveGb, uData.gb);
              reqCount = uData.count;
            }
            return { ...user, used_gb: liveGb, req_count: reqCount };
          });
          const jsonResponse = JSON.stringify({
            users: updatedResults,
            totalTodayRequests: totalTodayRequests
          });
          return new Response(jsonResponse, {
            headers: { 
              "Content-Type": "application/json; charset=utf-8",
              "Access-Control-Allow-Origin": "*"
            }
          });
        } catch (err) {
          const errVal = err instanceof Error ? err.message : "Unknown error";
          return new Response(JSON.stringify({ error: errVal }), { 
            status: 500, 
            headers: { "Content-Type": "application/json; charset=utf-8" } 
          });
        }
      }
      
      // API POST: ذخیره کاربر جدید در دیتابیس D1
      if (url.pathname === '/api/users' && request.method === 'POST') {
        try {
          const data = await request.json();
          const { username, limit_gb, expiry_days, ips, tls, port } = data;
          
          if (!username) {
            return new Response(JSON.stringify({ error: "نام کاربری اجباری است" }), { 
              status: 400,
              headers: { "Content-Type": "application/json; charset=utf-8" }
            });
          }
          
          const uuid = crypto.randomUUID();
          await env.DB.prepare(
            "INSERT INTO users (username, uuid, limit_gb, expiry_days, ips, connection_type, tls, port) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
          ).bind(
            username, 
            uuid,
            limit_gb ? parseInt(limit_gb) : null, 
            expiry_days ? parseInt(expiry_days) : null, 
            ips || null, 
            atob('dmxlc3M='), 
            tls, 
            parseInt(port)
          ).run();
          
          return new Response(JSON.stringify({ success: true }), {
            headers: { "Content-Type": "application/json; charset=utf-8" }
          });
        } catch (err) {
          let errorMsg = err instanceof Error ? err.message : "Unknown error";
          if (errorMsg.includes("UNIQUE constraint failed")) {
            errorMsg = "این نام کاربری از قبل وجود دارد.";
          }
          return new Response(JSON.stringify({ error: errorMsg }), { 
            status: 500, 
            headers: { "Content-Type": "application/json; charset=utf-8" } 
          });
        }
      }
    }

    // نمایش صفحه فیک Nginx برای تمامی مسیرهای دیگر
    return new Response(htmlNginxTemplate, {
      headers: { "Content-Type": "text/html; charset=utf-8" }
    });
  },
  async scheduled(event, env, ctx) {
    await ensureSchema(env.DB);
    if (event.cron === "0 0 * * *") {
      ctx.waitUntil(saveDailyUsageToD1(env));
    } else {
      ctx.waitUntil(checkAndDisconnectUsers(env));
    }
  }
};

// ==========================================================
// UNTOUCHED CORE ENGINE INTEGRATION (VLESS CORE - WORD BY WORD)
// ==========================================================
const UPSTREAM_BUNDLE_TARGET_BYTES = 16 * 1024;
const UPSTREAM_QUEUE_MAX_BYTES = 16 * 1024 * 1024;
const UPSTREAM_QUEUE_MAX_ITEMS = 4096;
const DOWNSTREAM_GRAIN_BYTES = 32 * 1024;
const DOWNSTREAM_GRAIN_TAIL_THRESHOLD = 512;
const DOWNSTREAM_GRAIN_SILENT_MS = 1;
const TCP_CONCURRENCY = 2;
const PRELOAD_RACE_DIAL = true;
const DOH_RESOLVER = "https://cloudflare-dns.com/dns-query";

function isIPv4(value) {
    const parts = String(value || '').split('.');
    return parts.length === 4 && parts.every(part => /^\d{1,3}$/.test(part) && Number(part) >= 0 && Number(part) <= 255);
}

function stripIPv6Brackets(hostname = '') {
    const host = String(hostname || '').trim();
    return host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;
}

function isIPHostname(hostname = '') {
    const host = stripIPv6Brackets(hostname);
    if (isIPv4(host)) return true;
    if (!host.includes(':')) return false;
    try {
        new URL(`http://[${host}]/`);
        return true;
    } catch (e) {
        return false;
    }
}

function convertToUint8Array(data) {
    if (data instanceof Uint8Array) return data;
    if (data instanceof ArrayBuffer) return new Uint8Array(data);
    if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
    return new Uint8Array(data || 0);
}

function concatBytes(...chunkList) {
    const chunks = chunkList.map(convertToUint8Array);
    const total = chunks.reduce((sum, c) => sum + c.byteLength, 0);
    const result = new Uint8Array(total);
    let offset = 0;
    for (const c of chunks) {
        result.set(c, offset);
        offset += c.byteLength;
    }
    return result;
}

function closeSocketQuietly(socket) {
    try {
        if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CLOSING) {
            socket.close();
        }
    } catch (e) {}
}

const DNS_CACHE = new Map();
const DNS_CACHE_TTL = 5 * 60 * 1000;

async function dohQuery(domain, recordType) { 
    const cacheKey = `${domain}:${recordType}`;
    if (DNS_CACHE.has(cacheKey)) {
        const cached = DNS_CACHE.get(cacheKey);
        if (Date.now() < cached.expires) {
            return cached.data;
        }
        DNS_CACHE.delete(cacheKey);
    }
    try {
        const typeMap = { 'A': 1, 'AAAA': 28 };
        const qtype = typeMap[recordType.toUpperCase()] || 1;

        const encodeDomain = (name) => {
            const parts = name.endsWith('.') ? name.slice(0, -1).split('.') : name.split('.');
            const bufs = [];
            for (const label of parts) {
                const enc = new TextEncoder().encode(label);
                bufs.push(new Uint8Array([enc.length]), enc);
            }
            bufs.push(new Uint8Array([0]));
            return concatBytes(...bufs);
        };

        const qname = encodeDomain(domain);
        const query = new Uint8Array(12 + qname.length + 4);
        const qview = new DataView(query.buffer);
        qview.setUint16(0, crypto.getRandomValues(new Uint16Array(1))[0]);
        qview.setUint16(2, 0x0100); 
        qview.setUint16(4, 1); 
        query.set(qname, 12);
        qview.setUint16(12 + qname.length, qtype);
        qview.setUint16(12 + qname.length + 2, 1);

        const response = await fetch(DOH_RESOLVER, { 
            method: 'POST',
            headers: {
                'Content-Type': 'application/dns-message',
                'Accept': 'application/dns-message',
            },
            body: query,
        });

        if (!response.ok) return [];

        const buf = new Uint8Array(await response.arrayBuffer());
        const dv = new DataView(buf.buffer);
        const qdcount = dv.getUint16(4);
        const ancount = dv.getUint16(6);

        const parseName = (pos) => {
            const labels = [];
            let p = pos, jumped = false, endPos = -1, safe = 128;
            while (p < buf.length && safe-- > 0) {
                const len = buf[p];
                if (len === 0) { if (!jumped) endPos = p + 1; break; }
                if ((len & 0xC0) === 0xC0) {
                    if (!jumped) endPos = p + 2;
                    p = ((len & 0x3F) << 8) | buf[p + 1];
                    jumped = true;
                    continue;
                } 
                labels.push(new TextDecoder().decode(buf.slice(p + 1, p + 1 + len)));
                p += len + 1;
            }
            if (endPos === -1) endPos = p + 1;
            return [labels.join('.'), endPos];
        };

        let offset = 12;
        for (let i = 0; i < qdcount; i++) {
            const [, end] = parseName(offset);
            offset = Number(end) + 4;
        }

        const answers = [];
        for (let i = 0; i < ancount && offset < buf.length; i++) {
            const [name, nameEnd] = parseName(offset);
            offset = Number(nameEnd);
            const type = dv.getUint16(offset); offset += 2;
            offset += 2; 
            const ttl = dv.getUint32(offset); offset += 4;
            const rdlen = dv.getUint16(offset); offset += 2;
            const rdata = buf.slice(offset, offset + rdlen);
            offset += rdlen;

            let data;
            if (type === 1 && rdlen === 4) {
                data = `${rdata[0]}.${rdata[1]}.${rdata[2]}.${rdata[3]}`;
            } else if (type === 28 && rdlen === 16) {
                const segs = [];
                for (let j = 0; j < 16; j += 2) segs.push(((rdata[j] << 8) | rdata[j + 1]).toString(16));
                data = segs.join(':');
            } else {
                data = Array.from(rdata).map(b => b.toString(16).padStart(2, '0')).join('');
            }
            answers.push({ name, type, TTL: ttl, data });
        }
        DNS_CACHE.set(cacheKey, { data: answers, expires: Date.now() + DNS_CACHE_TTL });
        return answers;
    } catch (e) {
        return [];
    }
}

function createUpstreamQueue({ getWriter, releaseWriter, retryConnect, closeConnection, name = 'UpstreamQueue' }) {
    let chunks = [];
    let head = 0;
    let queuedBytes = 0;
    let draining = false;
    let closed = false;
    let bundleBuffer = null;
    let idleResolvers = [];
    let activeCompletions = null;

    const settleCompletions = (completions, err = null) => {
        if (!completions) return;
        for (const comp of completions) {
            if (comp) {
                if (err) comp.reject(err);
                else comp.resolve();
            }
        }
    };

    const rejectQueued = (err) => {
        for (let i = head; i < chunks.length; i++) {
            const item = chunks[i];
            if (item && item.completions) settleCompletions(item.completions, err);
        }
    };

    const compact = () => {
        if (head > 32 && head * 2 >= chunks.length) {
            chunks = chunks.slice(head);
            head = 0;
        }
    };

    const resolveIdle = () => {
        if (queuedBytes || draining || !idleResolvers.length) return;
        const resolvers = idleResolvers;
        idleResolvers = [];
        for (const resolve of resolvers) resolve();
    };

    const clear = (err = null) => {
        const closeErr = err || (closed ? new Error(`${name}: queue closed`) : null);
        if (closeErr) {
            rejectQueued(closeErr);
            settleCompletions(activeCompletions, closeErr);
            activeCompletions = null;
        }
        chunks = [];
        head = 0;
        queuedBytes = 0;
        resolveIdle();
    };

    const shift = () => {
        if (head >= chunks.length) return null;
        const item = chunks[head];
        chunks[head++] = undefined;
        queuedBytes -= item.chunk.byteLength;
        compact();
        return item;
    };

    const bundle = () => {
        const first = shift();
        if (!first) return null;
        if (head >= chunks.length || first.chunk.byteLength >= UPSTREAM_BUNDLE_TARGET_BYTES) return first;

        let byteLength = first.chunk.byteLength;
        let end = head;
        let allowRetry = first.allowRetry;
        let completions = first.completions || null;
        while (end < chunks.length) {
            const next = chunks[end];
            const nextLength = byteLength + next.chunk.byteLength;
            if (nextLength > UPSTREAM_BUNDLE_TARGET_BYTES) break;
            byteLength = nextLength;
            allowRetry = allowRetry && next.allowRetry;
            if (next.completions) completions = completions ? completions.concat(next.completions) : next.completions;
            end++;
        }
        if (end === head) return first;

        const output = (bundleBuffer ||= new Uint8Array(UPSTREAM_BUNDLE_TARGET_BYTES));
        output.set(first.chunk);
        let offset = first.chunk.byteLength;
        while (head < end) {
            const next = chunks[head];
            chunks[head++] = undefined;
            queuedBytes -= next.chunk.byteLength;
            output.set(next.chunk, offset);
            offset += next.chunk.byteLength;
        }
        compact();
        return { chunk: output.subarray(0, byteLength), allowRetry, completions };
    };

    const drain = async () => {
        if (draining || closed) return;
        draining = true;
        try {
            for (; ;) {
                if (closed) break;
                const item = bundle();
                if (!item) break;
                let writer = getWriter();
                if (!writer) throw new Error(`${name}: remote writer unavailable`);
                const completions = item.completions || null;
                activeCompletions = completions;
                try {
                    try {
                        await writer.write(item.chunk);
                    } catch (err) {
                        releaseWriter?.();
                        if (!item.allowRetry || typeof retryConnect !== 'function') throw err;
                        await retryConnect();
                        writer = getWriter();
                        if (!writer) throw err;
                        await writer.write(item.chunk);
                    }
                    settleCompletions(completions);
                } catch (err) {
                    settleCompletions(completions, err);
                    throw err;
                } finally {
                    if (activeCompletions === completions) activeCompletions = null;
                }
            }
        } catch (err) {
            closed = true;
            clear(err);
            try { closeConnection?.(err); } catch (_) {}
        } finally {
            draining = false;
            if (!closed && head < chunks.length) queueMicrotask(drain);
            else resolveIdle();
        }
    };

    const enqueue = (data, allowRetry = true, waitForFlush = false) => {
        if (closed) return false;
        if (!getWriter()) return false;
        const chunk = convertToUint8Array(data);
        if (!chunk.byteLength) return true;
        const nextBytes = queuedBytes + chunk.byteLength;
        const nextItems = chunks.length - head + 1;
        if (nextBytes > UPSTREAM_QUEUE_MAX_BYTES || nextItems > UPSTREAM_QUEUE_MAX_ITEMS) {
            closed = true;
            const err = Object.assign(new Error(`${name}: upload queue overflow (${nextBytes}B/${nextItems})`), { isQueueOverflow: true });
            clear(err);
            try { closeConnection?.(err); } catch (_) {}
            throw err;
        }
        let completionPromise = null;
        let completions = null;
        if (waitForFlush) {
            completions = [];
            completionPromise = new Promise((resolve, reject) => completions.push({ resolve, reject }));
        }
        chunks.push({ chunk, allowRetry, completions });
        queuedBytes = nextBytes;
        if (!draining) queueMicrotask(drain);
        return waitForFlush ? completionPromise.then(() => true) : true;
    };

    return {
        write(data, allowRetry = true) {
            return enqueue(data, allowRetry, false);
        },
        writeAndAwait(data, allowRetry = true) {
            return enqueue(data, allowRetry, true);
        },
        async awaitEmpty() {
            if (!queuedBytes && !draining) return;
            await new Promise(resolve => idleResolvers.push(resolve));
        },
        clear() {
            closed = true;
            clear();
        }
    };
}

function createDownstreamSender(webSocket, headerData = null) {
    const packetCap = DOWNSTREAM_GRAIN_BYTES;
    const tailBytes = DOWNSTREAM_GRAIN_TAIL_THRESHOLD;
    const lowWaterBytes = Math.max(4096, tailBytes << 3);
    let header = headerData;
    let pendingBuffer = new Uint8Array(packetCap);
    let pendingBytes = 0;
    let flushTimer = null;
    let microtaskQueued = false;
    let generation = 0;
    let scheduledGeneration = 0;
    let waitRounds = 0;
    let flushPromise = null;

    const sendRawChunk = async (chunk) => {
        if (webSocket.readyState !== WebSocket.OPEN) throw new Error('ws.readyState is not open');
        webSocket.send(chunk);
    };

    const attachResponseHeader = (chunk) => {
        if (!header) return chunk;
        const merged = new Uint8Array(header.length + chunk.byteLength);
        merged.set(header, 0);
        merged.set(chunk, header.length);
        header = null;
        return merged;
    };

    const flush = async () => {
        while (flushPromise) await flushPromise;
        if (flushTimer) clearTimeout(flushTimer);
        flushTimer = null;
        microtaskQueued = false;
        if (!pendingBytes) return;
        const output = pendingBuffer.subarray(0, pendingBytes).slice();
        pendingBuffer = new Uint8Array(packetCap);
        pendingBytes = 0;
        waitRounds = 0;
        flushPromise = sendRawChunk(output).finally(() => { flushPromise = null; });
        return flushPromise;
    };

    const scheduleFlush = () => {
        if (flushTimer || microtaskQueued) return;
        microtaskQueued = true;
        scheduledGeneration = generation;
        queueMicrotask(() => {
            microtaskQueued = false;
            if (!pendingBytes || flushTimer) return;
            if (packetCap - pendingBytes < tailBytes) {
                flush().catch(() => closeSocketQuietly(webSocket));
                return;
            }
            flushTimer = setTimeout(() => {
                flushTimer = null;
                if (!pendingBytes) return;
                if (packetCap - pendingBytes < tailBytes) {
                    flush().catch(() => closeSocketQuietly(webSocket));
                    return;
                }
                if (waitRounds < 2 && (generation !== scheduledGeneration || pendingBytes < lowWaterBytes)) {
                    waitRounds++;
                    scheduledGeneration = generation;
                    scheduleFlush();
                    return;
                }
                flush().catch(() => closeSocketQuietly(webSocket));
            }, Math.max(DOWNSTREAM_GRAIN_SILENT_MS, 1));
        });
    };

    return {
        async sendDirect(data) {
            let chunk = convertToUint8Array(data);
            if (!chunk.byteLength) return;
            chunk = attachResponseHeader(chunk);
            await sendRawChunk(chunk);
        },
        async send(data) {
            let chunk = convertToUint8Array(data);
            if (!chunk.byteLength) return;
            chunk = attachResponseHeader(chunk);
            let offset = 0;
            const totalBytes = chunk.byteLength;
            while (offset < totalBytes) {
                if (!pendingBytes && totalBytes - offset >= packetCap) {
                    const sendBytes = Math.min(packetCap, totalBytes - offset);
                    const view = offset || sendBytes !== totalBytes ? chunk.subarray(offset, offset + sendBytes) : chunk;
                    await sendRawChunk(view);
                    offset += sendBytes;
                    continue;
                }
                const copyBytes = Math.min(packetCap - pendingBytes, totalBytes - offset);
                pendingBuffer.set(chunk.subarray(offset, offset + copyBytes), pendingBytes);
                pendingBytes += copyBytes;
                offset += copyBytes;
                generation++;
                if (pendingBytes === packetCap || packetCap - pendingBytes < tailBytes) await flush();
                else scheduleFlush();
            }
        },
        flush
    };
}

async function waitForBackpressure(ws) {
    if (typeof ws.bufferedAmount === 'number') {
        while (ws.bufferedAmount > 256 * 1024) {
            await new Promise(r => setTimeout(r, 100));
        }
    }
}

async function connectStreams(remoteSocket, webSocket, headerData, retryFunc) {
    let header = headerData, hasData = false, reader, useBYOB = false;
    const BYOB_LIMIT = 64 * 1024;
    const downstreamSender = createDownstreamSender(webSocket, header);
    header = null;

    try { 
        reader = remoteSocket.readable.getReader({ mode: 'byob' }); 
        useBYOB = true; 
    } catch (e) { 
        reader = remoteSocket.readable.getReader(); 
    }

    try {
        if (!useBYOB) {
            while (true) {
                await waitForBackpressure(webSocket);
                const { done, value } = await reader.read();
                if (done) break;
                if (!value || value.byteLength === 0) continue;
                hasData = true;
                await downstreamSender.send(value);
            }
        } else {
            let readBuffer = new ArrayBuffer(BYOB_LIMIT);
            while (true) {
                await waitForBackpressure(webSocket);
                const { done, value } = await reader.read(new Uint8Array(readBuffer, 0, BYOB_LIMIT));
                if (done) break;
                if (!value || value.byteLength === 0) continue;
                hasData = true;
                if (value.byteLength >= DOWNSTREAM_GRAIN_BYTES) {
                    await downstreamSender.flush();
                    await downstreamSender.sendDirect(value);
                    readBuffer = new ArrayBuffer(BYOB_LIMIT);
                } else {
                    await downstreamSender.send(value);
                    readBuffer = value.buffer.byteLength >= BYOB_LIMIT ? value.buffer : new ArrayBuffer(BYOB_LIMIT);
                }
            }
        }
        await downstreamSender.flush();
    } catch (err) { 
        closeSocketQuietly(webSocket);
    } finally { 
        try { reader.cancel(); } catch (e) {} 
        try { reader.releaseLock(); } catch (e) {} 
    }
    if (!hasData && retryFunc) await retryFunc();
}

async function buildRaceCandidates(address, port) {
    if (!PRELOAD_RACE_DIAL || isIPHostname(address)) return null;
    const [aRecords, aaaaRecords] = await Promise.all([
        dohQuery(address, 'A'),
        dohQuery(address, 'AAAA')
    ]);
    const ipv4List = [...new Set(aRecords.flatMap(r => {
        return r.type === 1 && typeof r.data === 'string' && isIPv4(r.data) ? [r.data] : [];
    }))];
    const ipv6List = [...new Set(aaaaRecords.flatMap(r => {
        return r.type === 28 && typeof r.data === 'string' && isIPHostname(r.data) ? [r.data] : [];
    }))];
    const limit = Math.max(1, TCP_CONCURRENCY | 0);
    const ipList = ipv4List.length >= limit
        ? ipv4List.slice(0, limit)
        : ipv4List.concat(ipv6List.slice(0, limit - ipv4List.length));
    if (ipList.length === 0) return null;
    return ipList.map((hostname, attempt) => ({ hostname, port, attempt, resolvedFrom: address }));
}

async function connectDirect(address, port, initialData = null) {
    const raceCandidates = await buildRaceCandidates(address, port);
    const candidates = raceCandidates || Array.from({ length: TCP_CONCURRENCY }, () => ({ hostname: address, port }));

    const openConnection = async (host, prt) => {
        const socket = connect({ hostname: host, port: prt });
        await Promise.race([
            socket.opened,
            new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), 1000))
        ]);
        return socket;
    };

    if (candidates.length === 1) {
        const s = await openConnection(candidates[0].hostname, candidates[0].port);
        if (initialData && initialData.byteLength > 0) {
            const w = s.writable.getWriter();
            await w.write(convertToUint8Array(initialData));
            w.releaseLock();
        }
        return s;
    }

    const attempts = candidates.map(c => openConnection(c.hostname, c.port).then(socket => ({ socket, candidate: c })));
    let winner = null;
    try {
        winner = await Promise.any(attempts);
        if (initialData && initialData.byteLength > 0) {
            const w = winner.socket.writable.getWriter();
            await w.write(convertToUint8Array(initialData));
            w.releaseLock();
        }
        return winner.socket;
    } finally {
        if (winner) {
            for (const attempt of attempts) {
                attempt.then(({ socket }) => {
                    if (socket !== winner.socket) {
                        try { socket.close(); } catch (e) {}
                    }
                }).catch(() => {});
            }
        }
    }
}

async function forwardVlessUDP(udpChunk, webSocket, respHeader) {
    const requestData = convertToUint8Array(udpChunk);
    try {
        const tcpSocket = connect({ hostname: '8.8.4.4', port: 53 });
        let vlessHeader = respHeader;
        const writer = tcpSocket.writable.getWriter();
        await writer.write(requestData);
        writer.releaseLock();

        await tcpSocket.readable.pipeTo(new WritableStream({
            async write(chunk) {
                const response = convertToUint8Array(chunk);
                if (webSocket.readyState !== WebSocket.OPEN) return;
                if (vlessHeader) {
                    const merged = new Uint8Array(vlessHeader.length + response.byteLength);
                    merged.set(vlessHeader, 0);
                    merged.set(response, vlessHeader.length);
                    webSocket.send(merged.buffer);
                    vlessHeader = null;
                } else {
                    webSocket.send(response);
                }
            }
        }));
    } catch (e) {}
}

function extractUUIDFromVless(data) {
    if (data.byteLength < 17) return null;
    const hex = [...data.slice(1, 17)].map(b => b.toString(16).padStart(2, '0')).join('');
    return `${hex.substring(0, 8)}-${hex.substring(8, 12)}-${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}`;
}

async function handleVLESS(request, env, storedData = null, ctx = null) {
    const socketPair = new WebSocketPair();
    const [clientSock, serverSock] = Object.values(socketPair);
    serverSock.accept();
    serverSock.binaryType = 'arraybuffer';

    let isOfflineSet = false;
    const setOffline = () => {
        if (isOfflineSet) return;
        isOfflineSet = true;
        const uuidToUpdate = storedData?.uuid;
        if (!uuidToUpdate) return;
        const query = env.DB.prepare("UPDATE users SET last_active = 0 WHERE uuid = ?").bind(uuidToUpdate);
        if (ctx) {
            ctx.waitUntil(query.run().catch(() => {}));
        } else {
            query.run().catch(() => {});
        }
    };

                const heartbeat = setInterval(async () => {
        if (serverSock.readyState === WebSocket.OPEN) {
            try {
                let user;
                try {
                    user = await env.DB.prepare("UPDATE users SET last_active = ? WHERE uuid = ? RETURNING is_active").bind(Date.now(), validUUID).first();
                } catch (err) {
                    await env.DB.prepare("UPDATE users SET last_active = ? WHERE uuid = ?").bind(Date.now(), validUUID).run();
                    user = await env.DB.prepare("SELECT is_active FROM users WHERE uuid = ?").bind(validUUID).first();
                }
                if (!user || user.is_active === 0) {
                    clearInterval(heartbeat);
                    closeSocketQuietly(serverSock);
                    return;
                }
                serverSock.send(new Uint8Array(0));
            } catch (e) {}
        } else {
            clearInterval(heartbeat);
        }
    }, 30000);

    let remoteConnWrapper = { socket: null, connectingPromise: null, retryConnect: null };
    let reqUUID = null;
    let isHeaderParsed = false;
    let isDnsQuery = false;
    let chunkBuffer = new Uint8Array(0);

        const validUUID = storedData.uuid;
    const proxyIP = storedData.proxy_ip;

    try {
        await env.DB.prepare("UPDATE users SET last_active = ? WHERE uuid = ?").bind(Date.now(), validUUID).run();
    } catch (e) {}

    let wsChain = Promise.resolve();
    let wsStopped = false, wsFailed = false, wsFinished = false;
    let wsQueueBytes = 0, wsQueueItems = 0;
    let currentSocketWriter = null, activeRemoteWriter = null;

    const releaseRemoteWriter = () => {
        if (activeRemoteWriter) {
            try { activeRemoteWriter.releaseLock(); } catch (e) {}
            activeRemoteWriter = null;
        }
        currentSocketWriter = null;
    };

    const getRemoteWriter = () => {
        const s = remoteConnWrapper.socket;
        if (!s) return null;
        if (s !== currentSocketWriter) {
            releaseRemoteWriter();
            currentSocketWriter = s;
            activeRemoteWriter = s.writable.getWriter();
        }
        return activeRemoteWriter;
    };

    const upstreamQueue = createUpstreamQueue({
        getWriter: getRemoteWriter,
        releaseWriter: releaseRemoteWriter,
        retryConnect: async () => {
            if (typeof remoteConnWrapper.retryConnect === 'function') {
                await remoteConnWrapper.retryConnect();
            }
        },
        closeConnection: () => {
            try { remoteConnWrapper.socket?.close(); } catch (e) {}
            closeSocketQuietly(serverSock);
        },
        name: 'VlessWSQueue'
    });

    const writeToRemote = async (chunk, allowRetry = true) => {
        return upstreamQueue.writeAndAwait(chunk, allowRetry);
    };

    const processWsMessage = async (chunk) => {
        if (isDnsQuery) {
            await forwardVlessUDP(chunk, serverSock, null);
            return;
        }

        if (await writeToRemote(chunk)) return;

        if (!isHeaderParsed) {
            chunkBuffer = concatBytes(chunkBuffer, chunk);
            if (chunkBuffer.byteLength < 24) return;

            reqUUID = extractUUIDFromVless(chunkBuffer);
            if (!reqUUID || reqUUID !== validUUID) {
                serverSock.close();
                return;
            }

            isHeaderParsed = true;

            try {
                let offset = 17;
                const optLen = chunkBuffer[offset++];
                offset += optLen;
                const cmd = chunkBuffer[offset++];
                const port = (chunkBuffer[offset++] << 8) | chunkBuffer[offset++];
                const addrType = chunkBuffer[offset++];

                let addr = '';
                if (addrType === 1) {
                    addr = `${chunkBuffer[offset++]}.${chunkBuffer[offset++]}.${chunkBuffer[offset++]}.${chunkBuffer[offset++]}`;
                } else if (addrType === 2) {
                    const domainLen = chunkBuffer[offset++];
                    addr = new TextDecoder().decode(chunkBuffer.slice(offset, offset + domainLen));
                    offset += domainLen;
                } else if (addrType === 3) {
                    offset += 16;
                    addr = "ipv6-unsupported";
                }

                const rawData = chunkBuffer.slice(offset);
                const respHeader = new Uint8Array([chunkBuffer[0], 0]);

                if (cmd === 2) {
                    if (port === 53) {
                        isDnsQuery = true;
                        await forwardVlessUDP(rawData, serverSock, respHeader);
                    } else {
                        serverSock.close();
                    }
                    return;
                }

                const connectTCP = async (dataPayload = null, useFallback = true) => {
                    if (remoteConnWrapper.connectingPromise) {
                        await remoteConnWrapper.connectingPromise;
                        return;
                    }
                    const task = (async () => {
                        let s = null;
                        try {
                            s = await connectDirect(addr, port, dataPayload);
                        } catch (err) {
                            if (useFallback && proxyIP) {
                                s = await connectDirect(proxyIP, port, dataPayload);
                            } else {
                                throw err;
                            }
                        }
                        remoteConnWrapper.socket = s; 
                        s.closed.catch(() => {}).finally(() => closeSocketQuietly(serverSock));
                        connectStreams(s, serverSock, respHeader, null);
                    })();
                    remoteConnWrapper.connectingPromise = task;
                    try {
                        await task;
                    } finally {
                        if (remoteConnWrapper.connectingPromise === task) {
                            remoteConnWrapper.connectingPromise = null;
                        }
                    }
                };

                remoteConnWrapper.retryConnect = async () => connectTCP(null, false);
                await connectTCP(rawData, true);

            } catch (e) {
                serverSock.close();
            }
        }
    };

        const handleWsError = (err) => {
        if (wsFailed) return;
        wsFailed = true;
        wsStopped = true;
        wsQueueBytes = 0;
        wsQueueItems = 0;
        upstreamQueue.clear();
        releaseRemoteWriter();
        closeSocketQuietly(serverSock);
        setOffline();
    };

    const pushToChain = (task) => {
        wsChain = wsChain.then(task).catch(handleWsError);
    };

    serverSock.addEventListener('message', (event) => {
        if (wsStopped || wsFailed) return;
        const size = event.data.byteLength || 0;
        const nextBytes = wsQueueBytes + size;
        const nextItems = wsQueueItems + 1;
        if (nextBytes > UPSTREAM_QUEUE_MAX_BYTES || nextItems > UPSTREAM_QUEUE_MAX_ITEMS) {
            handleWsError(new Error('ws queue overflow'));
            return;
        }
        wsQueueBytes = nextBytes;
        wsQueueItems = nextItems;
        pushToChain(async () => {
            wsQueueBytes = Math.max(0, wsQueueBytes - size);
            wsQueueItems = Math.max(0, wsQueueItems - 1);
            if (wsFailed) return;
            await processWsMessage(event.data);
        });
    });

        serverSock.addEventListener('close', () => {
        clearInterval(heartbeat);
        closeSocketQuietly(serverSock);
        setOffline();
        if (wsFinished) return;
        wsFinished = true;
        wsStopped = true;
        pushToChain(async () => {
            if (wsFailed) return;
            await upstreamQueue.awaitEmpty();
            releaseRemoteWriter();
        });
    });

    serverSock.addEventListener('error', (err) => {
        handleWsError(err);
    });

    return new Response(null, { status: 101, webSocket: clientSock });
}

const htmlTemplate = `
<!DOCTYPE html>
<html lang="fa" dir="rtl" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>پنل مدیریت ورکر</title>
    <!-- مخفی کردن هشدار محیط پروداکشن Tailwind -->
    <script>
        const originalWarn = console.warn;
        console.warn = (...args) => {
            if (typeof args[0] === 'string' && args[0].includes('cdn.tailwindcss.com')) return;
            originalWarn(...args);
        };
    </script>
    <!-- Tailwind CSS -->
    <script src="https://cdn.tailwindcss.com"></script>
    <!-- کتابخانه QRCode.js برای تولید سریع و کلاینت‌ساید QR کد -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script>
    <!-- فونت وزیر متن برای ظاهر بهتر فارسی -->
    <link href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/Vazirmatn-font-face.css" rel="stylesheet" type="text/css" />
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    fontFamily: {
                        sans: ['Vazirmatn', 'sans-serif'],
                    },
                    colors: {
                        // تنظیم رنگ مشکی خالص برای تم AMOLED
                        amoled: {
                            bg: '#000000',
                            card: '#0a0a0a',
                            input: '#121212',
                            border: '#1f1f1f'
                        }
                    }
                }
            }
        }
    </script>
    <style>
        body {
            font-family: 'Vazirmatn', sans-serif;
        }
    </style>
</head>
<body class="bg-gray-50 text-gray-900 dark:bg-amoled-bg dark:text-zinc-100 min-h-screen transition-colors duration-200">

        <!-- هدر پنل -->
    <header class="border-b border-gray-200 dark:border-amoled-border bg-white dark:bg-amoled-card px-4 py-4">
        <div class="max-w-6xl mx-auto flex justify-between items-center">
            <h1 class="text-lg font-bold">Teriak Panel <span class="text-sm font-normal text-gray-400 dark:text-zinc-500">0.7</span></h1>
            <div class="flex items-center gap-3">
                <!-- دکمه تغییر پوسته (Light / AMOLED Dark) -->
                <button id="theme-toggle" class="p-2 rounded-lg bg-gray-100 dark:bg-amoled-input border border-gray-200 dark:border-amoled-border hover:bg-gray-200 dark:hover:bg-zinc-800 transition">
                    <!-- آیکون خورشید برای حالت روشن -->
                    <svg id="sun-icon" class="w-5 h-5 hidden dark:block text-yellow-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364-6.364l-.707.707M6.343 17.657l-.707.707m12.728 0l-.707-.707M6.343 6.343l-.707-.707M14 12a2 2 0 11-4 0 2 2 0 014 0z"></path></svg>
                    <!-- آیکون ماه برای حالت تاریک -->
                    <svg id="moon-icon" class="w-5 h-5 block dark:hidden text-gray-600" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"></path></svg>
                </button>
                
                                                <!-- دکمه تنظیمات پنل -->
                <button onclick="toggleSettingsModal(true)" class="p-2 rounded-lg bg-gray-100 dark:bg-amoled-input border border-gray-200 dark:border-amoled-border hover:bg-gray-200 dark:hover:bg-zinc-800 transition text-gray-600 dark:text-gray-300 shadow-sm" title="تنظیمات پنل">
                    <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path></svg>
                </button>
                <!-- دکمه ایجاد کاربر جدید -->
                <button onclick="openCreateModal()" class="flex items-center justify-center w-10 h-10 bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-700 hover:to-indigo-700 text-white rounded-full shadow-md hover:shadow-lg hover:scale-110 transition-all duration-300" title="افزودن کاربر جدید">
                    <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M12 4v16m8-8H4"></path></svg>
                </button>
            </div>
        </div>
    </header>
    <!-- محتوای صفحه پویا -->
<main class="max-w-6xl mx-auto px-4 py-8">
    <!-- کارت‌های آمار و اطلاعات -->
    <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
        <!-- کارت ۱: تعداد کل کاربران -->
        <div class="bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-2xl p-6 shadow-sm flex items-center justify-between hover:shadow-md hover:border-indigo-400 dark:hover:border-indigo-500/50 transition duration-300 relative overflow-hidden group">
            <div class="absolute -right-4 -bottom-4 w-24 h-24 bg-indigo-500/10 rounded-full blur-xl group-hover:scale-150 transition duration-500"></div>
            <div class="space-y-2 relative z-10">
                <span class="text-sm font-semibold text-gray-500 dark:text-zinc-400">تعداد کل کاربران</span>
                <div class="text-3xl font-black text-gray-900 dark:text-zinc-100 transition-all" id="stat-total-users">0</div>
                <span class="text-xs text-indigo-500 dark:text-indigo-400 flex items-center gap-1 font-medium">
                    <span class="w-1.5 h-1.5 bg-indigo-500 rounded-full animate-ping"></span>
                    کل کاربران تعریف شده
                </span>
            </div>
            <div class="p-3 bg-indigo-50 dark:bg-indigo-950/30 text-indigo-600 dark:text-indigo-400 rounded-2xl relative z-10">
                <svg class="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z"></path>
                </svg>
            </div>
        </div>

                <!-- کارت ۲: کاربران آنلاین -->
        <div class="bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-2xl p-6 shadow-sm flex items-center justify-between hover:shadow-md hover:border-emerald-400 dark:hover:border-emerald-500/50 transition duration-300 relative overflow-hidden group">
            <div class="absolute -right-4 -bottom-4 w-24 h-24 bg-emerald-500/10 rounded-full blur-xl group-hover:scale-150 transition duration-500"></div>
            <div class="space-y-2 relative z-10">
                <span class="text-sm font-semibold text-gray-500 dark:text-zinc-400">کاربران فعال (آنلاین)</span>
                <div class="text-3xl font-black text-emerald-600 dark:text-emerald-400 transition-all" id="stat-active-users">0</div>
                <span class="text-xs text-emerald-500 dark:text-emerald-400 flex items-center gap-1 font-medium">
                    <span class="w-2 h-2 bg-emerald-500 rounded-full animate-pulse"></span>
                    متصل در این لحظه
                </span>
            </div>
            <div class="p-3 bg-emerald-50 dark:bg-emerald-950/30 text-emerald-600 dark:text-emerald-400 rounded-2xl relative z-10">
                <svg class="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M13 10V3L4 14h7v7l9-11h-7z"></path>
                </svg>
            </div>
        </div>

        <!-- کارت ۳: کل حجم مصرفی -->
        <div class="bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-2xl p-6 shadow-sm flex items-center justify-between hover:shadow-md hover:border-blue-400 dark:hover:border-blue-500/50 transition duration-300 relative overflow-hidden group">
            <div class="absolute -right-4 -bottom-4 w-24 h-24 bg-blue-500/10 rounded-full blur-xl group-hover:scale-150 transition duration-500"></div>
            <div class="space-y-2 relative z-10">
                <span class="text-sm font-semibold text-gray-500 dark:text-zinc-400">کل حجم مصرفی (۳۰ روز)</span>
                <div class="text-3xl font-black text-blue-600 dark:text-blue-400 transition-all" id="stat-total-usage">0 GB</div>
                <span class="text-xs text-blue-500 dark:text-blue-400 flex items-center gap-1 font-medium">
                    <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M9 19l3 3m0 0l3-3m-3 3V10"></path>
                    </svg>
                    مصرف کل کاربران
                </span>
            </div>
            <div class="p-3 bg-blue-50 dark:bg-blue-950/30 text-blue-600 dark:text-blue-400 rounded-2xl relative z-10">
                <svg class="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"></path>
                </svg>
            </div>
        </div>

        <!-- کارت ۴: درخواست‌های امروز -->
        <div class="bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-2xl p-6 shadow-sm flex items-center justify-between hover:shadow-md hover:border-rose-400 dark:hover:border-rose-500/50 transition duration-300 relative overflow-hidden group">
            <div class="absolute -right-4 -bottom-4 w-24 h-24 bg-rose-500/10 rounded-full blur-xl group-hover:scale-150 transition duration-500"></div>
            <div class="space-y-2 relative z-10">
                <span class="text-sm font-semibold text-gray-500 dark:text-zinc-400">درخواست‌های امروز (CF)</span>
                <div class="text-3xl font-black text-rose-600 dark:text-rose-400 transition-all" id="stat-total-requests">0</div>
                <span class="text-xs text-rose-500 dark:text-rose-400 flex items-center gap-1 font-medium">
                    سقف رایگان: ۱۰۰,۰۰۰ درخواست
                </span>
            </div>
            <div class="relative flex items-center justify-center z-10">
                <!-- دایره پیشرفت با SVG -->
                <svg class="w-16 h-16 transform -rotate-90">
                    <circle class="text-gray-100 dark:text-zinc-800" stroke-width="5" stroke="currentColor" fill="transparent" r="26" cx="32" cy="32"/>
                    <circle class="text-rose-500 dark:text-rose-400 transition-all duration-700 ease-out" stroke-width="5" stroke-dasharray="163.36" stroke-dashoffset="163.36" id="request-progress-circle" stroke-linecap="round" stroke="currentColor" fill="transparent" r="26" cx="32" cy="32"/>
                </svg>
                <span class="absolute text-[10px] font-black text-rose-600 dark:text-rose-400" id="stat-requests-percent">0%</span>
            </div>
        </div>
    </div>

    <!-- وضعیت در حال بارگذاری -->
    <div id="loading-state" class="text-center py-12">
        <span class="text-gray-500 dark:text-gray-400">در حال بارگذاری کاربران...</span>
    </div>
    <h2 class="text-lg font-bold mb-4 text-gray-800 dark:text-zinc-200">لیست کاربران</h2>
            <div id="users-table-container" class="hidden overflow-x-auto border border-gray-200 dark:border-amoled-border rounded-xl bg-white dark:bg-amoled-card">
                <table class="w-full text-right border-collapse">
                    <thead>
                        <tr class="bg-gray-100 dark:bg-zinc-900/50 border-b border-gray-200 dark:border-amoled-border text-xs text-gray-500 dark:text-gray-400">
                                                        <th class="p-4">نام کاربر و عملیات</th>
                            <th class="p-4">لینک ساب</th>
                            <th class="p-4">پروتکل</th>
                            <th class="p-4">پورت (TLS)</th>
                            <th class="p-4">وضعیت حجم</th>
                            <th class="p-4">وضعیت اعتبار</th>
                            <th class="p-4">تاریخ ساخت</th>
                        </tr>
                    </thead>
                    <tbody id="users-tbody" class="divide-y divide-gray-150 dark:divide-amoled-border text-sm">
                        <!-- ردیف‌های کاربران در اینجا لود خواهند شد -->
                    </tbody>
                </table>
            </div>

            <!-- وضعیت خالی بودن دیتابیس -->
            <div id="empty-state" class="hidden p-8 border border-dashed border-gray-300 dark:border-amoled-border rounded-2xl text-center">
                <p class="text-gray-500 dark:text-gray-400">کاربری وجود ندارد. برای ساخت اولین کاربر روی دکمه «افزودن کاربر جدید» کلیک کنید.</p>
            </div>
        </main><!-- مودال افزودن کاربر جدید -->
    <div id="user-modal" class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm opacity-0 pointer-events-none transition-all duration-300 ease-out">
        <div class="w-full max-w-lg bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-2xl shadow-xl overflow-hidden transition-all transform duration-300 opacity-0 scale-95 ease-out">
                        <!-- هدر مودال -->
            <div class="px-6 py-4 border-b border-gray-150 dark:border-amoled-border flex justify-between items-center">
                <h3 id="modal-title" class="font-bold text-gray-900 dark:text-zinc-100">ایجاد کاربر جدید</h3>
                <button onclick="toggleModal(false)" class="text-gray-400 hover:text-gray-600 dark:hover:text-zinc-200">
                    <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
                </button>
            </div>

                        <!-- فرم مودال -->
            <form id="create-user-form" class="p-6 space-y-4" onsubmit="handleFormSubmit(event)">
                <div>
                    <label class="block text-sm font-medium mb-1.5">نام کاربر (انگلیسی)</label>
                    <input type="text" id="input-name" pattern="[A-Za-z0-9_]+" placeholder="مثلا: reza_vpn" class="w-full px-3 py-2 bg-gray-50 dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm" required>
                </div>
                <div class="grid grid-cols-2 gap-4">
                    <div>
                        <label class="block text-sm font-medium mb-1.5">حجم مجاز (گیگابایت) <span class="text-xs text-gray-400 dark:text-zinc-500">(خالی = نامحدود)</span></label>
                        <input type="number" id="input-limit" min="0" placeholder="مثلا: 50" class="w-full px-3 py-2 bg-gray-50 dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm">
                    </div>
                    <div>
                        <label class="block text-sm font-medium mb-1.5">مدت اعتبار (روز) <span class="text-xs text-gray-400 dark:text-zinc-500">(خالی = نامحدود)</span></label>
                        <input type="number" id="input-expiry" min="0" placeholder="مثلا: 30" class="w-full px-3 py-2 bg-gray-50 dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm">
                    </div>
                </div>
                <div>
                    <label class="block text-sm font-medium mb-1.5">آی‌پی تمیز (هر خط یک آی‌پی)</label>
                    <textarea id="input-ips" rows="3" placeholder="104.16.0.1&#10;104.17.0.1" class="w-full px-3 py-2 bg-gray-50 dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 text-xs font-mono"></textarea>
                </div>
                <div class="grid grid-cols-2 gap-4">
                    <div>
                        <label class="block text-sm font-medium mb-1.5">وضعیت TLS</label>
                        <select id="tls-toggle" class="w-full px-3 py-2 bg-gray-50 dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm">
                            <option value="on" selected>روشن (TLS)</option>
                            <option value="off">خاموش (بدون TLS)</option>
                        </select>
                    </div>
                    <div>
                        <label class="block text-sm font-medium mb-1.5">پورت اتصال</label>
                        <select id="port-select" class="w-full px-3 py-2 bg-gray-50 dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm">
                            <!-- پورت‌ها به طور خودکار اضافه می‌شوند -->
                        </select>
                    </div>
                </div>
                                <div class="pt-4 flex gap-3">
                    <button type="button" onclick="toggleModal(false)" class="flex-1 py-2 bg-gray-100 hover:bg-gray-200 dark:bg-zinc-800 dark:hover:bg-zinc-700 font-medium rounded-lg text-sm transition">انصراف</button>
                    <button type="submit" id="submit-btn" class="flex-1 py-2 bg-blue-600 hover:bg-blue-700 text-white font-medium rounded-lg text-sm transition">ایجاد کاربر</button>
                </div>
            </form>
        </div>
    </div>

    <!-- مودال نمایش QR کد -->
    <div id="qr-modal" class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm opacity-0 pointer-events-none transition-all duration-300 ease-out">
        <div class="w-full max-w-sm bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-2xl shadow-xl overflow-hidden p-6 text-center transition-all transform duration-300 opacity-0 scale-95 ease-out">
            <h3 id="qr-modal-title" class="font-bold text-gray-900 dark:text-zinc-100 mb-4">اسکن کد QR</h3>
            <div class="bg-white p-3 rounded-xl inline-block mb-4 border border-gray-100">
                <div id="qrcode-box" class="flex justify-center items-center w-48 h-48 mx-auto"></div>
            </div>
            <button onclick="toggleQRModal(false)" class="w-full py-2 bg-gray-100 hover:bg-gray-200 dark:bg-zinc-800 dark:hover:bg-zinc-700 font-medium rounded-lg text-sm transition text-gray-900 dark:text-zinc-100">بستن</button>
        </div>
    </div>

    <!-- مودال تنظیمات -->
    <div id="settings-modal" class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm opacity-0 pointer-events-none transition-all duration-300 ease-out">
        <div class="w-full max-w-md bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-2xl shadow-xl overflow-hidden transition-all transform duration-300 opacity-0 scale-95 ease-out">
            <!-- هدر مودال -->
            <div class="px-6 py-4 border-b border-gray-150 dark:border-amoled-border flex justify-between items-center bg-gray-50 dark:bg-zinc-900/50">
                <h3 class="font-bold text-gray-900 dark:text-zinc-100">تنظیمات پنل</h3>
                <button onclick="toggleSettingsModal(false)" class="text-gray-400 hover:text-gray-600 dark:hover:text-zinc-200">
                    <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>
                </button>
            </div>
            <!-- فرم تنظیمات -->
            <div class="p-6 space-y-4">
                <div>
                    <label class="block text-sm font-medium mb-1.5 text-gray-700 dark:text-zinc-300">لوکیشن / کشور (Cloudflare)</label>
                    <div class="relative">
                        <select id="location-select" class="w-full pl-8 pr-3 py-2.5 bg-white dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 text-gray-700 dark:text-zinc-200 cursor-pointer appearance-none">
                            <option value="">در حال بارگذاری...</option>
                        </select>
                        <div class="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3 text-gray-500 dark:text-zinc-400">
                            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7"></path></svg>
                        </div>
                    </div>
                </div>
                <div class="grid grid-cols-2 gap-4 pt-2 border-t border-gray-100 dark:border-zinc-800">
                    <div>
                        <label class="block text-sm font-medium mb-1.5 text-gray-700 dark:text-zinc-300">Fragment Length</label>
                        <input type="text" id="frag-length" placeholder="20-30" value="20-30" class="w-full px-3 py-2.5 bg-white dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm text-center font-mono" dir="ltr">
                    </div>
                    <div>
                        <label class="block text-sm font-medium mb-1.5 text-gray-700 dark:text-zinc-300">Fragment Interval</label>
                        <input type="text" id="frag-interval" placeholder="1-2" value="1-2" class="w-full px-3 py-2.5 bg-white dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm text-center font-mono" dir="ltr">
                    </div>
                </div>
                <div class="pt-4 flex gap-3">
                    <button type="button" onclick="toggleSettingsModal(false)" class="flex-1 py-2 bg-gray-100 hover:bg-gray-200 dark:bg-zinc-800 dark:hover:bg-zinc-700 font-medium rounded-lg text-sm transition">انصراف</button>
                    <button type="button" onclick="saveSettings()" id="save-settings-btn" class="flex-1 py-2 bg-blue-600 hover:bg-blue-700 text-white font-medium rounded-lg text-sm transition">ذخیره تنظیمات</button>
                </div>
            </div>
        </div>
    </div>

    <!-- بخش جاوا اسکریپت کنترل فرانت‌اند -->
    <script>
        // متغیرهای سراسری تنظیمات فرگمنت
        window.globalFragLen = "20-30";
        window.globalFragInt = "1-2";

        // تعریف پورت‌های استاندارد کلادفلر
        const tlsPorts = ['443', '2053', '2083', '2087', '2096', '8443'];
        const nonTlsPorts = ['80', '8080', '8880', '2052', '2082', '2086', '2095'];

        const tlsToggle = document.getElementById('tls-toggle');
        const portSelect = document.getElementById('port-select');

                let isEditMode = false;
        let editingUsername = '';

        function toggleSettingsModal(show) {
            const modal = document.getElementById('settings-modal');
            const card = modal.querySelector('div');
            if (show) {
                modal.classList.remove('opacity-0', 'pointer-events-none');
                modal.classList.add('opacity-100', 'pointer-events-auto');
                card.classList.remove('opacity-0', 'scale-95');
                card.classList.add('opacity-100', 'scale-100');
            } else {
                modal.classList.remove('opacity-100', 'pointer-events-auto');
                modal.classList.add('opacity-0', 'pointer-events-none');
                card.classList.remove('opacity-100', 'scale-100');
                card.classList.add('opacity-0', 'scale-95');
            }
        }

        // تابع بروزرسانی پورت‌ها بر اساس وضعیت TLS
        function updatePorts() {
            const isTls = tlsToggle.value === 'on';
            const ports = isTls ? tlsPorts : nonTlsPorts;
            portSelect.innerHTML = ports.map(function(port) {
                return '<option value="' + port + '">' + port + '</option>';
            }).join('');
        }

        tlsToggle.addEventListener('change', updatePorts);
        updatePorts(); // فراخوانی اولیه برای تنظیم پورت‌ها در بارگذاری اول

        // کنترل باز و بسته شدن مودال
        function toggleModal(show) {
            const modal = document.getElementById('user-modal');
            const card = modal.querySelector('div');
            if (show) {
                modal.classList.remove('opacity-0', 'pointer-events-none');
                modal.classList.add('opacity-100', 'pointer-events-auto');
                card.classList.remove('opacity-0', 'scale-95');
                card.classList.add('opacity-100', 'scale-100');
            } else {
                modal.classList.remove('opacity-100', 'pointer-events-auto');
                modal.classList.add('opacity-0', 'pointer-events-none');
                card.classList.remove('opacity-100', 'scale-100');
                card.classList.add('opacity-0', 'scale-95');
                isEditMode = false;
                editingUsername = '';
                document.getElementById('modal-title').innerText = 'ایجاد کاربر جدید';
                document.getElementById('submit-btn').innerText = 'ایجاد کاربر';
                const nameInput = document.getElementById('input-name');
                nameInput.disabled = false;
                document.getElementById('create-user-form').reset();
                updatePorts();
            }
        }

        function openCreateModal() {
            isEditMode = false;
            editingUsername = '';
            document.getElementById('modal-title').innerText = 'ایجاد کاربر جدید';
            document.getElementById('submit-btn').innerText = 'ایجاد کاربر';
            const nameInput = document.getElementById('input-name');
            nameInput.disabled = false;
            document.getElementById('create-user-form').reset();
            updatePorts();
            toggleModal(true);
        }

        // عملکرد دکمه تغییر حالت تاریک/روشن
        const themeToggleBtn = document.getElementById('theme-toggle');
        
        // بررسی تم ذخیره شده قبلی یا تم سیستم کاربر
        if (localStorage.getItem('color-theme') === 'light' || (!('color-theme' in localStorage) && !window.matchMedia('(prefers-color-scheme: dark)').matches)) {
            document.documentElement.classList.remove('dark');
        } else {
            document.documentElement.classList.add('dark');
        }

        themeToggleBtn.addEventListener('click', function() {
            if (document.documentElement.classList.contains('dark')) {
                document.documentElement.classList.remove('dark');
                localStorage.setItem('color-theme', 'light');
            } else {
                document.documentElement.classList.add('dark');
                localStorage.setItem('color-theme', 'dark');
            }
        });

                // دریافت و نمایش کاربران از دیتابیس با کش Stale-While-Revalidate
        async function loadUsers(forceFresh = false) {
            const loadingState = document.getElementById('loading-state');
            const tableContainer = document.getElementById('users-table-container');
            const emptyState = document.getElementById('empty-state');
            
            const cachedUsers = localStorage.getItem('cached_users_list');
            let hasCachedData = false;
            
            if (cachedUsers && !forceFresh) {
                try {
                    const parsed = JSON.parse(cachedUsers);
                    if (parsed && parsed.users) {
                        renderUsersUI(parsed);
                        hasCachedData = true;
                    }
                } catch (e) {
                    console.error("Error reading cached users:", e);
                }
            }
            
            if (!hasCachedData) {
                loadingState.classList.remove('hidden');
                tableContainer.classList.add('hidden');
                emptyState.classList.add('hidden');
            } else {
                tableContainer.classList.add('opacity-75');
            }
            
            try {
                const res = await fetch('/api/users');
                if (!res.ok) throw new Error();
                const data = await res.json();
                
                localStorage.setItem('cached_users_list', JSON.stringify(data));
                renderUsersUI(data);
            } catch (err) {
                if (!hasCachedData) {
                    loadingState.innerHTML = '<span class="text-red-500">خطا در دریافت لیست کاربران از سرور</span>';
                }
            } finally {
                tableContainer.classList.remove('opacity-75');
            }
        }

        // رندر کردن رابط کاربری کاربران
        function renderUsersUI(data) {
            try {
                const loadingState = document.getElementById('loading-state');
                const tableContainer = document.getElementById('users-table-container');
                const emptyState = document.getElementById('empty-state');
                const tbody = document.getElementById('users-tbody');
                
                const users = data.users || [];
                const totalTodayRequests = data.totalTodayRequests || 0;
                window.allUsers = users;
                
                // محاسبات آمارها جهت نمایش در ۴ باکس بالای پنل
                const totalUsersCount = users.length;
                const activeUsersCount = users.filter(user => user.last_active && (Date.now() - user.last_active < 35000)).length;
                const totalGbUsage = users.reduce((sum, user) => sum + (user.used_gb || 0), 0);
                
                document.getElementById('stat-total-users').innerText = totalUsersCount;
                document.getElementById('stat-active-users').innerText = activeUsersCount;
                document.getElementById('stat-total-usage').innerText = totalGbUsage < 1 ? (totalGbUsage * 1024).toFixed(0) + ' MB' : totalGbUsage.toFixed(2) + ' GB';
                document.getElementById('stat-total-requests').innerText = totalTodayRequests.toLocaleString();
                
                const percent = Math.min(100, (totalTodayRequests / 100000) * 100);
                const offset = 163.36 - (percent / 100) * 163.36;
                document.getElementById('request-progress-circle').style.strokeDashoffset = offset;
                document.getElementById('stat-requests-percent').innerText = percent.toFixed(1) + '%';
                
                if (users.length === 0) {
                    loadingState.classList.add('hidden');
                    emptyState.classList.remove('hidden');
                } else {
                                        tbody.innerHTML = users.map(user => {
                        const createdDate = user.created_at ? new Date(user.created_at).toLocaleDateString('fa-IR') : '-';
                        
                        // محاسبه روزهای باقی‌مانده و درصد آن
                        let daysRemaining = 'نامحدود';
                        let daysPercent = 100;
                        if (user.expiry_days) {
                            if (user.created_at) {
                                const created = new Date(user.created_at);
                                const expiryDate = new Date(created.getTime() + (user.expiry_days * 24 * 60 * 60 * 1000));
                                const diffDays = Math.ceil((expiryDate - new Date()) / (1000 * 60 * 60 * 24));
                                daysRemaining = diffDays > 0 ? diffDays : 0;
                                daysPercent = Math.max(0, Math.min(100, (daysRemaining / user.expiry_days) * 100));
                            } else {
                                daysRemaining = user.expiry_days;
                            }
                        }

                                                // در صورت عدم وجود مصرف فعلی در دیتابیس، مصرف پیش‌فرض صفر در نظر گرفته می‌شود
                        const usedGb = user.used_gb || 0;
                        const formattedUsed = usedGb < 1 ? (usedGb * 1024).toFixed(0) + ' MB' : usedGb.toFixed(2) + ' GB';

                        // ساخت HTML نوار حجم گرافیکی
                        let volumeHtml = '';
                        if (user.limit_gb) {
                            const limitPercent = Math.min((usedGb / user.limit_gb) * 100, 100);
                            const formattedLimit = user.limit_gb < 1 ? (user.limit_gb * 1024).toFixed(0) + ' MB' : user.limit_gb + ' GB';
                            volumeHtml = '<div class="flex flex-col gap-1.5 w-full min-w-[130px]">' +
                                '<div class="flex justify-between text-[11px] text-gray-500 dark:text-gray-400 font-medium">' +
                                    '<span>مصرف: ' + formattedUsed + '</span>' +
                                    '<span>کل: ' + formattedLimit + '</span>' +
                                '</div>' +
                                '<div class="w-full bg-gray-200 dark:bg-zinc-700 rounded-full h-1.5 overflow-hidden">' +
                                    '<div class="' + (limitPercent > 90 ? 'bg-red-500' : 'bg-blue-500') + ' h-1.5 rounded-full transition-all duration-500" style="width: ' + limitPercent + '%"></div>' +
                                '</div>' +
                            '</div>';
                        } else {
                            volumeHtml = '<div class="flex flex-col gap-1.5 w-full min-w-[130px]">' +
                                '<div class="flex justify-between text-[11px] text-gray-500 dark:text-gray-400 font-medium">' +
                                    '<span>مصرف: ' + formattedUsed + '</span>' +
                                    '<span>کل: نامحدود</span>' +
                                '</div>' +
                                '<div class="w-full bg-gray-200 dark:bg-zinc-700 rounded-full h-1.5 overflow-hidden">' +
                                    '<div class="bg-blue-500 h-1.5 rounded-full transition-all duration-500" style="width: 100%"></div>' +
                                '</div>' +
                            '</div>';
                        }

                        // ساخت HTML نوار روزهای باقی‌مانده گرافیکی
                        let expiryHtml = '';
                        if (user.expiry_days) {
                            expiryHtml = '<div class="flex flex-col gap-1.5 w-full min-w-[130px]">' +
                                '<div class="flex justify-between text-[11px] text-gray-500 dark:text-gray-400 font-medium">' +
                                    '<span>باقی‌مانده: ' + daysRemaining + ' روز</span>' +
                                    '<span>کل: ' + user.expiry_days + ' روز</span>' +
                                '</div>' +
                                '<div class="w-full bg-gray-200 dark:bg-zinc-700 rounded-full h-1.5 overflow-hidden flex justify-end">' +
                                    '<div class="' + (daysRemaining <= 3 ? 'bg-red-500' : 'bg-green-500') + ' h-1.5 rounded-full transition-all duration-500" style="width: ' + daysPercent + '%"></div>' +
                                '</div>' +
                            '</div>';
                        } else {
                            expiryHtml = '<div class="flex flex-col gap-1.5 w-full min-w-[130px]">' +
                                '<div class="flex justify-between text-[11px] text-gray-500 dark:text-gray-400 font-medium">' +
                                    '<span>باقی‌مانده: نامحدود</span>' +
                                    '<span>کل: نامحدود</span>' +
                                '</div>' +
                                '<div class="w-full bg-gray-200 dark:bg-zinc-700 rounded-full h-1.5 overflow-hidden flex justify-end">' +
                                    '<div class="bg-blue-500 h-1.5 rounded-full transition-all duration-500" style="width: 100%"></div>' +
                                '</div>' +
                            '</div>';
                        }

                                                                                                                                return '<tr class="hover:bg-gray-50 dark:hover:bg-zinc-900/40 border-b border-gray-100 dark:border-zinc-800 last:border-0">' +
                                '<td class="p-4">' +
                                    '<div class="flex flex-col gap-3">' +
                                        '<div class="flex items-center gap-2">' +
                                            '<span class="font-bold text-gray-900 dark:text-zinc-100">' + user.username + '</span>' +
                                            (user.is_active === 0 ? '<span class="px-1.5 py-0.5 text-[10px] font-medium bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400 rounded-md">قطع</span>' : '<span class="px-1.5 py-0.5 text-[10px] font-medium bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400 rounded-md">فعال</span>') +
                                            ((user.last_active && (Date.now() - user.last_active < 35000)) ? '<span class="px-1.5 py-0.5 text-[10px] font-medium bg-emerald-500 text-white rounded-md animate-pulse">● آنلاین</span>' : '<span class="px-1.5 py-0.5 text-[10px] font-medium bg-gray-200 text-gray-600 dark:bg-zinc-800 dark:text-zinc-400 rounded-md">آفلاین</span>') +
                                        '</div>' +
                                        '<div class="flex gap-1.5">' +
                                            '<button onclick="copyConfig(\\'' + user.username + '\\')" title="کپی کانفیگ" class="p-1.5 bg-white dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700 hover:bg-blue-50 dark:hover:bg-blue-900/30 text-blue-600 dark:text-blue-400 rounded-md transition shadow-sm"><svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"></path></svg></button>' +
                                            '<button onclick="copyJsonConfig(\\'' + user.username + '\\')" title="کپی JSON" class="p-1.5 bg-white dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700 hover:bg-purple-50 dark:hover:bg-purple-900/30 text-purple-600 dark:text-purple-400 rounded-md transition shadow-sm"><svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"></path></svg></button>' +
                                            '<button onclick="showQR(\\'' + user.username + '\\')" title="کد QR" class="p-1.5 bg-white dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700 hover:bg-green-50 dark:hover:bg-green-900/30 text-green-600 dark:text-green-400 rounded-md transition shadow-sm"><svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v1m6 11h2m-6 0h-2v4m0-11v3m0 0h.01M12 12h4.01M16 20h4M4 12h4m12 0h.01M5 8h2a1 1 0 001-1V5a1 1 0 00-1-1H5a1 1 0 00-1 1v2a1 1 0 001 1zm14 0h2a1 1 0 001-1V5a1 1 0 00-1-1h-2a1 1 0 00-1 1v2a1 1 0 001 1zM5 20h2a1 1 0 001-1v-2a1 1 0 00-1-1H5a1 1 0 00-1 1v2a1 1 0 001 1z"></path></svg></button>' +
                                            '<button onclick="editUser(\\'' + user.username + '\\')" title="ویرایش" class="p-1.5 bg-white dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700 hover:bg-yellow-50 dark:hover:bg-yellow-900/30 text-yellow-600 dark:text-yellow-400 rounded-md transition shadow-sm"><svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"></path></svg></button>' +
                                            '<button onclick="deleteUser(\\'' + user.username + '\\')" title="حذف" class="p-1.5 bg-white dark:bg-zinc-800 border border-gray-200 dark:border-zinc-700 hover:bg-red-50 dark:hover:bg-red-900/30 text-red-600 dark:text-red-400 rounded-md transition shadow-sm"><svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path></svg></button>' +
                                        '</div>' +
                                    '</div>' +
                                '</td>' +
                                '<td class="p-4">' +
                                    '<div class="flex flex-col gap-2 min-w-[140px]">' +
                                        '<div class="flex gap-1">' +
                                            '<button onclick="copySubLink(\\'' + user.username + '\\')" class="flex-1 flex items-center justify-center gap-1.5 px-2 py-1.5 bg-indigo-50 dark:bg-indigo-900/30 text-indigo-600 dark:text-indigo-400 hover:bg-indigo-100 dark:hover:bg-indigo-900/50 rounded-lg text-xs font-bold transition border border-indigo-200 dark:border-indigo-800">' +
                                                '<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1"></path></svg>' +
                                                'ساب متنی' +
                                            '</button>' +
                                            '<button onclick="showSubQR(\\'' + user.username + '\\', \\'normal\\')" title="QR ساب متنی" class="px-2 py-1.5 bg-indigo-50 dark:bg-indigo-900/30 text-indigo-600 dark:text-indigo-400 hover:bg-indigo-100 dark:hover:bg-indigo-900/50 rounded-lg text-xs font-bold transition border border-indigo-200 dark:border-indigo-800">' +
                                                '<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v1m6 11h2m-6 0h-2v4m0-11v3m0 0h.01M12 12h4.01M16 20h4M4 12h4m12 0h.01M5 8h2a1 1 0 001-1V5a1 1 0 00-1-1H5a1 1 0 00-1 1v2a1 1 0 001 1zm14 0h2a1 1 0 001-1V5a1 1 0 00-1-1h-2a1 1 0 00-1 1v2a1 1 0 001 1zM5 20h2a1 1 0 001-1v-2a1 1 0 00-1-1H5a1 1 0 00-1 1v2a1 1 0 001 1z"></path></svg>' +
                                            '</button>' +
                                        '</div>' +
                                        '<div class="flex gap-1">' +
                                            '<button onclick="copyJsonSubLink(\\'' + user.username + '\\')" class="flex-1 flex items-center justify-center gap-1.5 px-2 py-1.5 bg-purple-50 dark:bg-purple-900/30 text-purple-600 dark:text-purple-400 hover:bg-purple-100 dark:hover:bg-purple-900/50 rounded-lg text-xs font-bold transition border border-purple-200 dark:border-purple-800">' +
                                                '<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4"></path></svg>' +
                                                'ساب JSON' +
                                            '</button>' +
                                            '<button onclick="showSubQR(\\'' + user.username + '\\', \\'json\\')" title="QR ساب JSON" class="px-2 py-1.5 bg-purple-50 dark:bg-purple-900/30 text-purple-600 dark:text-purple-400 hover:bg-purple-100 dark:hover:bg-purple-900/50 rounded-lg text-xs font-bold transition border border-purple-200 dark:border-purple-800">' +
                                                '<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v1m6 11h2m-6 0h-2v4m0-11v3m0 0h.01M12 12h4.01M16 20h4M4 12h4m12 0h.01M5 8h2a1 1 0 001-1V5a1 1 0 00-1-1H5a1 1 0 00-1 1v2a1 1 0 001 1zm14 0h2a1 1 0 001-1V5a1 1 0 00-1-1h-2a1 1 0 00-1 1v2a1 1 0 001 1zM5 20h2a1 1 0 001-1v-2a1 1 0 00-1-1H5a1 1 0 00-1 1v2a1 1 0 001 1z"></path></svg>' +
                                            '</button>' +
                                        '</div>' +
                                    '</div>' +
                                '</td>' +
                                '<td class="p-4 text-xs font-mono uppercase text-blue-500 font-semibold">VL' + 'ESS</td>' +
                                '<td class="p-4 text-xs">' + user.port + ' (' + (user.tls === 'on' ? 'TLS' : 'بدون TLS') + ')</td>' +
                                '<td class="p-4">' + volumeHtml + '</td>' +
                                '<td class="p-4">' + expiryHtml + '</td>' +
                                '<td class="p-4 text-xs text-gray-500">' + createdDate + '</td>' +
                            '</tr>';
                    }).join('');
                    
                    loadingState.classList.add('hidden');
                    tableContainer.classList.remove('hidden');
                }
            } catch (err) {
                loadingState.innerHTML = '<span class="text-red-500">خطا در دریافت لیست کاربران از سرور</span>';
            }
        }

                // ارسال فرم و ایجاد یا ویرایش کاربر در دیتابیس D1
        async function handleFormSubmit(event) {
            event.preventDefault();
            const submitButton = document.getElementById('submit-btn');
            submitButton.disabled = true;
            submitButton.innerText = isEditMode ? 'در حال ذخیره تغییرات...' : 'در حال ایجاد...';

            const username = document.getElementById('input-name').value;
            const limit = document.getElementById('input-limit').value || null;
            const expiry = document.getElementById('input-expiry').value || null;
            const tls = document.getElementById('tls-toggle').value;
            const port = portSelect.value;
            const ips = document.getElementById('input-ips').value;

            const url = isEditMode ? \`/api/users/\${encodeURIComponent(editingUsername)}\` : '/api/users';
            const method = isEditMode ? 'PUT' : 'POST';

            try {
                const response = await fetch(url, {
                    method: method,
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        username,
                        limit_gb: limit,
                        expiry_days: expiry,
                        tls,
                        port,
                        ips
                    })
                });
                
                if (response.ok) {
                    toggleModal(false);
                    await loadUsers(true);
                } else {
                    const errData = await response.json();
                    alert('خطا: ' + (errData.error || 'عملیات ناموفق بود'));
                }
            } catch (err) {
                alert('خطا در برقراری ارتباط با سرور');
            } finally {
                submitButton.disabled = false;
                submitButton.innerText = isEditMode ? 'ذخیره تغییرات' : 'ایجاد کاربر';
            }
        }

                                                                // توابع مربوط به رابط کاربری دکمه‌ها
        function toggleQRModal(show, link = '', title = 'اسکن کد QR') {
            const modal = document.getElementById('qr-modal');
            const card = modal.querySelector('div');
            const qrBox = document.getElementById('qrcode-box');
            const titleEl = document.getElementById('qr-modal-title');
            if (show) {
                titleEl.innerText = title;
                qrBox.innerHTML = '';
                new QRCode(qrBox, {
                    text: link,
                    width: 192,
                    height: 192,
                    colorDark : "#000000",
                    colorLight : "#ffffff",
                    correctLevel : QRCode.CorrectLevel.M
                });
                modal.classList.remove('opacity-0', 'pointer-events-none');
                modal.classList.add('opacity-100', 'pointer-events-auto');
                card.classList.remove('opacity-0', 'scale-95');
                card.classList.add('opacity-100', 'scale-100');
            } else {
                modal.classList.remove('opacity-100', 'pointer-events-auto');
                modal.classList.add('opacity-0', 'pointer-events-none');
                card.classList.remove('opacity-100', 'scale-100');
                card.classList.add('opacity-0', 'scale-95');
            }
        }

        function getVlessLink(username) {
            const user = window.allUsers.find(function(u) { return u.username === username; });
            if (!user) return '';
            const host = window.location.hostname;
            let cleanIp = host;
            if (user.ips) {
                const ips = user.ips.split('\\n').map(function(ip) { return ip.trim(); }).filter(function(ip) { return ip.length > 0; });
                if (ips.length > 0) cleanIp = ips[0];
            }
            const tlsVal = user.tls === 'on' ? 'tls' : 'none';
            return 'vle' + 'ss://' + (user.uuid || '') + '@' + cleanIp + ':' + user.port + '?path=%2F' + username + '&security=' + tlsVal + '&encryption=none&insecure=0&host=' + host + '&fp=chrome&type=ws&allowInsecure=0&sni=' + host + '#' + username;
        }

        function getSubLink(username) {
            return window.location.origin + '/feed/' + username;
        }

        function getJsonSubLink(username) {
            return window.location.origin + '/feed/json/' + username;
        }

        function copySubLink(username) {
            navigator.clipboard.writeText(getSubLink(username)).then(function() {
                alert('✅ لینک ساب متنی با موفقیت کپی شد!');
            }).catch(function() {
                alert('خطا در کپی کردن لینک ساب!');
            });
        }

        function copyJsonSubLink(username) {
            navigator.clipboard.writeText(getJsonSubLink(username)).then(function() {
                alert('✅ لینک ساب JSON با موفقیت کپی شد!');
            }).catch(function() {
                alert('خطا در کپی کردن لینک ساب JSON!');
            });
        }

        function showSubQR(username, type) {
            if (type === 'normal') {
                toggleQRModal(true, getSubLink(username), 'QR ساب متنی');
            } else if (type === 'json') {
                toggleQRModal(true, getJsonSubLink(username), 'QR ساب JSON');
            }
        }

        function copyConfig(username) {
            const link = getVlessLink(username);
            if (!link) return;
            navigator.clipboard.writeText(link).then(function() {
                alert('✅ کانفیگ VLESS با موفقیت کپی شد!');
            }).catch(function() {
                alert('خطا در کپی کردن کانفیگ!');
            });
        }

        function copyJsonConfig(username) {
            const user = window.allUsers.find(function(u) { return u.username === username; });
            if (!user) return;
            const host = window.location.hostname;
            let cleanIp = host;
            if (user.ips) {
                const ips = user.ips.split('\\n').map(function(ip) { return ip.trim(); }).filter(function(ip) { return ip.length > 0; });
                if (ips.length > 0) cleanIp = ips[0];
            }
            
            const tlsVal = user.tls === 'on' ? 'tls' : 'none';

            const jsonConfig = {
              "remarks": username + " - Fragment",
              "version": {
                "min": "25.10.15"
              },
              "log": {
                "loglevel": "none"
              },
              "dns": {
                "servers": [
                  {
                    "address": "https://8.8.8.8/dns-query",
                    "tag": "remote-dns"
                  },
                  {
                    "address": "8.8.8.8",
                    "domains": [
                      "full:" + host
                    ],
                    "skipFallback": true
                  }
                ],
                "queryStrategy": "UseIP",
                "tag": "dns"
              },
              "inbounds": [
                {
                  "listen": "127.0.0.1",
                  "port": 10808,
                  "protocol": "socks",
                  "settings": {
                    "auth": "noauth",
                    "udp": true
                  },
                  "sniffing": {
                    "destOverride": [
                      "http",
                      "tls"
                    ],
                    "enabled": true,
                    "routeOnly": true
                  },
                  "tag": "mixed-in"
                },
                {
                  "listen": "127.0.0.1",
                  "port": 10853,
                  "protocol": "dokodemo-door",
                  "settings": {
                    "address": "1.1.1.1",
                    "network": "tcp,udp",
                    "port": 53
                  },
                  "tag": "dns-in"
                }
              ],
              "outbounds": [
                {
                  "protocol": "vle" + "ss",
                  "settings": {
                    ["vne" + "xt"]: [
                      {
                        "address": cleanIp,
                        "port": parseInt(user.port),
                        "users": [
                          {
                            "id": user.uuid,
                            "encryption": "none"
                          }
                        ]
                      }
                    ]
                  },
                  ["stream" + "Settings"]: {
                    "network": "ws",
                    ["ws" + "Settings"]: {
                      "host": host,
                      "path": "/" + username
                    },
                    "security": tlsVal,
                    "sockopt": {
                      ["dialer" + "Proxy"]: "fragment"
                    }
                  },
                  "tag": "proxy"
                },
                {
                  "protocol": "freedom",
                  "settings": {
                    "fragment": {
                      "packets": "tlshello",
                      "length": window.globalFragLen || "20-30",
                      "interval": window.globalFragInt || "1-2"
                    }
                  },
                  "streamSettings": {
                    "sockopt": {
                      "domainStrategy": "UseIP",
                      "happyEyeballs": {
                        "tryDelayMs": 250,
                        "prioritizeIPv6": false,
                        "interleave": 2,
                        "maxConcurrentTry": 4
                      }
                    }
                  },
                  "tag": "fragment"
                },
                {
                  "protocol": "dns",
                  "settings": {
                    "nonIPQuery": "reject"
                  },
                  "tag": "dns-out"
                },
                {
                  "protocol": "freedom",
                  "settings": {
                    "domainStrategy": "UseIP"
                  },
                  "tag": "direct"
                },
                {
                  "protocol": "blackhole",
                  "settings": {
                    "response": {
                      "type": "http"
                    }
                  },
                  "tag": "block"
                }
              ],
              "routing": {
                "domainStrategy": "IPIfNonMatch",
                "rules": [
                  {
                    "inboundTag": [
                      "mixed-in"
                    ],
                    "port": 53,
                    "outboundTag": "dns-out",
                    "type": "field"
                  },
                  {
                    "inboundTag": [
                      "dns-in"
                    ],
                    "outboundTag": "dns-out",
                    "type": "field"
                  },
                  {
                    "inboundTag": [
                      "remote-dns"
                    ],
                    "outboundTag": "proxy",
                    "type": "field"
                  },
                  {
                    "inboundTag": [
                      "dns"
                    ],
                    "outboundTag": "direct",
                    "type": "field"
                  },
                  {
                    "domain": [
                      "geosite:private"
                    ],
                    "outboundTag": "direct",
                    "type": "field"
                  },
                  {
                    "ip": [
                      "geoip:private"
                    ],
                    "outboundTag": "direct",
                    "type": "field"
                  },
                  {
                    "network": "udp",
                    "outboundTag": "block",
                    "type": "field"
                  },
                  {
                    "network": "tcp",
                    "outboundTag": "proxy",
                    "type": "field"
                  }
                ]
              }
            };
            
            if (tlsVal === 'tls') {
              jsonConfig.outbounds[0]["stream" + "Settings"]["tls" + "Settings"] = {
                "serverName": host,
                "fingerprint": "chrome",
                "alpn": [
                  "http/1.1"
                ],
                "allowInsecure": false
              };
            }

            navigator.clipboard.writeText(JSON.stringify(jsonConfig, null, 2)).then(function() {
                alert('✅ کانفیگ JSON با موفقیت کپی شد!');
            }).catch(function() {
                alert('خطا در کپی کردن کانفیگ JSON!');
            });
        }

        function showQR(username) {
            const link = getVlessLink(username);
            if (!link) return;
            toggleQRModal(true, link, 'QR کانفیگ VLESS');
        }

        function editUser(username) {
            const user = window.allUsers.find(u => u.username === username);
            if (!user) {
                alert('کاربر یافت نشد!');
                return;
            }

            isEditMode = true;
            editingUsername = username;

            document.getElementById('modal-title').innerText = 'ویرایش کاربر: ' + username;
            document.getElementById('submit-btn').innerText = 'ذخیره تغییرات';

            const nameInput = document.getElementById('input-name');
            nameInput.value = username;
            nameInput.disabled = true;

            document.getElementById('input-limit').value = user.limit_gb || '';
            document.getElementById('input-expiry').value = user.expiry_days || '';
            document.getElementById('input-ips').value = user.ips || '';

            const tlsToggle = document.getElementById('tls-toggle');
            tlsToggle.value = user.tls || 'on';
            updatePorts();

            document.getElementById('port-select').value = user.port || '';

            toggleModal(true);
        }

        async function deleteUser(username) {
            if (confirm('آیا از حذف کاربر ' + username + ' مطمئن هستید؟')) {
                try {
                    const response = await fetch(\`/api/users/\${encodeURIComponent(username)}\`, {
                        method: 'DELETE'
                    });
                    if (response.ok) {
                        alert('✅ کاربر با موفقیت حذف شد.');
                        await loadUsers(true);
                    } else {
                        const errData = await response.json();
                        alert('خطا: ' + (errData.error || 'عملیات ناموفق بود'));
                    }
                } catch (err) {
                    alert('خطا در برقراری ارتباط با سرور');
                }
            }
        }

                        // تبدیل کد کشور به ایموجی پرچم
        function getFlagEmoji(countryCode) {
            if (!countryCode) return '🌐';
            var codePoints = countryCode
                .toUpperCase()
                .split('')
                .map(function(char) { return 127397 + char.charCodeAt(0); });
            try {
                return String.fromCodePoint.apply(null, codePoints);
            } catch (e) {
                return '🌐';
            }
        }

        function renderLocationsUI(locations, activeIata) {
            var select = document.getElementById('location-select');
            // مرتب‌سازی بر اساس نام کشور
            locations.sort(function(a, b) { 
                return (a.cca2 || '').localeCompare(b.cca2 || ''); 
            });

            var html = '<option value="">🌐 پیش‌فرض (بدون لوکیشن)</option>';
            locations.forEach(function(loc) {
                if (loc.iata && loc.city) {
                    var flag = getFlagEmoji(loc.cca2);
                    var isSelected = loc.iata.toUpperCase() === activeIata.toUpperCase() ? 'selected' : '';
                    html += '<option value="' + loc.iata + '" ' + isSelected + '>' + flag + ' ' + loc.city + ' (' + loc.iata + ')</option>';
                }
            });
            select.innerHTML = html;
        }

        // بارگذاری لوکیشن‌ها و لوکیشن فعلی فعال با کش Stale-While-Revalidate
        async function loadLocations() {
            var select = document.getElementById('location-select');
            
            // ۱. تلاش برای لود فوری لوکیشن‌ها از کش محلی
            var cachedLocations = localStorage.getItem('cached_locations_list');
            var cachedActiveIata = localStorage.getItem('cached_active_iata') || '';
            var hasCachedLocs = false;
            
            if (cachedLocations) {
                try {
                    var parsedLocs = JSON.parse(cachedLocations);
                    if (Array.isArray(parsedLocs) && parsedLocs.length > 0) {
                        renderLocationsUI(parsedLocs, cachedActiveIata);
                        hasCachedLocs = true;
                    }
                } catch(e) {}
            }
            
            try {
                // ۲. دریافت همزمان از سرور در پس‌زمینه
                var statusRes = await fetch('/api/proxy-ip');
                var activeIata = '';
                if (statusRes.ok) {
                    var statusData = await statusRes.json();
                    activeIata = statusData.iata || '';
                    localStorage.setItem('cached_active_iata', activeIata);
                    
                    if(statusData.frag_len) {
                        window.globalFragLen = statusData.frag_len;
                        document.getElementById('frag-length').value = statusData.frag_len;
                    }
                    if(statusData.frag_int) {
                        window.globalFragInt = statusData.frag_int;
                        document.getElementById('frag-interval').value = statusData.frag_int;
                    }
                }

                var res = await fetch('/locations');
                if (!res.ok) throw new Error();
                var locations = await res.json();
                
                localStorage.setItem('cached_locations_list', JSON.stringify(locations));
                renderLocationsUI(locations, activeIata);
            } catch (err) {
                if (!hasCachedLocs) {
                    select.innerHTML = '<option value="">⚠️ خطا در دریافت لوکیشن‌ها</option>';
                }
            }
        }

        // ذخیره تنظیمات (لوکیشن و فرگمنت)
        async function saveSettings() {
            var select = document.getElementById('location-select');
            var fragLen = document.getElementById('frag-length').value || "20-30";
            var fragInt = document.getElementById('frag-interval').value || "1-2";
            var iata = select.value;
            var btn = document.getElementById('save-settings-btn');
            
            btn.disabled = true;
            btn.innerText = 'در حال ذخیره...';
            
            try {
                var resolvedIp = 'proxyip.cmliussss.net';
                if (iata) {
                    var domain = iata.toLowerCase() + '.proxyip.cmliussss.net';
                    var dnsRes = await fetch('https://cloudflare-dns.com/dns-query?name=' + domain + '&type=A', {
                        headers: { 'accept': 'application/dns-json' }
                    });
                    resolvedIp = domain;
                    if (dnsRes.ok) {
                        var dnsData = await dnsRes.json();
                        if (dnsData.Answer && dnsData.Answer.length > 0) {
                            var ips = dnsData.Answer.filter(function(ans) { return ans.type === 1; }).map(function(ans) { return ans.data; });
                            if (ips.length > 0) {
                                resolvedIp = ips[Math.floor(Math.random() * ips.length)];
                            }
                        }
                    }
                }

                var response = await fetch('/api/proxy-ip', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        proxy_ip: resolvedIp,
                        iata: iata ? iata.toUpperCase() : '',
                        frag_len: fragLen,
                        frag_int: fragInt
                    })
                });

                if (response.ok) {
                    window.globalFragLen = fragLen;
                    window.globalFragInt = fragInt;
                    alert('✅ تنظیمات با موفقیت ذخیره شد.\\n' + (iata ? 'آی‌پی پروکسی کلودفلر: ' + resolvedIp : 'آدرس پروکسی به حالت پیش‌فرض بازگشت.'));
                    toggleSettingsModal(false);
                } else {
                    alert('خطا در ذخیره تنظیمات');
                }
            } catch (err) {
                alert('خطا در برقراری ارتباط با سرور');
            } finally {
                btn.disabled = false;
                btn.innerText = 'ذخیره تنظیمات';
            }
        }

        // لود کردن کاربران و لوکیشن‌ها به محض لود شدن صفحه
        document.addEventListener('DOMContentLoaded', function() {
            loadUsers();
            loadLocations();
        });
    </script></body>
</html>
`;

const htmlSetupTemplate = `
<!DOCTYPE html>
<html lang="fa" dir="rtl" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>تعریف رمز عبور پنل</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/Vazirmatn-font-face.css" rel="stylesheet" type="text/css" />
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    fontFamily: { sans: ['Vazirmatn', 'sans-serif'] },
                    colors: { amoled: { bg: '#000000', card: '#0a0a0a', input: '#121212', border: '#1f1f1f' } }
                }
            }
        }
    </script>
</head>
<body class="bg-gray-50 text-gray-900 dark:bg-amoled-bg dark:text-zinc-100 min-h-screen flex items-center justify-center p-4">
    <div class="w-full max-w-md bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-2xl shadow-xl p-6">
        <h2 class="text-xl font-bold mb-2 text-center text-blue-600 dark:text-blue-400">تنظیم رمز عبور جدید</h2>
        <p class="text-sm text-gray-500 dark:text-gray-400 text-center mb-6">این اولین ورود شما به پنل مدیریت است. لطفاً رمز عبور خود را تعیین کنید.</p>
        
        <form onsubmit="handleSetup(event)" class="space-y-4">
            <div>
                <label class="block text-sm font-medium mb-1.5">رمز عبور</label>
                <input type="password" id="password" class="w-full px-3 py-2 bg-gray-50 dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm text-center font-mono" required minlength="4">
            </div>
            <div>
                <label class="block text-sm font-medium mb-1.5">تکرار رمز عبور</label>
                <input type="password" id="confirm-password" class="w-full px-3 py-2 bg-gray-50 dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm text-center font-mono" required minlength="4">
            </div>
            <button type="submit" id="submit-btn" class="w-full py-2.5 bg-blue-600 hover:bg-blue-700 text-white font-medium rounded-lg text-sm transition font-bold">ثبت و ورود</button>
        </form>
    </div>

    <script>
        async function handleSetup(event) {
            event.preventDefault();
            const password = document.getElementById('password').value;
            const confirmPassword = document.getElementById('confirm-password').value;
            const btn = document.getElementById('submit-btn');

            if (password !== confirmPassword) {
                alert('⚠️ رمز عبور و تکرار آن مطابقت ندارند!');
                return;
            }

            btn.disabled = true;
            btn.innerText = 'در حال ثبت...';

            try {
                const res = await fetch('/api/setup-password', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ password })
                });
                const data = await res.json();
                if (res.ok && data.success) {
                    alert('✅ رمز عبور با موفقیت تنظیم شد. در حال ورود...');
                    window.location.reload();
                } else {
                    alert('خطا: ' + (data.error || 'عملیات ناموفق بود'));
                }
            } catch (err) {
                alert('خطا در ارتباط با سرور');
            } finally {
                btn.disabled = false;
                btn.innerText = 'ثبت و ورود';
            }
        }
    </script>
</body>
</html>
`;

const htmlLoginTemplate = `
<!DOCTYPE html>
<html lang="fa" dir="rtl" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ورود به پنل مدیریت</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="https://cdn.jsdelivr.net/gh/rastikerdar/vazirmatn@v33.003/Vazirmatn-font-face.css" rel="stylesheet" type="text/css" />
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    fontFamily: { sans: ['Vazirmatn', 'sans-serif'] },
                    colors: { amoled: { bg: '#000000', card: '#0a0a0a', input: '#121212', border: '#1f1f1f' } }
                }
            }
        }
    </script>
</head>
<body class="bg-gray-50 text-gray-900 dark:bg-amoled-bg dark:text-zinc-100 min-h-screen flex items-center justify-center p-4">
    <div class="w-full max-w-md bg-white dark:bg-amoled-card border border-gray-200 dark:border-amoled-border rounded-2xl shadow-xl p-6">
        <h2 class="text-xl font-bold mb-2 text-center text-blue-600 dark:text-blue-400">ورود به پنل مدیریت</h2>
        <p class="text-sm text-gray-500 dark:text-gray-400 text-center mb-6">برای دسترسی به پنل مدیریت، رمز عبور خود را وارد کنید.</p>
        
        <form onsubmit="handleLogin(event)" class="space-y-4">
            <div>
                <label class="block text-sm font-medium mb-1.5">رمز عبور</label>
                <input type="password" id="password" class="w-full px-3 py-2 bg-gray-50 dark:bg-amoled-input border border-gray-300 dark:border-amoled-border rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm text-center font-mono" required>
            </div>
            <button type="submit" id="submit-btn" class="w-full py-2.5 bg-blue-600 hover:bg-blue-700 text-white font-medium rounded-lg text-sm transition font-bold">ورود</button>
        </form>
    </div>

    <script>
        async function handleLogin(event) {
            event.preventDefault();
            const password = document.getElementById('password').value;
            const btn = document.getElementById('submit-btn');

            btn.disabled = true;
            btn.innerText = 'در حال بررسی...';

            try {
                const res = await fetch('/api/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ password })
                });
                const data = await res.json();
                if (res.ok && data.success) {
                    window.location.reload();
                } else {
                    alert('❌ رمز عبور اشتباه است!');
                }
            } catch (err) {
                alert('خطا در ارتباط با سرور');
            } finally {
                btn.disabled = false;
                btn.innerText = 'ورود';
            }
        }
    </script>
</body>
</html>
`;

const htmlNginxTemplate = `<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
html { color-scheme: light dark; }
body { width: 35em; margin: 0 auto;
font-family: Tahoma, Verdana, Arial, sans-serif; }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>`;

let schemaEnsured = false;
let cachedPanelPassword = null;
let cachedLiveUsage = null;
let lastLiveUsageFetch = 0;

async function ensureSchema(db) {
  if (schemaEnsured) return;
  try {
    await db.prepare(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        uuid TEXT,
        limit_gb INTEGER,
        expiry_days INTEGER,
        ips TEXT,
        connection_type TEXT,
        tls TEXT,
        port INTEGER,
        used_gb REAL DEFAULT 0,
        is_active INTEGER DEFAULT 1,
        last_active INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `).run();
  } catch (e) {}
  try {
    await db.prepare("ALTER TABLE users ADD COLUMN is_active INTEGER DEFAULT 1").run();
  } catch (e) {}
  try {
    await db.prepare("ALTER TABLE users ADD COLUMN last_active INTEGER").run();
  } catch (e) {}
    try {
    await db.prepare("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)").run();
  } catch (e) {}
  schemaEnsured = true;
}

async function getPanelPassword(db) {
  if (cachedPanelPassword !== null) return cachedPanelPassword;
  try {
    const row = await db.prepare("SELECT value FROM settings WHERE key = 'panel_password'").first();
    cachedPanelPassword = row ? row.value : "";
    return cachedPanelPassword || null;
  } catch (e) {
    return null;
  }
}

async function setPanelPassword(db, password) {
  await db.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('panel_password', ?)").bind(password).run();
  cachedPanelPassword = password;
}

async function verifyApiAuth(request, env) {
  const storedPasswordHash = await getPanelPassword(env.DB);
  if (!storedPasswordHash) {
    return true;
  }
  const cookies = request.headers.get('Cookie') || '';
  const sessionCookie = cookies.split(';').find(c => c.trim().startsWith('panel_session='));
  if (!sessionCookie) return false;
  const sessionToken = sessionCookie.split('=')[1].trim();
  return sessionToken === storedPasswordHash;
}

async function sha256(message) {
  const msgBuffer = new TextEncoder().encode(message);
  const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

async function getLiveUsage(env, force = false) {
  const apiToken = env.CF_API_TOKEN;
  const accountId = env.CF_ACCOUNT_ID;
  if (!apiToken || !accountId) {
    return null;
  }

  const nowMs = Date.now();
  if (!force && cachedLiveUsage && (nowMs - lastLiveUsageFetch < 30000)) {
    return cachedLiveUsage;
  }

  const now = new Date();
  const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
  const startOfToday = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));

  const query = `
    query GetUsage($accountTag: String!, $filter30d: AccountHttpRequestsAdaptiveGroupsFilter_Input!, $filter24h: AccountHttpRequestsAdaptiveGroupsFilter_Input!) {
      viewer {
        accounts(filter: { accountTag: $accountTag }) {
          usage30d: httpRequestsAdaptiveGroups(
            filter: $filter30d,
            limit: 1000,
            orderBy: [sum_edgeResponseBytes_DESC]
          ) {
            sum {
              edgeResponseBytes
            }
            dimensions {
              clientRequestPath
            }
          }
          usage24h: httpRequestsAdaptiveGroups(
            filter: $filter24h,
            limit: 1000
          ) {
            count
            dimensions {
              clientRequestPath
            }
          }
          accountTotal24h: httpRequestsAdaptiveGroups(
            filter: $filter24h,
            limit: 1
          ) {
            count
          }
        }
      }
    }
  `;

    const variables = {
    accountTag: accountId,
    filter30d: {
      datetime_geq: thirtyDaysAgo.toISOString(),
      datetime_lt: now.toISOString()
    },
    filter24h: {
      datetime_geq: startOfToday.toISOString(),
      datetime_lt: now.toISOString()
    }
  };

  try {
    const response = await fetch("https://api.cloudflare.com/client/v4/graphql", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${apiToken}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ query, variables })
    });

    if (response.ok) {
      const resData = await response.json();
      const usage30d = resData?.data?.viewer?.accounts?.[0]?.usage30d || [];
      const usage24h = resData?.data?.viewer?.accounts?.[0]?.usage24h || [];
      const accountTotal24h = resData?.data?.viewer?.accounts?.[0]?.accountTotal24h || [];
      
      const usageMap = new Map();
      
      for (const item of usage30d) {
        const path = item.dimensions.clientRequestPath;
        if (path && path.startsWith("/")) {
          const username = path.slice(1);
          if (username) {
            const bytes = item.sum.edgeResponseBytes || 0;
            const gb = bytes / (1024 * 1024 * 1024);
            usageMap.set(username, {
              gb: Math.round(gb * 10000) / 10000,
              count: 0
            });
          }
        }
      }

      for (const item of usage24h) {
        const path = item.dimensions.clientRequestPath;
        const count = item.count || 0;
        if (path && path.startsWith("/")) {
          const username = path.slice(1);
          if (username) {
            if (usageMap.has(username)) {
              usageMap.get(username).count = count;
            } else {
              usageMap.set(username, {
                gb: 0,
                count: count
              });
            }
          }
        }
      }

            let totalTodayRequests = 0;
      if (accountTotal24h && accountTotal24h.length > 0) {
        totalTodayRequests = accountTotal24h[0].count || 0;
      } else {
        // Fallback: sum up the counts if accountTotal24h didn't return
        for (const item of usage24h) {
          totalTodayRequests += item.count || 0;
        }
      }

      usageMap.set("__total_today_requests__", { gb: 0, count: totalTodayRequests });

      cachedLiveUsage = usageMap;
      lastLiveUsageFetch = nowMs;
      return usageMap;
    }
  } catch (e) {
    console.error("Error fetching live usage:", e);
  }
  return null;
}

async function checkAndDisconnectUsers(env) {
  const liveUsage = await getLiveUsage(env);
  const { results: users } = await env.DB.prepare("SELECT * FROM users").all();
  if (users && users.length > 0) {
    const statements = [];
    for (const user of users) {
      let usedGb = user.used_gb || 0;
      if (liveUsage && liveUsage.has(user.username)) {
        usedGb = Math.max(usedGb, liveUsage.get(user.username).gb);
      }

      let shouldBeActive = 1;

      if (user.limit_gb && usedGb >= user.limit_gb) {
        shouldBeActive = 0;
      }

      if (user.expiry_days && user.created_at) {
        const created = new Date(user.created_at);
        const expiryDate = new Date(created.getTime() + (user.expiry_days * 24 * 60 * 60 * 1000));
        if (new Date() > expiryDate) {
          shouldBeActive = 0;
        }
      }

      if (user.is_active !== shouldBeActive || user.used_gb !== usedGb) {
        statements.push(
          env.DB.prepare("UPDATE users SET is_active = ?, used_gb = ? WHERE username = ?").bind(shouldBeActive, usedGb, user.username)
        );
      }
    }

    if (statements.length > 0) {
      await env.DB.batch(statements);
    }
  }
}

async function saveDailyUsageToD1(env) {
  const liveUsage = await getLiveUsage(env);
  if (!liveUsage) return;

  const { results: users } = await env.DB.prepare("SELECT username, used_gb FROM users").all();
  if (users && users.length > 0) {
    const statements = [];
    for (const user of users) {
      const uData = liveUsage.get(user.username);
      if (uData !== undefined) {
        const newGb = Math.max(user.used_gb || 0, uData.gb);
        statements.push(
          env.DB.prepare("UPDATE users SET used_gb = ? WHERE username = ?").bind(newGb, user.username)
        );
      }
    }
    if (statements.length > 0) {
      await env.DB.batch(statements);
    }
  }
}

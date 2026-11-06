/* snake web UI. Vanilla JS, no dependencies; runs inside the Merlin Addons
 * page (token from custom_settings) or standalone on the API port. */
(function () {
  'use strict';
  var CTX = window.SNAKE_CTX || {};
  var TUNNELS = ['wgc1', 'wgc2', 'wgc3', 'wgc4', 'wgc5', 'ovpnc1', 'ovpnc2', 'ovpnc3', 'ovpnc4', 'ovpnc5'];
  var state = { tab: 'status', cfg: null, dirty: false, status: null, clients: [], edit: null, error: '' };
  var root;

  // ---------- helpers ----------
  function el(tag, attrs) {
    var e = document.createElement(tag);
    if (attrs) for (var k in attrs) {
      var v = attrs[k];
      if (v == null || v === false) continue;
      if (k === 'class') e.className = v;
      else if (k.slice(0, 2) === 'on') e.addEventListener(k.slice(2), v);
      else if (k === 'value') e.value = v;
      else if (k === 'checked') e.checked = !!v;
      else e.setAttribute(k, v === true ? '' : v);
    }
    for (var i = 2; i < arguments.length; i++) add(e, arguments[i]);
    return e;
  }
  function add(e, c) {
    if (c == null || c === false) return;
    if (Array.isArray(c)) { c.forEach(function (x) { add(e, x); }); return; }
    e.appendChild(c.nodeType ? c : document.createTextNode(String(c)));
  }
  function badge(text, kind) { return el('span', { class: 'badge' + (kind ? ' b-' + kind : '') }, text); }
  function btn(text, fn, cls) { return el('button', { type: 'button', class: 'btn ' + (cls || ''), onclick: fn }, text); }
  function toast(msg) {
    var t = el('div', { class: 'toast' }, msg);
    root.appendChild(t);
    setTimeout(function () { t.remove(); }, 3500);
  }
  function fmtBytes(n) {
    if (!n) return '0 B';
    var u = ['B', 'KB', 'MB', 'GB', 'TB'], i = 0;
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    return n.toFixed(i ? 1 : 0) + ' ' + u[i];
  }
  function ago(ts) {
    if (!ts || ts.indexOf('0001-') === 0) return 'never';
    var s = Math.round((Date.now() - new Date(ts).getTime()) / 1000);
    if (s < 0) s = 0;
    if (s < 90) return s + 's ago';
    if (s < 5400) return Math.round(s / 60) + 'm ago';
    return Math.round(s / 3600) + 'h ago';
  }
  function lines(s) { return (s || '').split(/[\n,]+/).map(function (x) { return x.trim(); }).filter(Boolean); }
  function clone(o) { return JSON.parse(JSON.stringify(o)); }

  function api(method, path, body) {
    var opt = { method: method, headers: {} };
    if (CTX.token) opt.headers['Authorization'] = 'Bearer ' + CTX.token;
    if (body !== undefined) { opt.headers['Content-Type'] = 'application/json'; opt.body = JSON.stringify(body); }
    return fetch((CTX.apiBase || '') + path, opt).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (j) {
        if (r.status === 401 && CTX.mode === 'standalone') { askToken(); }
        if (!r.ok) throw new Error(j.error || ('HTTP ' + r.status));
        return j;
      });
    }, function (e) {
      throw new Error('cannot reach snake daemon at ' + (CTX.apiBase || location.origin) +
        (location.protocol === 'https:' ? ' (open it once in a tab to accept the router certificate)' : '') + ': ' + e.message);
    });
  }
  function askToken() {
    var t = prompt('snake API token (run "snake token" on the router):', '');
    if (t) { try { localStorage.setItem('snake_token', t.trim()); } catch (e) {} CTX.token = t.trim(); load(); }
  }

  // ---------- data ----------
  function fixCfg(c) {
    c.policies = c.policies || []; c.groups = c.groups || []; c.devices = c.devices || []; c.rule_lists = c.rule_lists || [];
    c.rule_lists.forEach(function (l) { ['domains', 'asns', 'cidrs'].forEach(function (k) { l[k] = l[k] || []; }); });
    c.policies.forEach(function (p) {
      ['tunnels', 'domains', 'asns', 'cidrs', 'devices', 'lists'].forEach(function (k) { p[k] = p[k] || []; });
      p.leak = p.leak || {};
    });
    c.groups.forEach(function (g) { g.macs = g.macs || []; });
    return c;
  }
  function load() {
    state.error = '';
    return Promise.all([api('GET', '/api/config'), api('GET', '/api/status'), api('GET', '/api/clients')])
      .then(function (r) {
        if (!state.dirty) state.cfg = fixCfg(r[0]);
        state.status = r[1]; state.clients = r[2] || [];
        render();
      }).catch(function (e) { state.error = e.message; render(); });
  }
  function refreshStatus() {
    if (document.hidden) return;
    api('GET', '/api/status').then(function (s) { state.status = s; if (state.tab === 'status') render(); }).catch(function () {});
  }
  function save() {
    return api('PUT', '/api/config', state.cfg).then(function (c) {
      state.cfg = fixCfg(c); state.dirty = false; state.edit = null; toast('Saved and applied');
      return load();
    }).catch(function (e) { state.error = e.message; render(); });
  }
  function markDirty() { state.dirty = true; renderBanner(); }

  // ---------- layout ----------
  var TABS = [['status', 'Status'], ['policies', 'Policies'], ['lists', 'Rule lists'], ['devices', 'Devices & groups'], ['diag', 'Diagnostics'], ['settings', 'Settings'], ['import', 'Import']];
  var bannerBox;
  function render() {
    var scrollY = window.scrollY;
    root.innerHTML = '';
    root.appendChild(el('h2', null, 'snake: split tunnelling ', el('span', { class: 'muted small' }, state.status ? state.status.version : '')));
    root.appendChild(el('div', { class: 'tabs' }, TABS.map(function (t) {
      return el('button', { type: 'button', class: 'tab' + (state.tab === t[0] ? ' on' : ''), onclick: function () {
        if (state.listEdit && state.listEdit.changed && !confirm('Discard unsaved changes to the rule list?')) return;
        state.tab = t[0]; state.edit = null; state.listEdit = null; render();
      } }, t[1]);
    })));
    bannerBox = el('div');
    root.appendChild(bannerBox);
    renderBanner();
    if (state.error) root.appendChild(el('div', { class: 'err' }, state.error));
    if (!state.cfg) { root.appendChild(el('p', { class: 'muted' }, 'Loading...')); return; }
    var body = el('div');
    root.appendChild(body);
    ({ status: viewStatus, policies: viewPolicies, lists: viewLists, devices: viewDevices, diag: viewDiag, settings: viewSettings, import: viewImport })[state.tab](body);
    window.scrollTo(0, scrollY);
  }
  function renderBanner() {
    if (!bannerBox) return;
    bannerBox.innerHTML = '';
    if (state.dirty) bannerBox.appendChild(el('div', { class: 'banner' }, 'You have unsaved changes.',
      el('span', { class: 'row' }, btn('Discard', function () { state.dirty = false; state.edit = null; load(); }), btn('Save & apply', save, 'pri'))));
  }

  // ---------- status ----------
  function tunnelBadge(t) {
    if (!t) return badge('unknown');
    if (t.healthy) return badge('healthy', 'ok');
    if (!t.exists) return badge('missing', 'bad');
    return badge(t.reason || 'unhealthy', 'bad');
  }
  function viewStatus(b) {
    var s = state.status;
    if (!s) return;
    if (s.last_error) b.appendChild(el('div', { class: 'err' }, 'Last apply error: ' + s.last_error));
    b.appendChild(el('div', { class: 'row', style: 'margin-bottom:10px' },
      btn('Re-check tunnels', function () { api('POST', '/api/recheck').then(function () { toast('Health check scheduled'); setTimeout(refreshStatus, 4000); }); }),
      btn('Re-apply rules', function () { api('POST', '/api/apply').then(function () { toast('Applied'); refreshStatus(); }).catch(function (e) { toast(e.message); }); }),
      el('span', { class: 'muted small' }, 'WAN ' + (s.wan_ip || '?') + ' · uptime ' + s.uptime + ' · applied ' + ago(s.last_apply) + ' · IPv6 ' + (s.caps.ipv6 ? 'yes' : 'no') + ' · NFQUEUE ' + (s.caps.nfqueue ? 'yes' : 'no') +
        (s.dns_inspector ? ' · DNS inspector: ' + s.dns_inspector.answers + ' answers, ' + s.dns_inspector.matched + ' matched, ' + s.dns_inspector.added + ' IPs added' : ''))));

    var tn = Object.keys(s.tunnels || {}).sort();
    b.appendChild(el('h3', null, 'Tunnels'));
    if (!tn.length) b.appendChild(el('p', { class: 'muted' }, 'No tunnels in use. Create a policy first.'));
    b.appendChild(el('div', { class: 'grid' }, tn.map(function (k) {
      var t = s.tunnels[k];
      return el('div', { class: 'card' },
        el('div', { class: 'row', style: 'justify-content:space-between' }, el('b', null, k + ' (' + t.iface + ')'), tunnelBadge(t)),
        el('div', { class: 'kv', style: 'margin-top:6px' },
          el('span', null, 'Exit'), el('span', null, (t.exit_ip || '?') + ' ' + (t.country || '')),
          el('span', null, 'Probe'), el('span', null, t.probe_ok ? ('ok ' + (t.probe_rtt || '')) : ('failing (' + t.probe_fails + ')')),
          k.indexOf('wgc') === 0 ? [el('span', null, 'Handshake'), el('span', null, ago(t.handshake))] : [el('span', null, 'State'), el('span', null, t.client_state === '2' ? 'connected' : (t.client_state || '?'))],
          el('span', null, 'IPv6'), el('span', null, t.has_ipv6 ? 'yes' : 'no'),
          el('span', null, 'Geo'), el('span', null, t.geo_error ? t.geo_error : ago(t.geo_checked))));
    })));

    b.appendChild(el('h3', null, 'Policies'));
    b.appendChild(el('div', { class: 'scroll' }, el('table', null,
      el('tr', null, ['Policy', 'Scope', 'Route', 'IPv6', 'WebRTC', 'Learned', 'Traffic'].map(function (h) { return el('th', null, h); })),
      (s.policies || []).map(function (p) {
        var route = !p.enabled ? badge('disabled') : p.active ? badge(p.active + (p.country ? ' ' + p.country : ''), 'ok') :
          p.kill_engaged ? badge('kill switch: blocked', 'warn') : badge('WAN (no tunnel)', 'bad');
        var sets = Object.keys(p.sets || {}).map(function (k) { return k.replace(/^SNK_\d+_/, '') + ':' + p.sets[k]; }).join(' ');
        var cands = (p.candidates || []).map(function (c) { return el('div', { class: 'small ' + (c.ok ? '' : 'muted') }, (c.ok ? '✓ ' : '✗ ') + c.tunnel + (c.reason ? ' (' + c.reason + ')' : '')); });
        return el('tr', null,
          el('td', null, el('b', null, p.name), p.domain_mode ? el('div', { class: 'small ' + (p.domain_mode.indexOf('degraded') === 0 ? '' : 'muted'), style: p.domain_mode.indexOf('degraded') === 0 ? 'color:var(--warn)' : '' }, 'domains: ' + p.domain_mode) : null,
            (p.asn_errors || []).map(function (e) { return el('div', { class: 'small', style: 'color:var(--warn)' }, e); })),
          el('td', null, p.scope),
          el('td', null, route, cands),
          el('td', null, p.ipv6_mode || ''),
          el('td', null, p.webrtc_mode || '', p.webrtc ? el('div', { class: 'small muted' }, 'stun ' + p.webrtc.stun + ' · peers ' + p.webrtc.learned) : null),
          el('td', { class: 'mono' }, sets),
          el('td', null, fmtBytes(p.bytes), el('div', { class: 'small muted' }, p.packets + ' pkts')));
      }))));

    b.appendChild(el('h3', null, 'Events'));
    var ev = (s.events || []).slice(-40).reverse();
    b.appendChild(ev.length ? el('table', null, ev.map(function (e) {
      return el('tr', null, el('td', { class: 'small muted' }, new Date(e.time).toLocaleString()), el('td', null, badge(e.kind, e.kind === 'failover' ? 'warn' : 'info')), el('td', null, (e.policy ? e.policy + ': ' : '') + e.msg));
    })) : el('p', { class: 'muted' }, 'No events yet.'));
  }

  // ---------- rule file editor ----------
  var SYNTAX = [
    ['example.com', 'domain and all subdomains'],
    ['.example.com', 'subdomains only'],
    ['=example.com', 'exactly this name'],
    ['*.example.com', '* = any text within one label'],
    ['**.example.com', '** = any text across labels'],
    ['cdn-?.example.com', '? = one character'],
    ['~keyword', 'name contains keyword'],
    ['/regex/  or  re:regex', 'RE2 regular expression, case-insensitive'],
    ['!rule', 'exclusion: vetoes matches of the rules'],
    ['asn:2906', 'autonomous system (all its announced prefixes)'],
    ['cidr:23.246.0.0/18', 'address range or single IP (ip: also works)'],
    ['@name / @description / @source', 'list metadata (rule lists)'],
    ['# text', 'comment']
  ];
  function syntaxHelp() {
    return el('details', { class: 'small', style: 'margin:4px 0' }, el('summary', { class: 'muted', style: 'cursor:pointer' }, 'Rule file syntax'),
      el('table', null, SYNTAX.map(function (r) { return el('tr', null, el('td', { class: 'mono' }, r[0]), el('td', null, r[1])); })),
      el('div', { class: 'muted' }, 'Importing also converts AdGuard (||example.com^), hosts (0.0.0.0 example.com) and dnsmasq (server=/a/b/...) lines. With CNAME matching on, a rule also matches any name in the answer\'s CNAME chain.'));
  }
  function esc(s) { return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;'); }
  function span(cls, text) { return text ? '<span class="t-' + cls + '">' + esc(text) + '</span>' : ''; }
  // Highlight one line of the rule-file format.
  function hlLine(line) {
    var m, lead = (/^\s*/.exec(line) || [''])[0], t = line.slice(lead.length);
    if (!t) return esc(line);
    if (t[0] === '#') return esc(lead) + span('com', t);
    if (t[0] === '@') { m = /^(@\S*)(.*)$/.exec(t); return esc(lead) + span('dir', m[1]) + span('str', m[2]); }
    if ((m = /^(asn:|cidr:|ip:)(.*)$/i.exec(t))) {
      var c = splitComment(m[2]);
      return esc(lead) + span('kw', m[1]) + span('num', c[0]) + span('com', c[1]);
    }
    var out = esc(lead);
    if (t[0] === '!') { out += span('neg', '!'); t = t.slice(1); }
    if (t[0] === '/' || /^re:/i.test(t)) return out + span('re', t);
    var cm = splitComment(t); t = cm[0];
    if (t[0] === '~') out += span('kw', '~') + span('str', t.slice(1));
    else {
      if (t[0] === '=' || t[0] === '.') { out += span('op', t[0]); t = t.slice(1); }
      out += t.split(/(\*\*|\*|\?)/).map(function (part) { return /^(\*\*|\*|\?)$/.test(part) ? span('wild', part) : span('dom', part); }).join('');
    }
    return out + span('com', cm[1]);
  }
  function splitComment(t) { var i = t.indexOf(' #'); return i < 0 ? [t, ''] : [t.slice(0, i), t.slice(i)]; }

  // ruleEditor builds a highlighted editor for the rule-file format with
  // line numbers, live validation via the API, a name tester and Ctrl+S.
  function ruleEditor(opt) {
    var wrap = el('div', { class: 'redit', style: 'height:' + (opt.height || 280) + 'px' });
    var gutter = el('div', { class: 'redit-gut' });
    var hl = el('pre', { class: 'redit-hl', 'aria-hidden': 'true' });
    var ta = el('textarea', { class: 'redit-ta', spellcheck: 'false', wrap: 'off', autocapitalize: 'off', autocomplete: 'off', placeholder: opt.placeholder || '' });
    ta.value = opt.value || '';
    wrap.appendChild(gutter); wrap.appendChild(hl); wrap.appendChild(ta);
    var status = el('div', { class: 'small redit-status' });
    var issues = el('div', { class: 'small' });
    var testIn = el('input', { type: 'text', placeholder: 'test a name against these rules', style: 'flex:1;min-width:180px' });
    var testOut = el('span', { class: 'small' });
    var errLines = {}, warnLines = {}, last = null, timer = null, seq = 0;
    function paint() {
      var ls = ta.value.split('\n');
      hl.innerHTML = ls.map(function (l, i) {
        var cls = errLines[i + 1] ? ' class="l-err"' : warnLines[i + 1] ? ' class="l-warn"' : '';
        return '<div' + cls + '>' + (hlLine(l) || ' ') + '</div>';
      }).join('') + '<div> </div>';
      gutter.innerHTML = ls.map(function (l, i) {
        var n = i + 1, cls = errLines[n] ? 'g-err' : warnLines[n] ? 'g-warn' : '';
        return '<div class="' + cls + '" title="' + esc(errLines[n] || warnLines[n] || '') + '">' + n + '</div>';
      }).join('') + '<div> </div>';
      sync();
    }
    function sync() { hl.scrollTop = ta.scrollTop; hl.scrollLeft = ta.scrollLeft; gutter.scrollTop = ta.scrollTop; }
    function jump(line) {
      var ls = ta.value.split('\n'), pos = 0;
      for (var i = 0; i < line - 1 && i < ls.length; i++) pos += ls[i].length + 1;
      ta.focus(); ta.setSelectionRange(pos, pos + (ls[line - 1] || '').length);
      ta.scrollTop = Math.max(0, (line - 4) * 18);
      sync();
    }
    function check() {
      var my = ++seq;
      return api('POST', '/api/rulefile/parse', { text: ta.value, name: testIn.value.trim(), convert: false }).then(function (r) {
        if (my !== seq) return r;
        last = r; errLines = {}; warnLines = {};
        (r.errors || []).forEach(function (e) { errLines[e.line] = e.message; });
        (r.warnings || []).forEach(function (w) { warnLines[w.line] = w.message; });
        paint();
        var f = r.file || {}, k = r.kinds || {};
        var kinds = Object.keys(k).sort().map(function (x) { return k[x] + ' ' + x; }).join(', ');
        status.innerHTML = '';
        status.appendChild(el('span', null,
          (r.errors || []).length ? badge((r.errors.length) + ' error' + (r.errors.length > 1 ? 's' : ''), 'bad') : badge('valid', 'ok'), ' ',
          el('span', { class: 'muted' }, [kinds || 'no domain rules', (f.asns || []).length + ' ASNs', (f.cidrs || []).length + ' CIDRs'].join(' · ') +
            (r.inspector ? ' · needs DNS inspection' : ''))));
        issues.innerHTML = '';
        (r.errors || []).concat(r.warnings || []).slice(0, 30).forEach(function (e) {
          var isErr = !!errLines[e.line] && errLines[e.line] === e.message;
          issues.appendChild(el('div', { class: 'redit-issue', style: 'color:var(--' + (isErr ? 'bad' : 'warn') + ')', onclick: function () { jump(e.line); } },
            'line ' + e.line + ': ' + e.message));
        });
        testOut.innerHTML = '';
        if (r.result) {
          var x = r.result;
          testOut.appendChild(x.matched ? badge('match: ' + x.rule, 'ok') : x.excluded ? badge('excluded by ' + x.excluded, 'warn') : badge('no match'));
        }
        if (opt.onCheck) opt.onCheck(r);
        return r;
      }).catch(function (e) { status.textContent = e.message; });
    }
    function schedule() { clearTimeout(timer); timer = setTimeout(check, 300); }
    ta.addEventListener('input', function () { paint(); schedule(); if (opt.onChange) opt.onChange(ta.value); });
    ta.addEventListener('scroll', sync);
    ta.addEventListener('keydown', function (e) {
      if ((e.ctrlKey || e.metaKey) && e.key === 's') { e.preventDefault(); if (opt.onSave) opt.onSave(); }
      if (e.key === 'Tab' && !e.shiftKey) {
        e.preventDefault();
        var a = ta.selectionStart; ta.setRangeText('  ', a, ta.selectionEnd, 'end'); paint(); schedule();
      }
    });
    testIn.addEventListener('input', schedule);
    paint();
    setTimeout(check, 0);
    var root = el('div', null, wrap, status, issues, el('div', { class: 'row', style: 'margin-top:4px' }, testIn, testOut));
    return {
      el: root,
      get: function () { return ta.value; },
      set: function (v) { ta.value = v; paint(); check(); if (opt.onChange) opt.onChange(v); },
      check: check,
      last: function () { return last; },
      tidy: function () {
        return check().then(function (r) {
          if (r && r.formatted != null) { ta.value = r.formatted; paint(); check(); if (opt.onChange) opt.onChange(ta.value); }
          else toast('Fix the errors first');
        });
      }
    };
  }
  function download(name, text) {
    var a = el('a', { href: URL.createObjectURL(new Blob([text], { type: 'text/plain' })), download: name });
    document.body.appendChild(a); a.click(); setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
  }
  function fileName(n) { return (n || 'rules').replace(/[^A-Za-z0-9._-]/g, '_') + '.rules'; }
  function pickFile(cb) {
    var inp = el('input', { type: 'file', accept: '.rules,.txt,.list,.conf,text/plain', style: 'display:none' });
    inp.addEventListener('change', function () {
      var f = inp.files[0];
      if (!f) return;
      if (f.size > 4 * 1024 * 1024) { toast('File larger than 4 MB'); return; }
      var rd = new FileReader();
      rd.onload = function () { cb(String(rd.result), f.name); inp.remove(); };
      rd.readAsText(f);
    });
    document.body.appendChild(inp); inp.click();
  }
  // importText converts foreign formats and returns canonical rule-file text.
  function importText(text) {
    return api('POST', '/api/rulefile/parse', { text: text, convert: true }).then(function (r) {
      var f = r.file;
      var msg = [];
      if (r.converted) msg.push('converted ' + r.converted + ' line(s) from other formats');
      if ((r.errors || []).length) msg.push('skipped ' + r.errors.length + ' invalid line(s)');
      if (msg.length) toast(msg.join(', '));
      return { file: f, text: formatFile(f) };
    });
  }
  // formatFile mirrors rulefile.Format for client-side export.
  function formatFile(f) {
    var out = ['# snake rules v1'];
    if (f.name) out.push('@name ' + f.name);
    if (f.description) out.push('@description ' + f.description);
    if (f.source) out.push('@source ' + f.source);
    if ((f.domains || []).length) { out.push(''); out = out.concat(f.domains); }
    if ((f.asns || []).length) { out.push(''); out = out.concat(f.asns.slice().sort(function (a, b) { return a - b; }).map(function (a) { return 'asn:' + a; })); }
    if ((f.cidrs || []).length) { out.push(''); out = out.concat(f.cidrs.map(function (c) { return 'cidr:' + c; })); }
    return out.join('\n') + '\n';
  }
  // policyRulesText renders a policy's own rules (no header) for its editor.
  function policyRulesText(p) {
    var out = (p.domains || []).slice();
    if ((p.asns || []).length) { if (out.length) out.push(''); out = out.concat(p.asns.map(function (a) { return 'asn:' + a; })); }
    if ((p.cidrs || []).length) { if (out.length) out.push(''); out = out.concat(p.cidrs.map(function (c) { return 'cidr:' + c; })); }
    return out.join('\n');
  }

  // ---------- rule lists ----------
  function listUsers(name) {
    return (state.cfg.policies || []).filter(function (p) { return (p.lists || []).indexOf(name) >= 0; }).map(function (p) { return p.name; });
  }
  function ruleCount(l) { return (l.domains || []).filter(function (d) { return d[0] !== '#'; }).length; }
  function adoptConfig(c) {
    // Take the server's rule lists (and list references) without dropping
    // unsaved edits elsewhere.
    var lists = fixCfg(c).rule_lists;
    if (state.dirty) {
      state.cfg.rule_lists = lists;
      var byId = {};
      c.policies.forEach(function (p) { byId[p.id] = p; });
      state.cfg.policies.forEach(function (p) { if (byId[p.id]) p.lists = byId[p.id].lists; });
    } else state.cfg = c;
  }
  function viewLists(b) {
    var lists = state.cfg.rule_lists;
    if (state.listEdit) return viewListEditor(b);
    b.appendChild(el('p', { class: 'muted small' }, 'Rule lists are reusable .rules files (domain rules, ASNs, CIDRs) that policies include by name. Import them from a file or URL, edit them here, and export them to share.'));
    var urlIn = el('input', { type: 'text', placeholder: 'https://example.com/streaming.rules', size: 40 });
    b.appendChild(el('div', { class: 'row', style: 'margin-bottom:10px' },
      btn('+ New list', function () { state.listEdit = { orig: '', text: '# snake rules v1\n@name New list\n@description \n\n' }; render(); }, 'pri'),
      btn('Import file…', function () {
        pickFile(function (text, fname) {
          importText(text).then(function (r) {
            var t = r.text;
            if (!r.file.name) t = t.replace('# snake rules v1\n', '# snake rules v1\n@name ' + fname.replace(/\.[^.]+$/, '') + '\n');
            state.listEdit = { orig: '', text: t }; render();
          }).catch(function (e) { toast(e.message); });
        });
      }),
      urlIn, btn('Import URL', function () {
        var u = urlIn.value.trim();
        if (!u) return;
        api('POST', '/api/rulefile/fetch', { url: u }).then(function (r) { return importText(r.text); }).then(function (r) {
          var f = r.file;
          if (!f.source) f.source = u;
          if (!f.name) f.name = u.replace(/^.*\//, '').replace(/\.[^.]+$/, '') || 'imported';
          state.listEdit = { orig: '', text: formatFile(f) }; render();
        }).catch(function (e) { toast(e.message); });
      })));
    if (!lists.length) { b.appendChild(el('p', { class: 'muted' }, 'No rule lists yet.')); return; }
    b.appendChild(el('div', { class: 'scroll' }, el('table', null,
      el('tr', null, ['List', 'Contents', 'Used by', 'Source', ''].map(function (h) { return el('th', null, h); })),
      lists.map(function (l) {
        return el('tr', null,
          el('td', null, el('b', null, l.name), l.description ? el('div', { class: 'small muted' }, l.description) : null),
          el('td', { class: 'small' }, ruleCount(l) + ' rules · ' + l.asns.length + ' ASNs · ' + l.cidrs.length + ' CIDRs'),
          el('td', { class: 'small' }, listUsers(l.name).join(', ') || el('span', { class: 'muted' }, 'unused')),
          el('td', { class: 'small mono' }, l.source || ''),
          el('td', { class: 'row' },
            btn('Edit', function () { state.listEdit = { orig: l.name, text: formatFile(l) }; render(); }),
            btn('Export', function () { download(fileName(l.name), formatFile(l)); }),
            l.source ? btn('Refresh', function () {
              api('POST', '/api/lists/' + encodeURIComponent(l.name) + '/refresh').then(function (r) { adoptConfig(r.config); toast('Refreshed ' + l.name); render(); }).catch(function (e) { toast(e.message); });
            }) : null,
            btn('Delete', function () {
              if (!confirm('Delete rule list ' + l.name + '?')) return;
              api('DELETE', '/api/lists/' + encodeURIComponent(l.name)).then(function (r) { adoptConfig(r.config); render(); }).catch(function (e) { toast(e.message); });
            }, 'danger')));
      }))));
  }
  function viewListEditor(b) {
    var le = state.listEdit;
    var saving = false;
    var ed = ruleEditor({ value: le.text, height: 420, onChange: function (v) { le.text = v; le.changed = true; }, onSave: save });
    function save() {
      if (saving) return;
      saving = true;
      var name = encodeURIComponent(le.orig || 'new');
      api('PUT', '/api/lists/' + name + (le.orig ? '' : '?new=1'), { text: ed.get() }).then(function (r) {
        adoptConfig(r.config);
        var parsed = ed.last() && ed.last().file;
        le.orig = (parsed && parsed.name) || le.orig;
        le.changed = false;
        toast('Saved rule list ' + le.orig + ' and applied');
        saving = false;
      }).catch(function (e) { saving = false; toast(e.message); });
    }
    b.appendChild(el('h3', null, le.orig ? 'Edit rule list ' + le.orig : 'New rule list'));
    b.appendChild(syntaxHelp());
    b.appendChild(el('div', { class: 'row', style: 'margin-bottom:6px' },
      btn('Import file…', function () { pickFile(function (text) { importText(text).then(function (r) { ed.set(mergeMeta(ed.last(), r.text)); }); }); }),
      btn('Append file…', function () { pickFile(function (text) { importText(text).then(function (r) { ed.set(ed.get().replace(/\n*$/, '\n\n') + stripMeta(r.text)); }); }); }),
      btn('Tidy', function () { ed.tidy(); }),
      btn('Export', function () { var f = ed.last() && ed.last().file; download(fileName((f && f.name) || le.orig), ed.get()); }),
      el('span', { class: 'muted small' }, 'Ctrl+S saves')));
    b.appendChild(ed.el);
    b.appendChild(el('div', { class: 'row', style: 'margin-top:10px' },
      btn('Back', function () { if (le.changed && !confirm('Discard unsaved changes to this list?')) return; state.listEdit = null; render(); }),
      btn('Save & apply', save, 'pri'),
      le.orig && listUsers(le.orig).length ? el('span', { class: 'muted small' }, 'Used by: ' + listUsers(le.orig).join(', ')) : null));
  }
  // Keep the current list's name when importing over it.
  function mergeMeta(last, text) {
    var f = last && last.file;
    if (f && f.name && !/^@name /m.test(text)) return text.replace('# snake rules v1\n', '# snake rules v1\n@name ' + f.name + '\n');
    return text;
  }
  function stripMeta(text) { return text.split('\n').filter(function (l) { return !/^(# snake rules v1|@)/.test(l); }).join('\n').replace(/^\n+/, ''); }

  // ---------- policies ----------
  function defaultPolicy() {
    return { id: 0, name: '', enabled: true, tunnels: [], kill_switch: true, expected_country: '', domains: [], lists: [], ignore_cname: false, asns: [], cidrs: [], devices: [],
      leak: { dns_via_tunnel: true, dns_server: '9.9.9.9', hijack_dns: true, block_dot: true, block_doh: true, block_quic: false, ipv6: 'tunnel', webrtc: 'track' } };
  }
  function viewPolicies(b) {
    if (state.edit) return viewEditor(b);
    var pols = state.cfg.policies || [];
    b.appendChild(el('div', { class: 'row', style: 'margin-bottom:10px' },
      btn('+ New policy', function () { state.edit = { idx: -1, p: defaultPolicy() }; render(); }, 'pri')));
    if (!pols.length) { b.appendChild(el('p', { class: 'muted' }, 'No policies yet.')); return; }
    b.appendChild(el('p', { class: 'muted small' }, 'Policies are evaluated top to bottom; the first match wins.'));
    b.appendChild(el('div', { class: 'scroll' }, el('table', null,
      el('tr', null, ['', 'Name', 'Tunnels (failover order)', 'Matches', 'Protection', ''].map(function (h) { return el('th', null, h); })),
      pols.map(function (p, i) {
        var m = [];
        var nRules = p.domains.filter(function (d) { return d.trim() && d.trim()[0] !== '#'; }).length;
        if (nRules) m.push(nRules + ' domain rules');
        if (p.asns.length) m.push(p.asns.length + ' ASNs');
        if (p.cidrs.length) m.push(p.cidrs.length + ' CIDRs');
        if (p.devices.length) m.push(p.devices.length + ' devices/groups');
        if (p.lists.length) m.push('lists: ' + p.lists.join(', '));
        var prot = [];
        if (p.kill_switch) prot.push('kill');
        if (p.leak.hijack_dns) prot.push('dns53');
        if (p.leak.dns_via_tunnel) prot.push('dns→vpn');
        if (p.leak.block_doh) prot.push('doh');
        if (p.leak.block_dot) prot.push('dot');
        if (p.leak.block_quic) prot.push('quic');
        prot.push('v6:' + p.leak.ipv6);
        prot.push('rtc:' + p.leak.webrtc);
        return el('tr', null,
          el('td', null, el('input', { type: 'checkbox', checked: p.enabled, title: 'enabled', onchange: function (e) { p.enabled = e.target.checked; markDirty(); } })),
          el('td', null, el('b', null, p.name), p.expected_country ? el('div', { class: 'small muted' }, 'expects ' + p.expected_country) : null),
          el('td', null, p.tunnels.join(' → ')),
          el('td', { class: 'small' }, m.join(', ')),
          el('td', { class: 'small muted' }, prot.join(' · ')),
          el('td', { class: 'row' },
            btn('↑', function () { if (i > 0) { pols.splice(i - 1, 0, pols.splice(i, 1)[0]); markDirty(); render(); } }),
            btn('↓', function () { if (i < pols.length - 1) { pols.splice(i + 1, 0, pols.splice(i, 1)[0]); markDirty(); render(); } }),
            btn('Edit', function () { state.edit = { idx: i, p: clone(p) }; render(); }),
            btn('Flush learned', function () { api('POST', '/api/policies/' + p.id + '/flush').then(function () { toast('Flushed ' + p.name); }); }),
            btn('Delete', function () { if (confirm('Delete policy ' + p.name + '?')) { pols.splice(i, 1); markDirty(); render(); } }, 'danger')));
      }))));
  }

  function chk(obj, key, label, help) {
    return el('label', { class: 'chk' }, el('input', { type: 'checkbox', checked: obj[key], onchange: function (e) { obj[key] = e.target.checked; } }),
      el('span', null, label, help ? el('div', { class: 'small muted' }, help) : null));
  }
  function viewEditor(b) {
    var ed = state.edit, p = ed.p;
    b.appendChild(el('h3', null, ed.idx < 0 ? 'New policy' : 'Edit policy ' + p.name));
    var tunBox = el('ul', { class: 'tun-list' });
    function drawTunnels() {
      tunBox.innerHTML = '';
      p.tunnels.forEach(function (t, i) {
        var h = state.status && state.status.tunnels[t];
        tunBox.appendChild(el('li', null, el('b', null, (i + 1) + '. ' + t), h ? tunnelBadge(h) : badge('not monitored yet'),
          btn('↑', function () { if (i > 0) { p.tunnels.splice(i - 1, 0, p.tunnels.splice(i, 1)[0]); drawTunnels(); } }),
          btn('✕', function () { p.tunnels.splice(i, 1); drawTunnels(); })));
      });
      if (!p.tunnels.length) tunBox.appendChild(el('li', { class: 'muted' }, 'Add at least one tunnel. Extra tunnels are failover backups, in order.'));
    }
    drawTunnels();
    var tunSel = el('select', null, TUNNELS.map(function (t) { return el('option', { value: t }, t); }));

    var devSel = el('select', { multiple: true, size: 8, style: 'width:100%' },
      (state.cfg.groups || []).map(function (g) { var v = 'group:' + g.name; return el('option', { value: v, selected: p.devices.indexOf(v) >= 0 }, 'Group: ' + g.name); }),
      knownDevices().map(function (d) { return el('option', { value: d.mac, selected: p.devices.indexOf(d.mac) >= 0 }, (d.name || '?') + ' (' + d.mac + (d.ip ? ', ' + d.ip : '') + ')'); }));
    var extraMacs = p.devices.filter(function (d) { return d.indexOf('group:') !== 0 && !knownDevices().some(function (k) { return k.mac === d; }); });
    var macTA = el('textarea', { style: 'min-height:40px', placeholder: 'aa:bb:cc:dd:ee:ff' }, extraMacs.join('\n'));
    var rulesEd = ruleEditor({ value: policyRulesText(p), height: 240,
      placeholder: 'netflix.com\n**.nflxvideo.net\n/^ipv4-c\\d+-.*\\.oca\\.nflxvideo\\.net$/\n!=ads.netflix.com\nasn:2906\ncidr:23.246.0.0/18' });
    var listSel = el('select', { multiple: true, size: Math.min(6, Math.max(2, state.cfg.rule_lists.length)), style: 'width:100%' },
      state.cfg.rule_lists.map(function (l) { return el('option', { value: l.name, selected: p.lists.indexOf(l.name) >= 0 }, l.name + ' (' + ruleCount(l) + ' rules, ' + l.asns.length + ' ASNs, ' + l.cidrs.length + ' CIDRs)'); }));
    var rulesCard = el('div', { class: 'card', style: 'grid-column:1/-1' },
      el('div', { class: 'row', style: 'justify-content:space-between' }, el('b', null, 'Rules'),
        el('span', { class: 'row' },
          btn('Import file…', function () { pickFile(function (text) { importText(text).then(function (r) { rulesEd.set(stripMeta(r.text)); }); }); }),
          btn('Append file…', function () { pickFile(function (text) { importText(text).then(function (r) { rulesEd.set(rulesEd.get().replace(/\n*$/, '\n\n') + stripMeta(r.text)); }); }); }),
          btn('Tidy', function () { rulesEd.tidy().then(function () { rulesEd.set(stripMeta(rulesEd.get())); }); }),
          btn('Export', function () { download(fileName(p.name || 'policy'), '# snake rules v1\n' + (p.name ? '@name ' + p.name + '\n' : '') + '\n' + rulesEd.get().replace(/\n*$/, '\n')); }))),
      syntaxHelp(), rulesEd.el,
      el('label', { class: 'chk' }, el('input', { type: 'checkbox', checked: !p.ignore_cname, onchange: function (e) { p.ignore_cname = !e.target.checked; } }),
        el('span', null, 'Match CNAME chains', el('div', { class: 'small muted' }, 'Also match when the queried name is an alias (CNAME) of a matching name.'))),
      el('label', { class: 'f' }, 'Include rule lists (Ctrl/Cmd-click for several)'),
      state.cfg.rule_lists.length ? listSel : el('div', { class: 'small muted' }, 'No rule lists yet: create or import them in the Rule lists tab.'));
    var L = p.leak;

    b.appendChild(el('div', { class: 'cols' },
      el('div', { class: 'card' },
        el('label', { class: 'f' }, 'Name'), el('input', { type: 'text', value: p.name, oninput: function (e) { p.name = e.target.value; } }),
        chk(p, 'enabled', 'Enabled'),
        el('label', { class: 'f' }, 'Tunnels (priority order)'), tunBox,
        el('div', { class: 'row' }, tunSel, btn('Add tunnel', function () { if (p.tunnels.indexOf(tunSel.value) < 0) p.tunnels.push(tunSel.value); drawTunnels(); })),
        chk(p, 'kill_switch', 'Kill switch', 'When no tunnel is healthy, block this traffic instead of sending it via WAN.'),
        el('label', { class: 'f' }, 'Expected exit country (ISO code, optional)'),
        el('input', { type: 'text', value: p.expected_country, maxlength: 2, size: 4, placeholder: 'US', oninput: function (e) { p.expected_country = e.target.value.toUpperCase(); } }),
        el('div', { class: 'small muted' }, 'A tunnel whose exit country differs is treated as failed for this policy.')),
      el('div', { class: 'card' },
        el('label', { class: 'f' }, 'Devices (none = whole LAN). Ctrl/Cmd-click to select several.'), devSel,
        el('label', { class: 'f' }, 'Other MAC addresses'), macTA,
        el('div', { class: 'small muted' }, 'Devices only → the whole device goes through the tunnel. Devices + destinations → only those destinations, only for those devices.')),
      el('div', { class: 'card' },
        el('b', null, 'Leak protection'),
        chk(L, 'dns_via_tunnel', 'Resolve policy domains through the tunnel', 'CDNs choose servers by resolver location; this makes them pick ones near the VPN exit.'),
        el('div', { class: 'row' }, el('span', { class: 'small muted' }, 'Resolver'), el('input', { type: 'text', value: L.dns_server, size: 16, oninput: function (e) { L.dns_server = e.target.value.trim(); } })),
        chk(L, 'hijack_dns', 'Redirect hardcoded DNS (port 53) to the router', 'Catches smart TVs / apps that ignore DHCP DNS (e.g. 8.8.8.8).'),
        chk(L, 'block_doh', 'Block DNS-over-HTTPS resolvers', 'Forces browsers/apps back to router DNS so domains are detected.'),
        chk(L, 'block_dot', 'Block DNS-over-TLS / QUIC (port 853)', 'Android "Private DNS" falls back to normal DNS.'),
        chk(L, 'block_quic', 'Block QUIC (UDP 443)', 'Optional; forces HTTP/2 over TCP.'),
        el('label', { class: 'f' }, 'IPv6'),
        el('select', { onchange: function (e) { L.ipv6 = e.target.value; } },
          [['tunnel', 'Route via tunnel if it has IPv6, otherwise block'], ['block', 'Always block IPv6 for policy traffic'], ['off', 'Off (IPv6 may leak)']].map(function (o) { return el('option', { value: o[0], selected: L.ipv6 === o[0] }, o[1]); })),
        el('label', { class: 'f' }, 'WebRTC'),
        el('select', { onchange: function (e) { L.webrtc = e.target.value; } },
          [['track', 'Track: route this service\'s WebRTC peers via the tunnel'], ['off', 'Off']].map(function (o) { return el('option', { value: o[0], selected: L.webrtc === o[0] }, o[1]); })),
        el('div', { class: 'small muted' }, 'While a device talks to this policy\'s destinations, STUN it sends reveals the peers/relays of its calls; those are routed through the tunnel too. Other apps\' WebRTC stays on WAN.')),
      rulesCard));

    b.appendChild(el('div', { class: 'row', style: 'margin-top:10px' },
      btn('Cancel', function () { state.edit = null; render(); }),
      btn(ed.idx < 0 ? 'Add policy' : 'Update policy', function () {
        if (!p.name) { toast('Name required'); return; }
        if (!p.tunnels.length) { toast('Add at least one tunnel'); return; }
        rulesEd.check().then(function (r) {
          if (!r || (r.errors || []).length) { toast('Fix the rule errors first'); return; }
          p.domains = r.file.domains; p.asns = r.file.asns; p.cidrs = r.file.cidrs;
          var sel = Array.prototype.filter.call(devSel.options, function (o) { return o.selected; }).map(function (o) { return o.value; });
          p.devices = sel.concat(lines(macTA.value));
          p.lists = Array.prototype.filter.call(listSel.options, function (o) { return o.selected; }).map(function (o) { return o.value; });
          if (ed.idx < 0) state.cfg.policies.push(p); else state.cfg.policies[ed.idx] = p;
          state.edit = null; markDirty(); render();
        });
      }, 'pri'),
      el('span', { class: 'muted small' }, 'Changes are applied when you press "Save & apply".')));
  }
  function knownDevices() {
    var map = {};
    (state.clients || []).forEach(function (c) { map[c.mac] = { mac: c.mac, name: c.name, ip: c.ip }; });
    (state.cfg.devices || []).forEach(function (d) { map[d.mac] = map[d.mac] || { mac: d.mac }; map[d.mac].name = d.name; });
    return Object.keys(map).sort().map(function (k) { return map[k]; });
  }

  // ---------- devices ----------
  function viewDevices(b) {
    var cfg = state.cfg;
    cfg.groups = cfg.groups || []; cfg.devices = cfg.devices || [];
    b.appendChild(el('h3', null, 'Groups'));
    cfg.groups.forEach(function (g, i) {
      var ta = el('textarea', { style: 'min-height:50px', onchange: function (e) { g.macs = lines(e.target.value); markDirty(); } }, g.macs.join('\n'));
      b.appendChild(el('div', { class: 'card' },
        el('div', { class: 'row' }, el('input', { type: 'text', value: g.name, onchange: function (e) {
          var old = 'group:' + g.name; g.name = e.target.value.trim();
          cfg.policies.forEach(function (p) { p.devices = p.devices.map(function (d) { return d === old ? 'group:' + g.name : d; }); });
          markDirty();
        } }), btn('Delete group', function () { cfg.groups.splice(i, 1); markDirty(); render(); }, 'danger')),
        el('label', { class: 'f' }, 'MAC addresses'), ta));
    });
    b.appendChild(btn('+ New group', function () { cfg.groups.push({ name: 'group' + (cfg.groups.length + 1), macs: [] }); markDirty(); render(); }));

    b.appendChild(el('h3', null, 'LAN clients'));
    b.appendChild(el('div', { class: 'scroll' }, el('table', null,
      el('tr', null, ['Name', 'MAC', 'IP', 'Friendly name', 'Add to group'].map(function (h) { return el('th', null, h); })),
      knownDevices().map(function (d) {
        var named = cfg.devices.filter(function (x) { return x.mac === d.mac; })[0];
        var gsel = el('select', null, el('option', { value: '' }, '-'), cfg.groups.map(function (g) { return el('option', { value: g.name }, g.name); }));
        return el('tr', null, el('td', null, d.name || ''), el('td', { class: 'mono' }, d.mac), el('td', null, d.ip || ''),
          el('td', null, el('input', { type: 'text', value: named ? named.name : '', size: 14, onchange: function (e) {
            var v = e.target.value.trim();
            cfg.devices = cfg.devices.filter(function (x) { return x.mac !== d.mac; });
            if (v) cfg.devices.push({ name: v, mac: d.mac });
            markDirty();
          } })),
          el('td', { class: 'row' }, gsel, btn('Add', function () {
            var g = cfg.groups.filter(function (x) { return x.name === gsel.value; })[0];
            if (g && g.macs.indexOf(d.mac) < 0) { g.macs.push(d.mac); markDirty(); render(); }
          })));
      }))));
  }

  // ---------- diagnostics ----------
  function viewDiag(b) {
    // test domain
    var inp = el('input', { type: 'text', placeholder: 'www.netflix.com', size: 30 });
    var out = el('div');
    function run() {
      out.innerHTML = 'Testing...';
      api('GET', '/api/test?domain=' + encodeURIComponent(inp.value.trim())).then(function (r) {
        out.innerHTML = '';
        out.appendChild(el('div', { class: 'kv' },
          el('span', null, 'Domain'), el('span', null, r.domain),
          el('span', null, 'CNAME chain'), el('span', { class: 'mono' }, (r.chain || []).length ? r.domain + ' → ' + r.chain.join(' → ') : 'none'),
          el('span', null, 'Policy'), el('span', null, r.policy ? r.policy + ' (rule ' + r.matched + (r.matched_via && r.matched_via !== r.domain ? ' via ' + r.matched_via : '') + ')' : 'none'),
          (r.excluded || []).length ? [el('span', null, 'Excluded by'), el('span', null, r.excluded.join(', '))] : null,
          el('span', null, 'Tunnel'), el('span', null, r.tunnel ? r.tunnel + ' ' + (r.country || '') : '-'),
          el('span', null, 'Addresses'), el('span', null, (r.addrs || []).map(function (a) { return el('div', { class: 'mono' }, a.ip + (a.in_set ? '  ✓ ' + a.in_set : '  ✗ not in a set')); })),
          r.error ? [el('span', null, 'Error'), el('span', null, r.error)] : null));
        (r.notes || []).forEach(function (n) { out.appendChild(el('div', { class: 'small', style: 'color:var(--warn)' }, n)); });
      }).catch(function (e) { out.textContent = e.message; });
    }
    inp.addEventListener('keydown', function (e) { if (e.key === 'Enter') run(); });
    b.appendChild(el('div', { class: 'card' }, el('b', null, 'Test a domain'), el('div', { class: 'row', style: 'margin:6px 0' }, inp, btn('Test', run, 'pri')), out));

    // browser leak test
    var lt = el('div', { class: 'small' }, 'Checks what this browser exposes: HTTP exit IP and WebRTC (STUN) public IPs, compared with the WAN and tunnel exits.');
    b.appendChild(el('div', { class: 'card' }, el('b', null, 'Leak test for this device'), lt, el('div', { style: 'margin-top:6px' }, btn('Run browser leak test', function () { browserLeakTest(lt); }, 'pri'))));

    // router audit
    var audit = el('div', null, 'Loading...');
    b.appendChild(el('div', { class: 'card' }, el('b', null, 'Router-side leak audit'), audit));
    api('GET', '/api/leaks').then(function (r) {
      audit.innerHTML = '';
      if (!r.length) audit.textContent = 'No enabled policies.';
      r.forEach(function (lc) {
        audit.appendChild(el('div', { style: 'margin:6px 0' }, el('b', null, lc.policy),
          el('ul', null, (lc.ok || []).map(function (x) { return el('li', null, badge('ok', 'ok'), ' ', x); }), (lc.warn || []).map(function (x) { return el('li', null, badge('warn', 'warn'), ' ', x); }))));
      });
    }).catch(function (e) { audit.textContent = e.message; });

    // set viewer
    var setSel = el('select');
    var setOut = el('pre', null, '');
    (state.status.policies || []).forEach(function (p) { Object.keys(p.sets || {}).forEach(function (n) { setSel.appendChild(el('option', { value: n }, p.name + ': ' + n + ' (' + p.sets[n] + ')')); }); });
    b.appendChild(el('div', { class: 'card' }, el('b', null, 'Learned addresses'), el('div', { class: 'row', style: 'margin:6px 0' }, setSel,
      btn('Show', function () { api('GET', '/api/set?name=' + encodeURIComponent(setSel.value) + '&limit=1000').then(function (r) { setOut.textContent = (r.members || []).join('\n') || '(empty)'; }); })), setOut));

    // logs + plan
    var logOut = el('pre', null, '');
    var planOut = el('pre', null, '');
    b.appendChild(el('div', { class: 'card' }, el('b', null, 'Logs'), ' ', btn('Refresh', loadLogs), logOut));
    b.appendChild(el('div', { class: 'card' }, el('b', null, 'Generated firewall rules'), ' ', btn('Show', function () {
      api('GET', '/api/plan').then(function (p) { planOut.textContent = Object.keys(p.Restore || {}).sort().map(function (k) { return '### ' + k + '\n' + p.Restore[k]; }).join('\n'); });
    }), planOut));
    function loadLogs() { api('GET', '/api/logs').then(function (l) { logOut.textContent = l.slice(-200).map(function (e) { return new Date(e.time).toLocaleTimeString() + ' ' + e.level + ' ' + e.msg; }).join('\n'); }); }
    loadLogs();
  }

  function browserLeakTest(box) {
    box.innerHTML = 'Running...';
    var s = state.status;
    var known = {};
    if (s.wan_ip) known[s.wan_ip] = 'WAN (real IP)';
    Object.keys(s.tunnels || {}).forEach(function (k) { if (s.tunnels[k].exit_ip) known[s.tunnels[k].exit_ip] = 'tunnel ' + k + ' ' + (s.tunnels[k].country || ''); });
    function label(ip) { return known[ip] ? known[ip] : 'unknown (WAN behind CGNAT, or another VPN)'; }
    var res = { http: null, stun: {} };
    var httpP = fetch('https://api.ipify.org?format=json').then(function (r) { return r.json(); }).then(function (j) { res.http = j.ip; }).catch(function (e) { res.http = 'error: ' + e.message; });
    var stunP = new Promise(function (resolve) {
      if (!window.RTCPeerConnection) { res.stun.error = 'WebRTC not available'; return resolve(); }
      var pc = new RTCPeerConnection({ iceServers: (state.cfg.settings.stun_test_servers || []).map(function (u) { return { urls: u }; }) });
      pc.createDataChannel('x');
      pc.onicecandidate = function (e) {
        if (!e.candidate) { pc.close(); return resolve(); }
        var m = /candidate:\S+ \d+ \S+ \d+ (\S+) \d+ typ (\S+)/.exec(e.candidate.candidate);
        if (m && m[2] === 'srflx') res.stun[m[1]] = true;
      };
      pc.createOffer().then(function (o) { return pc.setLocalDescription(o); });
      setTimeout(function () { try { pc.close(); } catch (e) {} resolve(); }, 6000);
    });
    Promise.all([httpP, stunP]).then(function () {
      box.innerHTML = '';
      box.appendChild(el('div', { class: 'kv' },
        el('span', null, 'HTTP exit'), el('span', null, res.http + ' → ' + label(res.http)),
        el('span', null, 'WebRTC public IPs'), el('span', null, Object.keys(res.stun).filter(function (k) { return k !== 'error'; }).map(function (ip) {
          return el('div', null, ip + ' → ' + label(ip), known[ip] && known[ip].indexOf('WAN') === 0 ? ' ' : '', known[ip] && known[ip].indexOf('WAN') === 0 ? badge('real IP visible', 'warn') : null);
        }), res.stun.error || (Object.keys(res.stun).length ? '' : 'none (STUN blocked or no public candidates)'))));
      box.appendChild(el('div', { class: 'small muted', style: 'margin-top:6px' },
        'The test page itself and the STUN test servers are not policy destinations, so they normally exit via WAN. A WAN IP here is expected unless this device is in a whole-device policy. To test a policy, add api.ipify.org and the STUN server host to it temporarily.'));
    });
  }

  // ---------- settings ----------
  function viewSettings(b) {
    var s = state.cfg.settings;
    function num(key, label, help) {
      return el('div', null, el('label', { class: 'f' }, label), el('input', { type: 'number', value: s[key], onchange: function (e) { s[key] = parseInt(e.target.value, 10) || 0; markDirty(); } }), help ? el('div', { class: 'small muted' }, help) : null);
    }
    function txt(key, label, help) {
      return el('div', null, el('label', { class: 'f' }, label), el('input', { type: 'text', value: s[key], size: 36, onchange: function (e) { s[key] = e.target.value.trim(); markDirty(); } }), help ? el('div', { class: 'small muted' }, help) : null);
    }
    function list(key, label, help) {
      return el('div', null, el('label', { class: 'f' }, label), el('textarea', { style: 'min-height:50px', onchange: function (e) { s[key] = lines(e.target.value); markDirty(); } }, (s[key] || []).join('\n')), help ? el('div', { class: 'small muted' }, help) : null);
    }
    function bool(key, label, help) {
      return el('label', { class: 'chk' }, el('input', { type: 'checkbox', checked: s[key], onchange: function (e) { s[key] = e.target.checked; markDirty(); } }), el('span', null, label, help ? el('div', { class: 'small muted' }, help) : null));
    }
    b.appendChild(el('div', { class: 'cols' },
      el('div', { class: 'card' }, el('b', null, 'Health & failover'),
        num('health_interval', 'Health check interval (s)'),
        num('handshake_max_age', 'Max WireGuard handshake age (s)'),
        list('probe_targets', 'Probe targets (host:port, TCP through each tunnel)'),
        num('probe_failures', 'Consecutive probe failures before failover'),
        bool('auto_failback', 'Auto fail-back to higher-priority tunnel'),
        num('failback_hold', 'Fail-back hold-down (s)', 'The primary must be healthy this long before traffic moves back.'),
        bool('flush_conntrack', 'Flush connections on failover', 'Needs the conntrack tool; makes clients reconnect through the new tunnel immediately.')),
      el('div', { class: 'card' }, el('b', null, 'Exit country check'),
        txt('geo_url', 'Geo-IP URL (fetched through each tunnel)'),
        txt('geo_country_field', 'JSON field with country code'),
        txt('geo_ip_field', 'JSON field with IP'),
        num('geo_interval', 'Geo check interval (s)'),
        bool('geo_strict', 'Strict: unknown country counts as failure')),
      el('div', { class: 'card' }, el('b', null, 'WebRTC & sets'),
        num('session_timeout', 'WebRTC session window (s)', 'How long after the last policy connection a device\'s STUN is still attributed to the policy.'),
        num('peer_timeout', 'Learned peer lifetime (s)'),
        txt('stun_ports', 'STUN/TURN ports (fallback mode)'),
        num('domain_set_timeout', 'Domain set entry timeout (s, 0 = never)'),
        num('save_interval', 'Persist learned sets every (s)'),
        num('asn_refresh', 'ASN refresh (hours)'),
        list('stun_test_servers', 'STUN servers for the browser leak test')),
      el('div', { class: 'card' }, el('b', null, 'Advanced'),
        bool('doh_canary', 'Answer DoH canary domains with NXDOMAIN', 'Firefox and iCloud Private Relay turn themselves off network-wide.'),
        bool('pre_resolve', 'Pre-resolve policy domains at start'),
        txt('lan_interfaces', 'LAN interfaces (iptables -i pattern)'),
        num('api_port', 'API port (HTTPS uses port + 1)', 'Restart the daemon after changing.'),
        num('queue_base', 'NFQUEUE base number'),
        el('label', { class: 'f' }, 'Mark mask (hex)'),
        el('input', { type: 'text', value: '0x' + (s.mark_mask >>> 0).toString(16), onchange: function (e) { s.mark_mask = parseInt(e.target.value, 16) >>> 0; markDirty(); } }),
        el('div', { class: 'small muted' }, 'fwmark bits owned by snake. Default 0xff0000 avoids Merlin VPN Director (0xf000) and QoS bits.'))));
  }

  // ---------- import ----------
  function viewImport(b) {
    var dir = el('input', { type: 'text', value: '/jffs/configs/domain_vpn_routing', size: 40 });
    var out = el('div');
    function go(apply) {
      out.textContent = 'Reading...';
      api('POST', '/api/import-dvr?dir=' + encodeURIComponent(dir.value) + (apply ? '&apply=1' : '')).then(function (r) {
        out.innerHTML = '';
        (r.warnings || []).forEach(function (w) { out.appendChild(el('div', { class: 'small', style: 'color:var(--warn)' }, w)); });
        out.appendChild(el('table', null, el('tr', null, el('th', null, 'Policy'), el('th', null, 'Tunnel'), el('th', null, 'Domains'), el('th', null, 'ASNs')),
          (r.policies || []).map(function (p) { return el('tr', null, el('td', null, p.name), el('td', null, p.tunnels.join(',')), el('td', null, p.domains.length), el('td', null, p.asns.length)); })));
        if (apply) { toast('Imported'); state.dirty = false; load(); }
        else if ((r.policies || []).length) out.appendChild(el('div', { style: 'margin-top:8px' }, btn('Import these policies', function () { go(true); }, 'pri'),
          el('span', { class: 'small muted' }, ' Imported policies get full leak protection with kill switch off; review them afterwards.')));
      }).catch(function (e) { out.textContent = e.message; });
    }
    b.appendChild(el('div', { class: 'card' }, el('b', null, 'Import from Domain VPN Routing'),
      el('p', { class: 'small muted' }, 'Reads domain_vpn_routing.conf, the per-policy domain lists and asn.conf. WAN policies are skipped. Uninstall domain_vpn_routing afterwards so both do not fight over the same traffic.'),
      el('div', { class: 'row' }, dir, btn('Preview', function () { go(false); })), out));
    if (state.dirty) b.appendChild(el('p', { class: 'small', style: 'color:var(--warn)' }, 'Save or discard your unsaved changes before importing.'));
  }

  // ---------- boot ----------
  function boot() {
    root = document.getElementById('snake');
    if (!root) return;
    if (CTX.mode === 'standalone' && !CTX.token) {
      try { CTX.token = localStorage.getItem('snake_token') || ''; } catch (e) {}
      if (!CTX.token) askToken();
    }
    if (CTX.mode === 'asp' && !CTX.token) state.error = 'snake_token missing from custom_settings: is the snake daemon running? (snake start)';
    render();
    load();
    setInterval(refreshStatus, 10000);
    window.addEventListener('beforeunload', function (e) { if (state.dirty) { e.preventDefault(); e.returnValue = ''; } });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot); else boot();
})();

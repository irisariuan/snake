// Validation of device entries typed by hand. The daemon validates again
// when the configuration is saved; this gives feedback while typing.

const MAC = /^([0-9a-f]{2})[:-]([0-9a-f]{2})[:-]([0-9a-f]{2})[:-]([0-9a-f]{2})[:-]([0-9a-f]{2})[:-]([0-9a-f]{2})$/i;
const V4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

function isV6(s) {
  if (!s.includes(':') || !/^[0-9a-f:.]+$/i.test(s)) return false;
  try { new URL('http://[' + s + ']/'); return true; } catch { return false; }
}

/** Returns { value } (normalized) or { error }. */
export function parseDevice(text) {
  const s = (text || '').trim();
  if (!s) return { error: 'Enter a MAC address, IP address or subnet.' };
  const m = s.match(MAC);
  if (m) return { value: m.slice(1).join(':').toLowerCase() };
  const [addr, bits, extra] = s.split('/');
  if (extra === undefined) {
    const v4 = V4.test(addr), v6 = !v4 && isV6(addr);
    if (v4 || v6) {
      if (bits === undefined) return { value: v6 ? addr.toLowerCase() : addr };
      const n = Number(bits);
      if (/^\d+$/.test(bits) && n >= 0 && n <= (v4 ? 32 : 128)) return { value: (v6 ? addr.toLowerCase() : addr) + '/' + n };
      return { error: `/${bits} is not a valid prefix length for ${v4 ? 'IPv4 (0-32)' : 'IPv6 (0-128)'}.` };
    }
  }
  return { error: `"${s}" is not a MAC address (aa:bb:cc:dd:ee:ff), IP address or subnet (10.8.0.0/24).` };
}

function plural(n, one, many) { return `${n} ${n === 1 ? one : many}`; }

function describe(ids) {
  const g = ids.filter((i) => i.startsWith('group:')).length;
  const d = ids.length - g;
  return [d ? plural(d, 'device', 'devices') : '', g ? plural(g, 'group', 'groups') : ''].filter(Boolean).join(' and ');
}

/** The selection in one sentence, shown above the device list. */
export function summary({ include, exclude, emptyMeaning, noun, allowExclude }) {
  if (!allowExclude) return include.length ? `${noun} has ${describe(include)}.` : `${noun} has ${emptyMeaning}.`;
  if (!include.length && !exclude.length) return `${noun} applies to ${emptyMeaning}.`;
  if (!include.length) return `${noun} applies to ${emptyMeaning} except ${describe(exclude)}.`;
  return `${noun} applies only to ${describe(include)}` + (exclude.length ? `, minus ${describe(exclude)} excluded.` : '.');
}

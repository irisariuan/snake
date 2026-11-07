import { useMemo, useState } from 'react';
import { Button, FilterChips, SearchBox, SelectionToolbar, TriState } from './controls/index.js';
import { parseDevice, summary } from './device.js';

/**
 * Picks devices to include and, optionally, to exclude.
 *
 * Entries are MAC addresses, IP addresses, subnets (VPN server clients) and
 * "group:<name>". The value is controlled: { include, exclude } in, the new
 * value out through onChange.
 *
 * props:
 *   include, exclude   string[]
 *   onChange           ({ include, exclude }) => void
 *   devices            [{ id, name, ip }]: known devices (id = MAC / IP / subnet)
 *   groups             [{ name, members }]: device groups (omit to hide)
 *   allowExclude       show the Exclude choice (default true)
 *   emptyMeaning       what "nothing included" means, e.g. "every device"
 *   noun               what is being chosen, for the summary ("this policy")
 */
export default function DeviceSelector({
  include = [], exclude = [], onChange, devices = [], groups = [], allowExclude = true,
  emptyMeaning = 'every device', noun = 'This policy',
}) {
  const [q, setQ] = useState('');
  const [show, setShow] = useState('all');
  const [manual, setManual] = useState('');
  const [manualErr, setManualErr] = useState('');

  const inc = useMemo(() => new Set(include), [include]);
  const exc = useMemo(() => new Set(exclude), [exclude]);
  const stateOf = (id) => (inc.has(id) ? 'include' : exc.has(id) ? 'exclude' : 'none');

  // Every row: groups, known devices, then entries typed in by hand.
  const rows = useMemo(() => {
    const out = [];
    const seen = new Set();
    for (const g of groups) {
      const id = 'group:' + g.name;
      seen.add(id);
      out.push({ id, kind: 'group', name: g.name, detail: `${g.members.length} device${g.members.length === 1 ? '' : 's'}`, members: g.members });
    }
    for (const d of devices) {
      if (seen.has(d.id)) continue;
      seen.add(d.id);
      const vpn = !/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(d.id);
      out.push({ id: d.id, kind: vpn ? 'vpn' : 'device', name: d.name || 'unnamed device', detail: d.id + (d.ip && d.ip !== d.id ? ' · ' + d.ip : '') });
    }
    for (const id of [...include, ...exclude]) {
      if (seen.has(id)) continue;
      seen.add(id);
      out.push({ id, kind: id.startsWith('group:') ? 'group' : 'manual', name: id.startsWith('group:') ? id.slice(6) + ' (missing group)' : 'added by hand', detail: id.startsWith('group:') ? '' : id });
    }
    return out;
  }, [devices, groups, include, exclude]);

  // Included groups, to explain devices they already cover.
  const viaGroup = useMemo(() => {
    const m = new Map();
    for (const g of groups) {
      if (!inc.has('group:' + g.name)) continue;
      for (const id of g.members) m.set(id, [...(m.get(id) || []), g.name]);
    }
    return m;
  }, [groups, inc]);

  const needle = q.trim().toLowerCase();
  const visible = rows.filter((r) => {
    if (show !== 'all' && stateOf(r.id) !== show) return false;
    return !needle || (r.name + ' ' + r.detail + ' ' + r.id).toLowerCase().includes(needle);
  });

  const set = (ids, to) => {
    const i = new Set(include), e = new Set(exclude);
    for (const id of ids) {
      i.delete(id); e.delete(id);
      if (to === 'include') i.add(id);
      if (to === 'exclude') e.add(id);
    }
    onChange({ include: [...i], exclude: [...e] });
  };
  const ids = visible.map((r) => r.id);
  const filtered = visible.length !== rows.length;
  const actions = [
    { label: 'Include all', title: `Include the ${visible.length} shown`, onClick: () => set(ids, 'include'), disabled: !visible.length },
    allowExclude && { label: 'Exclude all', title: `Exclude the ${visible.length} shown`, onClick: () => set(ids, 'exclude'), disabled: !visible.length },
    { label: 'Clear', title: `Unselect the ${visible.length} shown`, onClick: () => set(ids, 'none'), disabled: !visible.some((r) => stateOf(r.id) !== 'none') },
    {
      label: 'Invert', title: 'Included ⇄ not selected, for the rows shown' + (allowExclude ? ' (excluded rows stay excluded)' : ''),
      onClick: () => {
        const i = new Set(include);
        for (const r of visible) {
          if (inc.has(r.id)) i.delete(r.id);
          else if (!exc.has(r.id)) i.add(r.id);
        }
        onChange({ include: [...i], exclude });
      },
      disabled: !visible.length,
    },
    allowExclude && {
      label: 'Swap include ⇄ exclude', title: 'Turn "only these devices" into "every device except these", and back, for the rows shown',
      onClick: () => {
        const i = new Set(include), e = new Set(exclude);
        for (const r of visible) {
          if (inc.has(r.id)) { i.delete(r.id); e.add(r.id); } else if (exc.has(r.id)) { e.delete(r.id); i.add(r.id); }
        }
        onChange({ include: [...i], exclude: [...e] });
      },
      disabled: !visible.some((r) => stateOf(r.id) !== 'none'),
    },
  ].filter(Boolean);

  const addManual = (to) => {
    const r = parseDevice(manual);
    if (r.error) { setManualErr(r.error); return; }
    set([r.value], to);
    setManual(''); setManualErr('');
  };

  const counts = { include: include.length, exclude: exclude.length };
  const chips = [
    { id: 'all', label: 'All', count: rows.length },
    { id: 'include', label: 'Included', count: counts.include },
    allowExclude && { id: 'exclude', label: 'Excluded', count: counts.exclude },
    { id: 'none', label: 'Not selected', count: rows.length - counts.include - counts.exclude },
  ].filter(Boolean);

  return (
    <div className="picker">
      <p className="picker-summary" aria-live="polite">{summary({ include, exclude, emptyMeaning, noun, allowExclude })}</p>
      <div className="tw:flex tw:flex-wrap tw:items-center tw:gap-2 tw:mb-1.5">
        <SearchBox value={q} onChange={setQ} placeholder="Search name, MAC or address" label="Search devices" />
        <FilterChips options={chips} value={show} onChange={setShow} />
      </div>
      <SelectionToolbar actions={actions} scope={filtered ? `acts on the ${visible.length} shown` : ''} />
      <div className="pick-list" role="list" aria-label="Devices">
        {visible.length === 0 ? <div className="small muted tw:p-2">{rows.length ? 'Nothing matches.' : 'No known devices yet: add one below.'}</div> : null}
        {visible.map((r) => {
          const st = stateOf(r.id);
          const via = viaGroup.get(r.id);
          let hint = '';
          if (via && st === 'none') hint = 'included through group ' + via.join(', ');
          if (via && st === 'exclude') hint = 'excluded although group ' + via.join(', ') + ' is included';
          if (st === 'exclude' && include.length && !via && !inc.has(r.id) && r.kind !== 'group') hint = 'no effect: not included anyway';
          return (
            <div key={r.id} role="listitem" className={'pick-row st-' + st}>
              <TriState value={st} allowExclude={allowExclude} label={r.name} onChange={(v) => set([r.id], v)} />
              <span className={'kind kind-' + r.kind}>{KIND[r.kind]}</span>
              <span className="tw:min-w-0 tw:flex-1">
                <b>{r.name}</b> <span className="mono muted">{r.detail}</span>
                {hint ? <div className={'small ' + (hint.startsWith('no effect') ? 'tw:text-warn' : 'muted')}>{hint}</div> : null}
              </span>
            </div>
          );
        })}
      </div>
      <div className="tw:flex tw:flex-wrap tw:items-center tw:gap-1.5 tw:mt-1.5">
        <input
          type="text"
          className="tw:flex-1 tw:min-w-[180px]"
          value={manual}
          placeholder="Other device: aa:bb:cc:dd:ee:ff, 10.6.0.2 or 10.8.0.0/24"
          aria-label="Add a device by MAC, IP address or subnet"
          onChange={(e) => { setManual(e.target.value); setManualErr(''); }}
          onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); addManual('include'); } }}
        />
        <Button small onClick={() => addManual('include')} disabled={!manual.trim()}>Include</Button>
        {allowExclude ? <Button small onClick={() => addManual('exclude')} disabled={!manual.trim()}>Exclude</Button> : null}
      </div>
      {manualErr ? <div className="small tw:text-warn tw:mt-1">{manualErr}</div> : null}
    </div>
  );
}

const KIND = { group: 'Group', device: 'Device', vpn: 'VPN client', manual: 'Manual' };

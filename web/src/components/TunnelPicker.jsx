import { useState } from 'react';
import { Badge, Button, TunnelHealth } from './controls/index.js';

/**
 * A policy's tunnels in failover order: the first healthy one carries the
 * traffic, the others are backups.
 *
 * props:
 *   value     string[]: tunnel ids in order
 *   onChange  (ids) => void
 *   options   [{ id, label, group, disabled, note }]: every tunnel that can be
 *             added; group names the <optgroup> ("Router WireGuard", ...)
 *   status    { [id]: health } from the daemon (may be missing)
 */
export default function TunnelPicker({ value = [], onChange, options = [], status = {} }) {
  const left = options.filter((o) => !value.includes(o.id));
  const [pick, setPick] = useState('');
  const chosen = left.some((o) => o.id === pick) ? pick : (left[0] || {}).id || '';
  const byId = Object.fromEntries(options.map((o) => [o.id, o]));
  const move = (i, to) => {
    const v = [...value];
    const [t] = v.splice(i, 1);
    v.splice(to, 0, t);
    onChange(v);
  };
  const groups = [...new Set(left.map((o) => o.group))];
  return (
    <div className="picker">
      <ol className="tun-order" aria-label="Tunnels in failover order">
        {value.length === 0 ? <li className="muted small">Add at least one tunnel. Tunnels after the first are failover backups, in order.</li> : null}
        {value.map((t, i) => {
          const o = byId[t] || { label: t };
          return (
            <li key={t} className="tun-row">
              <div className="tw:flex tw:items-center tw:gap-2">
                <span className={'tun-role' + (i === 0 ? ' primary' : '')}>{i === 0 ? 'Primary' : 'Backup ' + i}</span>
                <b className="tw:flex-1 tw:break-words">{o.label}</b>
                {o.disabled ? <Badge kind="warn" title="Enable it in the Tunnels tab">disabled</Badge> : <TunnelHealth status={status[t]} />}
              </div>
              <div className="tw:flex tw:justify-end tw:gap-1 tw:mt-1">
                <Button small aria-label={'Move ' + t + ' up'} title="Move up" disabled={i === 0} onClick={() => move(i, i - 1)}>↑</Button>
                <Button small aria-label={'Move ' + t + ' down'} title="Move down" disabled={i === value.length - 1} onClick={() => move(i, i + 1)}>↓</Button>
                <Button small aria-label={'Make ' + t + ' the primary tunnel'} title="Make it the primary tunnel" disabled={i === 0} onClick={() => move(i, 0)}>⤒ Primary</Button>
                <Button small variant="danger" aria-label={'Remove ' + t} title="Remove" onClick={() => onChange(value.filter((x) => x !== t))}>✕</Button>
              </div>
            </li>
          );
        })}
      </ol>
      {left.length ? (
        <div className="tw:flex tw:flex-wrap tw:items-center tw:gap-1.5 tw:mt-1.5">
          <select value={chosen} onChange={(e) => setPick(e.target.value)} aria-label="Tunnel to add">
            {groups.map((g) => (
              <optgroup key={g} label={g}>
                {left.filter((o) => o.group === g).map((o) => (
                  <option key={o.id} value={o.id}>{o.label}{o.note ? ' (' + o.note + ')' : ''}</option>
                ))}
              </optgroup>
            ))}
          </select>
          <Button onClick={() => chosen && onChange([...value, chosen])}>{value.length ? 'Add backup' : 'Add tunnel'}</Button>
        </div>
      ) : <div className="small muted tw:mt-1.5">Every tunnel is in the list.</div>}
    </div>
  );
}

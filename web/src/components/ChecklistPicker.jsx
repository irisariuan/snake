import { useState } from 'react';
import { FilterChips, SearchBox, SelectionToolbar } from './controls/index.js';

/**
 * Chooses any number of items from a list, with search and bulk actions
 * (no Ctrl/Cmd-click).
 *
 * props:
 *   items     [{ id, label, detail }]
 *   value     string[]: chosen ids
 *   onChange  (ids) => void
 *   empty     text when there are no items
 *   label     accessible name of the list
 */
export default function ChecklistPicker({ items = [], value = [], onChange, empty = 'Nothing to choose from.', label = 'Items' }) {
  const [q, setQ] = useState('');
  const [show, setShow] = useState('all');
  if (!items.length) return <div className="small muted">{empty}</div>;
  const on = new Set(value);
  const needle = q.trim().toLowerCase();
  const visible = items.filter((it) => {
    if (show === 'on' && !on.has(it.id)) return false;
    if (show === 'off' && on.has(it.id)) return false;
    return !needle || (it.label + ' ' + (it.detail || '')).toLowerCase().includes(needle);
  });
  const update = (fn) => {
    const s = new Set(value);
    fn(s);
    onChange(items.map((it) => it.id).filter((id) => s.has(id))); // keep list order
  };
  const ids = visible.map((it) => it.id);
  return (
    <div className="picker">
      {items.length > 5 ? (
        <div className="tw:flex tw:flex-wrap tw:items-center tw:gap-2 tw:mb-1.5">
          <SearchBox value={q} onChange={setQ} label={'Search ' + label} />
          <FilterChips value={show} onChange={setShow} options={[
            { id: 'all', label: 'All', count: items.length },
            { id: 'on', label: 'Selected', count: value.length },
            { id: 'off', label: 'Not selected', count: items.length - value.length },
          ]} />
        </div>
      ) : null}
      <SelectionToolbar
        scope={visible.length !== items.length ? `acts on the ${visible.length} shown` : `${value.length} of ${items.length} selected`}
        actions={[
          { label: 'Select all', onClick: () => update((s) => ids.forEach((id) => s.add(id))), disabled: ids.every((id) => on.has(id)) },
          { label: 'Clear', onClick: () => update((s) => ids.forEach((id) => s.delete(id))), disabled: !ids.some((id) => on.has(id)) },
          { label: 'Invert', onClick: () => update((s) => ids.forEach((id) => (s.has(id) ? s.delete(id) : s.add(id)))), disabled: !ids.length },
        ]}
      />
      <div className="pick-list" role="group" aria-label={label}>
        {visible.length === 0 ? <div className="small muted tw:p-2">Nothing matches.</div> : null}
        {visible.map((it) => (
          <label key={it.id} className={'pick-row' + (on.has(it.id) ? ' st-include' : '')}>
            <input type="checkbox" checked={on.has(it.id)} onChange={(e) => update((s) => (e.target.checked ? s.add(it.id) : s.delete(it.id)))} />
            <span className="tw:min-w-0 tw:flex-1"><b>{it.label}</b> {it.detail ? <span className="small muted">{it.detail}</span> : null}</span>
          </label>
        ))}
      </div>
    </div>
  );
}

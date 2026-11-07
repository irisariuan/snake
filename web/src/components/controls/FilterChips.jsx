/** One-of filter buttons with counts: [All 12] [Included 3] [Excluded 1]. */
export default function FilterChips({ options, value, onChange, label = 'Show' }) {
  return (
    <span className="tw:inline-flex tw:flex-wrap tw:gap-1" role="group" aria-label={label}>
      {options.map((o) => (
        <button key={o.id} type="button" className={'chip' + (value === o.id ? ' on' : '')} aria-pressed={value === o.id} onClick={() => onChange(o.id)}>
          {o.label}{o.count !== undefined ? <span className="chip-n">{o.count}</span> : null}
        </button>
      ))}
    </span>
  );
}

/**
 * A segmented control for one item: Include / — / Exclude (or just
 * Include / — when exclude is off). Arrow keys move between the choices.
 */
const CHOICES = [
  { id: 'include', label: 'Include', short: '✓' },
  { id: 'none', label: '—', short: '—' },
  { id: 'exclude', label: 'Exclude', short: '✕' },
];

export default function TriState({ value, onChange, allowExclude = true, label }) {
  const choices = allowExclude ? CHOICES : CHOICES.slice(0, 2);
  const move = (e) => {
    const i = choices.findIndex((c) => c.id === value);
    const d = e.key === 'ArrowRight' ? 1 : e.key === 'ArrowLeft' ? -1 : 0;
    if (!d) return;
    e.preventDefault();
    onChange(choices[(i + d + choices.length) % choices.length].id);
  };
  return (
    <span className="seg" role="radiogroup" aria-label={label} onKeyDown={move}>
      {choices.map((c) => (
        <button
          key={c.id}
          type="button"
          role="radio"
          aria-checked={value === c.id}
          tabIndex={value === c.id ? 0 : -1}
          className={'seg-b seg-' + c.id + (value === c.id ? ' on' : '')}
          title={c.id === 'none' ? 'Not selected' : c.label}
          onClick={() => onChange(c.id)}
        >
          {c.label}
        </button>
      ))}
    </span>
  );
}

/** A filter field with a clear button; Escape clears it too. */
export default function SearchBox({ value, onChange, placeholder = 'Search', label = 'Search' }) {
  return (
    <span className="tw:relative tw:inline-flex tw:items-center tw:flex-1 tw:min-w-[160px]">
      <input
        type="text"
        className="tw:w-full tw:pr-6"
        value={value}
        placeholder={placeholder}
        aria-label={label}
        onChange={(e) => onChange(e.target.value)}
        onKeyDown={(e) => { if (e.key === 'Escape' && value) { e.preventDefault(); onChange(''); } }}
      />
      {value ? (
        <button type="button" className="clear-x" aria-label="Clear search" title="Clear (Esc)" onClick={() => onChange('')}>×</button>
      ) : null}
    </span>
  );
}

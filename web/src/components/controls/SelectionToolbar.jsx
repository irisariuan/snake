import Button from './Button.jsx';

/**
 * Bulk actions for a list (select all, clear, invert, ...). Each action:
 * { label, onClick, title, disabled, variant }. scope says what they act
 * on, e.g. "the 8 shown".
 */
export default function SelectionToolbar({ actions, scope }) {
  return (
    <div className="tw:flex tw:flex-wrap tw:items-center tw:gap-1" role="toolbar" aria-label="Selection">
      {actions.map((a) => (
        <Button key={a.label} small variant={a.variant} title={a.title} disabled={a.disabled} onClick={a.onClick}>{a.label}</Button>
      ))}
      {scope ? <span className="small muted tw:ml-1">{scope}</span> : null}
    </div>
  );
}

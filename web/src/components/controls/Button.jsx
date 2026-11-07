/** A button in the UI's style. variant: '' | 'pri' | 'danger'; small for toolbars and rows. */
export default function Button({ variant = '', small = false, className = '', ...props }) {
  const cls = ['btn', variant, small ? 'btn-sm' : '', className].filter(Boolean).join(' ');
  return <button type="button" className={cls} {...props} />;
}

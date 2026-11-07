/** A small status pill. kind: '' | 'ok' | 'warn' | 'bad' | 'info'. */
export default function Badge({ kind = '', title, children }) {
  return <span className={'badge' + (kind ? ' b-' + kind : '')} title={title}>{children}</span>;
}

/** A tunnel's health from the daemon's status (the same wording as the Status tab). */
export function TunnelHealth({ status }) {
  if (!status) return <Badge title="snake has not checked this tunnel yet">not monitored yet</Badge>;
  if (status.healthy) return <Badge kind="ok">healthy</Badge>;
  if (!status.exists) return <Badge kind="bad">missing</Badge>;
  return <Badge kind="bad">{status.reason || 'unhealthy'}</Badge>;
}

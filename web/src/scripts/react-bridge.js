// Bridge between the app (src/scripts/app.js), which builds the page with
// plain DOM calls, and the React components in src/components: the app
// leaves an empty element where a component goes and mounts it there.
//
// The components are controlled (value in, onChange out). mountState keeps
// their value in React state and reports every change to the app, which
// stores it in its own state object (saved with "Save & apply").
//
// The app redraws by emptying its root element; it calls unmountAll()
// first so React releases the roots it rendered into.
import { createElement, useState } from 'react';
import { createRoot } from 'react-dom/client';

const roots = new Set();

/** Mounts Component with props into node, which the app created. */
export function mount(node, Component, props) {
  const root = createRoot(node);
  root.render(createElement(Component, props));
  roots.add(root);
  return root;
}

function Stateful({ component, initial, bind, onChange, props }) {
  const [value, setValue] = useState(initial);
  return createElement(component, {
    ...props,
    ...bind(value),
    onChange: (next) => { setValue(next); onChange(next); },
  });
}

/**
 * Mounts a controlled component that holds its own value. bind turns the
 * value into the component's props (e.g. v => ({ value: v })); onChange
 * receives each new value.
 */
export function mountState(node, component, { initial, bind = (v) => ({ value: v }), onChange, props = {} }) {
  return mount(node, Stateful, { component, initial, bind, onChange, props });
}

/** Unmounts every mounted component (before the app empties its page). */
export function unmountAll() {
  roots.forEach((r) => r.unmount());
  roots.clear();
}

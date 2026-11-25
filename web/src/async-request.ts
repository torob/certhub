// useAsync sends its request from a React effect. React runs the effect again
// only when an item of this list changes (Object.is). The path is in the list,
// so a request whose path depends on data that loads later (for example the
// identity from GET /v1/auth/me) is sent when that data arrives.
export function asyncEffectDeps(path: string, deps: readonly unknown[]): unknown[] {
  return [path, ...deps];
}

// After the path changes, the state that useAsync stored belongs to the old
// path until the effect runs. useAsync then reports the first load of the new
// path, so a page never shows a result (or an empty result) for a path that it
// did not request.
export function asyncStateIsStale(statePath: string | undefined, path: string): boolean {
  return Boolean(path) && statePath !== path;
}

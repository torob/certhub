// Paging of list responses.
//
// The API pages every list with the `limit` and `offset` query parameters and
// returns `pagination: { limit, offset, total }` (api/openapi.yaml PageMeta,
// specs/backend-spec.md "List endpoints use limit and offset pagination").
// The list UI sends the first page request with its own path, as before. It
// requests the rows after that page with the same path and `offset` set to
// pagination.offset + pagination.limit, until that offset reaches
// pagination.total.
export type PageMeta = {
  limit?: number;
  offset?: number;
  total?: number;
};

export type ListPage<Row = unknown> = {
  rows: Row[];
  pagination?: PageMeta;
};

// Page size of the follow-up requests that load all rows of a list for
// choices (selects, label maps). It is the maximum of the OpenAPI Limit
// parameter. The first request keeps its own limit.
export const allPagesLimit = 500;

// The offset of the page after this page, or undefined when this page is the
// last page. A response without pagination (for example the discovered zones
// of a DNS provider) has no next page.
export function nextPageOffset(page: ListPage | undefined): number | undefined {
  const meta = page?.pagination;
  if (!page || !meta || page.rows.length === 0) return undefined;
  const { limit, offset = 0, total } = meta;
  if (typeof total !== "number" || typeof limit !== "number" || limit < 1) return undefined;
  const next = offset + limit;
  return next < total ? next : undefined;
}

// The path of the list page at offset. It keeps the text of the first page
// path (filters and their encoding) and only sets limit and offset at the end.
export function listPagePath(firstPath: string, offset: number, limit: number): string {
  const queryStart = firstPath.indexOf("?");
  const base = queryStart < 0 ? firstPath : firstPath.slice(0, queryStart);
  const params = queryStart < 0 ? [] : firstPath.slice(queryStart + 1).split("&").filter((param) => {
    const name = param.split("=", 1)[0];
    return param !== "" && name !== "limit" && name !== "offset";
  });
  return `${base}?${[...params, `limit=${limit}`, `offset=${offset}`].join("&")}`;
}

// The request for the rows after this page, or "" when this page is the last
// page. The limit is the page size of the response unless limit is given.
export function nextListPagePath(firstPath: string, page: ListPage | undefined, limit?: number): string {
  const offset = nextPageOffset(page);
  if (offset === undefined) return "";
  return listPagePath(firstPath, offset, limit ?? page?.pagination?.limit ?? 0);
}

// Appends rows of later pages. Offset pages can repeat a row when rows are
// added while the pages load, so a row whose id is already shown is dropped.
export function appendListRows<Row>(rows: Row[], more: Row[]): Row[] {
  if (more.length === 0) return rows;
  const seen = new Set(rows.map(rowID).filter(Boolean));
  return [...rows, ...more.filter((row) => {
    const id = rowID(row);
    if (!id) return true;
    if (seen.has(id)) return false;
    seen.add(id);
    return true;
  })];
}

function rowID(row: unknown): string | undefined {
  const id = (row as { id?: unknown } | null | undefined)?.id;
  return typeof id === "string" && id ? id : undefined;
}

// The identity of one list request: the first page path and the deps of the
// request effect (filters, refresh counter, ids). The rows after the first
// page belong to one list request.
export function listRequestKey(effectDeps: readonly unknown[]): string {
  return JSON.stringify(effectDeps);
}

// The rows after the first page. The generation increases on each reset, and
// a response of an older generation is ignored.
export type MorePages<Row = unknown> = {
  generation: number;
  key: string;
  rows: Row[];
  last?: ListPage<Row>;
  loading: boolean;
  error?: unknown;
};

export function initialMorePages<Row = unknown>(key: string): MorePages<Row> {
  return { generation: 0, key, rows: [], loading: false };
}

// A new list request (other path, filters, or refresh) shows the first page
// only.
export function resetMorePages<Row>(state: MorePages<Row>, key: string): MorePages<Row> {
  return { generation: state.generation + 1, key, rows: [], loading: false };
}

export function startMorePages<Row>(state: MorePages<Row>, generation: number): MorePages<Row> {
  if (state.generation !== generation) return state;
  return { ...state, loading: true, error: undefined };
}

export function addMorePage<Row>(state: MorePages<Row>, generation: number, page: ListPage<Row>): MorePages<Row> {
  if (state.generation !== generation) return state;
  return { ...state, rows: [...state.rows, ...page.rows], last: page, loading: false, error: undefined };
}

export function failMorePages<Row>(state: MorePages<Row>, generation: number, error: unknown): MorePages<Row> {
  if (state.generation !== generation) return state;
  return { ...state, loading: false, error };
}

export type PagedListView<Row = unknown> = {
  // The first page rows, then the rows of the loaded later pages.
  rows: Row[];
  // The pagination of the first page, with the total of the last loaded page.
  pagination?: PageMeta;
  // True when rows of later pages are shown.
  extended: boolean;
  // The request for the next page, or "" when all rows are shown.
  nextPath: string;
  loading: boolean;
  error?: unknown;
  // False until the reset for the current list request is stored.
  current: boolean;
};

// What the list shows for the current list request. first is the first page
// response, or undefined while it loads.
export function pagedListView<Row>(state: MorePages<Row>, key: string, firstPath: string, first: ListPage<Row> | undefined, limit?: number): PagedListView<Row> {
  const current = state.key === key;
  const more = current ? state : initialMorePages<Row>(key);
  if (!first) return { rows: [], extended: false, nextPath: "", loading: false, current };
  const last = more.last ?? first;
  const extended = more.last !== undefined;
  // A next page response must start after the first page. Otherwise (a server
  // that ignores offset) the same request would repeat, so paging stops.
  const progressed = !extended || (last.pagination?.offset ?? 0) > (first.pagination?.offset ?? 0);
  return {
    rows: extended ? appendListRows(first.rows, more.rows) : first.rows,
    pagination: extended ? { ...first.pagination, total: last.pagination?.total ?? first.pagination?.total } : first.pagination,
    extended,
    nextPath: progressed ? nextListPagePath(firstPath, last, limit) : "",
    loading: more.loading,
    error: more.error,
    current
  };
}

import assert from "node:assert/strict";
import test from "node:test";
import { asyncEffectDeps } from "../src/async-request.ts";
import {
  addMorePage,
  allPagesLimit,
  appendListRows,
  failMorePages,
  initialMorePages,
  listPagePath,
  listRequestKey,
  nextListPagePath,
  pagedListView,
  resetMorePages,
  startMorePages,
  type ListPage,
  type MorePages,
  type PagedListView
} from "../src/list-pages.ts";

type Row = { id: string };

function rows(count: number, start = 0): Row[] {
  return Array.from({ length: count }, (_, i) => ({ id: `row-${start + i}` }));
}

// A response of the API for the rows from offset (api/openapi.yaml PageMeta).
function page(total: number, limit: number, offset = 0): ListPage<Row> {
  return { rows: rows(Math.max(0, Math.min(limit, total - offset)), offset), pagination: { limit, offset, total } };
}

// A model of one usePagedList call (src/app.ts). The view is computed in the
// render. After the render, React runs the reset effect when an item of the
// effect deps changed (Object.is), like the useAsync request effect.
class PagedListHook {
  state?: MorePages<Row>;
  private previous?: unknown[];
  view?: PagedListView<Row>;
  private key = "";
  private disabled = true;

  render(path: string, deps: unknown[], first: ListPage<Row> | undefined, options: { firstLoading?: boolean; limit?: number } = {}) {
    const effectDeps = asyncEffectDeps(path, deps);
    this.key = listRequestKey(effectDeps);
    this.state ??= initialMorePages<Row>(this.key);
    this.view = pagedListView(this.state, this.key, path, first, options.limit);
    this.disabled = !this.view.current || Boolean(options.firstLoading) || this.view.loading;
    const previous = this.previous;
    const changed = !previous || previous.length !== effectDeps.length || effectDeps.some((value, i) => !Object.is(value, previous[i]));
    this.previous = effectDeps;
    if (changed) this.state = resetMorePages(this.state, this.key);
    return this.view;
  }

  // A click on "Load more". It returns the request that the pager sends, or
  // undefined when the pager sends nothing.
  loadMore() {
    if (!this.state || !this.view || this.disabled || !this.view.nextPath) return undefined;
    const generation = this.state.generation;
    this.state = startMorePages(this.state, generation);
    return { path: this.view.nextPath, generation };
  }

  respond(request: { generation: number }, response: ListPage<Row>) {
    this.state = addMorePage(this.state!, request.generation, response);
  }

  fail(request: { generation: number }, error: unknown) {
    this.state = failMorePages(this.state!, request.generation, error);
  }
}

test("a list page of 100 rows of 250 offers the request for the next page", () => {
  const page = { rows: rows(100), pagination: { limit: 100, offset: 0, total: 250 } };
  assert.equal(nextListPagePath("/v1/audit-events?limit=100", page), "/v1/audit-events?limit=100&offset=100");
});

test("a list page that shows all rows offers no next request", () => {
  const page = { rows: rows(40), pagination: { limit: 100, offset: 0, total: 40 } };
  assert.equal(nextListPagePath("/v1/audit-events?limit=100", page), "");
  assert.equal(nextListPagePath("/v1/users?limit=100", { rows: rows(100), pagination: { limit: 100, offset: 0, total: 100 } }), "");
  assert.equal(nextListPagePath("/v1/users?limit=100", { rows: [], pagination: { limit: 100, offset: 0, total: 0 } }), "");
  // GET /v1/dns-providers/{id}/zones/discovered has no pagination.
  assert.equal(nextListPagePath("/v1/dns-providers/p1/zones/discovered?limit=100", { rows: rows(300) }), "");
});

test("the next page offset is pagination.offset + pagination.limit of the response", () => {
  assert.equal(nextListPagePath("/v1/users?limit=100", page(250, 100, 100)), "/v1/users?limit=100&offset=200");
  assert.equal(nextListPagePath("/v1/users?limit=100", page(250, 100, 200)), "");
  // The response limit is the page size, also when the server clamps it.
  assert.equal(nextListPagePath("/v1/users?limit=100", { rows: rows(50), pagination: { limit: 50, offset: 0, total: 250 } }), "/v1/users?limit=50&offset=50");
});

test("next page paths keep the first page path and its filters", () => {
  assert.equal(
    listPagePath("/v1/audit-events?action=private_key_read&result=failure&created_at_from=2026-11-01T00%3A00%3A00.000Z&limit=100", 100, 100),
    "/v1/audit-events?action=private_key_read&result=failure&created_at_from=2026-11-01T00%3A00%3A00.000Z&limit=100&offset=100"
  );
  assert.equal(listPagePath("/v1/certificates?status=failed&limit=100", 200, 100), "/v1/certificates?status=failed&limit=100&offset=200");
  assert.equal(listPagePath("/v1/certificates?application=a1&limit=100", 100, 100), "/v1/certificates?application=a1&limit=100&offset=100");
  assert.equal(listPagePath("/v1/users?limit=100&offset=100", 200, 100), "/v1/users?limit=100&offset=200");
  assert.equal(listPagePath("/v1/users", 100, 100), "/v1/users?limit=100&offset=100");
});

test("lists with a smaller first page use the same page size for the next pages", () => {
  assert.equal(nextListPagePath("/v1/certificates/c1/versions?limit=20", page(45, 20)), "/v1/certificates/c1/versions?limit=20&offset=20");
  assert.equal(nextListPagePath("/v1/certificates/c1/events?limit=20", page(21, 20)), "/v1/certificates/c1/events?limit=20&offset=20");
  assert.equal(nextListPagePath("/v1/audit-events?application_id=a1&limit=50", page(51, 50)), "/v1/audit-events?application_id=a1&limit=50&offset=50");
});

test("the first page is shown as before", () => {
  const hook = new PagedListHook();
  const first = page(250, 100);
  const view = hook.render("/v1/audit-events?limit=100", [0], first);
  assert.equal(view.rows, first.rows);
  assert.equal(view.pagination, first.pagination);
  assert.equal(view.extended, false);
  assert.equal(view.nextPath, "/v1/audit-events?limit=100&offset=100");
});

test("Load more appends the next pages until all rows are shown", () => {
  const hook = new PagedListHook();
  const path = "/v1/audit-events?limit=100";
  hook.render(path, [0], page(250, 100));
  hook.render(path, [0], page(250, 100));
  const second = hook.loadMore();
  assert.deepEqual(second?.path, "/v1/audit-events?limit=100&offset=100");
  // A second click while the request runs sends nothing.
  hook.render(path, [0], page(250, 100));
  assert.equal(hook.loadMore(), undefined);
  hook.respond(second!, page(250, 100, 100));
  let view = hook.render(path, [0], page(250, 100));
  assert.equal(view.rows.length, 200);
  assert.deepEqual(view.pagination, { limit: 100, offset: 0, total: 250 });
  assert.equal(view.nextPath, "/v1/audit-events?limit=100&offset=200");
  const third = hook.loadMore();
  assert.equal(third?.path, "/v1/audit-events?limit=100&offset=200");
  hook.respond(third!, page(250, 100, 200));
  view = hook.render(path, [0], page(250, 100));
  assert.equal(view.rows.length, 250);
  assert.deepEqual(view.rows.map((row) => row.id), rows(250).map((row) => row.id));
  assert.equal(view.nextPath, "");
  assert.equal(hook.loadMore(), undefined);
});

test("no pager is offered when the first page shows all rows", () => {
  const hook = new PagedListHook();
  hook.render("/v1/issuers?limit=100", [0], page(7, 100));
  const view = hook.render("/v1/issuers?limit=100", [0], page(7, 100));
  assert.equal(view.nextPath, "");
  assert.equal(hook.loadMore(), undefined);
});

test("a filter change shows the first page of the new filter", () => {
  const hook = new PagedListHook();
  const all = "/v1/audit-events?limit=100";
  hook.render(all, [all, 0], page(250, 100));
  hook.render(all, [all, 0], page(250, 100));
  hook.respond(hook.loadMore()!, page(250, 100, 100));
  assert.equal(hook.render(all, [all, 0], page(250, 100)).rows.length, 200);

  const filtered = "/v1/audit-events?result=failure&limit=100";
  // useAsync reports the first load of the new path until its response.
  let view = hook.render(filtered, [filtered, 0], undefined, { firstLoading: true });
  assert.deepEqual(view.rows, []);
  assert.equal(view.nextPath, "");
  view = hook.render(filtered, [filtered, 0], page(130, 100));
  assert.equal(view.rows.length, 100);
  assert.equal(view.extended, false);
  assert.equal(view.nextPath, "/v1/audit-events?result=failure&limit=100&offset=100");

  // Back to the old filter: the rows loaded before are not shown again.
  hook.render(all, [all, 0], undefined, { firstLoading: true });
  view = hook.render(all, [all, 0], page(250, 100));
  assert.equal(view.rows.length, 100);
  assert.equal(view.nextPath, "/v1/audit-events?limit=100&offset=100");
});

test("Refresh shows the first page again", () => {
  const hook = new PagedListHook();
  const path = "/v1/users?limit=100";
  hook.render(path, [0], page(250, 100));
  hook.render(path, [0], page(250, 100));
  hook.respond(hook.loadMore()!, page(250, 100, 100));
  assert.equal(hook.render(path, [0], page(250, 100)).rows.length, 200);
  // Refresh: the same path with a new refresh counter. useAsync keeps the old
  // data while it loads the first page again.
  let view = hook.render(path, [1], page(250, 100));
  assert.equal(view.rows.length, 100);
  assert.equal(view.current, false);
  // The pager sends nothing while the first page loads again.
  view = hook.render(path, [1], page(250, 100), { firstLoading: true });
  assert.equal(view.rows.length, 100);
  assert.equal(hook.loadMore(), undefined);
  view = hook.render(path, [1], page(251, 100));
  assert.equal(view.rows.length, 100);
  assert.equal(view.nextPath, "/v1/users?limit=100&offset=100");
});

test("a next page response that arrives after Refresh is ignored", () => {
  const hook = new PagedListHook();
  const path = "/v1/certificates?limit=100";
  hook.render(path, [path, 0], page(250, 100));
  hook.render(path, [path, 0], page(250, 100));
  const request = hook.loadMore()!;
  hook.render(path, [path, 1], page(250, 100));
  hook.respond(request, page(250, 100, 100));
  const view = hook.render(path, [path, 1], page(250, 100));
  assert.equal(view.rows.length, 100);
  assert.equal(view.loading, false);
});

test("a failed next page request keeps the rows and can be sent again", () => {
  const hook = new PagedListHook();
  const path = "/v1/dns-providers/p1/zones?limit=100";
  hook.render(path, [0], page(150, 100));
  hook.render(path, [0], page(150, 100));
  const request = hook.loadMore()!;
  const error = { status: 503, error: { code: "service_unavailable" } };
  hook.fail(request, error);
  let view = hook.render(path, [0], page(150, 100));
  assert.equal(view.rows.length, 100);
  assert.equal(view.error, error);
  assert.equal(view.nextPath, "/v1/dns-providers/p1/zones?limit=100&offset=100");
  const retry = hook.loadMore()!;
  assert.equal(retry.path, "/v1/dns-providers/p1/zones?limit=100&offset=100");
  hook.respond(retry, page(150, 100, 100));
  view = hook.render(path, [0], page(150, 100));
  assert.equal(view.rows.length, 150);
  assert.equal(view.error, undefined);
  assert.equal(view.nextPath, "");
});

test("choice lists load all pages with the maximum page size", () => {
  // useAllPages (src/app.ts): the first request keeps its path, then the
  // next pages are requested until all rows are loaded.
  const hook = new PagedListHook();
  const path = "/v1/applications?limit=100";
  hook.render(path, [0], page(1234, 100), { limit: allPagesLimit });
  const sent: string[] = [];
  for (;;) {
    const view = hook.render(path, [0], page(1234, 100), { limit: allPagesLimit });
    const request = hook.loadMore();
    if (!request) {
      assert.equal(view.rows.length, 1234);
      break;
    }
    sent.push(request.path);
    const offset = Number(new URLSearchParams(request.path.split("?")[1]).get("offset"));
    hook.respond(request, page(1234, allPagesLimit, offset));
  }
  assert.equal(allPagesLimit, 500);
  assert.deepEqual(sent, [
    "/v1/applications?limit=500&offset=100",
    "/v1/applications?limit=500&offset=600",
    "/v1/applications?limit=500&offset=1100"
  ]);
});

test("paging stops when a next page response does not start after the first page", () => {
  const hook = new PagedListHook();
  const path = "/v1/applications?limit=100";
  hook.render(path, [0], page(1234, 100), { limit: allPagesLimit });
  hook.render(path, [0], page(1234, 100), { limit: allPagesLimit });
  const request = hook.loadMore()!;
  // The response repeats offset 0, so the same request would be sent again.
  hook.respond(request, { rows: rows(500, 100), pagination: { limit: 500, offset: 0, total: 1234 } });
  const view = hook.render(path, [0], page(1234, 100), { limit: allPagesLimit });
  assert.equal(view.nextPath, "");
  assert.equal(hook.loadMore(), undefined);
});

test("rows that a later page repeats are shown once", () => {
  const first = rows(3);
  assert.equal(appendListRows(first, []), first);
  assert.deepEqual(appendListRows(first, [{ id: "row-2" }, { id: "row-3" }, { id: "row-3" }]).map((row) => row.id), ["row-0", "row-1", "row-2", "row-3"]);
});

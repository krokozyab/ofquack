# How metadata is read, and why it is cached

Every question about Fusion's dictionary is answered by running a query through
BI Publisher, exactly like a query about data. There is no cheaper channel. A
dictionary read therefore costs seconds and leaves a BI Publisher session
behind on the server.

That single fact shapes everything below.

## Where the answers come from

| Question | Source in Fusion |
|---|---|
| Which tables and views exist | `FND_VIEWS` ∪ `FND_TABLES` |
| Columns of a table | `FND_COLUMNS` joined to `FND_TABLES` on `table_id` |
| Columns of a view | `ALL_TAB_COLUMNS` |
| Primary keys | `ALL_CONSTRAINTS` + `ALL_CONS_COLUMNS` |
| Foreign keys | the same, `constraint_type = 'R'` |
| Indexes | `ALL_INDEXES` + `ALL_IND_COLUMNS` |

The schema is always `FUSION`.

Two of these deserve a note, because both look like mistakes:

**Tables come from Fusion's own dictionary, not `ALL_TABLES`.** Only `FND_TABLES`
carries `TABLE_ID`, and `TABLE_ID` is how columns are looked up. Views are not
in `FND_COLUMNS` at all, which is why they take a different path.

**The column queries alias `data_precision` as `DECIMAL_DIGITS` and `data_scale`
as `NUM_PREC_RADIX`** — shifted by one from what the names suggest. The
statements are inherited from the JDBC driver, where the type mapper reads them
in that shifted sense. Here the shift is undone once, in `metadata_fetch.cpp`,
so nothing downstream has to know about it. Correcting one end without the other
turns `NUMBER(10,0)` into `DECIMAL(0,10)`.

## Paging and batching

The dictionary is far larger than one report response can carry, so every
listing is paged. How it is paged differs by statement, and the difference is
not cosmetic.

**The table listing seeks, it does not skip.** Each page asks for the names that
sort after the last name of the previous page:

```sql
... WHERE (t.table_name > '<last>'
           OR (t.table_name = '<last>' AND t.table_type > '<last type>'))
    ORDER BY t.table_name, t.table_type FETCH FIRST 2000 ROWS ONLY
```

`OFFSET 20000 ROWS` makes the server sort and discard twenty thousand rows
before returning a page, and that cost grows with every page. Seeking from the
last name keeps every page the same price however deep the listing runs.

A page the report cut short — it has a limit on how much one response carries
and says nothing when it is reached — yields the rows that arrived whole, and
the next page seeks from the last of them. That cut, skipped as unparseable
and mistaken for an empty page, is what stopped the listing partway through
the alphabet. Where a page comes back genuinely empty, the session is
discarded and the same page asked once more on a fresh one before the end is
believed; it costs one request.

Columns still page by `OFFSET`/`FETCH`, because they never run deep enough for
the difference to matter, and are fetched **ten tables at a time**. Not one —
that would be ten times the round trips — and not a hundred: the report
truncates a response past roughly 500 rows, and ten tables of thirty columns
stays under that.

Table-list pages default to 2,000 rows and can be lowered when an instance is
stingier than that. The setting applies wherever the name index is first loaded:
direct listing, cache prefetch, and an attached catalog's first named lookup.
Column metadata has an independent 400-row page size because its rows are wider;
changing the table-list setting cannot make that path less reliable.

```sql
SET fusion_scanner_metadata_page_size = 1000;
```

A listing that ends short is never cached. Before listing anything, the fetcher
asks the instance how many distinct tables and views it holds, and refuses a
listing that returned fewer — a partial dictionary that looks complete is worse
than an error, because it is cached for a week and every later lookup misses
with nothing to show for it. The check lives in the fetcher rather than in
`oracle_fusion_tables()`, so `ATTACH`, `oracle_fusion_columns()` and
`fusion_scanner_cache_warm()` are covered by it too.

If the independent count cannot be obtained, the listing may serve the current
call but is not persisted. There is no safe way to distinguish its final page
from a silently truncated BI Publisher response.

Column pages use the parser's truncation marker: a complete short page ends the
lookup immediately, while a page cut off mid-XML resumes after the complete rows
that arrived. An exactly full final page still needs one empty request, but that
empty result is not retried on a new BI Publisher session.

The count is `COUNT(DISTINCT UPPER(table_name))` rather than `COUNT(*)`: a name
that exists as both a table and a view is one entry in the listing, so counting
rows of the union would report every complete listing as short.

## The cache

`~/.fusion_scanner/metadata.duckdb`, a DuckDB database of its own. Not tables in your
database, because it has to work for an in-memory session, must not appear in
your catalog, and is shared between connections.

Rows are keyed by endpoint + report path + authenticated principal, so a
development and a production instance — or two users with different metadata
visibility — never share metadata. The default lifetime is a week: Fusion's
dictionary changes when someone deploys, not continuously.

```sql
SELECT * FROM fusion_scanner_cache_status();
SELECT * FROM oracle_fusion_tables(refresh := true);
SELECT * FROM fusion_scanner_cache_invalidate();
SELECT * FROM fusion_scanner_cache_invalidate(table_name := 'GL_JE_HEADERS');
```

If the cache file cannot be opened read-write it falls back to read-only, and
then to memory. A cache problem is always a miss, never an error you see:
slower is acceptable, refusing to work is not. `fusion_scanner_cache_status()` reports
which mode is in effect.

Table rows and the instance's expected table count are replaced atomically.
Invalidation also removes cached primary/unique ordering keys; otherwise an
attached scan could continue keyset paging with a key that no longer exists.
An already materialised attached table cannot change its DuckDB schema in place:
after refreshing or invalidating its metadata, `DETACH` and `ATTACH` the catalog.

Freshness is compared against an epoch integer rather than SQL `now()`. `now()`
carries a time zone and the stored value does not, so a cache written in UTC and
read back in another zone looks stale — every lookup misses and the cache does
nothing at all. This was a real bug, caught by a test asserting that a second
listing costs no requests.

## What an attached catalog costs

| Action | Requests |
|---|---|
| `ATTACH` | 0 |
| `SHOW TABLES` (cold) | 0 — and lists nothing |
| `SHOW TABLES` (after a patterned schema prefetch) | 0 |
| `SELECT … FROM f.main.T`, cold cache | the name index, then 1 request for that table's columns |
| the same, table list already cached | 1, for that table's columns |
| the same query again | 0 |

`SHOW TABLES` on a cold catalog is empty rather than slow. Listing the whole
dictionary takes long enough that blocking a tab-completion on it would be
worse than showing nothing, so `GetDefaultEntries()` answers from the cache and
never from the network.

The name index and the generic tree are deliberately separate. Run
`oracle_fusion_tables()` once to index every name; after that every named lookup
can fetch just its own columns. The generic tree contains the tables already
queried plus modules explicitly prefetched with a required pattern, for example:

```sql
SELECT * FROM fusion_scanner_cache_warm(pattern := 'AP\_%', max_tables := 500);
```

A complete generic tree is not supported. DuckDB v1.5.5 materialises each table
entry while enumerating it, so advertising all names would also fetch all
columns and turn a tree refresh into hours of SOAP calls. Use
`oracle_fusion_tables()` as the complete browsing surface.

## Secured HR views

`secured_views := true` rewrites eleven HR base tables to their
`*_SECURED_LIST_V` counterparts, which do apply Fusion's row-level security. It
is off by default, it only rewrites statements passed to `oracle_fusion_query()`,
and it is a client-side text substitution rather than a control — see
[the security notes](CAPABILITIES.md#row-level-security-is-not-inherited) for
what that does and does not buy you.

The JDBC driver lists twelve pairs, but `HR_ALL_ORGANIZATION_UNITS_F` appears
twice and its map keeps the last, so `PER_DEPARTMENT_SECURED_LIST_V` has never
been in effect. That resolution is reproduced deliberately and pinned by a test
rather than left to container ordering, which C++ does not guarantee.

---

See also: [the function reference](REFERENCE.md) for every function and
setting, and the [README](../README.md) to start from the beginning.

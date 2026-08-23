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
    ORDER BY t.table_name, t.table_type FETCH FIRST 400 ROWS ONLY
```

`OFFSET 20000 ROWS` makes the server sort and discard twenty thousand rows to
return four hundred, and the cost grows with every page — deep in the alphabet
the report gives up and answers with nothing, which is indistinguishable from
the end of the data. Seeking from the last name keeps every page the same
price, so page five hundred costs what page one did.

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

Page size is 400 rows and can be lowered when an instance is stingier than that:

```sql
SET ofquack_metadata_page_size = 200;
```

A listing that ends short is never cached. Before listing anything, the fetcher
asks the instance how many distinct tables and views it holds, and refuses a
listing that returned fewer — a partial dictionary that looks complete is worse
than an error, because it is cached for a week and every later lookup misses
with nothing to show for it. The check lives in the fetcher rather than in
`oracle_fusion_tables()`, so `ATTACH`, `oracle_fusion_columns()` and
`ofquack_cache_warm()` are covered by it too.

The count is `COUNT(DISTINCT UPPER(table_name))` rather than `COUNT(*)`: a name
that exists as both a table and a view is one entry in the listing, so counting
rows of the union would report every complete listing as short.

## The cache

`~/.ofquack/metadata.duckdb`, a DuckDB database of its own. Not tables in your
database, because it has to work for an in-memory session, must not appear in
your catalog, and is shared between connections.

Rows are keyed by endpoint + report path, so a development and a production
instance never share metadata. The default lifetime is a week: Fusion's
dictionary changes when someone deploys, not continuously.

```sql
SELECT * FROM ofquack_cache_status();
SELECT * FROM oracle_fusion_tables(refresh := true);
SELECT * FROM ofquack_cache_invalidate();
SELECT * FROM ofquack_cache_invalidate(table := 'GL_JE_HEADERS');
```

If the cache file cannot be opened read-write it falls back to read-only, and
then to memory. A cache problem is always a miss, never an error you see:
slower is acceptable, refusing to work is not. `ofquack_cache_status()` reports
which mode is in effect.

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
| `SHOW TABLES` (after warming) | 0 |
| `SELECT … FROM f.main.T`, cold cache | **the whole table listing** — dozens of requests, minutes — plus 1 for that table's columns |
| the same, table list already cached | 1, for that table's columns |
| the same query again | 0 |

`SHOW TABLES` on a cold catalog is empty rather than slow. Listing the whole
dictionary takes long enough that blocking a tab-completion on it would be
worse than showing nothing, so `GetDefaultEntries()` answers from the cache and
never from the network.

The consequence is worth stating plainly, because it is what a first-time user
meets: on a machine that has never connected to the instance, an attached
schema appears empty, and the first query that names a table pays for the
entire dictionary listing inside that query. Both are avoided by warming
deliberately — `oracle_fusion_tables()` for the names, then
`ofquack_cache_warm()` for the columns, since a table is listed only once its
columns are known.

## Secured HR views

`secured_views := true` rewrites eleven HR base tables to their
`*_SECURED_LIST_V` counterparts so Fusion's row-level security applies. It is
off by default.

The JDBC driver lists twelve pairs, but `HR_ALL_ORGANIZATION_UNITS_F` appears
twice and its map keeps the last, so `PER_DEPARTMENT_SECURED_LIST_V` has never
been in effect. That resolution is reproduced deliberately and pinned by a test
rather than left to container ordering, which C++ does not guarantee.

---

See also: [the function reference](REFERENCE.md) for every function and
setting, and the [README](../README.md) to start from the beginning.

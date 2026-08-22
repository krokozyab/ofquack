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

Dictionary statements are paged with an outer `ROWNUM` wrapper rather than
`OFFSET`/`FETCH`, because they are assembled by concatenation and may already
end in `ORDER BY`:

```sql
SELECT * FROM (SELECT ROWNUM AS rn, sub.* FROM (<statement>) sub
               WHERE ROWNUM <= <offset+2000>) WHERE rn > <offset>
```

Columns are fetched **ten tables at a time**. Not one — that would be ten times
the round trips — and not a hundred: the report truncates a response past
roughly 500 rows, and ten tables of thirty columns stays under that.

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
| `SELECT … FROM f.main.T`, first time | 1 for the table list (if cold) + 1 for that table's columns |
| the same query again | 0 metadata requests |

`SHOW TABLES` on a cold catalog is empty rather than slow. Listing the whole
dictionary takes long enough that blocking a tab-completion on it would be
worse than showing nothing; `SELECT * FROM oracle_fusion_tables()` warms it.

## Secured HR views

`secured_views := true` rewrites eleven HR base tables to their
`*_SECURED_LIST_V` counterparts so Fusion's row-level security applies. It is
off by default.

The JDBC driver lists twelve pairs, but `HR_ALL_ORGANIZATION_UNITS_F` appears
twice and its map keeps the last, so `PER_DEPARTMENT_SECURED_LIST_V` has never
been in effect. That resolution is reproduced deliberately and pinned by a test
rather than left to container ordering, which C++ does not guarantee.

-- crates/openbot-infra/sql/schema_facts.sql
--
-- 从活库提取 schema 事实，返回**一行一列**的规范 JSON（text）。
--
-- 两处消费者共用同一份 SQL，这是刻意的：
--   1. `fixtures/db/schema-0012.json` 由本文件在参照库（上游 13 条 migration 跑完的库）上跑出；
--   2. `openbot-infra::db::schema_facts::fetch` 以 include_str! 嵌入本文件，在任意活库上跑。
-- 两边跑的是同一条语句，所以比对结果的差异只可能来自 schema 本身，不可能来自提取方式。
--
-- 只看 `public` schema。`extensions` 刻意排除 `plpgsql`（它是 PostgreSQL 建库时自带的，
-- 数进来会让「0 个 extension」这条事实恒为假）；`relkind='r'` 只取普通表，不含视图 / 物化视图 /
-- 分区父表 —— v3 §8.6 逐字「审计表不做分区」。
--
-- 排序全部显式给出（表按名、列按 attnum、约束 / 索引 / 触发器 / enum / 函数按名，
-- enum 标签按 enumsortorder）：没有 ORDER BY 的聚合，其顺序取决于计划器当天选了什么，
-- 那样的输出没法逐字段比对。
--
-- `NOT NULL` 只认 `columns[].notnull`。PostgreSQL 18 会把同一事实另以 `pg_constraint.contype='n'`
-- 暴露，PostgreSQL 17 不会；把 `n` 再收进 constraints 会既重复计数，又让同一份 DDL 的输出
-- 随服务端大版本变化。因此 constraints 显式排除 `n`，列级非空事实仍逐列完整保留。
--
-- 输出结构（与 `fixtures/db/schema-0012.json` 逐字段对应，Rust 侧类型见
-- `openbot-infra::db::schema_facts::SchemaFacts`）：
--   {tables:[{name,columns:[{name,type,notnull,default,ordinal}],
--             constraints:[{name,type,def}],indexes:[{name,def}],triggers:[{name,def}]}],
--    enums:[{name,values}], functions:[{name,def}], extensions:[]}

SELECT jsonb_pretty(jsonb_build_object(
  'tables', (SELECT coalesce(jsonb_agg(t ORDER BY t->>'name'), '[]'::jsonb) FROM (
      SELECT jsonb_build_object(
        'name', c.relname,
        'columns', (SELECT coalesce(jsonb_agg(jsonb_build_object(
             'name', a.attname,
             'type', format_type(a.atttypid, a.atttypmod),
             'notnull', a.attnotnull,
             'default', pg_get_expr(ad.adbin, ad.adrelid),
             'ordinal', a.attnum
           ) ORDER BY a.attnum), '[]'::jsonb)
           FROM pg_attribute a LEFT JOIN pg_attrdef ad ON ad.adrelid=a.attrelid AND ad.adnum=a.attnum
           WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped),
        'constraints', (SELECT coalesce(jsonb_agg(jsonb_build_object(
             'name', con.conname, 'type', con.contype, 'def', pg_get_constraintdef(con.oid)
           ) ORDER BY con.conname), '[]'::jsonb)
           FROM pg_constraint con WHERE con.conrelid=c.oid AND con.contype <> 'n'),
        'indexes', (SELECT coalesce(jsonb_agg(jsonb_build_object(
             'name', ci.relname, 'def', pg_get_indexdef(i.indexrelid)
           ) ORDER BY ci.relname), '[]'::jsonb)
           FROM pg_index i JOIN pg_class ci ON ci.oid=i.indexrelid WHERE i.indrelid=c.oid),
        'triggers', (SELECT coalesce(jsonb_agg(jsonb_build_object(
             'name', tg.tgname, 'def', pg_get_triggerdef(tg.oid)
           ) ORDER BY tg.tgname), '[]'::jsonb)
           FROM pg_trigger tg WHERE tg.tgrelid=c.oid AND NOT tg.tgisinternal)
      ) AS t
      FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
      WHERE n.nspname='public' AND c.relkind='r'
    ) s),
  'enums', (SELECT coalesce(jsonb_agg(jsonb_build_object(
       'name', t.typname,
       'values', (SELECT coalesce(jsonb_agg(e.enumlabel ORDER BY e.enumsortorder), '[]'::jsonb)
                  FROM pg_enum e WHERE e.enumtypid=t.oid)
     ) ORDER BY t.typname), '[]'::jsonb)
     FROM pg_type t JOIN pg_namespace n ON n.oid=t.typnamespace
     WHERE n.nspname='public' AND t.typtype='e'),
  'functions', (SELECT coalesce(jsonb_agg(jsonb_build_object(
       'name', p.proname, 'def', pg_get_functiondef(p.oid)
     ) ORDER BY p.proname), '[]'::jsonb)
     FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
     WHERE n.nspname='public'),
  'extensions', (SELECT coalesce(jsonb_agg(extname ORDER BY extname), '[]'::jsonb)
     FROM pg_extension WHERE extname <> 'plpgsql')
));

-- OpenBot native schema 0015：把 Rust session 绑定到签发时的 auth generation。
--
-- 旧 Better Auth 行保持 NULL，并因 token 不是 keyed-hash 前缀而统一失效；兼容窗口不回填、
-- 不 SET NOT NULL。新 session 写入当前 generation，resolver 与 users 当前值逐次比较。

ALTER TABLE public.sessions
    ADD COLUMN auth_generation bigint;

ALTER TABLE ONLY public.sessions
    ADD CONSTRAINT sessions_auth_generation_nonnegative
    CHECK (auth_generation IS NULL OR auth_generation >= 0);

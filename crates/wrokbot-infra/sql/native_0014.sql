-- OpenBot native schema 0014：持久化每个用户的 auth generation。
--
-- 只追加 nullable 列与非破坏性 CHECK。旧行 NULL 在读侧等价 generation 0；兼容窗口内不做
-- SET NOT NULL。角色/撤权写路径用 coalesce(auth_generation, 0) + 1 原子递增。

ALTER TABLE public.users
    ADD COLUMN auth_generation bigint;

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_auth_generation_nonnegative
    CHECK (auth_generation IS NULL OR auth_generation >= 0);

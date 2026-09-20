-- Native 0022: actor-scoped runtime memory write control.
-- Absence means writes are enabled for upgrade compatibility. The row is not a memory record and
-- cannot enter recall; it governs only runtime retention paths.

CREATE TABLE public.user_memory_controls (
    tenant_id text NOT NULL,
    actor_user_id text NOT NULL,
    writes_enabled boolean DEFAULT true NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT user_memory_controls_pkey
        PRIMARY KEY (tenant_id, actor_user_id),
    CONSTRAINT user_memory_controls_identity_nonempty
        CHECK (tenant_id <> '' AND actor_user_id <> ''),
    CONSTRAINT user_memory_controls_actor_user_id_users_id_fk
        FOREIGN KEY (actor_user_id) REFERENCES public.users(id) ON DELETE CASCADE
);

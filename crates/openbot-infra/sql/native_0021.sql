-- Native 0021: independently optional, actor-scoped Server UI preferences.
-- The host fallback remains authoritative while a column is NULL; writes only merge supplied
-- closed enum values and never accept actor/deployment/tenant from the renderer.

CREATE TABLE public.user_ui_preferences (
    deployment_id text NOT NULL,
    tenant_id text NOT NULL,
    actor_user_id text NOT NULL,
    theme text,
    locale text,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT user_ui_preferences_pkey
        PRIMARY KEY (deployment_id, tenant_id, actor_user_id),
    CONSTRAINT user_ui_preferences_nonempty
        CHECK (theme IS NOT NULL OR locale IS NOT NULL),
    CONSTRAINT user_ui_preferences_theme_known
        CHECK (theme IS NULL OR theme IN ('system', 'light', 'dark')),
    CONSTRAINT user_ui_preferences_locale_known
        CHECK (locale IS NULL OR locale IN ('en', 'zh-CN')),
    CONSTRAINT user_ui_preferences_actor_user_id_users_id_fk
        FOREIGN KEY (actor_user_id) REFERENCES public.users(id) ON DELETE CASCADE
);

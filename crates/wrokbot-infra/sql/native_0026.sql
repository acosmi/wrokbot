-- Native 0026: actor-scoped per-run provider cost caps and immutable run snapshots.
-- A preference row is either absent (no user cap) or fully currency-bound. New runs copy the
-- current row in the same begin transaction so later preference changes cannot drift an active run.

CREATE TABLE public.user_run_cost_budgets (
    deployment_id text NOT NULL,
    tenant_id text NOT NULL,
    actor_user_id text NOT NULL,
    currency text NOT NULL,
    max_cost_micro_units bigint NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT user_run_cost_budgets_pkey
        PRIMARY KEY (deployment_id, tenant_id, actor_user_id),
    CONSTRAINT user_run_cost_budgets_identity_nonempty
        CHECK (deployment_id <> '' AND tenant_id <> '' AND actor_user_id <> ''),
    CONSTRAINT user_run_cost_budgets_currency_known
        CHECK (currency ~ '^[A-Z]{3}$'),
    CONSTRAINT user_run_cost_budgets_amount_positive
        CHECK (max_cost_micro_units > 0),
    CONSTRAINT user_run_cost_budgets_actor_user_id_users_id_fk
        FOREIGN KEY (actor_user_id) REFERENCES public.users(id) ON DELETE CASCADE
);

ALTER TABLE public.runs
    ADD COLUMN budget_cost_currency text,
    ADD COLUMN budget_max_cost_micro_units bigint,
    ADD CONSTRAINT runs_cost_budget_shape CHECK (
        (
            budget_cost_currency IS NULL
            AND budget_max_cost_micro_units IS NULL
        )
        OR (
            budget_cost_currency ~ '^[A-Z]{3}$'
            AND budget_max_cost_micro_units > 0
        )
    );

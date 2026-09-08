-- Native 0025: operator-attested maximum price snapshot and exact run cost upper bound.
-- Expand-only: absent snapshot means explicitly unpriced, never zero cost.

ALTER TABLE public.runs
    ADD COLUMN cost_currency text,
    ADD COLUMN cost_provider text,
    ADD COLUMN cost_model text,
    ADD COLUMN cost_max_input_micro_units_per_million_tokens bigint,
    ADD COLUMN cost_max_output_micro_units_per_million_tokens bigint,
    ADD COLUMN cost_source_url text,
    ADD COLUMN cost_source_sha256 text,
    ADD COLUMN cost_observed_at timestamp with time zone,
    ADD COLUMN usage_cost_upper_bound_micro_units bigint,
    ADD COLUMN usage_cost_upper_bound_remainder_millionths integer;

ALTER TABLE public.runs
    ADD CONSTRAINT runs_cost_accounting_shape CHECK (
        (
            cost_currency IS NULL
            AND cost_provider IS NULL
            AND cost_model IS NULL
            AND cost_max_input_micro_units_per_million_tokens IS NULL
            AND cost_max_output_micro_units_per_million_tokens IS NULL
            AND cost_source_url IS NULL
            AND cost_source_sha256 IS NULL
            AND cost_observed_at IS NULL
            AND usage_cost_upper_bound_micro_units IS NULL
            AND usage_cost_upper_bound_remainder_millionths IS NULL
        ) OR (
            cost_currency ~ '^[A-Z]{3}$'
            AND cost_provider IN ('openai_compatible','anthropic','google')
            AND length(cost_model) BETWEEN 1 AND 256
            AND cost_max_input_micro_units_per_million_tokens >= 0
            AND cost_max_output_micro_units_per_million_tokens >= 0
            AND length(cost_source_url) BETWEEN 1 AND 2048
            AND cost_source_url LIKE 'https://%'
            AND cost_source_sha256 ~ '^[0-9a-f]{64}$'
            AND cost_observed_at >= timestamp with time zone '1970-01-01 00:00:00+00'
            AND usage_cost_upper_bound_micro_units >= 0
            AND usage_cost_upper_bound_remainder_millionths BETWEEN 0 AND 999999
        )
    );

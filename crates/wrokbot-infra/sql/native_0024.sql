-- Native 0024: durable run-wide normalized provider token accounting.
-- Expand-only: existing runs begin with an empty counter and no run-output ceiling.

ALTER TABLE public.runs
    ADD COLUMN budget_max_output_tokens bigint,
    ADD COLUMN usage_input_tokens bigint DEFAULT 0 NOT NULL,
    ADD COLUMN usage_output_tokens bigint DEFAULT 0 NOT NULL,
    ADD COLUMN usage_total_tokens bigint DEFAULT 0 NOT NULL,
    ADD COLUMN usage_next_sampling integer DEFAULT 0 NOT NULL,
    ADD COLUMN usage_last_sampling integer,
    ADD COLUMN usage_last_input_tokens bigint,
    ADD COLUMN usage_last_output_tokens bigint,
    ADD COLUMN usage_last_total_tokens bigint;

ALTER TABLE public.runs
    ADD CONSTRAINT runs_budget_max_output_positive CHECK (
        budget_max_output_tokens IS NULL OR budget_max_output_tokens > 0
    ),
    ADD CONSTRAINT runs_usage_aggregate_nonnegative CHECK (
        usage_input_tokens >= 0
        AND usage_output_tokens >= 0
        AND usage_total_tokens >= 0
        AND usage_total_tokens >= usage_input_tokens + usage_output_tokens
        AND usage_next_sampling >= 0
    ),
    ADD CONSTRAINT runs_usage_last_shape CHECK (
        (
            usage_next_sampling = 0
            AND usage_last_sampling IS NULL
            AND usage_last_input_tokens IS NULL
            AND usage_last_output_tokens IS NULL
            AND usage_last_total_tokens IS NULL
        ) OR (
            usage_next_sampling > 0
            AND usage_last_sampling = usage_next_sampling - 1
            AND usage_last_input_tokens >= 0
            AND usage_last_output_tokens >= 0
            AND usage_last_total_tokens >= usage_last_input_tokens + usage_last_output_tokens
        )
    );

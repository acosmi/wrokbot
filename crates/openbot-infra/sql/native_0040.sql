-- Native 0040: editing revision for the already-delivered UI preference row.
-- Existing rows remain nullable; their editing read is version one, without a backfill.
ALTER TABLE public.user_ui_preferences
    ADD COLUMN revision bigint DEFAULT 1,
    ADD CONSTRAINT user_ui_preferences_revision_positive
        CHECK (revision IS NULL OR revision > 0);

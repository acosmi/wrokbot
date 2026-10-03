-- Independent editing CAS; the original integer publication revision keeps its meaning.
ALTER TABLE public.sandboxed_components
  ADD COLUMN editing_revision bigint DEFAULT 1;
ALTER TABLE public.sandboxed_components
  ADD CONSTRAINT sandboxed_components_editing_revision_positive
  CHECK (editing_revision IS NULL OR editing_revision > 0);

-- A deleted stable name cannot acquire a new version 1 and accept old write requests.
-- No business FK/cascade or retention sweep owns these minimal retired identities.
CREATE TABLE public.sandboxed_component_retired_names (
  name text PRIMARY KEY,
  retired_editing_revision bigint NOT NULL CHECK (retired_editing_revision > 0),
  retired_at timestamptz NOT NULL
);

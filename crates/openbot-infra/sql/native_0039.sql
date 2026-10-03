-- Editing revisions are independent of skill grants and instruction snapshots at run begin.
ALTER TABLE public.skills ADD COLUMN revision bigint DEFAULT 1;
ALTER TABLE public.skills ADD CONSTRAINT skills_revision_positive
  CHECK (revision IS NULL OR revision > 0);

-- Keep the original upstream skills row/FK. Permanently retire deleted slugs so an old
-- editing request or an orphan grant cannot acquire authority over a replacement source.
CREATE TABLE public.skill_retired_slugs (
  slug text PRIMARY KEY,
  retired_revision bigint NOT NULL CHECK (retired_revision > 0),
  retired_at timestamptz NOT NULL
);

CREATE FUNCTION openbot_internal.retire_deleted_skill() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  -- This trigger also runs on owner FK cascades. No advisory lock is taken after the
  -- source lock. Overflow aborts the deletion atomically instead of recycling identity.
  INSERT INTO public.skill_retired_slugs(slug,retired_revision,retired_at)
    VALUES(OLD.slug,coalesce(OLD.revision,1)+1,clock_timestamp())
    ON CONFLICT (slug) DO NOTHING;
  RETURN OLD;
END;
$$;
CREATE TRIGGER skills_retire_deleted_slug AFTER DELETE ON public.skills
FOR EACH ROW EXECUTE FUNCTION openbot_internal.retire_deleted_skill();

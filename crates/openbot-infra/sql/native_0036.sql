-- R409: compatibility occupancy projection. The original status index remains unchanged.
LOCK TABLE public.runs IN ACCESS EXCLUSIVE MODE;

ALTER TABLE public.runs
    ADD CONSTRAINT runs_thread_run_key UNIQUE (thread_id, run_id);

CREATE TABLE public.thread_run_occupancy (
    thread_id text NOT NULL,
    run_id text NOT NULL,
    CONSTRAINT thread_run_occupancy_pkey PRIMARY KEY (thread_id),
    CONSTRAINT thread_run_occupancy_run_pair_fkey
        FOREIGN KEY (thread_id, run_id) REFERENCES public.runs(thread_id, run_id)
        ON UPDATE RESTRICT ON DELETE RESTRICT NOT DEFERRABLE
);

INSERT INTO public.thread_run_occupancy(thread_id, run_id)
    SELECT thread_id, run_id FROM public.runs
    WHERE foreground AND status IN ('queued', 'running', 'reconciliation_required');

CREATE FUNCTION openbot_internal.maintain_thread_run_occupancy() RETURNS trigger
    LANGUAGE plpgsql VOLATILE
    SET search_path = pg_catalog
    SET lock_timeout = '5s'
    AS $$
DECLARE
    old_occupied boolean;
    new_occupied boolean;
    removed bigint;
BEGIN
    IF TG_OP = 'INSERT' THEN
        new_occupied := NEW.foreground AND NEW.status IN ('queued', 'running', 'reconciliation_required');
        IF new_occupied THEN
            IF EXISTS (SELECT 1 FROM public.thread_run_occupancy
                       WHERE thread_id = NEW.thread_id OR run_id = NEW.run_id) THEN
                RAISE EXCEPTION USING ERRCODE = '23514',
                    CONSTRAINT = 'thread_run_occupancy_pair_unexpected', MESSAGE = 'occupancy pair unexpected';
            END IF;
            INSERT INTO public.thread_run_occupancy(thread_id, run_id) VALUES (NEW.thread_id, NEW.run_id);
        ELSIF EXISTS (SELECT 1 FROM public.thread_run_occupancy WHERE run_id = NEW.run_id) THEN
            RAISE EXCEPTION USING ERRCODE = '23514',
                CONSTRAINT = 'thread_run_occupancy_pair_unexpected', MESSAGE = 'occupancy pair unexpected';
        END IF;
        RETURN NULL;
    END IF;

    old_occupied := OLD.foreground AND OLD.status IN ('queued', 'running', 'reconciliation_required');
    IF TG_OP = 'DELETE' THEN
        IF old_occupied OR OLD.status = 'reconciliation_required' THEN
            RAISE EXCEPTION USING ERRCODE = '23514',
                CONSTRAINT = 'thread_run_occupancy_release_forbidden', MESSAGE = 'occupancy release forbidden';
        END IF;
        IF EXISTS (SELECT 1 FROM public.thread_run_occupancy WHERE run_id = OLD.run_id) THEN
            RAISE EXCEPTION USING ERRCODE = '23514',
                CONSTRAINT = 'thread_run_occupancy_pair_unexpected', MESSAGE = 'occupancy pair unexpected';
        END IF;
        RETURN NULL;
    END IF;

    IF NEW.run_id IS DISTINCT FROM OLD.run_id OR NEW.thread_id IS DISTINCT FROM OLD.thread_id
       OR NEW.foreground IS DISTINCT FROM OLD.foreground THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            CONSTRAINT = 'thread_run_occupancy_identity_immutable', MESSAGE = 'occupancy identity immutable';
    END IF;
    IF OLD.status = 'reconciliation_required' AND NEW.status IS DISTINCT FROM OLD.status THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            CONSTRAINT = 'thread_run_occupancy_rr_immutable', MESSAGE = 'reconciliation status immutable';
    END IF;
    IF OLD.status IN ('completed', 'failed', 'cancelled')
       AND NEW.status IN ('queued', 'running', 'reconciliation_required') THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            CONSTRAINT = 'thread_run_occupancy_terminal_reactivation', MESSAGE = 'terminal reactivation forbidden';
    END IF;
    new_occupied := NEW.foreground AND NEW.status IN ('queued', 'running', 'reconciliation_required');
    IF old_occupied THEN
        -- Only this run's exact slot is locked, after the caller's original run DML.
        PERFORM 1 FROM public.thread_run_occupancy
            WHERE thread_id = OLD.thread_id AND run_id = OLD.run_id FOR UPDATE NOWAIT;
        IF NOT FOUND THEN
            RAISE EXCEPTION USING ERRCODE = '23514',
                CONSTRAINT = 'thread_run_occupancy_pair_missing', MESSAGE = 'occupancy pair missing';
        END IF;
        IF EXISTS (SELECT 1 FROM public.thread_run_occupancy
                   WHERE run_id = OLD.run_id AND thread_id <> OLD.thread_id) THEN
            RAISE EXCEPTION USING ERRCODE = '23514',
                CONSTRAINT = 'thread_run_occupancy_pair_unexpected', MESSAGE = 'occupancy pair unexpected';
        END IF;
        IF NOT new_occupied THEN
            IF NEW.status NOT IN ('completed', 'failed', 'cancelled') THEN
                RAISE EXCEPTION USING ERRCODE = '23514',
                    CONSTRAINT = 'thread_run_occupancy_release_forbidden', MESSAGE = 'occupancy release forbidden';
            END IF;
            DELETE FROM public.thread_run_occupancy
                WHERE thread_id = OLD.thread_id AND run_id = OLD.run_id;
            GET DIAGNOSTICS removed = ROW_COUNT;
            IF removed <> 1 THEN
                RAISE EXCEPTION USING ERRCODE = '23514',
                    CONSTRAINT = 'thread_run_occupancy_pair_missing', MESSAGE = 'occupancy pair missing';
            END IF;
        END IF;
    ELSE
        IF new_occupied OR EXISTS (SELECT 1 FROM public.thread_run_occupancy WHERE run_id = OLD.run_id) THEN
            RAISE EXCEPTION USING ERRCODE = '23514',
                CONSTRAINT = 'thread_run_occupancy_pair_unexpected', MESSAGE = 'occupancy pair unexpected';
        END IF;
    END IF;
    RETURN NULL;
END;
$$;

CREATE FUNCTION openbot_internal.guard_thread_run_occupancy() RETURNS trigger
    LANGUAGE plpgsql VOLATILE
    SET search_path = pg_catalog
    AS $$
BEGIN
    IF TG_OP = 'TRUNCATE' THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            CONSTRAINT = 'thread_run_occupancy_no_truncate', MESSAGE = 'occupancy truncate forbidden';
    END IF;
    -- Depth prevents accidental direct SQL; it grants no authority against a DDL-capable DB owner.
    IF TG_OP = 'UPDATE' OR pg_trigger_depth() < 2 THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            CONSTRAINT = 'thread_run_occupancy_direct_write', MESSAGE = 'direct occupancy write forbidden';
    END IF;
    IF TG_OP = 'INSERT' THEN
        IF NOT EXISTS (SELECT 1 FROM public.runs WHERE run_id = NEW.run_id AND thread_id = NEW.thread_id
                       AND foreground AND status IN ('queued', 'running', 'reconciliation_required')) THEN
            RAISE EXCEPTION USING ERRCODE = '23514',
                CONSTRAINT = 'thread_run_occupancy_pair_invalid', MESSAGE = 'occupancy pair invalid';
        END IF;
        RETURN NEW;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM public.runs WHERE run_id = OLD.run_id AND thread_id = OLD.thread_id
                   AND foreground AND status IN ('completed', 'failed', 'cancelled')) THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            CONSTRAINT = 'thread_run_occupancy_release_forbidden', MESSAGE = 'occupancy release forbidden';
    END IF;
    RETURN OLD;
END;
$$;

CREATE TRIGGER runs_maintain_thread_run_occupancy
    AFTER INSERT OR UPDATE OR DELETE ON public.runs
    FOR EACH ROW EXECUTE FUNCTION openbot_internal.maintain_thread_run_occupancy();
CREATE TRIGGER thread_run_occupancy_guard
    BEFORE INSERT OR UPDATE OR DELETE ON public.thread_run_occupancy
    FOR EACH ROW EXECUTE FUNCTION openbot_internal.guard_thread_run_occupancy();
CREATE TRIGGER thread_run_occupancy_no_truncate
    BEFORE TRUNCATE ON public.thread_run_occupancy
    FOR EACH STATEMENT EXECUTE FUNCTION openbot_internal.guard_thread_run_occupancy();
CREATE TRIGGER runs_occupancy_no_truncate
    BEFORE TRUNCATE ON public.runs
    FOR EACH STATEMENT EXECUTE FUNCTION openbot_internal.guard_thread_run_occupancy();

DO $$
BEGIN
    IF EXISTS (
        (SELECT thread_id, run_id FROM public.runs
         WHERE foreground AND status IN ('queued', 'running', 'reconciliation_required')
         EXCEPT SELECT thread_id, run_id FROM public.thread_run_occupancy)
        UNION ALL
        (SELECT thread_id, run_id FROM public.thread_run_occupancy
         EXCEPT SELECT thread_id, run_id FROM public.runs
         WHERE foreground AND status IN ('queued', 'running', 'reconciliation_required'))
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '23514',
            CONSTRAINT = 'thread_run_occupancy_backfill_inconsistent', MESSAGE = 'occupancy backfill inconsistent';
    END IF;
END;
$$;

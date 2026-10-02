-- Immutable material provenance. Expand only; old unknown facts are never backfilled.
ALTER TABLE public.memories
    ADD COLUMN source_run_id text,
    ADD COLUMN source_authorization_snapshot jsonb;

ALTER TABLE public.memories
    ADD CONSTRAINT memories_source_run_shape CHECK (
        source_run_id IS NULL OR
        (source_run_id <> '' AND source_thread_id IS NOT NULL AND source_message_id IS NOT NULL)
    ),
    ADD CONSTRAINT memories_source_authorization_shape CHECK (
        source_authorization_snapshot IS NULL OR (
          jsonb_typeof(source_authorization_snapshot) = 'object'
          AND source_authorization_snapshot ?& ARRAY['actorId','tenantId','deploymentId','authGeneration','roles','scope','capturedAt']
          AND source_authorization_snapshot - ARRAY['actorId','tenantId','deploymentId','authGeneration','roles','scope','capturedAt'] = '{}'::jsonb
          AND source_authorization_snapshot->>'actorId' = owner_user_id
          AND jsonb_typeof(source_authorization_snapshot->'actorId') = 'string'
          AND source_authorization_snapshot->>'tenantId' = tenant_id
          AND jsonb_typeof(source_authorization_snapshot->'tenantId') = 'string'
          AND jsonb_typeof(source_authorization_snapshot->'deploymentId') = 'string'
          AND source_authorization_snapshot->>'deploymentId' <> ''
          AND CASE WHEN jsonb_typeof(source_authorization_snapshot->'authGeneration') = 'number'
                        AND source_authorization_snapshot->>'authGeneration' ~ '^(0|[1-9][0-9]*)$'
                   THEN (source_authorization_snapshot->>'authGeneration')::numeric <= 9223372036854775807
                   ELSE false END
          AND jsonb_typeof(source_authorization_snapshot->'roles') = 'array'
          AND source_authorization_snapshot->'roles' IN ('["user"]'::jsonb, '["admin"]'::jsonb, '["admin","user"]'::jsonb)
          AND source_authorization_snapshot->'scope' = CASE scope_kind
              WHEN 'user' THEN jsonb_build_object('kind','user')
              WHEN 'bot' THEN jsonb_build_object('kind','bot','bot_id',scope_id)
              WHEN 'thread' THEN jsonb_build_object('kind','thread','thread_id',scope_id)
              END
          AND jsonb_typeof(source_authorization_snapshot->'capturedAt') = 'string'
          AND source_authorization_snapshot->>'capturedAt'
              ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]+)?(Z|[+-][0-9]{2}:[0-9]{2})$'
          AND CASE WHEN pg_input_is_valid(source_authorization_snapshot->>'capturedAt', 'timestamp with time zone')
                   THEN (source_authorization_snapshot->>'capturedAt')::timestamptz <= created_at
                   ELSE false END
        )
    );

CREATE FUNCTION public.guard_memory_provenance() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF ROW(NEW.tenant_id,NEW.owner_user_id,NEW.scope_kind,NEW.scope_id,NEW.memory_kind,
         NEW.source_thread_id,NEW.source_message_id,NEW.source_run_id,
         NEW.source_authorization_snapshot,NEW.origin,NEW.created_by,NEW.created_at)
     IS DISTINCT FROM
     ROW(OLD.tenant_id,OLD.owner_user_id,OLD.scope_kind,OLD.scope_id,OLD.memory_kind,
         OLD.source_thread_id,OLD.source_message_id,OLD.source_run_id,
         OLD.source_authorization_snapshot,OLD.origin,OLD.created_by,OLD.created_at) THEN
    RAISE EXCEPTION 'memory provenance is immutable' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER memory_provenance_immutable
BEFORE UPDATE ON public.memories
FOR EACH ROW EXECUTE FUNCTION public.guard_memory_provenance();

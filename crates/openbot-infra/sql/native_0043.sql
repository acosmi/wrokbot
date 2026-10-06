-- Internal remember preference records. This schema grants no current authority or CAS.
-- The complete text key must fit the actual standard PostgreSQL 17 btree page.
DO $$
BEGIN
    IF current_setting('server_encoding') <> 'UTF8'
       OR current_setting('block_size')::integer <> 8192
       OR current_setting('server_version_num')::integer NOT BETWEEN 170000 AND 179999 THEN
        RAISE EXCEPTION 'approval preference storage prerequisites are unavailable'
            USING ERRCODE = '55000';
    END IF;
END;
$$;

CREATE TABLE openbot_internal.approval_preferences (
    preference_id uuid NOT NULL,
    deployment_id text COLLATE "C" NOT NULL,
    tenant_id text COLLATE "C" NOT NULL,
    actor_id text COLLATE "C" NOT NULL,
    bot_id text COLLATE "C" NOT NULL,
    target_kind text COLLATE "C" NOT NULL,
    target_id text COLLATE "C" NOT NULL,
    tool_name text NOT NULL,
    effect text NOT NULL,
    preference text NOT NULL,
    revision bigint NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CONSTRAINT approval_preferences_pkey PRIMARY KEY (preference_id),
    CONSTRAINT approval_preferences_complete_key UNIQUE
        (deployment_id, tenant_id, actor_id, bot_id, target_kind, target_id),
    CONSTRAINT approval_preferences_uuid_v7 CHECK
        (preference_id::text ~ '^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'),
    CONSTRAINT approval_preferences_identity_shape CHECK (
        octet_length(deployment_id) BETWEEN 1 AND 512
        AND (deployment_id COLLATE "C") !~ U&'[\0001-\001F\007F-\009F]'
        AND octet_length(tenant_id) BETWEEN 1 AND 512
        AND (tenant_id COLLATE "C") !~ U&'[\0001-\001F\007F-\009F]'
        AND octet_length(actor_id) BETWEEN 1 AND 512
        AND (actor_id COLLATE "C") !~ U&'[\0001-\001F\007F-\009F]'
        AND octet_length(bot_id) BETWEEN 1 AND 512
        AND (bot_id COLLATE "C") !~ U&'[\0001-\001F\007F-\009F]'
        AND octet_length(target_id) BETWEEN 1 AND 512
        AND (target_id COLLATE "C") !~ U&'[\0001-\001F\007F-\009F]'
    ),
    CONSTRAINT approval_preferences_target_kind CHECK
        (target_kind IN ('memory_user', 'memory_bot', 'memory_thread')),
    CONSTRAINT approval_preferences_target_identity CHECK (
        (target_kind = 'memory_user' AND target_id = actor_id)
        OR (target_kind = 'memory_bot' AND target_id = bot_id)
        OR target_kind = 'memory_thread'
    ),
    CONSTRAINT approval_preferences_tool CHECK (tool_name = 'remember'),
    CONSTRAINT approval_preferences_effect CHECK (effect = 'write'),
    CONSTRAINT approval_preferences_preference CHECK
        (preference IN ('never', 'ask', 'allow_if_policy')),
    CONSTRAINT approval_preferences_positive_revision CHECK (revision > 0)
);

-- This guard preserves record identity and monotone versions. It does not compare the caller's
-- expected revision, observe current permission, or prove an original operation's commit.
CREATE FUNCTION openbot_internal.prevent_approval_preference_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP IN ('DELETE', 'TRUNCATE') THEN
        RAISE EXCEPTION 'approval preference records cannot be removed'
            USING ERRCODE = '55000';
    END IF;
    IF ROW(NEW.preference_id, NEW.deployment_id, NEW.tenant_id, NEW.actor_id,
           NEW.bot_id, NEW.target_kind, NEW.target_id, NEW.created_at)
       IS DISTINCT FROM
       ROW(OLD.preference_id, OLD.deployment_id, OLD.tenant_id, OLD.actor_id,
           OLD.bot_id, OLD.target_kind, OLD.target_id, OLD.created_at) THEN
        RAISE EXCEPTION 'approval preference identity is immutable'
            USING ERRCODE = '55000';
    END IF;
    IF OLD.revision = 9223372036854775807 THEN
        RAISE EXCEPTION 'approval preference revision is exhausted'
            USING ERRCODE = '55000';
    END IF;
    IF NEW.revision IS DISTINCT FROM OLD.revision + 1 THEN
        RAISE EXCEPTION 'approval preference revision must advance exactly once'
            USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER approval_preferences_mutation_guard
    BEFORE UPDATE OR DELETE ON openbot_internal.approval_preferences
    FOR EACH ROW EXECUTE FUNCTION openbot_internal.prevent_approval_preference_mutation();

CREATE TRIGGER approval_preferences_no_truncate
    BEFORE TRUNCATE ON openbot_internal.approval_preferences
    FOR EACH STATEMENT EXECUTE FUNCTION openbot_internal.prevent_approval_preference_mutation();

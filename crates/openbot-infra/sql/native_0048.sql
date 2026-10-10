-- Independent SDK authorization-attempt journal foundation; no runtime send authority.
-- Applied only on the original native migration transaction. No legacy backfill.

DO $gateway_authorization_owner$
DECLARE
    v_original_owner pg_catalog.oid;
    v_current_role pg_catalog.oid;
BEGIN
    SELECT c.relowner INTO v_original_owner
    FROM pg_catalog.pg_class c
    JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relname = 'sdk_gateway_connections' AND c.relkind = 'r';
    SELECT r.oid INTO v_current_role
    FROM pg_catalog.pg_roles r WHERE r.rolname = CURRENT_USER;
    IF v_original_owner IS NULL OR v_current_role IS NULL OR
       NOT EXISTS (SELECT 1 FROM pg_catalog.pg_namespace n
                   WHERE n.nspname = 'openbot_internal' AND n.nspowner = v_original_owner) OR
       NOT EXISTS (SELECT 1 FROM pg_catalog.pg_class c
                   JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
                   WHERE n.nspname = 'openbot_internal' AND c.relname = 'schema_migrations'
                     AND c.relkind = 'r' AND c.relpersistence = 'p'
                     AND c.relowner = v_original_owner) OR
       v_current_role IS DISTINCT FROM v_original_owner THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'gateway_authorization_schema_invalid';
    END IF;
END;
$gateway_authorization_owner$;

CREATE TABLE openbot_internal.gateway_authorization_attempts (
    attempt_id uuid NOT NULL,
    journal_schema smallint NOT NULL,
    deployment_id text COLLATE pg_catalog."C" NOT NULL,
    tenant_id text COLLATE pg_catalog."C" NOT NULL,
    owner_user_id text COLLATE pg_catalog."C" NOT NULL,
    auth_generation bigint NOT NULL,
    installation_id text COLLATE pg_catalog."C" NOT NULL,
    runtime_epoch text COLLATE pg_catalog."C" NOT NULL,
    issuer text COLLATE pg_catalog."C" NOT NULL,
    redirect_uri text COLLATE pg_catalog."C" NOT NULL,
    phase text COLLATE pg_catalog."C" NOT NULL,
    client_id text COLLATE pg_catalog."C",
    enrollment_id uuid,
    registration_admitted_at timestamp with time zone,
    code_admitted_at timestamp with time zone,
    created_at timestamp with time zone NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    finished_at timestamp with time zone,
    outcome_code text COLLATE pg_catalog."C",
    CONSTRAINT ga_attempts_pkey PRIMARY KEY (attempt_id),
    CONSTRAINT ga_attempts_enrollment_key UNIQUE (enrollment_id),
    CONSTRAINT ga_attempts_owner_fkey FOREIGN KEY (owner_user_id) REFERENCES public.users (id)
        MATCH SIMPLE ON UPDATE RESTRICT ON DELETE CASCADE
        NOT DEFERRABLE INITIALLY IMMEDIATE,
    CONSTRAINT ga_attempts_schema_check CHECK(journal_schema=1),
    CONSTRAINT ga_attempts_scope_check CHECK(pg_catalog.octet_length(deployment_id) BETWEEN 1 AND 512 AND deployment_id !~ U&'[\0001-\001F\007F-\009F]' AND deployment_id=pg_catalog.btrim(deployment_id) AND pg_catalog.octet_length(tenant_id) BETWEEN 1 AND 512 AND tenant_id !~ U&'[\0001-\001F\007F-\009F]' AND tenant_id=pg_catalog.btrim(tenant_id) AND pg_catalog.octet_length(owner_user_id) BETWEEN 1 AND 512 AND owner_user_id !~ U&'[\0001-\001F\007F-\009F]' AND owner_user_id=pg_catalog.btrim(owner_user_id)),
    CONSTRAINT ga_attempts_generation_check CHECK(auth_generation>=0),
    CONSTRAINT ga_attempts_installation_check CHECK(installation_id ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ga_attempts_runtime_check CHECK(runtime_epoch ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ga_attempts_issuer_check CHECK(pg_catalog.octet_length(issuer) BETWEEN 1 AND 2048 AND issuer LIKE 'https://%' AND issuer !~ U&'[\0001-\001F\007F-\009F]' AND issuer=pg_catalog.btrim(issuer)),
    CONSTRAINT ga_attempts_redirect_check CHECK(pg_catalog.octet_length(redirect_uri) BETWEEN 1 AND 128 AND redirect_uri ~ '^http://127[.]0[.]0[.]1:([1-9][0-9]{0,4})/callback$' AND COALESCE(pg_catalog.substring(redirect_uri,'^http://127[.]0[.]0[.]1:([1-9][0-9]{0,4})/callback$')::integer BETWEEN 1 AND 65535,false)),
    CONSTRAINT ga_attempts_client_check CHECK(client_id IS NULL OR (pg_catalog.octet_length(client_id) BETWEEN 1 AND 256 AND client_id !~ U&'[\0001-\001F\007F-\009F]' AND client_id=pg_catalog.btrim(client_id))),
    CONSTRAINT ga_attempts_phase_check CHECK(phase IN('created','registration_admitted','registered','code_admitted','enrolled','closed')),
    CONSTRAINT ga_attempts_attempt_uuid_check CHECK(pg_catalog.substring(attempt_id::text,15,1)='7' AND pg_catalog.substring(attempt_id::text,20,1) IN('8','9','a','b')),
    CONSTRAINT ga_attempts_enrollment_uuid_check CHECK(enrollment_id IS NULL OR (pg_catalog.substring(enrollment_id::text,15,1)='7' AND pg_catalog.substring(enrollment_id::text,20,1) IN('8','9','a','b'))),
    CONSTRAINT ga_attempts_time_check CHECK(pg_catalog.isfinite(created_at) AND pg_catalog.isfinite(expires_at) AND pg_catalog.isfinite(updated_at) AND expires_at>created_at AND updated_at>=created_at AND (registration_admitted_at IS NULL OR (pg_catalog.isfinite(registration_admitted_at) AND registration_admitted_at>=created_at AND registration_admitted_at<=expires_at)) AND (code_admitted_at IS NULL OR (pg_catalog.isfinite(code_admitted_at) AND code_admitted_at>=created_at AND code_admitted_at<=expires_at AND code_admitted_at>=registration_admitted_at)) AND (finished_at IS NULL OR (pg_catalog.isfinite(finished_at) AND finished_at>=created_at AND updated_at=finished_at)) AND (phase<>'enrolled' OR finished_at<=expires_at)),
    CONSTRAINT ga_attempts_admission_check CHECK(((client_id IS NULL)=(enrollment_id IS NULL)) AND (client_id IS NULL OR registration_admitted_at IS NOT NULL) AND (code_admitted_at IS NULL OR (registration_admitted_at IS NOT NULL AND client_id IS NOT NULL))),
    CONSTRAINT ga_attempts_stage_check CHECK((phase='created' AND registration_admitted_at IS NULL AND client_id IS NULL AND code_admitted_at IS NULL) OR (phase='registration_admitted' AND registration_admitted_at IS NOT NULL AND client_id IS NULL AND code_admitted_at IS NULL) OR (phase='registered' AND registration_admitted_at IS NOT NULL AND client_id IS NOT NULL AND code_admitted_at IS NULL) OR (phase IN('code_admitted','enrolled') AND registration_admitted_at IS NOT NULL AND client_id IS NOT NULL AND code_admitted_at IS NOT NULL) OR phase='closed'),
    CONSTRAINT ga_attempts_terminal_check CHECK((phase IN('enrolled','closed'))=(finished_at IS NOT NULL)),
    CONSTRAINT ga_attempts_outcome_check CHECK((phase='enrolled' AND outcome_code IS NOT NULL AND outcome_code='enrolled') OR (phase='closed' AND outcome_code IS NOT NULL AND outcome_code IN('cancelled','expired','host_revoked','dependency_unknown','registration_unknown','code_unknown','enrollment_unknown','restart_denied','refused')) OR (phase NOT IN('enrolled','closed') AND outcome_code IS NULL))
);

DO $gateway_authorization_postconditions$
DECLARE
    v_original_owner pg_catalog.oid;
    v_current_role pg_catalog.oid;
    v_attempt_oid pg_catalog.oid;
    v_attempt_owner pg_catalog.oid;
BEGIN
    SELECT c.relowner INTO v_original_owner
    FROM pg_catalog.pg_class c
    JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'public' AND c.relname = 'sdk_gateway_connections' AND c.relkind = 'r';
    SELECT r.oid INTO v_current_role
    FROM pg_catalog.pg_roles r WHERE r.rolname = CURRENT_USER;
    SELECT c.oid, c.relowner INTO v_attempt_oid, v_attempt_owner
    FROM pg_catalog.pg_class c
    JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = 'openbot_internal' AND c.relname = 'gateway_authorization_attempts'
      AND c.relkind = 'r' AND c.relpersistence = 'p' AND NOT c.relispartition
      AND NOT c.relrowsecurity AND NOT c.relforcerowsecurity;
    IF v_original_owner IS NULL OR v_current_role IS NULL OR v_attempt_oid IS NULL OR
       v_current_role IS DISTINCT FROM v_original_owner OR
       v_attempt_owner IS DISTINCT FROM v_original_owner THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'gateway_authorization_schema_invalid';
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_catalog.pg_attribute a
        WHERE a.attrelid = v_attempt_oid AND a.attnum > 0
          AND (a.attisdropped OR a.attacl IS NOT NULL)
    ) OR (SELECT pg_catalog.count(*) FROM pg_catalog.pg_attribute a
          WHERE a.attrelid = v_attempt_oid AND a.attnum > 0) <> 20 THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'gateway_authorization_schema_invalid';
    END IF;
    IF (SELECT pg_catalog.count(*) FROM pg_catalog.pg_constraint
        WHERE conrelid = v_attempt_oid) <> 19 OR
       (SELECT pg_catalog.count(*) FROM pg_catalog.pg_constraint
        WHERE conrelid = v_attempt_oid AND contype = 'c') <> 16 THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'gateway_authorization_schema_invalid';
    END IF;
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_policy WHERE polrelid = v_attempt_oid) OR
       EXISTS (SELECT 1 FROM pg_catalog.pg_rewrite WHERE ev_class = v_attempt_oid) OR
       EXISTS (SELECT 1 FROM pg_catalog.pg_trigger
               WHERE tgrelid = v_attempt_oid AND NOT tgisinternal) THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'gateway_authorization_schema_invalid';
    END IF;
    IF (SELECT pg_catalog.count(*) FROM pg_catalog.pg_index
        WHERE indrelid = v_attempt_oid) <> 2 OR EXISTS (
        SELECT 1 FROM pg_catalog.pg_index i
        JOIN pg_catalog.pg_class idx ON idx.oid = i.indexrelid
        JOIN pg_catalog.pg_am am ON am.oid = idx.relam
        WHERE i.indrelid = v_attempt_oid AND (
            idx.relowner IS DISTINCT FROM v_original_owner OR idx.relacl IS NOT NULL OR
            idx.relname NOT IN ('ga_attempts_pkey', 'ga_attempts_enrollment_key') OR
            (idx.relname = 'ga_attempts_pkey' AND (NOT i.indisprimary OR i.indkey::text <> '1')) OR
            (idx.relname = 'ga_attempts_enrollment_key' AND (i.indisprimary OR i.indkey::text <> '13')) OR
            idx.relkind <> 'i' OR idx.relpersistence <> 'p' OR idx.relispartition OR
            am.amname <> 'btree' OR NOT i.indisunique OR NOT i.indisvalid OR
            NOT i.indisready OR NOT i.indislive OR NOT i.indimmediate OR
            i.indnullsnotdistinct OR i.indnkeyatts <> 1 OR i.indnatts <> 1 OR
            i.indpred IS NOT NULL OR i.indexprs IS NOT NULL
        )
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'gateway_authorization_schema_invalid';
    END IF;
    -- NULL and explicit builtin owner-only ACLs are the sole allowed states.
    -- EXCEPT ALL retains duplicate entries, grant options and PG17 MAINTAIN.
    -- Inherited additional default grants fail this migration; never REVOKE/repair them.
    IF EXISTS (
        (SELECT a.grantor, a.grantee, a.privilege_type, a.is_grantable
         FROM pg_catalog.pg_class c
         CROSS JOIN LATERAL pg_catalog.aclexplode(
             COALESCE(c.relacl, pg_catalog.acldefault('r'::pg_catalog."char", c.relowner))) a
         WHERE c.oid = v_attempt_oid)
        EXCEPT ALL
        (SELECT a.grantor, a.grantee, a.privilege_type, a.is_grantable
         FROM pg_catalog.aclexplode(pg_catalog.acldefault('r'::pg_catalog."char", v_original_owner)) a)
    ) OR EXISTS (
        (SELECT a.grantor, a.grantee, a.privilege_type, a.is_grantable
         FROM pg_catalog.aclexplode(pg_catalog.acldefault('r'::pg_catalog."char", v_original_owner)) a)
        EXCEPT ALL
        (SELECT a.grantor, a.grantee, a.privilege_type, a.is_grantable
         FROM pg_catalog.pg_class c
         CROSS JOIN LATERAL pg_catalog.aclexplode(
             COALESCE(c.relacl, pg_catalog.acldefault('r'::pg_catalog."char", c.relowner))) a
         WHERE c.oid = v_attempt_oid)
    ) THEN
        RAISE EXCEPTION USING ERRCODE = '55000', MESSAGE = 'gateway_authorization_schema_invalid';
    END IF;
END;
$gateway_authorization_postconditions$;

-- crates/openbot-infra/sql/baseline_0012.sql
--
-- Fresh install 的 baseline DDL（v3 §14.1 逐字：「Fresh install 使用当前最终 schema 的 Rust
-- baseline，不创建已删除的 document/vector 表」）。把一个空库直接建成上游第 13 条 migration
-- （server/drizzle/0012_truncate_is_not_a_way_around_append_only.sql）跑完之后的终态。
--
-- 来源与生成方式：上游 CopilotKit/openbot@891df72f1827454d8b353d108fe5dd2313b7e30d 的
-- server/drizzle/0000..0012 按序应用到一个空库，再 `pg_dump --schema-only --no-owner
-- --no-privileges` 导出，然后清理掉 psql 元命令（\restrict / \unrestrict）、pg_dump 的版本
-- 注释、以及与本项目无关的会话级 SET。DDL 语句本身逐字保留，未做任何改写。
--
-- 终态事实（由 crates/openbot-infra/sql/schema_facts.sql 在参照库上实跑得出）：
--   28 张表 / 204 列 / 59 个非 NOT-NULL 约束 / 44 个索引 / 2 个触发器 /
--   4 个 enum / 1 个函数 / 0 个 extension；另有 153 个列级 NOT NULL 事实。
--   59 个 pg_constraint = 28 PRIMARY KEY + 27 FOREIGN KEY + 4 UNIQUE；NOT NULL 由
--   schema_facts.sql 的 columns[].notnull 表达，不在 PostgreSQL 17 的 pg_constraint 里重复计。
--
-- 刻意**不含** `CREATE EXTENSION vector`：0010 已 `DROP EXTENSION vector`，v3 §14.1 的 Rust 兼容
-- migration 对 extension 零操作，本项目不需要 pgvector（repository contract §3〈数据库〉）。同理刻意不建
-- 0010 / 0011 已删除的 documents / chunks / document_acls / connector_instances /
-- connector_cursors / sync_runs / webhook_subscriptions 七张表，也不建它们的
-- acl_effect / connector_type / sync_status 三个 enum。
--
-- 这份文件由 openbot-infra::db::baseline::BASELINE_0012_SQL 以 include_str! 嵌入二进制；
-- 它与参照库的等价性由集成测试 schema_baseline_parity 逐字段验证（需真库，见该文件头注释）。
--
-- NOT NULL 一律用列内联写法而不是 PostgreSQL 18 的具名约束语法，这样 17 与 18 都能执行，
-- 且在 18 上生成的 pg_constraint 具名行与上游 migration 跑出来的逐字相同。

CREATE TYPE public.agent_type AS ENUM (
    'built_in',
    'remote_ag_ui'
);

CREATE TYPE public.agent_visibility AS ENUM (
    'public',
    'private'
);

CREATE TYPE public.credential_kind AS ENUM (
    'model',
    'connector',
    'agent',
    'mcp',
    'mcp_oauth_client',
    'mcp_user_token'
);

CREATE TYPE public.role AS ENUM (
    'admin',
    'user'
);

CREATE FUNCTION public.prevent_audit_event_mutation() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
DECLARE
  retention_days integer;
BEGIN
  -- Answered before anything else is read, so no setting and no missing OLD record can change it.
  IF TG_OP = 'TRUNCATE' OR TG_OP = 'UPDATE' THEN
    RAISE EXCEPTION 'Audit events are append-only';
  END IF;

  -- `true` so a session that never set it reads NULL instead of raising, which is the ordinary case
  -- and has to stay a plain refusal.
  BEGIN
    retention_days := nullif(current_setting('openbot.audit_retention_days', true), '')::integer;
  EXCEPTION WHEN others THEN
    retention_days := NULL;
  END;

  IF retention_days IS NULL OR retention_days < 1 THEN
    RAISE EXCEPTION 'Audit events are append-only';
  END IF;

  IF OLD.created_at >= now() - (retention_days || ' days')::interval THEN
    RAISE EXCEPTION 'Audit events are append-only within the retention window';
  END IF;

  RETURN OLD;
END;
$$;

CREATE TABLE public.accounts (
    id text NOT NULL,
    account_id text NOT NULL,
    provider_id text NOT NULL,
    user_id text NOT NULL,
    access_token text,
    refresh_token text,
    id_token text,
    access_token_expires_at timestamp with time zone,
    refresh_token_expires_at timestamp with time zone,
    scope text,
    password text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    issuer text
);

CREATE TABLE public.action_policy (
    id text NOT NULL,
    mode text NOT NULL,
    deny text[] NOT NULL,
    allow text[] NOT NULL,
    updated_by text,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.agent_preferences (
    user_id text NOT NULL,
    agent_id text NOT NULL,
    hidden_at timestamp with time zone
);

CREATE TABLE public.agent_profiles (
    agent_id text NOT NULL,
    owner_user_id text,
    title text NOT NULL,
    role_description text NOT NULL,
    avatar_seed text NOT NULL,
    visibility public.agent_visibility NOT NULL,
    deleted_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    callback_token_hash text,
    callback_token_issued_at timestamp with time zone
);

CREATE TABLE public.agents (
    id text NOT NULL,
    name text NOT NULL,
    type public.agent_type NOT NULL,
    configuration jsonb NOT NULL,
    package_id uuid,
    override jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.audit_events (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    actor_user_id text,
    event_type text NOT NULL,
    target_type text NOT NULL,
    target_id text,
    payload jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.channel_agents (
    channel_id text NOT NULL,
    agent_id text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.channel_memberships (
    channel_id text NOT NULL,
    user_id text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.channels (
    id text NOT NULL,
    name text NOT NULL,
    description text NOT NULL,
    suggested_prompts text[] DEFAULT '{}'::text[] NOT NULL,
    allowed_groups text[] DEFAULT '{}'::text[] NOT NULL,
    package_id uuid,
    override jsonb,
    last_message text,
    last_message_at timestamp with time zone,
    last_message_agent_id text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.component_exclusions (
    component_name text NOT NULL,
    agent_id text NOT NULL,
    withheld_by text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.component_functions (
    component_name text NOT NULL,
    function_name text NOT NULL,
    granted_by text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.components (
    name text NOT NULL,
    title text NOT NULL,
    kind text NOT NULL,
    draft_description text NOT NULL,
    published_description text,
    published boolean DEFAULT false NOT NULL,
    published_at timestamp with time zone,
    updated_by text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.computer_snapshot (
    computer_id text NOT NULL,
    snapshot_id integer NOT NULL,
    url text NOT NULL,
    elements jsonb NOT NULL,
    taken_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.credentials (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    kind public.credential_kind NOT NULL,
    provider text NOT NULL,
    encrypted_value text NOT NULL,
    key_id text NOT NULL,
    metadata jsonb NOT NULL,
    revoked_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.deployment_packages (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id text NOT NULL,
    source_path text NOT NULL,
    checksum text NOT NULL,
    loaded_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.intelligence_channel_mappings (
    user_id text NOT NULL,
    channel_id text NOT NULL,
    thread_id text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.mcp_servers (
    id text NOT NULL,
    title text NOT NULL,
    vendor text NOT NULL,
    url text NOT NULL,
    provenance text DEFAULT 'first-party'::text NOT NULL,
    credential_id uuid,
    tools_refreshed_at timestamp with time zone,
    last_error text,
    added_by text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.mcp_tools (
    server_id text NOT NULL,
    name text NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    input_schema jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.mcp_user_credentials (
    server_id text NOT NULL,
    user_id text NOT NULL,
    credential_id uuid NOT NULL,
    scope text NOT NULL,
    connected_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.plugin_grants (
    kind text NOT NULL,
    ref text NOT NULL,
    agent_id text NOT NULL,
    granted_by text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.revoked_access (
    email text NOT NULL,
    revoked_at timestamp with time zone DEFAULT now() NOT NULL,
    revoked_by text NOT NULL
);

CREATE TABLE public.sandboxed_components (
    name text NOT NULL,
    title text NOT NULL,
    draft_description text DEFAULT ''::text NOT NULL,
    draft_html text DEFAULT ''::text NOT NULL,
    draft_css text DEFAULT ''::text NOT NULL,
    draft_js_functions text DEFAULT ''::text NOT NULL,
    draft_argument_schema jsonb DEFAULT '{}'::jsonb NOT NULL,
    published_description text,
    published_html text,
    published_css text,
    published_js_functions text,
    published_argument_schema jsonb,
    sample_arguments jsonb DEFAULT '{}'::jsonb NOT NULL,
    revision integer DEFAULT 0 NOT NULL,
    published boolean DEFAULT false NOT NULL,
    published_at timestamp with time zone,
    authored_by text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.sessions (
    id text NOT NULL,
    user_id text NOT NULL,
    token text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    ip_address text,
    user_agent text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.skills (
    id text NOT NULL,
    owner_user_id text,
    slug text NOT NULL,
    title text NOT NULL,
    summary text NOT NULL,
    instructions text NOT NULL,
    origin text DEFAULT 'yours'::text NOT NULL,
    installed_by text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.sso_providers (
    id text NOT NULL,
    issuer text NOT NULL,
    oidc_config text,
    saml_config text,
    user_id text,
    provider_id text NOT NULL,
    organization_id text,
    domain text NOT NULL
);

CREATE TABLE public.user_roles (
    user_id text NOT NULL,
    role public.role NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.users (
    id text NOT NULL,
    email text NOT NULL,
    name text,
    image text,
    email_verified boolean DEFAULT false NOT NULL,
    groups text[] DEFAULT '{}'::text[] NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE public.verifications (
    id text NOT NULL,
    identifier text NOT NULL,
    value text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

ALTER TABLE ONLY public.accounts
    ADD CONSTRAINT accounts_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.action_policy
    ADD CONSTRAINT action_policy_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.agent_preferences
    ADD CONSTRAINT agent_preferences_user_id_agent_id_pk PRIMARY KEY (user_id, agent_id);

ALTER TABLE ONLY public.agent_profiles
    ADD CONSTRAINT agent_profiles_pkey PRIMARY KEY (agent_id);

ALTER TABLE ONLY public.agents
    ADD CONSTRAINT agents_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.audit_events
    ADD CONSTRAINT audit_events_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.channel_agents
    ADD CONSTRAINT channel_agents_channel_id_agent_id_pk PRIMARY KEY (channel_id, agent_id);

ALTER TABLE ONLY public.channel_memberships
    ADD CONSTRAINT channel_memberships_channel_id_user_id_pk PRIMARY KEY (channel_id, user_id);

ALTER TABLE ONLY public.channels
    ADD CONSTRAINT channels_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.component_exclusions
    ADD CONSTRAINT component_exclusions_component_name_agent_id_pk PRIMARY KEY (component_name, agent_id);

ALTER TABLE ONLY public.component_functions
    ADD CONSTRAINT component_functions_component_name_function_name_pk PRIMARY KEY (component_name, function_name);

ALTER TABLE ONLY public.components
    ADD CONSTRAINT components_pkey PRIMARY KEY (name);

ALTER TABLE ONLY public.computer_snapshot
    ADD CONSTRAINT computer_snapshot_pkey PRIMARY KEY (computer_id);

ALTER TABLE ONLY public.credentials
    ADD CONSTRAINT credentials_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.deployment_packages
    ADD CONSTRAINT deployment_packages_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.deployment_packages
    ADD CONSTRAINT deployment_packages_tenant_id_unique UNIQUE (tenant_id);

ALTER TABLE ONLY public.intelligence_channel_mappings
    ADD CONSTRAINT intelligence_channel_mappings_user_id_channel_id_pk PRIMARY KEY (user_id, channel_id);

ALTER TABLE ONLY public.mcp_servers
    ADD CONSTRAINT mcp_servers_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.mcp_tools
    ADD CONSTRAINT mcp_tools_server_id_name_pk PRIMARY KEY (server_id, name);

ALTER TABLE ONLY public.mcp_user_credentials
    ADD CONSTRAINT mcp_user_credentials_server_id_user_id_pk PRIMARY KEY (server_id, user_id);

ALTER TABLE ONLY public.plugin_grants
    ADD CONSTRAINT plugin_grants_kind_ref_agent_id_pk PRIMARY KEY (kind, ref, agent_id);

ALTER TABLE ONLY public.revoked_access
    ADD CONSTRAINT revoked_access_pkey PRIMARY KEY (email);

ALTER TABLE ONLY public.sandboxed_components
    ADD CONSTRAINT sandboxed_components_pkey PRIMARY KEY (name);

ALTER TABLE ONLY public.sessions
    ADD CONSTRAINT sessions_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.sessions
    ADD CONSTRAINT sessions_token_unique UNIQUE (token);

ALTER TABLE ONLY public.skills
    ADD CONSTRAINT skills_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.sso_providers
    ADD CONSTRAINT sso_providers_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.sso_providers
    ADD CONSTRAINT sso_providers_provider_id_unique UNIQUE (provider_id);

ALTER TABLE ONLY public.user_roles
    ADD CONSTRAINT user_roles_user_id_role_pk PRIMARY KEY (user_id, role);

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_email_unique UNIQUE (email);

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.verifications
    ADD CONSTRAINT verifications_pkey PRIMARY KEY (id);

CREATE UNIQUE INDEX accounts_provider_account_idx ON public.accounts USING btree (provider_id, account_id);

CREATE INDEX agent_profiles_visibility_deleted_idx ON public.agent_profiles USING btree (visibility, deleted_at);

CREATE INDEX audit_events_actor_time_idx ON public.audit_events USING btree (actor_user_id, created_at DESC NULLS LAST, id DESC NULLS LAST);

CREATE INDEX audit_events_created_at_idx ON public.audit_events USING btree (created_at);

CREATE INDEX audit_events_target_time_idx ON public.audit_events USING btree (target_type, target_id, created_at DESC NULLS LAST, id DESC NULLS LAST);

CREATE INDEX audit_events_type_time_idx ON public.audit_events USING btree (event_type, created_at DESC NULLS LAST, id DESC NULLS LAST);

CREATE INDEX channels_recent_activity_idx ON public.channels USING btree (COALESCE(last_message_at, created_at) DESC);

CREATE UNIQUE INDEX intelligence_channel_mappings_thread_idx ON public.intelligence_channel_mappings USING btree (thread_id);

CREATE INDEX mcp_user_credentials_user_idx ON public.mcp_user_credentials USING btree (user_id);

CREATE INDEX plugin_grants_agent_idx ON public.plugin_grants USING btree (agent_id);

CREATE INDEX skills_owner_idx ON public.skills USING btree (owner_user_id);

CREATE UNIQUE INDEX skills_slug_key ON public.skills USING btree (slug);

CREATE TRIGGER audit_events_append_only BEFORE DELETE OR UPDATE ON public.audit_events FOR EACH ROW EXECUTE FUNCTION public.prevent_audit_event_mutation();

CREATE TRIGGER audit_events_no_truncate BEFORE TRUNCATE ON public.audit_events FOR EACH STATEMENT EXECUTE FUNCTION public.prevent_audit_event_mutation();

ALTER TABLE ONLY public.accounts
    ADD CONSTRAINT accounts_user_id_users_id_fk FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.agent_preferences
    ADD CONSTRAINT agent_preferences_agent_id_agents_id_fk FOREIGN KEY (agent_id) REFERENCES public.agents(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.agent_preferences
    ADD CONSTRAINT agent_preferences_user_id_users_id_fk FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.agent_profiles
    ADD CONSTRAINT agent_profiles_agent_id_agents_id_fk FOREIGN KEY (agent_id) REFERENCES public.agents(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.agent_profiles
    ADD CONSTRAINT agent_profiles_owner_user_id_users_id_fk FOREIGN KEY (owner_user_id) REFERENCES public.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY public.agents
    ADD CONSTRAINT agents_package_id_deployment_packages_id_fk FOREIGN KEY (package_id) REFERENCES public.deployment_packages(id) ON DELETE SET NULL;

ALTER TABLE ONLY public.channel_agents
    ADD CONSTRAINT channel_agents_agent_id_agents_id_fk FOREIGN KEY (agent_id) REFERENCES public.agents(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.channel_agents
    ADD CONSTRAINT channel_agents_channel_id_channels_id_fk FOREIGN KEY (channel_id) REFERENCES public.channels(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.channel_memberships
    ADD CONSTRAINT channel_memberships_channel_id_channels_id_fk FOREIGN KEY (channel_id) REFERENCES public.channels(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.channel_memberships
    ADD CONSTRAINT channel_memberships_user_id_users_id_fk FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.channels
    ADD CONSTRAINT channels_last_message_agent_id_agents_id_fk FOREIGN KEY (last_message_agent_id) REFERENCES public.agents(id) ON DELETE SET NULL;

ALTER TABLE ONLY public.channels
    ADD CONSTRAINT channels_package_id_deployment_packages_id_fk FOREIGN KEY (package_id) REFERENCES public.deployment_packages(id) ON DELETE SET NULL;

ALTER TABLE ONLY public.component_exclusions
    ADD CONSTRAINT component_exclusions_agent_id_agents_id_fk FOREIGN KEY (agent_id) REFERENCES public.agents(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.component_exclusions
    ADD CONSTRAINT component_exclusions_component_name_components_name_fk FOREIGN KEY (component_name) REFERENCES public.components(name) ON DELETE CASCADE;

ALTER TABLE ONLY public.component_functions
    ADD CONSTRAINT component_functions_component_name_components_name_fk FOREIGN KEY (component_name) REFERENCES public.components(name) ON DELETE CASCADE;

ALTER TABLE ONLY public.intelligence_channel_mappings
    ADD CONSTRAINT intelligence_channel_mappings_channel_id_channels_id_fk FOREIGN KEY (channel_id) REFERENCES public.channels(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.intelligence_channel_mappings
    ADD CONSTRAINT intelligence_channel_mappings_user_id_users_id_fk FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.mcp_servers
    ADD CONSTRAINT mcp_servers_credential_id_credentials_id_fk FOREIGN KEY (credential_id) REFERENCES public.credentials(id) ON DELETE RESTRICT;

ALTER TABLE ONLY public.mcp_tools
    ADD CONSTRAINT mcp_tools_server_id_mcp_servers_id_fk FOREIGN KEY (server_id) REFERENCES public.mcp_servers(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.mcp_user_credentials
    ADD CONSTRAINT mcp_user_credentials_credential_id_credentials_id_fk FOREIGN KEY (credential_id) REFERENCES public.credentials(id);

ALTER TABLE ONLY public.mcp_user_credentials
    ADD CONSTRAINT mcp_user_credentials_server_id_mcp_servers_id_fk FOREIGN KEY (server_id) REFERENCES public.mcp_servers(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.mcp_user_credentials
    ADD CONSTRAINT mcp_user_credentials_user_id_users_id_fk FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.plugin_grants
    ADD CONSTRAINT plugin_grants_agent_id_agents_id_fk FOREIGN KEY (agent_id) REFERENCES public.agents(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.sessions
    ADD CONSTRAINT sessions_user_id_users_id_fk FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.skills
    ADD CONSTRAINT skills_owner_user_id_users_id_fk FOREIGN KEY (owner_user_id) REFERENCES public.users(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.sso_providers
    ADD CONSTRAINT sso_providers_user_id_users_id_fk FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE SET NULL;

ALTER TABLE ONLY public.user_roles
    ADD CONSTRAINT user_roles_user_id_users_id_fk FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;

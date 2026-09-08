-- fixtures/db/seed-0012.sql —— read checksum 的对抗性种子（自动生成，勿手改）
-- 生成器：见交付报告；输入 = fixtures/db/schema-0012.json
-- 插入顺序 = 外键拓扑序，28 张表全覆盖。

-- action_policy（6 行）
INSERT INTO "action_policy" ("id", "mode", "deny", "allow", "updated_by", "updated_at") VALUES
  (E'action_policy_00', E'plain-ascii', E'{NULL,x}'::text[], E'{"含,逗号","含\\"引号","含 空格"}'::text[], E'مرحبا rtl', E'2026-08-22 07:30:45.123456-07'::timestamptz),
  (E'action_policy_01', E'中文测试文本', E'{}'::text[], E'{NULL,x}'::text[], NULL, E'2038-01-19 03:14:08+00'::timestamptz),
  (E'action_policy_02', E'emoji🙂🏽', E'{a,b,c}'::text[], E'{}'::text[], E'plain-ascii', E'2026-01-01 00:00:00+00'::timestamptz),
  (E'action_policy_03', E'é-combining', E'{"含,逗号","含\\"引号","含 空格"}'::text[], E'{a,b,c}'::text[], E'中文测试文本', E'1970-01-01 00:00:00.000001+00'::timestamptz),
  (E'action_policy_04', E'quote''single "double"', E'{NULL,x}'::text[], E'{"含,逗号","含\\"引号","含 空格"}'::text[], E'emoji🙂🏽', E'2026-08-22 07:30:45.123456-07'::timestamptz),
  (E'action_policy_05', E'back\\slash and \\\\double', E'{}'::text[], E'{NULL,x}'::text[], E'é-combining', E'2038-01-19 03:14:08+00'::timestamptz);

-- audit_events（6 行）
INSERT INTO "audit_events" ("id", "actor_user_id", "event_type", "target_type", "target_id", "payload", "created_at") VALUES
  (E'00000000-0000-0000-0000-000000000000'::uuid, E'back\\slash and \\\\double', E'', E'back\\slash and \\\\double', E'plain-ascii', E'{}'::jsonb, E'2038-01-19 03:14:08+00'::timestamptz),
  (E'ffffffff-ffff-ffff-ffff-ffffffffffff'::uuid, NULL, E'plain-ascii', E'line1\nline2\ttabbed', NULL, E'{"empty_str": "", "false": false, "nested_arr": [[], [null]]}'::jsonb, E'2026-01-01 00:00:00+00'::timestamptz),
  (E'018f3c6e-0000-7000-8000-000000000001'::uuid, E'مرحبا rtl', E'中文测试文本', E'مرحبا rtl', E'emoji🙂🏽', E'{"b": 1, "a": 2, "c": {"z": null, "y": [1, 2]}}'::jsonb, E'1970-01-01 00:00:00.000001+00'::timestamptz),
  (E'9c5b94b1-35ad-49bb-b118-8e8fc24abf80'::uuid, E'', E'emoji🙂🏽', E'', E'é-combining', E'{"中文键": "值", "n": 1.5, "big": 9007199254740993}'::jsonb, E'2026-08-22 07:30:45.123456-07'::timestamptz),
  (E'018f3c6e-0000-7000-8000-001974584420'::uuid, E'plain-ascii', E'é-combining', E'plain-ascii', E'quote''single "double"', E'[]'::jsonb, E'2038-01-19 03:14:08+00'::timestamptz),
  (E'018f3c6e-0000-7000-8000-001974584421'::uuid, E'中文测试文本', E'quote''single "double"', E'中文测试文本', E'back\\slash and \\\\double', E'{}'::jsonb, E'2026-01-01 00:00:00+00'::timestamptz);

-- components（6 行）
INSERT INTO "components" ("name", "title", "kind", "draft_description", "published_description", "published", "published_at", "updated_by", "created_at", "updated_at") VALUES
  (E'components_00', E'plain-ascii', E'quote''single "double"', E'مرحبا rtl', E'emoji🙂🏽', false, E'2026-01-01 00:00:00+00'::timestamptz, E'', E'2026-08-22 07:30:45.123456-07'::timestamptz, E'2038-01-19 03:14:08+00'::timestamptz),
  (E'components_01', E'中文测试文本', E'back\\slash and \\\\double', E'', NULL, true, NULL, NULL, E'2038-01-19 03:14:08+00'::timestamptz, E'2026-01-01 00:00:00+00'::timestamptz),
  (E'components_02', E'emoji🙂🏽', E'line1\nline2\ttabbed', E'plain-ascii', E'quote''single "double"', false, E'2026-08-22 07:30:45.123456-07'::timestamptz, E'中文测试文本', E'2026-01-01 00:00:00+00'::timestamptz, E'1970-01-01 00:00:00.000001+00'::timestamptz),
  (E'components_03', E'é-combining', E'مرحبا rtl', E'中文测试文本', E'back\\slash and \\\\double', true, E'2038-01-19 03:14:08+00'::timestamptz, E'emoji🙂🏽', E'1970-01-01 00:00:00.000001+00'::timestamptz, E'2026-08-22 07:30:45.123456-07'::timestamptz),
  (E'components_04', E'quote''single "double"', E'', E'emoji🙂🏽', E'line1\nline2\ttabbed', false, E'2026-01-01 00:00:00+00'::timestamptz, E'é-combining', E'2026-08-22 07:30:45.123456-07'::timestamptz, E'2038-01-19 03:14:08+00'::timestamptz),
  (E'components_05', E'back\\slash and \\\\double', E'plain-ascii', E'é-combining', E'مرحبا rtl', true, E'1970-01-01 00:00:00.000001+00'::timestamptz, E'quote''single "double"', E'2038-01-19 03:14:08+00'::timestamptz, E'2026-01-01 00:00:00+00'::timestamptz);

-- computer_snapshot（6 行）
INSERT INTO "computer_snapshot" ("computer_id", "snapshot_id", "url", "elements", "taken_at") VALUES
  (E'computer_snapshot_00', 0, E'emoji🙂🏽', E'{"b": 1, "a": 2, "c": {"z": null, "y": [1, 2]}}'::jsonb, E'1970-01-01 00:00:00.000001+00'::timestamptz),
  (E'computer_snapshot_01', -1, E'é-combining', E'{"中文键": "值", "n": 1.5, "big": 9007199254740993}'::jsonb, E'2026-08-22 07:30:45.123456-07'::timestamptz),
  (E'computer_snapshot_02', 2147483647, E'quote''single "double"', E'[]'::jsonb, E'2038-01-19 03:14:08+00'::timestamptz),
  (E'computer_snapshot_03', 42, E'back\\slash and \\\\double', E'{}'::jsonb, E'2026-01-01 00:00:00+00'::timestamptz),
  (E'computer_snapshot_04', 0, E'line1\nline2\ttabbed', E'{"empty_str": "", "false": false, "nested_arr": [[], [null]]}'::jsonb, E'1970-01-01 00:00:00.000001+00'::timestamptz),
  (E'computer_snapshot_05', -1, E'مرحبا rtl', E'{"b": 1, "a": 2, "c": {"z": null, "y": [1, 2]}}'::jsonb, E'2026-08-22 07:30:45.123456-07'::timestamptz);

-- credentials（6 行）
INSERT INTO "credentials" ("id", "kind", "provider", "encrypted_value", "key_id", "metadata", "revoked_at", "created_at", "updated_at") VALUES
  (E'00000000-0000-0000-0000-000000000000'::uuid, E'agent'::credential_kind, E'emoji🙂🏽', E'', E'quote''single "double"', E'{"中文键": "值", "n": 1.5, "big": 9007199254740993}'::jsonb, E'2026-08-22 07:30:45.123456-07'::timestamptz, E'2026-01-01 00:00:00+00'::timestamptz, E'1970-01-01 00:00:00.000001+00'::timestamptz),
  (E'ffffffff-ffff-ffff-ffff-ffffffffffff'::uuid, E'mcp'::credential_kind, E'é-combining', E'plain-ascii', E'back\\slash and \\\\double', E'[]'::jsonb, NULL, E'1970-01-01 00:00:00.000001+00'::timestamptz, E'2026-08-22 07:30:45.123456-07'::timestamptz),
  (E'018f3c6e-0000-7000-8000-000000000001'::uuid, E'mcp_oauth_client'::credential_kind, E'quote''single "double"', E'中文测试文本', E'line1\nline2\ttabbed', E'{}'::jsonb, E'2026-01-01 00:00:00+00'::timestamptz, E'2026-08-22 07:30:45.123456-07'::timestamptz, E'2038-01-19 03:14:08+00'::timestamptz),
  (E'9c5b94b1-35ad-49bb-b118-8e8fc24abf80'::uuid, E'mcp_user_token'::credential_kind, E'back\\slash and \\\\double', E'emoji🙂🏽', E'مرحبا rtl', E'{"empty_str": "", "false": false, "nested_arr": [[], [null]]}'::jsonb, E'1970-01-01 00:00:00.000001+00'::timestamptz, E'2038-01-19 03:14:08+00'::timestamptz, E'2026-01-01 00:00:00+00'::timestamptz),
  (E'018f3c6e-0000-7000-8000-003144868433'::uuid, E'model'::credential_kind, E'line1\nline2\ttabbed', E'é-combining', E'', E'{"b": 1, "a": 2, "c": {"z": null, "y": [1, 2]}}'::jsonb, E'2026-08-22 07:30:45.123456-07'::timestamptz, E'2026-01-01 00:00:00+00'::timestamptz, E'1970-01-01 00:00:00.000001+00'::timestamptz),
  (E'018f3c6e-0000-7000-8000-003144868434'::uuid, E'connector'::credential_kind, E'مرحبا rtl', E'quote''single "double"', E'plain-ascii', E'{"中文键": "值", "n": 1.5, "big": 9007199254740993}'::jsonb, E'2038-01-19 03:14:08+00'::timestamptz, E'1970-01-01 00:00:00.000001+00'::timestamptz, E'2026-08-22 07:30:45.123456-07'::timestamptz);

-- deployment_packages（6 行）
INSERT INTO "deployment_packages" ("id", "tenant_id", "source_path", "checksum", "loaded_at") VALUES
  (E'00000000-0000-0000-0000-000000000000'::uuid, E'back\\slash and \\\\double', E'é-combining', E'', E'2026-08-22 07:30:45.123456-07'::timestamptz),
  (E'ffffffff-ffff-ffff-ffff-ffffffffffff'::uuid, E'line1\nline2\ttabbed', E'quote''single "double"', E'plain-ascii', E'2038-01-19 03:14:08+00'::timestamptz),
  (E'018f3c6e-0000-7000-8000-000000000001'::uuid, E'مرحبا rtl', E'back\\slash and \\\\double', E'中文测试文本', E'2026-01-01 00:00:00+00'::timestamptz),
  (E'9c5b94b1-35ad-49bb-b118-8e8fc24abf80'::uuid, E'', E'line1\nline2\ttabbed', E'emoji🙂🏽', E'1970-01-01 00:00:00.000001+00'::timestamptz),
  (E'018f3c6e-0000-7000-8000-001433671414'::uuid, E'plain-ascii', E'مرحبا rtl', E'é-combining', E'2026-08-22 07:30:45.123456-07'::timestamptz),
  (E'018f3c6e-0000-7000-8000-001433671415'::uuid, E'中文测试文本', E'', E'quote''single "double"', E'2038-01-19 03:14:08+00'::timestamptz);

-- mcp_servers（6 行）
INSERT INTO "mcp_servers" ("id", "title", "vendor", "url", "provenance", "credential_id", "tools_refreshed_at", "last_error", "added_by", "created_at", "updated_at") VALUES
  (E'mcp_servers_00', E'back\\slash and \\\\double', E'é-combining', E'line1\nline2\ttabbed', E'plain-ascii', E'00000000-0000-0000-0000-000000000000'::uuid, E'2038-01-19 03:14:08+00'::timestamptz, E'quote''single "double"', E'back\\slash and \\\\double', E'1970-01-01 00:00:00.000001+00'::timestamptz, E'2026-08-22 07:30:45.123456-07'::timestamptz),
  (E'mcp_servers_01', E'line1\nline2\ttabbed', E'quote''single "double"', E'مرحبا rtl', E'中文测试文本', E'ffffffff-ffff-ffff-ffff-ffffffffffff'::uuid, NULL, NULL, NULL, E'2026-08-22 07:30:45.123456-07'::timestamptz, E'2038-01-19 03:14:08+00'::timestamptz),
  (E'mcp_servers_02', E'مرحبا rtl', E'back\\slash and \\\\double', E'', E'emoji🙂🏽', E'018f3c6e-0000-7000-8000-000000000001'::uuid, E'1970-01-01 00:00:00.000001+00'::timestamptz, E'line1\nline2\ttabbed', E'مرحبا rtl', E'2038-01-19 03:14:08+00'::timestamptz, E'2026-01-01 00:00:00+00'::timestamptz),
  (E'mcp_servers_03', E'', E'line1\nline2\ttabbed', E'plain-ascii', E'é-combining', E'9c5b94b1-35ad-49bb-b118-8e8fc24abf80'::uuid, E'2026-08-22 07:30:45.123456-07'::timestamptz, E'مرحبا rtl', E'', E'2026-01-01 00:00:00+00'::timestamptz, E'1970-01-01 00:00:00.000001+00'::timestamptz),
  (E'mcp_servers_04', E'plain-ascii', E'مرحبا rtl', E'中文测试文本', E'quote''single "double"', E'018f3c6e-0000-7000-8000-003144868433'::uuid, E'2038-01-19 03:14:08+00'::timestamptz, E'', E'plain-ascii', E'1970-01-01 00:00:00.000001+00'::timestamptz, E'2026-08-22 07:30:45.123456-07'::timestamptz),
  (E'mcp_servers_05', E'中文测试文本', E'', E'emoji🙂🏽', E'back\\slash and \\\\double', E'018f3c6e-0000-7000-8000-003144868434'::uuid, E'2026-01-01 00:00:00+00'::timestamptz, E'plain-ascii', E'中文测试文本', E'2026-08-22 07:30:45.123456-07'::timestamptz, E'2038-01-19 03:14:08+00'::timestamptz);

-- mcp_tools（6 行）
INSERT INTO "mcp_tools" ("server_id", "name", "description", "input_schema", "created_at") VALUES
  (E'mcp_servers_00', E'mcp_tools_00', E'مرحبا rtl', E'{"empty_str": "", "false": false, "nested_arr": [[], [null]]}'::jsonb, E'2026-08-22 07:30:45.123456-07'::timestamptz),
  (E'mcp_servers_01', E'mcp_tools_01', E'', E'{"b": 1, "a": 2, "c": {"z": null, "y": [1, 2]}}'::jsonb, E'2038-01-19 03:14:08+00'::timestamptz),
  (E'mcp_servers_02', E'mcp_tools_02', E'plain-ascii', E'{"中文键": "值", "n": 1.5, "big": 9007199254740993}'::jsonb, E'2026-01-01 00:00:00+00'::timestamptz),
  (E'mcp_servers_03', E'mcp_tools_03', E'中文测试文本', E'[]'::jsonb, E'1970-01-01 00:00:00.000001+00'::timestamptz),
  (E'mcp_servers_04', E'mcp_tools_04', E'emoji🙂🏽', E'{}'::jsonb, E'2026-08-22 07:30:45.123456-07'::timestamptz),
  (E'mcp_servers_05', E'mcp_tools_05', E'é-combining', E'{"empty_str": "", "false": false, "nested_arr": [[], [null]]}'::jsonb, E'2038-01-19 03:14:08+00'::timestamptz);

-- revoked_access（6 行）
INSERT INTO "revoked_access" ("email", "revoked_at", "revoked_by") VALUES
  (E'revoked_access_00', E'1970-01-01 00:00:00.000001+00'::timestamptz, E'quote''single "double"'),
  (E'revoked_access_01', E'2026-08-22 07:30:45.123456-07'::timestamptz, E'back\\slash and \\\\double'),
  (E'revoked_access_02', E'2038-01-19 03:14:08+00'::timestamptz, E'line1\nline2\ttabbed'),
  (E'revoked_access_03', E'2026-01-01 00:00:00+00'::timestamptz, E'مرحبا rtl'),
  (E'revoked_access_04', E'1970-01-01 00:00:00.000001+00'::timestamptz, E''),
  (E'revoked_access_05', E'2026-08-22 07:30:45.123456-07'::timestamptz, E'plain-ascii');

-- sandboxed_components（6 行）
INSERT INTO "sandboxed_components" ("name", "title", "draft_description", "draft_html", "draft_css", "draft_js_functions", "draft_argument_schema", "published_description", "published_html", "published_css", "published_js_functions", "published_argument_schema", "sample_arguments", "revision", "published", "published_at", "authored_by", "created_at", "updated_at") VALUES
  (E'sandboxed_components_00', E'quote''single "double"', E'', E'', E'é-combining', E'مرحبا rtl', E'{"b": 1, "a": 2, "c": {"z": null, "y": [1, 2]}}'::jsonb, E'plain-ascii', E'', E'quote''single "double"', E'مرحبا rtl', E'{}'::jsonb, E'{}'::jsonb, 2147483647, true, E'2038-01-19 03:14:08+00'::timestamptz, E'back\\slash and \\\\double', E'1970-01-01 00:00:00.000001+00'::timestamptz, E'2026-08-22 07:30:45.123456-07'::timestamptz),
  (E'sandboxed_components_01', E'back\\slash and \\\\double', E'plain-ascii', E'plain-ascii', E'quote''single "double"', E'', E'{"中文键": "值", "n": 1.5, "big": 9007199254740993}'::jsonb, NULL, NULL, NULL, NULL, NULL, E'{"empty_str": "", "false": false, "nested_arr": [[], [null]]}'::jsonb, 42, false, NULL, NULL, E'2026-08-22 07:30:45.123456-07'::timestamptz, E'2038-01-19 03:14:08+00'::timestamptz),
  (E'sandboxed_components_02', E'line1\nline2\ttabbed', E'中文测试文本', E'中文测试文本', E'back\\slash and \\\\double', E'plain-ascii', E'[]'::jsonb, E'emoji🙂🏽', E'中文测试文本', E'line1\nline2\ttabbed', E'plain-ascii', E'{"b": 1, "a": 2, "c": {"z": null, "y": [1, 2]}}'::jsonb, E'{"b": 1, "a": 2, "c": {"z": null, "y": [1, 2]}}'::jsonb, 0, true, E'1970-01-01 00:00:00.000001+00'::timestamptz, E'مرحبا rtl', E'2038-01-19 03:14:08+00'::timestamptz, E'2026-01-01 00:00:00+00'::timestamptz),
  (E'sandboxed_components_03', E'مرحبا rtl', E'emoji🙂🏽', E'emoji🙂🏽', E'line1\nline2\ttabbed', E'中文测试文本', E'{}'::jsonb, E'é-combining', E'emoji🙂🏽', E'مرحبا rtl', E'中文测试文本', E'{"中文键": "值", "n": 1.5, "big": 9007199254740993}'::jsonb, E'{"中文键": "值", "n": 1.5, "big": 9007199254740993}'::jsonb, -1, false, E'2026-08-22 07:30:45.123456-07'::timestamptz, E'', E'2026-01-01 00:00:00+00'::timestamptz, E'1970-01-01 00:00:00.000001+00'::timestamptz),
  (E'sandboxed_components_04', E'', E'é-combining', E'é-combining', E'مرحبا rtl', E'emoji🙂🏽', E'{"empty_str": "", "false": false, "nested_arr": [[], [null]]}'::jsonb, E'quote''single "double"', E'é-combining', E'', E'emoji🙂🏽', E'[]'::jsonb, E'[]'::jsonb, 2147483647, true, E'2038-01-19 03:14:08+00'::timestamptz, E'plain-ascii', E'1970-01-01 00:00:00.000001+00'::timestamptz, E'2026-08-22 07:30:45.123456-07'::timestamptz),
  (E'sandboxed_components_05', E'plain-ascii', E'quote''single "double"', E'quote''single "double"', E'', E'é-combining', E'{"b": 1, "a": 2, "c": {"z": null, "y": [1, 2]}}'::jsonb, E'back\\slash and \\\\double', E'quote''single "double"', E'plain-ascii', E'é-combining', E'{}'::jsonb, E'{}'::jsonb, 42, false, E'2026-01-01 00:00:00+00'::timestamptz, E'中文测试文本', E'2026-08-22 07:30:45.123456-07'::timestamptz, E'2038-01-19 03:14:08+00'::timestamptz);

-- users（6 行）
INSERT INTO "users" ("id", "email", "name", "image", "email_verified", "groups", "created_at", "updated_at") VALUES
  (E'users_00', E'emoji🙂🏽', E'emoji🙂🏽', E'中文测试文本', true, E'{"含,逗号","含\\"引号","含 空格"}'::text[], E'2026-01-01 00:00:00+00'::timestamptz, E'1970-01-01 00:00:00.000001+00'::timestamptz),
  (E'users_01', E'é-combining', NULL, NULL, false, E'{NULL,x}'::text[], E'1970-01-01 00:00:00.000001+00'::timestamptz, E'2026-08-22 07:30:45.123456-07'::timestamptz),
  (E'users_02', E'quote''single "double"', E'quote''single "double"', E'é-combining', true, E'{}'::text[], E'2026-08-22 07:30:45.123456-07'::timestamptz, E'2038-01-19 03:14:08+00'::timestamptz),
  (E'users_03', E'back\\slash and \\\\double', E'back\\slash and \\\\double', E'quote''single "double"', false, E'{a,b,c}'::text[], E'2038-01-19 03:14:08+00'::timestamptz, E'2026-01-01 00:00:00+00'::timestamptz),
  (E'users_04', E'line1\nline2\ttabbed', E'line1\nline2\ttabbed', E'back\\slash and \\\\double', true, E'{"含,逗号","含\\"引号","含 空格"}'::text[], E'2026-01-01 00:00:00+00'::timestamptz, E'1970-01-01 00:00:00.000001+00'::timestamptz),
  (E'users_05', E'مرحبا rtl', E'مرحبا rtl', E'line1\nline2\ttabbed', false, E'{NULL,x}'::text[], E'1970-01-01 00:00:00.000001+00'::timestamptz, E'2026-08-22 07:30:45.123456-07'::timestamptz);

-- verifications（6 行）
INSERT INTO "verifications" ("id", "identifier", "value", "expires_at", "created_at", "updated_at") VALUES
  (E'verifications_00', E'é-combining', E'line1\nline2\ttabbed', E'2026-01-01 00:00:00+00'::timestamptz, E'2026-01-01 00:00:00+00'::timestamptz, E'1970-01-01 00:00:00.000001+00'::timestamptz),
  (E'verifications_01', E'quote''single "double"', E'مرحبا rtl', E'1970-01-01 00:00:00.000001+00'::timestamptz, E'1970-01-01 00:00:00.000001+00'::timestamptz, E'2026-08-22 07:30:45.123456-07'::timestamptz),
  (E'verifications_02', E'back\\slash and \\\\double', E'', E'2026-08-22 07:30:45.123456-07'::timestamptz, E'2026-08-22 07:30:45.123456-07'::timestamptz, E'2038-01-19 03:14:08+00'::timestamptz),
  (E'verifications_03', E'line1\nline2\ttabbed', E'plain-ascii', E'2038-01-19 03:14:08+00'::timestamptz, E'2038-01-19 03:14:08+00'::timestamptz, E'2026-01-01 00:00:00+00'::timestamptz),
  (E'verifications_04', E'مرحبا rtl', E'中文测试文本', E'2026-01-01 00:00:00+00'::timestamptz, E'2026-01-01 00:00:00+00'::timestamptz, E'1970-01-01 00:00:00.000001+00'::timestamptz),
  (E'verifications_05', E'', E'emoji🙂🏽', E'1970-01-01 00:00:00.000001+00'::timestamptz, E'1970-01-01 00:00:00.000001+00'::timestamptz, E'2026-08-22 07:30:45.123456-07'::timestamptz);

-- accounts（6 行）
INSERT INTO "accounts" ("id", "account_id", "provider_id", "user_id", "access_token", "refresh_token", "id_token", "access_token_expires_at", "refresh_token_expires_at", "scope", "password", "created_at", "updated_at", "issuer") VALUES
  (E'accounts_00', E'é-combining', E'line1\nline2\ttabbed', E'users_00', E'中文测试文本', E'quote''single "double"', E'中文测试文本', E'2038-01-19 03:14:08+00'::timestamptz, E'2026-01-01 00:00:00+00'::timestamptz, E'quote''single "double"', E'plain-ascii', E'2026-08-22 07:30:45.123456-07'::timestamptz, E'2038-01-19 03:14:08+00'::timestamptz, E'مرحبا rtl'),
  (E'accounts_01', E'quote''single "double"', E'مرحبا rtl', E'users_01', NULL, NULL, NULL, NULL, NULL, NULL, NULL, E'2038-01-19 03:14:08+00'::timestamptz, E'2026-01-01 00:00:00+00'::timestamptz, NULL),
  (E'accounts_02', E'back\\slash and \\\\double', E'', E'users_02', E'é-combining', E'line1\nline2\ttabbed', E'é-combining', E'1970-01-01 00:00:00.000001+00'::timestamptz, E'2026-08-22 07:30:45.123456-07'::timestamptz, E'line1\nline2\ttabbed', E'emoji🙂🏽', E'2026-01-01 00:00:00+00'::timestamptz, E'1970-01-01 00:00:00.000001+00'::timestamptz, E'plain-ascii'),
  (E'accounts_03', E'line1\nline2\ttabbed', E'plain-ascii', E'users_03', E'quote''single "double"', E'مرحبا rtl', E'quote''single "double"', E'2026-08-22 07:30:45.123456-07'::timestamptz, E'2038-01-19 03:14:08+00'::timestamptz, E'مرحبا rtl', E'é-combining', E'1970-01-01 00:00:00.000001+00'::timestamptz, E'2026-08-22 07:30:45.123456-07'::timestamptz, E'中文测试文本'),
  (E'accounts_04', E'مرحبا rtl', E'中文测试文本', E'users_04', E'back\\slash and \\\\double', E'', E'back\\slash and \\\\double', E'2038-01-19 03:14:08+00'::timestamptz, E'2026-01-01 00:00:00+00'::timestamptz, E'', E'quote''single "double"', E'2026-08-22 07:30:45.123456-07'::timestamptz, E'2038-01-19 03:14:08+00'::timestamptz, E'emoji🙂🏽'),
  (E'accounts_05', E'', E'emoji🙂🏽', E'users_05', E'line1\nline2\ttabbed', E'plain-ascii', E'line1\nline2\ttabbed', E'2026-01-01 00:00:00+00'::timestamptz, E'1970-01-01 00:00:00.000001+00'::timestamptz, E'plain-ascii', E'back\\slash and \\\\double', E'2038-01-19 03:14:08+00'::timestamptz, E'2026-01-01 00:00:00+00'::timestamptz, E'é-combining');

-- agents（6 行）
INSERT INTO "agents" ("id", "name", "type", "configuration", "package_id", "override", "created_at", "updated_at") VALUES
  (E'agents_00', E'quote''single "double"', E'built_in'::agent_type, E'{"中文键": "值", "n": 1.5, "big": 9007199254740993}'::jsonb, E'00000000-0000-0000-0000-000000000000'::uuid, E'[]'::jsonb, E'2026-08-22 07:30:45.123456-07'::timestamptz, E'2038-01-19 03:14:08+00'::timestamptz),
  (E'agents_01', E'back\\slash and \\\\double', E'remote_ag_ui'::agent_type, E'[]'::jsonb, E'ffffffff-ffff-ffff-ffff-ffffffffffff'::uuid, NULL, E'2038-01-19 03:14:08+00'::timestamptz, E'2026-01-01 00:00:00+00'::timestamptz),
  (E'agents_02', E'line1\nline2\ttabbed', E'built_in'::agent_type, E'{}'::jsonb, E'018f3c6e-0000-7000-8000-000000000001'::uuid, E'{"empty_str": "", "false": false, "nested_arr": [[], [null]]}'::jsonb, E'2026-01-01 00:00:00+00'::timestamptz, E'1970-01-01 00:00:00.000001+00'::timestamptz),
  (E'agents_03', E'مرحبا rtl', E'remote_ag_ui'::agent_type, E'{"empty_str": "", "false": false, "nested_arr": [[], [null]]}'::jsonb, E'9c5b94b1-35ad-49bb-b118-8e8fc24abf80'::uuid, E'{"b": 1, "a": 2, "c": {"z": null, "y": [1, 2]}}'::jsonb, E'1970-01-01 00:00:00.000001+00'::timestamptz, E'2026-08-22 07:30:45.123456-07'::timestamptz),
  (E'agents_04', E'', E'built_in'::agent_type, E'{"b": 1, "a": 2, "c": {"z": null, "y": [1, 2]}}'::jsonb, E'018f3c6e-0000-7000-8000-001433671414'::uuid, E'{"中文键": "值", "n": 1.5, "big": 9007199254740993}'::jsonb, E'2026-08-22 07:30:45.123456-07'::timestamptz, E'2038-01-19 03:14:08+00'::timestamptz),
  (E'agents_05', E'plain-ascii', E'remote_ag_ui'::agent_type, E'{"中文键": "值", "n": 1.5, "big": 9007199254740993}'::jsonb, E'018f3c6e-0000-7000-8000-001433671415'::uuid, E'[]'::jsonb, E'2038-01-19 03:14:08+00'::timestamptz, E'2026-01-01 00:00:00+00'::timestamptz);

-- channels（6 行）
INSERT INTO "channels" ("id", "name", "description", "suggested_prompts", "allowed_groups", "package_id", "override", "last_message", "last_message_at", "last_message_agent_id", "created_at", "updated_at") VALUES
  (E'channels_00', E'مرحبا rtl', E'é-combining', E'{a,b,c}'::text[], E'{a,b,c}'::text[], E'00000000-0000-0000-0000-000000000000'::uuid, E'{"empty_str": "", "false": false, "nested_arr": [[], [null]]}'::jsonb, E'line1\nline2\ttabbed', E'2026-08-22 07:30:45.123456-07'::timestamptz, E'agents_00', E'2026-01-01 00:00:00+00'::timestamptz, E'1970-01-01 00:00:00.000001+00'::timestamptz),
  (E'channels_01', E'', E'quote''single "double"', E'{"含,逗号","含\\"引号","含 空格"}'::text[], E'{"含,逗号","含\\"引号","含 空格"}'::text[], E'ffffffff-ffff-ffff-ffff-ffffffffffff'::uuid, NULL, NULL, NULL, E'agents_01', E'1970-01-01 00:00:00.000001+00'::timestamptz, E'2026-08-22 07:30:45.123456-07'::timestamptz),
  (E'channels_02', E'plain-ascii', E'back\\slash and \\\\double', E'{NULL,x}'::text[], E'{NULL,x}'::text[], E'018f3c6e-0000-7000-8000-000000000001'::uuid, E'{"中文键": "值", "n": 1.5, "big": 9007199254740993}'::jsonb, E'', E'2026-01-01 00:00:00+00'::timestamptz, E'agents_02', E'2026-08-22 07:30:45.123456-07'::timestamptz, E'2038-01-19 03:14:08+00'::timestamptz),
  (E'channels_03', E'中文测试文本', E'line1\nline2\ttabbed', E'{}'::text[], E'{}'::text[], E'9c5b94b1-35ad-49bb-b118-8e8fc24abf80'::uuid, E'[]'::jsonb, E'plain-ascii', E'1970-01-01 00:00:00.000001+00'::timestamptz, E'agents_03', E'2038-01-19 03:14:08+00'::timestamptz, E'2026-01-01 00:00:00+00'::timestamptz),
  (E'channels_04', E'emoji🙂🏽', E'مرحبا rtl', E'{a,b,c}'::text[], E'{a,b,c}'::text[], E'018f3c6e-0000-7000-8000-001433671414'::uuid, E'{}'::jsonb, E'中文测试文本', E'2026-08-22 07:30:45.123456-07'::timestamptz, E'agents_04', E'2026-01-01 00:00:00+00'::timestamptz, E'1970-01-01 00:00:00.000001+00'::timestamptz),
  (E'channels_05', E'é-combining', E'', E'{"含,逗号","含\\"引号","含 空格"}'::text[], E'{"含,逗号","含\\"引号","含 空格"}'::text[], E'018f3c6e-0000-7000-8000-001433671415'::uuid, E'{"empty_str": "", "false": false, "nested_arr": [[], [null]]}'::jsonb, E'emoji🙂🏽', E'2038-01-19 03:14:08+00'::timestamptz, E'agents_05', E'1970-01-01 00:00:00.000001+00'::timestamptz, E'2026-08-22 07:30:45.123456-07'::timestamptz);

-- component_exclusions（6 行）
INSERT INTO "component_exclusions" ("component_name", "agent_id", "withheld_by", "created_at", "updated_at") VALUES
  (E'components_00', E'agents_00', E'é-combining', E'1970-01-01 00:00:00.000001+00'::timestamptz, E'2026-08-22 07:30:45.123456-07'::timestamptz),
  (E'components_01', E'agents_01', NULL, E'2026-08-22 07:30:45.123456-07'::timestamptz, E'2038-01-19 03:14:08+00'::timestamptz),
  (E'components_02', E'agents_02', E'back\\slash and \\\\double', E'2038-01-19 03:14:08+00'::timestamptz, E'2026-01-01 00:00:00+00'::timestamptz),
  (E'components_03', E'agents_03', E'line1\nline2\ttabbed', E'2026-01-01 00:00:00+00'::timestamptz, E'1970-01-01 00:00:00.000001+00'::timestamptz),
  (E'components_04', E'agents_04', E'مرحبا rtl', E'1970-01-01 00:00:00.000001+00'::timestamptz, E'2026-08-22 07:30:45.123456-07'::timestamptz),
  (E'components_05', E'agents_05', E'', E'2026-08-22 07:30:45.123456-07'::timestamptz, E'2038-01-19 03:14:08+00'::timestamptz);

-- component_functions（6 行）
INSERT INTO "component_functions" ("component_name", "function_name", "granted_by", "created_at", "updated_at") VALUES
  (E'components_00', E'component_functions_00', E'emoji🙂🏽', E'2038-01-19 03:14:08+00'::timestamptz, E'2026-01-01 00:00:00+00'::timestamptz),
  (E'components_01', E'component_functions_01', NULL, E'2026-01-01 00:00:00+00'::timestamptz, E'1970-01-01 00:00:00.000001+00'::timestamptz),
  (E'components_02', E'component_functions_02', E'quote''single "double"', E'1970-01-01 00:00:00.000001+00'::timestamptz, E'2026-08-22 07:30:45.123456-07'::timestamptz),
  (E'components_03', E'component_functions_03', E'back\\slash and \\\\double', E'2026-08-22 07:30:45.123456-07'::timestamptz, E'2038-01-19 03:14:08+00'::timestamptz),
  (E'components_04', E'component_functions_04', E'line1\nline2\ttabbed', E'2038-01-19 03:14:08+00'::timestamptz, E'2026-01-01 00:00:00+00'::timestamptz),
  (E'components_05', E'component_functions_05', E'مرحبا rtl', E'2026-01-01 00:00:00+00'::timestamptz, E'1970-01-01 00:00:00.000001+00'::timestamptz);

-- intelligence_channel_mappings（6 行）
INSERT INTO "intelligence_channel_mappings" ("user_id", "channel_id", "thread_id", "created_at", "updated_at") VALUES
  (E'users_00', E'channels_00', E'emoji🙂🏽', E'2038-01-19 03:14:08+00'::timestamptz, E'2026-01-01 00:00:00+00'::timestamptz),
  (E'users_01', E'channels_01', E'é-combining', E'2026-01-01 00:00:00+00'::timestamptz, E'1970-01-01 00:00:00.000001+00'::timestamptz),
  (E'users_02', E'channels_02', E'quote''single "double"', E'1970-01-01 00:00:00.000001+00'::timestamptz, E'2026-08-22 07:30:45.123456-07'::timestamptz),
  (E'users_03', E'channels_03', E'back\\slash and \\\\double', E'2026-08-22 07:30:45.123456-07'::timestamptz, E'2038-01-19 03:14:08+00'::timestamptz),
  (E'users_04', E'channels_04', E'line1\nline2\ttabbed', E'2038-01-19 03:14:08+00'::timestamptz, E'2026-01-01 00:00:00+00'::timestamptz),
  (E'users_05', E'channels_05', E'مرحبا rtl', E'2026-01-01 00:00:00+00'::timestamptz, E'1970-01-01 00:00:00.000001+00'::timestamptz);

-- mcp_user_credentials（6 行）
INSERT INTO "mcp_user_credentials" ("server_id", "user_id", "credential_id", "scope", "connected_at", "updated_at") VALUES
  (E'mcp_servers_00', E'users_00', E'00000000-0000-0000-0000-000000000000'::uuid, E'line1\nline2\ttabbed', E'2026-08-22 07:30:45.123456-07'::timestamptz, E'2026-01-01 00:00:00+00'::timestamptz),
  (E'mcp_servers_01', E'users_01', E'ffffffff-ffff-ffff-ffff-ffffffffffff'::uuid, E'مرحبا rtl', E'2038-01-19 03:14:08+00'::timestamptz, E'1970-01-01 00:00:00.000001+00'::timestamptz),
  (E'mcp_servers_02', E'users_02', E'018f3c6e-0000-7000-8000-000000000001'::uuid, E'', E'2026-01-01 00:00:00+00'::timestamptz, E'2026-08-22 07:30:45.123456-07'::timestamptz),
  (E'mcp_servers_03', E'users_03', E'9c5b94b1-35ad-49bb-b118-8e8fc24abf80'::uuid, E'plain-ascii', E'1970-01-01 00:00:00.000001+00'::timestamptz, E'2038-01-19 03:14:08+00'::timestamptz),
  (E'mcp_servers_04', E'users_04', E'018f3c6e-0000-7000-8000-003144868433'::uuid, E'中文测试文本', E'2026-08-22 07:30:45.123456-07'::timestamptz, E'2026-01-01 00:00:00+00'::timestamptz),
  (E'mcp_servers_05', E'users_05', E'018f3c6e-0000-7000-8000-003144868434'::uuid, E'emoji🙂🏽', E'2038-01-19 03:14:08+00'::timestamptz, E'1970-01-01 00:00:00.000001+00'::timestamptz);

-- plugin_grants（6 行）
INSERT INTO "plugin_grants" ("kind", "ref", "agent_id", "granted_by", "created_at", "updated_at") VALUES
  (E'plugin_grants_00', E'plugin_grants_00', E'agents_00', E'back\\slash and \\\\double', E'1970-01-01 00:00:00.000001+00'::timestamptz, E'2026-08-22 07:30:45.123456-07'::timestamptz),
  (E'plugin_grants_01', E'plugin_grants_01', E'agents_01', NULL, E'2026-08-22 07:30:45.123456-07'::timestamptz, E'2038-01-19 03:14:08+00'::timestamptz),
  (E'plugin_grants_02', E'plugin_grants_02', E'agents_02', E'مرحبا rtl', E'2038-01-19 03:14:08+00'::timestamptz, E'2026-01-01 00:00:00+00'::timestamptz),
  (E'plugin_grants_03', E'plugin_grants_03', E'agents_03', E'', E'2026-01-01 00:00:00+00'::timestamptz, E'1970-01-01 00:00:00.000001+00'::timestamptz),
  (E'plugin_grants_04', E'plugin_grants_04', E'agents_04', E'plain-ascii', E'1970-01-01 00:00:00.000001+00'::timestamptz, E'2026-08-22 07:30:45.123456-07'::timestamptz),
  (E'plugin_grants_05', E'plugin_grants_05', E'agents_05', E'中文测试文本', E'2026-08-22 07:30:45.123456-07'::timestamptz, E'2038-01-19 03:14:08+00'::timestamptz);

-- sessions（6 行）
INSERT INTO "sessions" ("id", "user_id", "token", "expires_at", "ip_address", "user_agent", "created_at", "updated_at") VALUES
  (E'sessions_00', E'users_00', E'plain-ascii', E'2038-01-19 03:14:08+00'::timestamptz, E'plain-ascii', E'back\\slash and \\\\double', E'2038-01-19 03:14:08+00'::timestamptz, E'2026-01-01 00:00:00+00'::timestamptz),
  (E'sessions_01', E'users_01', E'中文测试文本', E'2026-01-01 00:00:00+00'::timestamptz, NULL, NULL, E'2026-01-01 00:00:00+00'::timestamptz, E'1970-01-01 00:00:00.000001+00'::timestamptz),
  (E'sessions_02', E'users_02', E'emoji🙂🏽', E'1970-01-01 00:00:00.000001+00'::timestamptz, E'emoji🙂🏽', E'مرحبا rtl', E'1970-01-01 00:00:00.000001+00'::timestamptz, E'2026-08-22 07:30:45.123456-07'::timestamptz),
  (E'sessions_03', E'users_03', E'é-combining', E'2026-08-22 07:30:45.123456-07'::timestamptz, E'é-combining', E'', E'2026-08-22 07:30:45.123456-07'::timestamptz, E'2038-01-19 03:14:08+00'::timestamptz),
  (E'sessions_04', E'users_04', E'quote''single "double"', E'2038-01-19 03:14:08+00'::timestamptz, E'quote''single "double"', E'plain-ascii', E'2038-01-19 03:14:08+00'::timestamptz, E'2026-01-01 00:00:00+00'::timestamptz),
  (E'sessions_05', E'users_05', E'back\\slash and \\\\double', E'2026-01-01 00:00:00+00'::timestamptz, E'back\\slash and \\\\double', E'中文测试文本', E'2026-01-01 00:00:00+00'::timestamptz, E'1970-01-01 00:00:00.000001+00'::timestamptz);

-- skills（6 行）
INSERT INTO "skills" ("id", "owner_user_id", "slug", "title", "summary", "instructions", "origin", "installed_by", "created_at", "updated_at") VALUES
  (E'skills_00', E'users_00', E'中文测试文本', E'quote''single "double"', E'emoji🙂🏽', E'emoji🙂🏽', E'中文测试文本', E'line1\nline2\ttabbed', E'2026-08-22 07:30:45.123456-07'::timestamptz, E'2038-01-19 03:14:08+00'::timestamptz),
  (E'skills_01', E'users_01', E'emoji🙂🏽', E'back\\slash and \\\\double', E'é-combining', E'é-combining', E'emoji🙂🏽', NULL, E'2038-01-19 03:14:08+00'::timestamptz, E'2026-01-01 00:00:00+00'::timestamptz),
  (E'skills_02', E'users_02', E'é-combining', E'line1\nline2\ttabbed', E'quote''single "double"', E'quote''single "double"', E'é-combining', E'', E'2026-01-01 00:00:00+00'::timestamptz, E'1970-01-01 00:00:00.000001+00'::timestamptz),
  (E'skills_03', E'users_03', E'quote''single "double"', E'مرحبا rtl', E'back\\slash and \\\\double', E'back\\slash and \\\\double', E'quote''single "double"', E'plain-ascii', E'1970-01-01 00:00:00.000001+00'::timestamptz, E'2026-08-22 07:30:45.123456-07'::timestamptz),
  (E'skills_04', E'users_04', E'back\\slash and \\\\double', E'', E'line1\nline2\ttabbed', E'line1\nline2\ttabbed', E'back\\slash and \\\\double', E'中文测试文本', E'2026-08-22 07:30:45.123456-07'::timestamptz, E'2038-01-19 03:14:08+00'::timestamptz),
  (E'skills_05', E'users_05', E'line1\nline2\ttabbed', E'plain-ascii', E'مرحبا rtl', E'مرحبا rtl', E'line1\nline2\ttabbed', E'emoji🙂🏽', E'2038-01-19 03:14:08+00'::timestamptz, E'2026-01-01 00:00:00+00'::timestamptz);

-- sso_providers（6 行）
INSERT INTO "sso_providers" ("id", "issuer", "oidc_config", "saml_config", "user_id", "provider_id", "organization_id", "domain") VALUES
  (E'sso_providers_00', E'plain-ascii', E'emoji🙂🏽', E'back\\slash and \\\\double', E'users_00', E'emoji🙂🏽', E'é-combining', E'plain-ascii'),
  (E'sso_providers_01', E'中文测试文本', NULL, NULL, E'users_01', E'é-combining', NULL, E'中文测试文本'),
  (E'sso_providers_02', E'emoji🙂🏽', E'quote''single "double"', E'مرحبا rtl', E'users_02', E'quote''single "double"', E'back\\slash and \\\\double', E'emoji🙂🏽'),
  (E'sso_providers_03', E'é-combining', E'back\\slash and \\\\double', E'', E'users_03', E'back\\slash and \\\\double', E'line1\nline2\ttabbed', E'é-combining'),
  (E'sso_providers_04', E'quote''single "double"', E'line1\nline2\ttabbed', E'plain-ascii', E'users_04', E'line1\nline2\ttabbed', E'مرحبا rtl', E'quote''single "double"'),
  (E'sso_providers_05', E'back\\slash and \\\\double', E'مرحبا rtl', E'中文测试文本', E'users_05', E'مرحبا rtl', E'', E'back\\slash and \\\\double');

-- user_roles（6 行）
INSERT INTO "user_roles" ("user_id", "role", "created_at") VALUES
  (E'users_00', E'user'::role, E'2038-01-19 03:14:08+00'::timestamptz),
  (E'users_01', E'admin'::role, E'2026-01-01 00:00:00+00'::timestamptz),
  (E'users_02', E'user'::role, E'1970-01-01 00:00:00.000001+00'::timestamptz),
  (E'users_03', E'admin'::role, E'2026-08-22 07:30:45.123456-07'::timestamptz),
  (E'users_04', E'user'::role, E'2038-01-19 03:14:08+00'::timestamptz),
  (E'users_05', E'admin'::role, E'2026-01-01 00:00:00+00'::timestamptz);

-- agent_preferences（6 行）
INSERT INTO "agent_preferences" ("user_id", "agent_id", "hidden_at") VALUES
  (E'users_00', E'agents_00', E'2026-01-01 00:00:00+00'::timestamptz),
  (E'users_01', E'agents_01', NULL),
  (E'users_02', E'agents_02', E'2026-08-22 07:30:45.123456-07'::timestamptz),
  (E'users_03', E'agents_03', E'2038-01-19 03:14:08+00'::timestamptz),
  (E'users_04', E'agents_04', E'2026-01-01 00:00:00+00'::timestamptz),
  (E'users_05', E'agents_05', E'1970-01-01 00:00:00.000001+00'::timestamptz);

-- agent_profiles（6 行）
INSERT INTO "agent_profiles" ("agent_id", "owner_user_id", "title", "role_description", "avatar_seed", "visibility", "deleted_at", "created_at", "updated_at", "callback_token_hash", "callback_token_issued_at") VALUES
  (E'agents_00', E'users_00', E'', E'quote''single "double"', E'plain-ascii', E'public'::agent_visibility, E'2038-01-19 03:14:08+00'::timestamptz, E'2026-01-01 00:00:00+00'::timestamptz, E'1970-01-01 00:00:00.000001+00'::timestamptz, E'é-combining', E'1970-01-01 00:00:00.000001+00'::timestamptz),
  (E'agents_01', E'users_01', E'plain-ascii', E'back\\slash and \\\\double', E'中文测试文本', E'private'::agent_visibility, NULL, E'1970-01-01 00:00:00.000001+00'::timestamptz, E'2026-08-22 07:30:45.123456-07'::timestamptz, NULL, NULL),
  (E'agents_02', E'users_02', E'中文测试文本', E'line1\nline2\ttabbed', E'emoji🙂🏽', E'public'::agent_visibility, E'1970-01-01 00:00:00.000001+00'::timestamptz, E'2026-08-22 07:30:45.123456-07'::timestamptz, E'2038-01-19 03:14:08+00'::timestamptz, E'back\\slash and \\\\double', E'2038-01-19 03:14:08+00'::timestamptz),
  (E'agents_03', E'users_03', E'emoji🙂🏽', E'مرحبا rtl', E'é-combining', E'private'::agent_visibility, E'2026-08-22 07:30:45.123456-07'::timestamptz, E'2038-01-19 03:14:08+00'::timestamptz, E'2026-01-01 00:00:00+00'::timestamptz, E'line1\nline2\ttabbed', E'2026-01-01 00:00:00+00'::timestamptz),
  (E'agents_04', E'users_04', E'é-combining', E'', E'quote''single "double"', E'public'::agent_visibility, E'2038-01-19 03:14:08+00'::timestamptz, E'2026-01-01 00:00:00+00'::timestamptz, E'1970-01-01 00:00:00.000001+00'::timestamptz, E'مرحبا rtl', E'1970-01-01 00:00:00.000001+00'::timestamptz),
  (E'agents_05', E'users_05', E'quote''single "double"', E'plain-ascii', E'back\\slash and \\\\double', E'private'::agent_visibility, E'2026-01-01 00:00:00+00'::timestamptz, E'1970-01-01 00:00:00.000001+00'::timestamptz, E'2026-08-22 07:30:45.123456-07'::timestamptz, E'', E'2026-08-22 07:30:45.123456-07'::timestamptz);

-- channel_agents（6 行）
INSERT INTO "channel_agents" ("channel_id", "agent_id", "created_at") VALUES
  (E'channels_00', E'agents_00', E'2026-08-22 07:30:45.123456-07'::timestamptz),
  (E'channels_01', E'agents_01', E'2038-01-19 03:14:08+00'::timestamptz),
  (E'channels_02', E'agents_02', E'2026-01-01 00:00:00+00'::timestamptz),
  (E'channels_03', E'agents_03', E'1970-01-01 00:00:00.000001+00'::timestamptz),
  (E'channels_04', E'agents_04', E'2026-08-22 07:30:45.123456-07'::timestamptz),
  (E'channels_05', E'agents_05', E'2038-01-19 03:14:08+00'::timestamptz);

-- channel_memberships（6 行）
INSERT INTO "channel_memberships" ("channel_id", "user_id", "created_at") VALUES
  (E'channels_00', E'users_00', E'2038-01-19 03:14:08+00'::timestamptz),
  (E'channels_01', E'users_01', E'2026-01-01 00:00:00+00'::timestamptz),
  (E'channels_02', E'users_02', E'1970-01-01 00:00:00.000001+00'::timestamptz),
  (E'channels_03', E'users_03', E'2026-08-22 07:30:45.123456-07'::timestamptz),
  (E'channels_04', E'users_04', E'2038-01-19 03:14:08+00'::timestamptz),
  (E'channels_05', E'users_05', E'2026-01-01 00:00:00+00'::timestamptz);

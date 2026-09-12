#!/usr/bin/env python3
"""Mutation tests for the Desktop Local staged-shutdown guard."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
TOOLS = Path(__file__).resolve().parent
ROOT = TOOLS.parent
sys.path.insert(0, str(TOOLS))

from tauri_background_assembly_guard import GuardError, check_source  # noqa: E402


SOURCE_PATH = ROOT / "crates/openbot-desktop/src/tauri_background.rs"


def replace_once(source: str, old: str, new: str) -> str:
    count = source.count(old)
    if count != 1:
        raise AssertionError(f"mutation anchor count for {old!r}: {count}")
    return source.replace(old, new, 1)


def replace_after(source: str, marker: str, old: str, new: str) -> str:
    before, separator, after = source.partition(marker)
    if not separator:
        raise AssertionError(f"missing mutation marker {marker!r}")
    return before + separator + replace_once(after, old, new)


class AssemblyGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = SOURCE_PATH.read_text(encoding="utf-8")

    def assert_rejected(self, source: str) -> None:
        with self.assertRaises(GuardError):
            check_source(source)

    def test_current_production_source_passes(self) -> None:
        check_source(self.source)

    def test_local_aliases_comments_and_join_branch_order_are_accepted(self) -> None:
        source = replace_once(
            self.source,
            "let agent_host = self.agent_host.take();",
            "let agent_worker = self.agent_host.take();",
        )
        source = replace_once(
            source,
            "if let Some(host) = agent_host {",
            "if let Some(host_alias) = agent_worker {",
        )
        source = replace_once(source, "host.stop().await;", "host_alias.stop().await;")
        original = """            let (transport, (), (), ()) = tokio::join!(
                self.transport.shutdown(),
                async {
                    if let Some(host_alias) = agent_worker {
                        host_alias.stop().await;
                    }
                },
                async {
                    if let Some(assembly) = assembly {
                        assembly.shutdown().await;
                    }
                },
                self.lifecycle.wait_local_confirmation_stopped(),
            );"""
        reordered = """            let ((), (), (), transport) = tokio::join!(
                /* native confirmation branch may be listed first */
                self.lifecycle.wait_local_confirmation_stopped(),
                async {
                    if let Some(assembly_alias) = assembly {
                        assembly_alias.shutdown().await;
                    }
                },
                async {
                    if let Some(host_alias) = agent_worker {
                        host_alias.stop().await;
                    }
                },
                self.transport.shutdown(),
            );"""
        check_source(replace_once(source, original, reordered))

    def test_stage_future_and_deadline_aliases_are_accepted(self) -> None:
        source = replace_once(
            self.source,
            "        finish_shutdown_stages(non_database, database, crate::cancel::SHUTDOWN_DEADLINE).await",
            """        let non_database_alias = non_database;
        let database_alias = database;
        let deadline_alias = crate::cancel::SHUTDOWN_DEADLINE;
        finish_shutdown_stages(non_database_alias, database_alias, deadline_alias).await""",
        )
        marker = "async fn finish_shutdown_stages("
        source = replace_after(
            source,
            marker,
            "    let non_database_ok = match tokio::time::timeout(non_database_window, non_database).await {",
            """    let window_alias = non_database_window;
    let non_database_alias = non_database;
    let non_database_ok = match tokio::time::timeout(window_alias, non_database_alias).await {""",
        )
        source = replace_after(
            source,
            marker,
            "    let database_ok = database.await;",
            "    let database_alias = database;\n    let database_ok = database_alias.await;",
        )
        check_source(source)

    def test_stage_result_aliases_are_accepted(self) -> None:
        source = replace_once(
            self.source,
            "            authority_ok && transport.within_deadline",
            """            let authority_result_alias = authority_ok;
            let transport_result_alias = transport.within_deadline;
            authority_result_alias && transport_result_alias""",
        )
        source = replace_after(
            source,
            "async fn finish_shutdown_stages(",
            "    if non_database_ok && database_ok {",
            """    let non_database_result_alias = non_database_ok;
    let database_result_alias = database_ok;
    if database_result_alias && non_database_result_alias {""",
        )
        check_source(source)

    def test_each_required_concurrent_stop_is_required_in_the_production_join(self) -> None:
        mutations = [
            ("host.stop().await;", "drop(host);"),
            (
                "                        assembly.shutdown().await;",
                "                        drop(assembly);",
            ),
            (
                "self.transport.shutdown(),",
                "async { core::future::ready(()).await },",
            ),
            (
                "self.lifecycle.wait_local_confirmation_stopped(),",
                "async { core::future::ready(()).await },",
            ),
        ]
        for old, new in mutations:
            with self.subTest(removed=old):
                self.assert_rejected(replace_once(self.source, old, new))

    def test_comment_or_test_only_stop_cannot_replace_production_agent_stop(self) -> None:
        source = replace_once(
            self.source,
            "host.stop().await;",
            "// host.stop().await;\n                        drop(host);",
        )
        source += "\n#[cfg(test)] mod fake_guard_evidence { fn only_test() { agent_host.stop(); } }\n"
        self.assert_rejected(source)

    def test_async_stop_method_names_without_await_are_not_evidence(self) -> None:
        for old, new in [
            ("host.stop().await;", "let _unpolled = host.stop();"),
            (
                "                        assembly.shutdown().await;",
                "                        let _unpolled = assembly.shutdown();",
            ),
        ]:
            with self.subTest(unpolled=old):
                self.assert_rejected(replace_once(self.source, old, new))
        self.assert_rejected(
            replace_once(
                self.source,
                "host.stop().await;",
                "let _nested = async { host.stop().await; };",
            )
        )
        self.assert_rejected(
            replace_once(
                self.source,
                "host.stop().await;",
                "return; host.stop().await;",
            )
        )

    def test_authority_must_be_revoked_before_join_without_serial_await(self) -> None:
        self.assert_rejected(
            replace_once(
                self.source,
                "let authority_ok = self.lifecycle.shutdown_authority().is_ok();",
                "let authority_ok = true;",
            )
        )
        self.assert_rejected(
            replace_once(
                self.source,
                "authority_ok && transport.within_deadline",
                "transport.within_deadline",
            )
        )
        self.assert_rejected(
            replace_once(
                self.source,
                "authority_ok && transport.within_deadline",
                "authority_ok && true",
            )
        )
        self.assert_rejected(
            replace_once(
                self.source,
                "            let (transport, (), (), ()) = tokio::join!(",
                "            self.transport.shutdown().await;\n            let (transport, (), (), ()) = tokio::join!(",
            )
        )

    def test_database_cannot_run_before_or_only_after_successful_non_database_stage(self) -> None:
        marker = "async fn finish_shutdown_stages("
        pg_first = replace_after(
            self.source,
            marker,
            "    let non_database_ok = match tokio::time::timeout(non_database_window, non_database).await {",
            "    let database_ok = database.await;\n    let non_database_ok = match tokio::time::timeout(non_database_window, non_database).await {",
        )
        pg_first = replace_after(
            pg_first,
            marker,
            "    let database_ok = database.await;\n    observe_exit(\"postgresql\"",
            "    observe_exit(\"postgresql\"",
        )
        self.assert_rejected(pg_first)

        conditional = replace_after(
            self.source,
            marker,
            "    let database_ok = database.await;",
            "    let database_ok = if non_database_ok { database.await } else { false };",
        )
        self.assert_rejected(conditional)

    def test_shared_deadline_and_real_helper_call_are_required(self) -> None:
        self.assert_rejected(
            replace_once(
                self.source,
                "finish_shutdown_stages(non_database, database, crate::cancel::SHUTDOWN_DEADLINE)",
                "finish_shutdown_stages(non_database, database, Duration::from_secs(60))",
            )
        )
        self.assert_rejected(
            replace_once(
                self.source,
                "finish_shutdown_stages(non_database, database, crate::cancel::SHUTDOWN_DEADLINE)",
                "fake_finish_shutdown_stages(non_database, database, crate::cancel::SHUTDOWN_DEADLINE)",
            )
        )
        self.assert_rejected(
            replace_after(
                self.source,
                "async fn finish_shutdown_stages(",
                "tokio::time::timeout(non_database_window, non_database).await",
                "non_database.await",
            )
        )
        self.assert_rejected(
            replace_once(
                self.source,
                "finish_shutdown_stages(non_database, database, crate::cancel::SHUTDOWN_DEADLINE)",
                "finish_shutdown_stages(non_database, database, crate::cancel::SHUTDOWN_DEADLINE * 100)",
            )
        )

    def test_any_stage_failure_must_remain_a_shutdown_failure(self) -> None:
        source = replace_after(
            self.source,
            "async fn finish_shutdown_stages(",
            "    } else {\n        Err(DesktopLocalRuntimeError::Shutdown)\n    }",
            "    } else {\n        Ok(())\n    }",
        )
        self.assert_rejected(source)
        self.assert_rejected(
            replace_after(
                self.source,
                "async fn finish_shutdown_stages(",
                "if non_database_ok && database_ok",
                "if !non_database_ok && !database_ok",
            )
        )
        self.assert_rejected(
            replace_after(
                self.source,
                "async fn finish_shutdown_stages(",
                """    if non_database_ok && database_ok {
        Ok(())
    } else {
        Err(DesktopLocalRuntimeError::Shutdown)
    }""",
                """    let _ignored = if non_database_ok && database_ok {
        Ok(())
    } else {
        Err(DesktopLocalRuntimeError::Shutdown)
    };
    Ok(())""",
            )
        )
        self.assert_rejected(
            replace_after(
                self.source,
                "async fn finish_shutdown_stages(",
                "    let database_ok = database.await;",
                """    if !non_database_ok {
        return Err(DesktopLocalRuntimeError::Shutdown);
    }
    let database_ok = database.await;""",
            )
        )

    def test_timeout_false_and_timeout_error_cannot_be_projected_as_success(self) -> None:
        marker = "async fn finish_shutdown_stages("
        for old, new in [
            (
                """        Ok(false) => {
            observe_exit("non_database", "failed");
            false
        }""",
                """        Ok(false) => {
            observe_exit("non_database", "failed");
            true
        }""",
            ),
            (
                """        Err(_) => {
            observe_exit("non_database", "timed_out");
            false
        }""",
                """        Err(_) => {
            observe_exit("non_database", "timed_out");
            true
        }""",
            ),
        ]:
            with self.subTest(arm=old.splitlines()[0].strip()):
                self.assert_rejected(replace_after(self.source, marker, old, new))

    def test_shadowed_resource_alias_cannot_reuse_the_old_owner_binding(self) -> None:
        for declaration in [
            "let agent_host: Option<DesktopAgentHost> = None;",
            "let assembly: Option<PostgresApplicationAssembly> = None;",
            "let data_plane: Option<RunningDesktopLocalDataPlane> = None;",
        ]:
            with self.subTest(shadow=declaration):
                self.assert_rejected(
                    replace_once(
                        self.source,
                        "        let non_database = async {",
                        f"        {declaration}\n        let non_database = async {{",
                    )
                )

    def test_shadowed_helper_parameter_is_not_a_database_stage(self) -> None:
        self.assert_rejected(
            replace_after(
                self.source,
                "async fn finish_shutdown_stages(",
                "    let database_ok = database.await;",
                """    let database = async { true };
    let database_ok = database.await;""",
            )
        )

    def test_database_shutdown_must_stay_in_the_independent_database_future(self) -> None:
        self.assert_rejected(
            replace_once(
                self.source,
                "Some(data_plane) => data_plane.shutdown().await.is_ok(),",
                "Some(data_plane) => { drop(data_plane); true },",
            )
        )
        self.assert_rejected(
            replace_once(
                self.source,
                "Some(data_plane) => data_plane.shutdown().await.is_ok(),",
                "Some(data_plane) => { let _ignored = data_plane.shutdown().await; true },",
            )
        )
        self.assert_rejected(
            replace_once(self.source, "                None => false,", "                None => true,")
        )

    def test_database_owner_and_some_binding_aliases_are_accepted(self) -> None:
        source = replace_once(
            self.source,
            "let data_plane = self.data_plane.take();",
            "let database_owner = self.data_plane.take();",
        )
        source = replace_once(source, "match data_plane {", "match database_owner {")
        source = replace_once(
            source,
            "Some(data_plane) => data_plane.shutdown().await.is_ok(),",
            "Some(running_database) => running_database.shutdown().await.is_ok(),",
        )
        check_source(source)


if __name__ == "__main__":
    unittest.main(verbosity=2)

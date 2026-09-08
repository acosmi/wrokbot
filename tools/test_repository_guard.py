"""Regression tests for accidental publication of local material."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('guard', Path(__file__).with_name('repository_guard.py'))
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


class PublicationGuardTests(unittest.TestCase):
    def test_private_paths_and_unreviewed_documents_are_rejected(self):
        for path in ['docs/notes.md', 'grok-bot/src/index.ts', 'crates/x/implementation.md', 'crates/x/.env', '.local-private/backup.tar.gz', 'artifacts/logo.zip', 'crates/x/node_modules/a.js']:
            with self.subTest(path=path):
                self.assertIsNotNone(guard.forbidden(path))
        for path in ['README.md', 'Cargo.lock', 'crates/openbot-ui/assets/brand/wrok-bot-motion.gif']:
            self.assertIsNone(guard.forbidden(path))

    def test_content_rules_preserve_public_status_but_block_internal_plans(self):
        self.assertIsNotNone(guard.content_reason('README.md', '实施方案：内部任务分配'.encode()))
        self.assertIsNone(guard.content_reason('README.md', '当前进度：macOS 首版开发中；预计完成日期待确认。'.encode()))

    def test_staged_content_is_scanned_even_when_worktree_is_cleaned(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.init(root)
            (root / 'README.md').write_text('实施方案：内部内容')
            self.run_git(root, 'add', 'README.md')
            (root / 'README.md').write_text('Wrok Bot')
            with self.assertRaisesRegex(RuntimeError, 'internal implementation'):
                guard.inspect(root=root)

    def test_deleted_private_file_still_blocks_history(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.init(root)
            (root / 'docs').mkdir()
            (root / 'docs/notes.md').write_text('private')
            self.run_git(root, 'add', 'docs/notes.md')
            self.run_git(root, 'commit', '-qm', 'initial')
            self.run_git(root, 'rm', '-q', 'docs/notes.md')
            (root / 'README.md').write_text('Wrok Bot')
            self.run_git(root, 'add', 'README.md')
            self.run_git(root, 'commit', '-qm', 'remove private file')
            with patch.object(guard, 'scan'):
                with self.assertRaisesRegex(RuntimeError, 'docs/notes.md'):
                    guard.check_history(['HEAD'], root)

    def test_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.init(root)
            (root / 'README.md').symlink_to('/etc/passwd')
            self.run_git(root, 'add', 'README.md')
            with self.assertRaisesRegex(RuntimeError, 'symlink'):
                guard.inspect(root=root)

    @staticmethod
    def run_git(root, *args):
        subprocess.run(['git', *args], cwd=root, check=True, capture_output=True)

    def init(self, root):
        self.run_git(root, 'init', '-q', '-b', 'main')
        self.run_git(root, 'config', 'user.name', 'Guard Test')
        self.run_git(root, 'config', 'user.email', 'guard@example.invalid')
        self.run_git(root, 'config', 'commit.gpgsign', 'false')
        self.run_git(root, 'config', 'core.hooksPath', '/dev/null')


if __name__ == '__main__':
    unittest.main()

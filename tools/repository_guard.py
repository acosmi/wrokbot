#!/usr/bin/env python3
"""Prevent local material and credentials from entering published Git history."""
import argparse
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
POLICY = json.loads((ROOT / 'tools/repository-policy.json').read_text())


def git(*args, root=None):
    return subprocess.check_output(['git', *args], cwd=root)


def forbidden(path):
    p = PurePosixPath(path)
    if p.parts[0] not in POLICY['roots']:
        return 'unapproved top-level path'
    if any(part in POLICY['blocked_components'] for part in p.parts):
        return 'local-only directory or file'
    if path in POLICY['blocked_paths']:
        return 'local-only file'
    if re.search(POLICY['blocked_names'], p.name, re.I):
        return 'private, generated, or archived file'
    if p.suffix.lower() in POLICY['document_extensions'] and path not in POLICY['documents']:
        if not re.fullmatch(r'(?:LICENSE|COPYING|NOTICE)(?:\.(?:txt|md))?', p.name, re.I):
            return 'document requires explicit publication review'
    return None


def content_reason(path, data):
    if path in POLICY['content_rule_sources']:
        return None
    try:
        text = data.decode('utf-8')
    except UnicodeDecodeError:
        return None
    if re.search(POLICY['private_content'], text):
        return 'internal implementation material or private reference'
    return None


def entries(ref=None, root=None):
    if ref is None:
        records = git('ls-files', '--stage', '-z', root=root).split(b'\0')
    else:
        records = git('ls-tree', '-r', '-z', ref, root=root).split(b'\0')
    for record in records:
        if not record:
            continue
        meta, raw_path = record.split(b'\t', 1)
        bits = meta.decode().split()
        mode, oid = (bits[0], bits[1]) if ref is None else (bits[0], bits[2])
        if ref is None and bits[2] != '0':
            raise RuntimeError('Resolve merge conflicts before publishing')
        yield mode, oid, raw_path.decode('utf-8')


def inspect(ref=None, root=None, seen=None):
    seen = set() if seen is None else seen
    files = []
    for mode, oid, path in entries(ref, root):
        reason = forbidden(path)
        if mode not in ('100644', '100755'):
            reason = 'symlink or embedded repository is not allowed'
        if reason:
            raise RuntimeError(f'{path}: {reason}')
        if (path, oid) in seen:
            continue
        seen.add((path, oid))
        size = int(git('cat-file', '-s', oid, root=root))
        if size > POLICY.get('file_size_limits', {}).get(path, POLICY['max_file_bytes']):
            raise RuntimeError(f'{path}: exceeds reviewed file size limit')
        data = git('cat-file', 'blob', oid, root=root)
        reason = content_reason(path, data)
        if reason:
            raise RuntimeError(f'{path}: {reason}')
        files.append((path, data))
    return files


def scan(files):
    scanner = shutil.which('gitleaks')
    if scanner is None:
        raise RuntimeError('Install Gitleaks before committing or pushing')
    with tempfile.TemporaryDirectory(prefix='wrokbot-guard-') as tmp:
        base = Path(tmp)
        for path, data in files:
            out = base / path
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(data)
        result = subprocess.run([
            scanner, 'dir', str(base), '--config', str(ROOT / '.gitleaks.toml'),
            '--redact=100', '--no-banner', '--no-color', '--ignore-gitleaks-allow',
            '--gitleaks-ignore-path', str(base / 'no-ignored-findings'),
        ], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if result.returncode:
            # Never echo matched secret values or scanner output into a Git hook log.
            raise RuntimeError('Gitleaks rejected the candidate; run a redacted local scan to inspect')


def check_history(refs, root=None):
    if not refs:
        raise RuntimeError('No commit references to verify')
    commits = git('rev-list', *refs, root=root).decode().splitlines()
    seen = set()
    # Scan each distinct blob/path pair, including files deleted by later commits.
    for commit in commits:
        scan(inspect(commit, root, seen))
    return len(commits), len(seen)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['install', 'staged', 'history', 'pre-push'])
    parser.add_argument('args', nargs='*')
    args = parser.parse_args()
    if args.command == 'install':
        current = subprocess.run(['git', 'config', '--local', '--get', 'core.hooksPath'], cwd=ROOT, capture_output=True, text=True)
        if current.returncode == 0 and current.stdout.strip() not in ('.githooks', str(ROOT / '.githooks')):
            raise RuntimeError('Existing custom hooksPath must be reviewed before replacement')
        subprocess.run(['git', 'config', '--local', 'core.hooksPath', str(ROOT / '.githooks')], cwd=ROOT, check=True)
        print('Publication hooks installed')
    elif args.command == 'staged':
        files = inspect()
        scan(files)
        print(f'Publication guard: staged tree accepted ({len(files)} files)')
    elif args.command == 'history':
        refs = args.args or ['HEAD']
        commits, blobs = check_history(refs)
        print(f'Publication guard: history accepted ({commits} commits, {blobs} file versions)')
    else:
        if len(args.args) != 2 or args.args[1] not in POLICY['push_urls']:
            raise RuntimeError('Push destination is not the approved Wrok Bot repository')
        refs = []
        for line in sys.stdin:
            local_ref, local_oid, remote_ref, remote_oid = line.split()
            if set(local_oid) == {'0'}:
                continue
            if not remote_ref.startswith(('refs/heads/', 'refs/tags/')):
                raise RuntimeError('Only reviewed branches and tags may be published')
            refs.append(local_oid)
        if refs:
            commits, blobs = check_history(refs)
            print(f'Publication guard: push accepted ({commits} commits, {blobs} file versions)')


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, subprocess.CalledProcessError, OSError, ValueError) as exc:
        print(f'Publication guard blocked: {exc}', file=sys.stderr)
        sys.exit(1)

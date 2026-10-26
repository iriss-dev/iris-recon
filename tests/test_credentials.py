import json
from pathlib import Path
import tempfile
import unittest

from iriscore.credentials import audit_credentials, extract
from iriscore.reporting import save_assessment


class CredentialTests(unittest.TestCase):
    def test_masked_changed_unchanged_and_removed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            env = root / '.env'
            key = root / 'comparison.key'
            first_password = 'fixture-only-first-73!'
            second_password = 'fixture-only-second-48!'
            env.write_text(f'DB_USER=analyst\nDB_PASSWORD={first_password}\n', encoding='utf-8')
            first = audit_credentials(env, key)
            self.assertNotIn(first_password, json.dumps(first))
            self.assertEqual(first['data']['credentials'][0]['username'], 'analyst')
            save_assessment(first, root / 'reports')
            baseline = root / 'reports/report.json'
            same = audit_credentials(env, key, baseline)
            self.assertEqual(same['data']['credentials'][0]['comparison'], 'unchanged')
            env.write_text(f'DB_USER=analyst\nDB_PASSWORD={second_password}\n', encoding='utf-8')
            changed = audit_credentials(env, key, baseline)
            self.assertEqual(changed['data']['credentials'][0]['comparison'], 'changed')
            self.assertNotIn(second_password, json.dumps(changed))
            reveal = audit_credentials(env, key, baseline, reveal=True)
            self.assertEqual(reveal['data']['credentials'][0]['password_or_secret'], second_password)
            env.write_text('DB_USER=analyst\n', encoding='utf-8')
            removed = audit_credentials(env, key, baseline)
            self.assertEqual(len(removed['data']['no_longer_observed']), 1)

    def test_json_username_context_and_connection_url(self):
        found = extract('{"db":{"user":"alice","password":"test-literal-123"}}', '.json')
        self.assertEqual(found[0]['username'], 'alice')
        found = extract('DATABASE_URL=postgresql://alice:fixture%21@localhost/lab', '.env')
        self.assertEqual(found[0]['value'], 'fixture!')
        self.assertNotIn('fixture', found[0]['key'])

    def test_different_key_rejects_comparison(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            env = root / '.env'
            env.write_text('PASSWORD=test-fixture-123\n', encoding='utf-8')
            save_assessment(audit_credentials(env, root / 'first.key'), root / 'reports')
            with self.assertRaisesRegex(ValueError, 'same comparison key'):
                audit_credentials(env, root / 'second.key', root / 'reports/report.json')

    def test_code_expressions_and_placeholders_are_not_secrets(self):
        self.assertEqual(extract('password = os.environ["PASSWORD"]', '.py'), [])
        self.assertEqual(extract('PASSWORD=${PASSWORD}\n', '.env'), [])
        self.assertEqual(extract('# PASSWORD=not-a-secret\n', '.env'), [])

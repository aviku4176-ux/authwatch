import sys, os, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import authwatch


def ev(ip, user=None, kind="auth_failed", service="ssh", ts=None, detail=""):
    return authwatch.Event(ts=ts, ip=ip, user=user, kind=kind,
                           service=service, detail=detail)


class TestParsers(unittest.TestCase):
    def test_ssh_failed(self):
        e = authwatch.parse_ssh('Aug  7 08:00:01 web1 sshd[2412]: Failed password for root from 203.0.113.10 port 54321 ssh2')
        self.assertEqual(e.kind, 'auth_failed')
        self.assertEqual(e.ip, '203.0.113.10')
        self.assertEqual(e.user, 'root')
        self.assertEqual(e.service, 'ssh')

    def test_ssh_invalid_user(self):
        e = authwatch.parse_ssh('Aug  7 08:01:02 web1 sshd[2501]: Invalid user postgres from 198.51.100.7 port 40001')
        self.assertEqual(e.kind, 'auth_failed')
        self.assertEqual(e.user, 'postgres')

    def test_ssh_accepted(self):
        e = authwatch.parse_ssh('Aug  7 08:00:20 web1 sshd[2418]: Accepted password for root from 203.0.113.10 port 54327 ssh2')
        self.assertEqual(e.kind, 'auth_success')

    def test_ssh_lockout(self):
        e = authwatch.parse_ssh('Aug  7 08:00:20 web1 sshd[2418]: error: maximum authentication attempts exceeded for root from 203.0.113.10 port 54327 ssh2')
        self.assertEqual(e.kind, 'lockout')

    def test_pam(self):
        e = authwatch.parse_pam('Aug  7 08:00:01 web1 sshd[1234]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.10  user=admin')
        self.assertEqual(e.kind, 'auth_failed')
        self.assertEqual(e.ip, '203.0.113.10')
        self.assertEqual(e.user, 'admin')

    def test_dovecot(self):
        e = authwatch.parse_dovecot('Aug  7 08:00:01 mail1 dovecot: pop3-login: Disconnected (auth failed, 1 attempts in 2 secs): user=<alice>, method=PLAIN, rip=203.0.113.11, lip=10.0.0.1')
        self.assertEqual(e.kind, 'auth_failed')
        self.assertEqual(e.ip, '203.0.113.11')
        self.assertEqual(e.user, 'alice')

    def test_postfix(self):
        e = authwatch.parse_postfix('Aug  7 08:00:01 mx1 postfix/smtpd[456]: warning: unknown[203.0.113.12]: SASL authentication failed: authentication failure')
        self.assertEqual(e.kind, 'auth_failed')
        self.assertEqual(e.ip, '203.0.113.12')

    def test_http_401_login(self):
        e = authwatch.parse_http('203.0.113.10 - - [07/Aug/2026:09:00:01 +0000] "POST /wp-login.php HTTP/1.1" 401 512')
        self.assertEqual(e.kind, 'auth_failed')
        self.assertEqual(e.ip, '203.0.113.10')

    def test_http_404_recon(self):
        e = authwatch.parse_http('198.51.100.7 - - [07/Aug/2026:09:05:00 +0000] "GET /wp-admin.php HTTP/1.1" 404 256')
        self.assertEqual(e.kind, 'recon')

    def test_http_200_not_auth(self):
        e = authwatch.parse_http('198.51.100.7 - - [07/Aug/2026:09:05:00 +0000] "GET /index.html HTTP/1.1" 200 1024')
        self.assertIsNone(e.kind)

    def test_json_event(self):
        e = authwatch.parse_json('{"ts":"2026-08-07T10:00:00Z","src_ip":"203.0.113.99","user":"admin","kind":"auth_failed","service":"ssh"}')
        self.assertEqual(e.kind, 'auth_failed')
        self.assertEqual(e.ip, '203.0.113.99')
        self.assertEqual(e.service, 'ssh')


class TestDetector(unittest.TestCase):
    def setUp(self):
        self.d = authwatch.Detector(window=300, fail_threshold=5)
        self.d.set_now(1_700_000_000)

    def rules(self):
        return {a.rule for a in self.d.alerts}

    def test_ssh_bruteforce_threshold(self):
        for i in range(6):
            self.d.feed(ev('1.2.3.4', 'root', ts=1_700_000_000 + i))
        self.assertIn('ssh_bruteforce', self.rules())
        self.assertEqual([a for a in self.d.alerts
                          if a.rule == 'ssh_bruteforce'][0].count, 5)

    def test_no_alert_below_threshold(self):
        for i in range(4):
            self.d.feed(ev('1.2.3.4', 'root', ts=1_700_000_000 + i))
        self.assertEqual(self.d.alerts, [])

    def test_escalation_tier(self):
        for i in range(16):
            self.d.feed(ev('1.2.3.4', 'root', ts=1_700_000_000 + i))
        self.assertIn('auth_bruteforce_escalated', self.rules())

    def test_username_spray(self):
        for i, u in enumerate(['a', 'b', 'c', 'd', 'e', 'f']):
            self.d.feed(ev('5.6.7.8', u, ts=1_700_000_000 + i))
        self.assertIn('username_spray', self.rules())

    def test_focused_account(self):
        d = authwatch.Detector(window=300, fail_threshold=99,
                               user_threshold=3,
                               focus_users=frozenset(['admin']))
        d.set_now(1_700_000_000)
        for i in range(3):
            d.feed(ev('1.2.3.4', 'admin', ts=1_700_000_000 + i))
        self.assertIn('focused_account_attack', {a.rule for a in d.alerts})

    def test_success_after_bruteforce(self):
        for i in range(5):
            self.d.feed(ev('9.9.9.9', 'root', ts=1_700_000_000 + i))
        self.d.feed(ev('9.9.9.9', 'root', kind='auth_success',
                       ts=1_700_000_100))
        self.assertIn('success_after_bruteforce', self.rules())

    def test_multi_vector(self):
        d = authwatch.Detector(window=300, fail_threshold=2)
        d.set_now(1_700_000_000)
        d.feed(ev('1.1.1.1', 'a', service='ssh', ts=1_700_000_000))
        d.feed(ev('1.1.1.1', 'a', service='ssh', ts=1_700_000_001))
        d.feed(ev('1.1.1.1', 'a', service='dovecot', ts=1_700_000_002))
        d.feed(ev('1.1.1.1', 'a', service='dovecot', ts=1_700_000_003))
        self.assertIn('multi_vector_attack', {a.rule for a in d.alerts})

    def test_persistent_attacker(self):
        d = authwatch.Detector(window=10, fail_threshold=5, persist_buckets=3)
        d.set_now(1_700_000_000)
        for b in range(4):
            base = 1_700_000_000 + b * 10
            for i in range(5):
                d.feed(ev('7.7.7.7', 'root', ts=base + i))
        self.assertIn('persistent_attacker', {a.rule for a in d.alerts})

    def test_scanner_recon(self):
        d = authwatch.Detector(window=300, recon_threshold=5)
        d.set_now(1_700_000_000)
        for i in range(5):
            d.feed(ev('8.8.8.8', kind='recon', service='http',
                      ts=1_700_000_000 + i))
        self.assertIn('scanner_recon', {a.rule for a in d.alerts})

    def test_allowlist_ignored(self):
        d = authwatch.Detector(window=300, fail_threshold=5,
                               allowlist=('10.0.0.0/8',))
        d.set_now(1_700_000_000)
        for i in range(10):
            d.feed(ev('10.1.2.3', 'root', ts=1_700_000_000 + i))
        self.assertEqual(d.alerts, [])

    def test_denylist_flagged(self):
        d = authwatch.Detector(window=300, fail_threshold=99,
                               denylist=('203.0.113.0/24',))
        d.set_now(1_700_000_000)
        d.feed(ev('203.0.113.9', 'root', ts=1_700_000_000))
        self.assertIn('denylisted_ip', {a.rule for a in d.alerts})

    def test_window_expiry(self):
        d = authwatch.Detector(window=10, fail_threshold=5)
        d.set_now(1_700_000_000)
        for i in range(5):
            d.feed(ev('1.2.3.4', 'root', ts=1_700_000_000 + i))
        self.assertIn('ssh_bruteforce', {a.rule for a in d.alerts})
        d.set_now(1_700_000_000 + 60)
        self.assertEqual(d.win_fail.count('1.2.3.4'), 0)

    def test_credential_stuffing_http(self):
        d = authwatch.Detector(window=300, stuff_threshold=5)
        d.set_now(1_700_000_000)
        for i in range(5):
            d.feed(ev('1.2.3.4', kind='auth_failed', service='http',
                      ts=1_700_000_000 + i))
        self.assertIn('credential_stuffing', {a.rule for a in d.alerts})


class TestState(unittest.TestCase):
    def test_state_restore(self):
        import tempfile
        d = authwatch.Detector(window=300, fail_threshold=5)
        d.set_now(1_700_000_000)
        for i in range(5):
            d.feed(ev('1.2.3.4', 'root', ts=1_700_000_000 + i))
        with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
            path = f.name
        try:
            authwatch.StateStore(path).save(d)
            d2 = authwatch.Detector(window=300, fail_threshold=5)
            d2.set_now(1_700_000_000)
            authwatch.StateStore(path).restore(d2)
            self.assertIn('root', d2.users_failed['1.2.3.4'])
        finally:
            os.unlink(path)

    def test_dry_run_prints_command(self):
        import io as _io
        buf = _io.StringIO()
        b = authwatch.Bans(cmd_template='iptables -A INPUT -s {ip} -j DROP',
                           dry_run=True, out=buf)
        b.maybe_ban(authwatch.Alert(ts=0, rule='ssh_bruteforce', severity='high',
                                    ip='1.2.3.4', user='root', count=5,
                                    window=300, detail='x'))
        self.assertIn('iptables -A INPUT -s 1.2.3.4 -j DROP', buf.getvalue())


if __name__ == '__main__':
    unittest.main()

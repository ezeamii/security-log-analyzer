
import unittest

from python.analyzer import analyze_logs


def make_event(timestamp, ip, username, status):
    return {
        "timestamp": timestamp,
        "source_ip": ip,
        "username": username,
        "status": status,
        "service": "SSH",
    }


class TestSecurityLogAnalyzer(unittest.TestCase):

    def test_repeated_failures_trigger_alert(self):
        events = [
            make_event(
                f"2026-10-12 10:00:{second:02d}",
                "192.0.2.10",
                "alice",
                "FAILURE",
            )
            for second in range(5)
        ]

        results = analyze_logs(events, threshold=5)

        self.assertEqual(len(results["alerts"]), 1)
        self.assertEqual(
            results["alerts"][0]["severity"], "MEDIUM"
        )

    def test_success_after_failures_triggers_high_alert(self):
        events = [
            make_event(
                f"2026-10-12 10:00:{second:02d}",
                "192.0.2.20",
                "bob",
                "FAILURE",
            )
            for second in range(5)
        ]
        events.append(
            make_event(
                "2026-10-12 10:01:00",
                "192.0.2.20",
                "bob",
                "SUCCESS",
            )
        )

        results = analyze_logs(events, threshold=5)

        self.assertEqual(len(results["alerts"]), 1)
        self.assertEqual(results["alerts"][0]["severity"], "HIGH")
        self.assertIn(
            "Successful login after failed attempts",
            results["alerts"][0]["reason"],
        )

    def test_password_spraying_candidate(self):
        events = [
            make_event(
                f"2026-10-12 10:00:{second:02d}",
                "198.51.100.10",
                f"user{second}",
                "FAILURE",
            )
            for second in range(5)
        ]

        results = analyze_logs(events, threshold=5)

        self.assertEqual(
            len(results["password_spray_candidates"]), 1
        )
        self.assertEqual(
            results["password_spray_candidates"][0][
                "distinct_usernames"
            ],
            5,
        )

    def test_below_threshold_does_not_trigger_alert(self):
        events = [
            make_event(
                f"2026-10-12 10:00:{second:02d}",
                "192.0.2.30",
                "charlie",
                "FAILURE",
            )
            for second in range(4)
        ]

        results = analyze_logs(events, threshold=5)

        self.assertEqual(results["alerts"], [])

    def test_empty_events_produce_empty_results(self):
        results = analyze_logs([], threshold=5)

        self.assertEqual(results["total_events"], 0)
        self.assertEqual(results["failed_logins"], 0)
        self.assertEqual(results["alerts"], [])


if __name__ == "__main__":
    unittest.main()

"""ENC-TSK-I82 AC-5: idempotent processing on duplicate deduplication id.

Processing the same deduplication id twice increments the counter exactly once.
"""

import unittest

from counter_store import InMemoryCounterStore, record_observation

ATTR = "enceladus#task#category"


class TestIdempotency(unittest.TestCase):
    def test_ac5_duplicate_dedup_id_counts_once(self):
        store = InMemoryCounterStore()
        first = record_observation(
            store, ATTR, "implementation", dedup_id="dup-1",
            observed_at="2026-06-28T00:00:00Z", expires_at=0,
        )
        second = record_observation(
            store, ATTR, "implementation", dedup_id="dup-1",
            observed_at="2026-06-28T00:00:00Z", expires_at=0,
        )

        self.assertEqual(first["status"], "recorded")
        self.assertEqual(second["status"], "duplicate")
        self.assertEqual(store.get(ATTR, "implementation")["count"], 1)

    def test_distinct_dedup_ids_increment_each_time(self):
        store = InMemoryCounterStore()
        for i in range(3):
            record_observation(
                store, ATTR, "implementation", dedup_id=f"obs-{i}",
                observed_at="2026-06-28T00:00:00Z", expires_at=0,
            )
        self.assertEqual(store.get(ATTR, "implementation")["count"], 3)

    def test_duplicate_does_not_evict_or_create(self):
        store = InMemoryCounterStore()
        record_observation(
            store, ATTR, "documentation", dedup_id="d-1",
            observed_at="2026-06-28T00:00:00Z", expires_at=0,
        )
        before = store.distinct_count(ATTR)
        record_observation(
            store, ATTR, "documentation", dedup_id="d-1",
            observed_at="2026-06-28T00:00:00Z", expires_at=0,
        )
        self.assertEqual(store.distinct_count(ATTR), before)


if __name__ == "__main__":
    unittest.main()

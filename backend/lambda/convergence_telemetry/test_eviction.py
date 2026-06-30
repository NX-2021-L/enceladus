"""ENC-TSK-I82 AC-4: capacity-cap eviction unit test.

The 10,001st canonical value for a single attribute evicts the lowest-count entry.
"""

import unittest

from counter_store import InMemoryCounterStore, record_observation

ATTR = "enceladus#task#tags"


def _seed(store, n, base_count, *, observed_at="2026-06-28T00:00:00Z"):
    """Insert n distinct canonical values, each with `base_count` observations."""
    for i in range(n):
        value = f"tag-{i:05d}"
        for c in range(base_count):
            record_observation(
                store,
                ATTR,
                value,
                dedup_id=f"{value}:{c}",
                observed_at=observed_at,
                expires_at=0,
                cap=10000,
            )


class TestEviction(unittest.TestCase):
    def test_ac4_10001st_value_evicts_lowest_count(self):
        store = InMemoryCounterStore()
        # 9,999 values at count=5, plus one deliberately-lowest value at count=1.
        _seed(store, 9999, base_count=5)
        record_observation(
            store, ATTR, "lowest-value", dedup_id="lowest:1",
            observed_at="2026-06-28T00:00:00Z", expires_at=0, cap=10000,
        )
        self.assertEqual(store.distinct_count(ATTR), 10000)
        self.assertEqual(store.lowest(ATTR), ("lowest-value", 1))

        # Insert the 10,001st distinct value -> must evict the lowest-count entry.
        result = record_observation(
            store, ATTR, "the-10001st", dedup_id="the-10001st:1",
            observed_at="2026-06-28T01:00:00Z", expires_at=0, cap=10000,
        )

        self.assertEqual(result["status"], "recorded")
        self.assertEqual(result["evicted"], "lowest-value")
        self.assertEqual(store.distinct_count(ATTR), 10000)
        self.assertIsNone(store.get(ATTR, "lowest-value"))
        self.assertIsNotNone(store.get(ATTR, "the-10001st"))

    def test_existing_value_increment_never_evicts(self):
        store = InMemoryCounterStore()
        _seed(store, 10000, base_count=1)
        self.assertEqual(store.distinct_count(ATTR), 10000)
        # Re-observing an existing value (new dedup id) increments, no eviction.
        result = record_observation(
            store, ATTR, "tag-00000", dedup_id="tag-00000:again",
            observed_at="2026-06-28T02:00:00Z", expires_at=0, cap=10000,
        )
        self.assertEqual(result["status"], "recorded")
        self.assertIsNone(result["evicted"])
        self.assertEqual(store.distinct_count(ATTR), 10000)
        self.assertEqual(store.get(ATTR, "tag-00000")["count"], 2)

    def test_under_cap_no_eviction(self):
        store = InMemoryCounterStore()
        _seed(store, 5, base_count=1)
        record_observation(
            store, ATTR, "sixth", dedup_id="sixth:1",
            observed_at="2026-06-28T00:00:00Z", expires_at=0, cap=10000,
        )
        self.assertEqual(store.distinct_count(ATTR), 6)


if __name__ == "__main__":
    unittest.main()

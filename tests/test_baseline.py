import unittest
from unittest.mock import patch

from baseline.baseline import BaselineManager


class BaselineTests(unittest.TestCase):
    def test_fast_polling_does_not_replace_seconds_of_baseline_with_one_burst(self):
        manager = BaselineManager(30)
        with patch('time.monotonic', return_value=0):
            manager.add_sample(10)
        with patch('time.monotonic', return_value=0.1):
            for _ in range(100):
                manager.add_sample(1000)
        with patch('time.monotonic', return_value=1):
            manager.add_sample(20)
        self.assertEqual(manager.get_baseline(), 15)
        self.assertEqual(len(manager.samples), 2)


if __name__ == '__main__':
    unittest.main()

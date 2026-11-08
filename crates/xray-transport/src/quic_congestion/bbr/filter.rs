//! Kathleen Nichols' windowed best-of filter, as Xray-core's
//! `bbr/windowed_filter.go`: the best, second-best and third-best samples of
//! the last `window_length` round trips, each measured no earlier than the
//! one before it.

use std::cmp::Ordering;

use super::RoundTripCount;

/// Go's `entry`: a sample and the round trip it was taken in.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
struct Entry<V> {
    sample: V,
    time: RoundTripCount,
}

/// `WindowedFilter[V, roundTripCount]`. `compare` returns `Greater` when the
/// first sample is the better one, Go's `comparator(a, b) == 1`.
#[derive(Debug, Clone)]
pub(super) struct WindowedFilter<V> {
    window_length: RoundTripCount,
    estimates: [Entry<V>; 3],
    compare: fn(&V, &V) -> Ordering,
}

impl<V: Copy + Default> WindowedFilter<V> {
    pub(super) fn new(window_length: RoundTripCount, compare: fn(&V, &V) -> Ordering) -> Self {
        Self {
            window_length,
            estimates: [Entry::default(); 3],
            compare,
        }
    }

    pub(super) fn best(&self) -> V {
        self.estimates[0].sample
    }

    pub(super) fn second_best(&self) -> V {
        self.estimates[1].sample
    }

    pub(super) fn third_best(&self) -> V {
        self.estimates[2].sample
    }

    /// `Update`. Round-trip arithmetic wraps like Go's `uint64`.
    pub(super) fn update(&mut self, new_sample: V, new_time: RoundTripCount) {
        let better_or_equal = |a: &V, b: &V| (self.compare)(a, b) != Ordering::Less;
        // Reset all estimates if they have not yet been initialized, if the
        // new sample is a new best, or if the newest recorded estimate is too
        // old.
        if (self.compare)(&self.estimates[0].sample, &V::default()) == Ordering::Equal
            || better_or_equal(&new_sample, &self.estimates[0].sample)
            || new_time.wrapping_sub(self.estimates[2].time) > self.window_length
        {
            self.reset(new_sample, new_time);
            return;
        }

        let new_entry = Entry {
            sample: new_sample,
            time: new_time,
        };
        if better_or_equal(&new_sample, &self.estimates[1].sample) {
            self.estimates[1] = new_entry;
            self.estimates[2] = self.estimates[1];
        } else if better_or_equal(&new_sample, &self.estimates[2].sample) {
            self.estimates[2] = new_entry;
        }

        // Expire and update estimates as necessary.
        if new_time.wrapping_sub(self.estimates[0].time) > self.window_length {
            // The best estimate hasn't been updated for an entire window, so
            // promote the second and third best estimates.
            self.estimates[0] = self.estimates[1];
            self.estimates[1] = self.estimates[2];
            self.estimates[2] = new_entry;
            // The new best may have been recorded a long time ago as well.
            if new_time.wrapping_sub(self.estimates[0].time) > self.window_length {
                self.estimates[0] = self.estimates[1];
                self.estimates[1] = self.estimates[2];
            }
            return;
        }
        if (self.compare)(&self.estimates[1].sample, &self.estimates[0].sample) == Ordering::Equal
            && new_time.wrapping_sub(self.estimates[1].time) > self.window_length / 4
        {
            // A quarter of the window has passed without a better sample, so
            // the second-best estimate is taken from the second quarter.
            self.estimates[1] = new_entry;
            self.estimates[2] = self.estimates[1];
            return;
        }

        if (self.compare)(&self.estimates[2].sample, &self.estimates[1].sample) == Ordering::Equal
            && new_time.wrapping_sub(self.estimates[2].time) > self.window_length / 2
        {
            // Half the window has passed without a better estimate, so the
            // third-best estimate is taken from the second half.
            self.estimates[2] = new_entry;
        }
    }

    /// Resets all estimates to the new sample.
    pub(super) fn reset(&mut self, new_sample: V, new_time: RoundTripCount) {
        self.estimates = [Entry {
            sample: new_sample,
            time: new_time,
        }; 3];
    }

    /// `Clear`: back to zero-valued samples at round zero.
    pub(super) fn clear(&mut self) {
        self.estimates = [Entry::default(); 3];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn max_filter() -> WindowedFilter<u64> {
        WindowedFilter::new(10, |a, b| a.cmp(b))
    }

    #[test]
    fn a_new_best_resets_every_estimate() {
        let mut filter = max_filter();
        filter.update(5, 1);
        filter.update(3, 2);
        // A worse sample within the first quarter of the window is dropped.
        assert_eq!((filter.best(), filter.second_best()), (5, 5));
        filter.update(3, 4);
        assert_eq!((filter.best(), filter.second_best()), (5, 3));
        filter.update(9, 3);
        assert_eq!(
            (filter.best(), filter.second_best(), filter.third_best()),
            (9, 9, 9)
        );
    }

    #[test]
    fn the_best_expires_after_a_full_window() {
        let mut filter = max_filter();
        filter.update(9, 0);
        filter.update(7, 4);
        filter.update(5, 8);
        assert_eq!(filter.best(), 9);
        // Round 11 is more than ten rounds after the best: the second best,
        // taken in round 4, is promoted.
        filter.update(1, 11);
        assert_eq!(filter.best(), 7);
    }

    #[test]
    fn a_zero_best_is_uninitialized() {
        let mut filter = max_filter();
        filter.update(0, 1);
        filter.update(0, 2);
        assert_eq!(filter.estimates[2].time, 2, "a zero best always resets");
        filter.clear();
        assert_eq!(filter.estimates, [Entry::default(); 3]);
    }
}

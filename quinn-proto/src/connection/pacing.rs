//! Pacing of packet transmissions.

use crate::{Duration, Instant};

use tracing::warn;

/// A simple token-bucket pacer
///
/// The pacer's capacity is derived on a fraction of the congestion window
/// which can be sent in regular intervals
/// Once the bucket is empty, further transmission is blocked.
/// The bucket refills at a rate slightly faster
/// than one congestion window per RTT, as recommended in
/// <https://tools.ietf.org/html/draft-ietf-quic-recovery-34#section-7.7>
pub(super) struct Pacer {
    capacity: u64,
    last_window: u64,
    last_mtu: u16,
    /// Last controller-declared pacing rate (bytes/s), so a change resizes
    /// the bucket the same way a window change does.
    last_rate: Option<u64>,
    tokens: u64,
    prev: Instant,
}

impl Pacer {
    /// Obtains a new [`Pacer`].
    pub(super) fn new(smoothed_rtt: Duration, window: u64, mtu: u16, now: Instant) -> Self {
        let capacity = optimal_capacity(smoothed_rtt, window, mtu);
        Self {
            capacity,
            last_window: window,
            last_mtu: mtu,
            last_rate: None,
            tokens: capacity,
            prev: now,
        }
    }

    /// Record that a packet has been transmitted.
    pub(super) fn on_transmit(&mut self, packet_length: u16) {
        self.tokens = self.tokens.saturating_sub(packet_length.into())
    }

    /// Return how long we need to wait before sending `bytes_to_send`
    ///
    /// If we can send a packet right away, this returns `None`. Otherwise, returns `Some(d)`,
    /// where `d` is the time before this function should be called again.
    ///
    /// The 5/4 ratio used here comes from the suggestion that N = 1.25 in the draft IETF RFC for
    /// QUIC.
    ///
    /// `pacing_rate` is the controller's [`ControllerMetrics::pacing_rate`]
    /// (bits/s) when it declares one. Without it the bucket refills at
    /// `1.25 x window / srtt`, i.e. **the congestion window is the send rate**.
    /// That is fine for window-based controllers, but a rate-based one
    /// (Hysteria2 Brutal, whose whole contract is "send at exactly this many
    /// bytes per second regardless of loss") cannot be expressed that way at
    /// all: whenever `bps x srtt` falls below the controller's own minimum
    /// window — small rates, or LAN/loopback RTTs — the floor sets the rate
    /// and the declared one is ignored entirely. With a rate present the
    /// bucket refills at that rate instead and the window goes back to being
    /// what it is elsewhere: a cap on bytes in flight, not a throttle.
    ///
    /// [`ControllerMetrics::pacing_rate`]: crate::congestion::ControllerMetrics::pacing_rate
    pub(super) fn delay(
        &mut self,
        smoothed_rtt: Duration,
        bytes_to_send: u64,
        mtu: u16,
        window: u64,
        pacing_rate: Option<u64>,
        now: Instant,
    ) -> Option<Instant> {
        debug_assert_ne!(
            window, 0,
            "zero-sized congestion control window is nonsense"
        );

        // bits/s -> bytes/s. A declared rate of 0 (or one that rounds to 0)
        // is not a request to stall the connection; fall back to the window.
        let rate = pacing_rate.map(|bits| bits / 8).filter(|bytes| *bytes > 0);

        if window != self.last_window || mtu != self.last_mtu || rate != self.last_rate {
            self.capacity = match rate {
                Some(r) => rate_capacity(r, mtu),
                None => optimal_capacity(smoothed_rtt, window, mtu),
            };

            // Clamp the tokens
            self.tokens = self.capacity.min(self.tokens);
            self.last_window = window;
            self.last_mtu = mtu;
            self.last_rate = rate;
        }

        // if we can already send a packet, there is no need for delay
        if self.tokens >= bytes_to_send {
            return None;
        }

        let time_elapsed = now.checked_duration_since(self.prev).unwrap_or_else(|| {
            warn!("received a timestamp early than a previous recorded time, ignoring");
            Default::default()
        });

        if let Some(rate) = rate {
            // Plain token bucket at the declared rate. Deliberately not
            // RTT-scaled: the whole point of a declared rate is that it does
            // not move with the path.
            let new_tokens = (u128::from(rate) * time_elapsed.as_nanos()) / NANOS_PER_SEC;
            self.tokens = self
                .tokens
                .saturating_add(u64::try_from(new_tokens).unwrap_or(u64::MAX))
                .min(self.capacity);

            self.prev = now;

            if self.tokens >= bytes_to_send {
                return None;
            }

            let missing = bytes_to_send.max(self.capacity) - self.tokens;
            let wait_nanos = (u128::from(missing) * NANOS_PER_SEC) / u128::from(rate);
            let unscaled_delay =
                Duration::from_nanos(u64::try_from(wait_nanos).unwrap_or(u64::MAX));

            return Some(self.prev + (unscaled_delay / 5) * 4);
        }

        // we disable pacing for extremely large windows
        if window > u64::from(u32::MAX) {
            return None;
        }

        let window = window as u32;

        if smoothed_rtt.as_nanos() == 0 {
            return None;
        }

        let elapsed_rtts = time_elapsed.as_secs_f64() / smoothed_rtt.as_secs_f64();
        let new_tokens = window as f64 * 1.25 * elapsed_rtts;
        self.tokens = self
            .tokens
            .saturating_add(new_tokens as _)
            .min(self.capacity);

        self.prev = now;

        // if we can already send a packet, there is no need for delay
        if self.tokens >= bytes_to_send {
            return None;
        }

        let unscaled_delay = smoothed_rtt
            .checked_mul((bytes_to_send.max(self.capacity) - self.tokens) as _)
            .unwrap_or(Duration::MAX)
            / window;

        // divisions come before multiplications to prevent overflow
        // this is the time at which the pacing window becomes empty
        Some(self.prev + (unscaled_delay / 5) * 4)
    }
}

/// Calculates a pacer capacity for a certain window and RTT
///
/// The goal is to emit a burst (of size `capacity`) in timer intervals
/// which compromise between
/// - ideally distributing datagrams over time
/// - constantly waking up the connection to produce additional datagrams
///
/// Too short burst intervals means we will never meet them since the timer
/// accuracy in user-space is not high enough. If we miss the interval by more
/// than 25%, we will lose that part of the congestion window since no additional
/// tokens for the extra-elapsed time can be stored.
///
/// Too long burst intervals make pacing less effective.
fn optimal_capacity(smoothed_rtt: Duration, window: u64, mtu: u16) -> u64 {
    let rtt = smoothed_rtt.as_nanos().max(1);

    let capacity = ((window as u128 * BURST_INTERVAL_NANOS) / rtt) as u64;

    // Small bursts are less efficient (no GSO), could increase latency and don't effectively
    // use the channel's buffer capacity. Large bursts might block the connection on sending.
    capacity.clamp(MIN_BURST_SIZE * mtu as u64, MAX_BURST_SIZE * mtu as u64)
}

/// Burst size for a controller-declared byte rate: one
/// [`BURST_INTERVAL_NANOS`] worth of bytes, clamped exactly like the
/// window-derived path.
///
/// The [`MIN_BURST_SIZE`] floor is **not** cosmetic here. Refills are capped
/// at the capacity, and the wakeup is scheduled at 4/5 of the fill time — so
/// tokens are only preserved while scheduler jitter stays under 20 % of that
/// fill time. A bucket sized strictly at 2 ms of a 10 Mbps target is 2500 B,
/// i.e. a 0.4 ms margin against a timer whose granularity is ~1 ms: every
/// late wakeup then silently drops the overrun and the connection settles
/// *below* the declared rate (measured 0.72x before this floor went in).
/// Ten MTUs at that rate is ~12 ms of fill, whose 20 % margin comfortably
/// covers the jitter — and it is the same burst the window-derived path
/// already permits, so this is not a new burstiness.
fn rate_capacity(rate_bytes_per_s: u64, mtu: u16) -> u64 {
    let capacity = ((u128::from(rate_bytes_per_s) * BURST_INTERVAL_NANOS) / NANOS_PER_SEC) as u64;
    capacity.clamp(MIN_BURST_SIZE * u64::from(mtu), MAX_BURST_SIZE * u64::from(mtu))
}

const NANOS_PER_SEC: u128 = 1_000_000_000;

/// The burst interval
///
/// The capacity will we refilled in 4/5 of that time.
/// 2ms is chosen here since framework timers might have 1ms precision.
/// If kernel-level pacing is supported later a higher time here might be
/// more applicable.
const BURST_INTERVAL_NANOS: u128 = 2_000_000; // 2ms

/// Allows some usage of GSO, and doesn't slow down the handshake.
const MIN_BURST_SIZE: u64 = 10;

/// Creating 256 packets took 1ms in a benchmark, so larger bursts don't make sense.
const MAX_BURST_SIZE: u64 = 256;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn does_not_panic_on_bad_instant() {
        let old_instant = Instant::now();
        let new_instant = old_instant + Duration::from_micros(15);
        let rtt = Duration::from_micros(400);

        assert!(
            Pacer::new(rtt, 30000, 1500, new_instant)
                .delay(Duration::from_micros(0), 0, 1500, 1, None, old_instant)
                .is_none()
        );
        assert!(
            Pacer::new(rtt, 30000, 1500, new_instant)
                .delay(Duration::from_micros(0), 1600, 1500, 1, None, old_instant)
                .is_none()
        );
        assert!(
            Pacer::new(rtt, 30000, 1500, new_instant)
                .delay(Duration::from_micros(0), 1500, 1500, 3000, None, old_instant)
                .is_none()
        );
    }

    /// A declared rate must set the send rate even when the window is at a
    /// controller's floor and the RTT is sub-millisecond — the exact shape in
    /// which the window-derived refill silently ignores the rate.
    ///
    /// Mutation: drop the `rate` branch in `delay` and the drained pacer is
    /// refilled at `1.25 x window / srtt` = ~2 packets per 50 us = ~450 Mbps,
    /// so `emitted` blows past the 10 Mbps budget and this fails.
    #[test]
    fn declared_rate_paces_independently_of_window() {
        let mtu = 1452u16;
        let rtt = Duration::from_micros(50);
        // Brutal at the cwnd floor: window is 2 MTU, i.e. ~460 Mbps if the
        // window were the rate.
        let window = 2 * u64::from(mtu) + 1;
        let bits_per_s = 10_000_000u64;
        let bytes_per_s = bits_per_s / 8;

        let start = Instant::now();
        let mut pacer = Pacer::new(rtt, window, mtu, start);
        // Drain the initial bucket so we measure the refill, not the burst.
        pacer.tokens = 0;

        let step = Duration::from_micros(50);
        let run = Duration::from_millis(200);
        let mut now = start;
        let mut emitted = 0u64;
        while now < start + run {
            if pacer
                .delay(rtt, u64::from(mtu), mtu, window, Some(bits_per_s), now)
                .is_none()
            {
                pacer.on_transmit(mtu);
                emitted += u64::from(mtu);
                continue;
            }
            now += step;
        }

        let budget = bytes_per_s * run.as_millis() as u64 / 1000;
        assert!(
            emitted <= budget + u64::from(mtu),
            "declared 10 Mbps must not be exceeded: emitted {emitted} B > budget {budget} B"
        );
        assert!(
            emitted * 2 >= budget,
            "declared 10 Mbps must actually be reached: emitted {emitted} B < half of {budget} B"
        );
    }

    /// A rate of 0 (or one that rounds to 0 bytes/s) is not a request to
    /// stall: fall back to the window-derived refill.
    #[test]
    fn zero_declared_rate_falls_back_to_window() {
        let mtu = 1500u16;
        let rtt = Duration::from_millis(50);
        let window = 2_000_000u64;
        let now = Instant::now();

        let mut pacer = Pacer::new(rtt, window, mtu, now);
        assert_eq!(pacer.capacity, optimal_capacity(rtt, window, mtu));
        assert!(pacer
            .delay(rtt, u64::from(mtu), mtu, window, Some(0), now)
            .is_none());
        assert_eq!(pacer.capacity, optimal_capacity(rtt, window, mtu));
        assert_eq!(pacer.last_rate, None);
    }

    /// Switching rate resizes the bucket, like a window change does.
    #[test]
    fn rate_change_resizes_capacity() {
        let mtu = 1500u16;
        let rtt = Duration::from_millis(50);
        let window = 2_000_000u64;
        let now = Instant::now();

        let mut pacer = Pacer::new(rtt, window, mtu, now);
        let _ = pacer.delay(rtt, u64::from(mtu), mtu, window, Some(80_000_000), now);
        assert_eq!(pacer.capacity, rate_capacity(10_000_000, mtu));
        let _ = pacer.delay(rtt, u64::from(mtu), mtu, window, Some(8_000_000), now);
        assert_eq!(pacer.capacity, rate_capacity(1_000_000, mtu));
    }

    #[test]
    fn derives_initial_capacity() {
        let window = 2_000_000;
        let mtu = 1500;
        let rtt = Duration::from_millis(50);
        let now = Instant::now();

        let pacer = Pacer::new(rtt, window, mtu, now);
        assert_eq!(
            pacer.capacity,
            (window as u128 * BURST_INTERVAL_NANOS / rtt.as_nanos()) as u64
        );
        assert_eq!(pacer.tokens, pacer.capacity);

        let pacer = Pacer::new(Duration::from_millis(0), window, mtu, now);
        assert_eq!(pacer.capacity, MAX_BURST_SIZE * mtu as u64);
        assert_eq!(pacer.tokens, pacer.capacity);

        let pacer = Pacer::new(rtt, 1, mtu, now);
        assert_eq!(pacer.capacity, MIN_BURST_SIZE * mtu as u64);
        assert_eq!(pacer.tokens, pacer.capacity);
    }

    #[test]
    fn adjusts_capacity() {
        let window = 2_000_000;
        let mtu = 1500;
        let rtt = Duration::from_millis(50);
        let now = Instant::now();

        let mut pacer = Pacer::new(rtt, window, mtu, now);
        assert_eq!(
            pacer.capacity,
            (window as u128 * BURST_INTERVAL_NANOS / rtt.as_nanos()) as u64
        );
        assert_eq!(pacer.tokens, pacer.capacity);
        let initial_tokens = pacer.tokens;

        pacer.delay(rtt, mtu as u64, mtu, window * 2, None, now);
        assert_eq!(
            pacer.capacity,
            (2 * window as u128 * BURST_INTERVAL_NANOS / rtt.as_nanos()) as u64
        );
        assert_eq!(pacer.tokens, initial_tokens);

        pacer.delay(rtt, mtu as u64, mtu, window / 2, None, now);
        assert_eq!(
            pacer.capacity,
            (window as u128 / 2 * BURST_INTERVAL_NANOS / rtt.as_nanos()) as u64
        );
        assert_eq!(pacer.tokens, initial_tokens / 2);

        pacer.delay(rtt, mtu as u64, mtu * 2, window, None, now);
        assert_eq!(
            pacer.capacity,
            (window as u128 * BURST_INTERVAL_NANOS / rtt.as_nanos()) as u64
        );

        pacer.delay(rtt, mtu as u64, 20_000, window, None, now);
        assert_eq!(pacer.capacity, 20_000_u64 * MIN_BURST_SIZE);
    }

    #[test]
    fn computes_pause_correctly() {
        let window = 2_000_000u64;
        let mtu = 1000;
        let rtt = Duration::from_millis(50);
        let old_instant = Instant::now();

        let mut pacer = Pacer::new(rtt, window, mtu, old_instant);
        let packet_capacity = pacer.capacity / mtu as u64;

        for _ in 0..packet_capacity {
            assert_eq!(
                pacer.delay(rtt, mtu as u64, mtu, window, None, old_instant),
                None,
                "When capacity is available packets should be sent immediately"
            );

            pacer.on_transmit(mtu);
        }

        let pace_duration = Duration::from_nanos((BURST_INTERVAL_NANOS * 4 / 5) as u64);

        assert_eq!(
            pacer
                .delay(rtt, mtu as u64, mtu, window, None, old_instant)
                .expect("Send must be delayed")
                .duration_since(old_instant),
            pace_duration
        );

        // Refill half of the tokens
        assert_eq!(
            pacer.delay(
                rtt,
                mtu as u64,
                mtu,
                window,
                None,
                old_instant + pace_duration / 2
            ),
            None
        );
        assert_eq!(pacer.tokens, pacer.capacity / 2);

        for _ in 0..packet_capacity / 2 {
            assert_eq!(
                pacer.delay(rtt, mtu as u64, mtu, window, None, old_instant),
                None,
                "When capacity is available packets should be sent immediately"
            );

            pacer.on_transmit(mtu);
        }

        // Refill all capacity by waiting more than the expected duration
        assert_eq!(
            pacer.delay(
                rtt,
                mtu as u64,
                mtu,
                window,
                None,
                old_instant + pace_duration * 3 / 2
            ),
            None
        );
        assert_eq!(pacer.tokens, pacer.capacity);
    }
}

# Mobile Flow Budget Design

## Goal

Prevent iOS Network Extension memory spikes during bursty TUN traffic while preserving normal throughput and latency. The runtime should use available resources aggressively under healthy load, then shed or evict the least valuable work before RSS can climb into the NE kill range.

## Approach

TCP and UDP keep separate transport implementations because their lifecycle is different:

- TCP is stream-oriented and already has backpressure through smoltcp sockets and remote pending byte limits.
- UDP is NAT-association-oriented and has no protocol close signal, so it needs idle/LRU eviction and an active association budget.

The shared layer is resource policy, not packet I/O. A `FlowBudgetState` owns mobile/desktop budget constants and cheap counters for active TCP flows, active UDP flows, pending TCP remote bytes, UDP drops, UDP evictions, and budget rejections. TCP continues using byte pressure. UDP gains admission control and least-recently-used eviction.

## Mobile Policy

Mobile targets use conservative limits tuned for iOS NE:

- Keep existing TCP remote byte policy.
- Cap active UDP flows.
- Prefer evicting the oldest idle UDP flow when a new UDP flow arrives and the cap is full.
- Drop the new packet if no UDP flow can be evicted safely.
- Keep per-flow UDP channel depth bounded.
- Keep hot-path work O(1) average with `HashMap` lookups and a small timestamp/sequence field per UDP flow.

Desktop targets keep higher limits so benchmarks and local development are not artificially constrained.

## Observability

Expose stats through the existing `TunStats`/FFI path:

- active TCP flows
- active UDP flows
- UDP flow limit
- UDP budget drops
- UDP evictions
- UDP packets dropped because a per-flow channel is full

Apple debug logging includes those stats with the existing packet pump stats.

## Testing

Tests should cover:

- A new UDP flow is accepted below the limit.
- Existing UDP flows keep using their current channel.
- When the UDP budget is full, the oldest flow is evicted and the new flow is admitted.
- If no flow can be evicted, the new packet is dropped and stats increase.
- TCP pending-byte behavior remains unchanged.

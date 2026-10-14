# Changelog

## 0.1.10 — 2026-10-14

- Add LiveKit/WebRTC streaming for supported newer SimpliSafe cameras, including outdoor
  wired/battery cameras that advertise the LiveKit transport through the API.
- Add two-way audio through Scrypted's WebRTC and Intercom interfaces, with shared microphone
  ownership, unmuting and continuous RTP across sessions. Recover failed microphone publishers
  and keep talk-back working after token-expiry rollover.
- Share one upstream stream between viewers, pre-warm replacement sessions, and cache snapshots
  from received H264 keyframes.
- Fix timeout, failed-negotiation and device-disposal cleanup for sockets, peer connections,
  timers, subscriptions and intercom processes. Prevent stale intercom/publisher callbacks from
  stopping replacement sessions.
- Improve camera discovery concurrency and motion/doorbell event identifier matching. Preserve
  the legacy FLV/snapshot paths with HTTPS hostname URLs and TLS verification enabled.
- Add 31 automated regression and dependency-reachability checks, plus strict type checking.

Validation: automated checks pass on Node 20 and 24, with independent checks on Node 26. The
author and another user report newer/outdoor-camera WebRTC and HomeKit success. Physical legacy
SimpliCam/doorbell streaming, snapshots and event compatibility have not been verified for this
release. Deployed FFmpeg TLS trust/hostname behavior, ICE/TURN reachability, playback quality and
extended hardware rollover remain runtime acceptance gaps; synthetic tests do not prove them.

Dependency audit: existing findings remain. Reviewed Werift call paths do not invoke the newly
flagged IP classification, Elliptic ECDSA-signing or UUID buffer APIs. No compatible dependency
upgrade removes the new IP/Elliptic findings, and no forced overrides were applied.

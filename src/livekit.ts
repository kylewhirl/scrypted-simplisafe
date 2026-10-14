/**
 * LiveKit live streaming for newer SimpliSafe cameras.
 *
 * Despite reporting `providers.webrtc === 'kvs'`, newer SimpliSafe cameras actually stream over
 * LiveKit (not Amazon KVS). The `/v2/cameras/{uuid}/{location}/live-view` endpoint returns:
 *   { liveKitDetails: { liveKitURL: "wss://livestream.services.simplisafe.com:7880",
 *                       userToken: "<LiveKit access-token JWT>" }, cameraStatus: "online" }
 *
 * We connect to LiveKit as a subscriber (auto_subscribe), let the server offer its subscriber
 * peer connection, answer it with werift, and receive the camera's encoded audio/video RTP tracks.
 * Those tracks are then forwarded (no transcoding) into a second werift peer connection that is
 * negotiated with the Scrypted consumer `RTCSignalingSession`. The WeriftSignalingSession /
 * connectRTCSignalingClients helpers are adapted from @scrypted/webrtc.
 *
 * Signaling protocol reference: livekit/client-sdk-js (SignalClient/RTCEngine). Messages are
 * @livekit/protocol SignalRequest/SignalResponse protobufs sent as binary websocket frames.
 */

import WebSocket from 'ws';
import {
    MediaStreamTrack,
    RtpPacket,
    RTCIceCandidate,
    RTCPeerConnection,
    RTCRtpCodecParameters,
} from '@koush/werift';

// SimpliSafe's LiveKit cameras publish multiple video codecs (VP8/VP9/H264/AV1/H265). werift
// defaults to VP8, but Scrypted's WebRTC->RTSP path only accepts H264. Constraining the
// subscriber to H264 makes the camera send H264 directly, avoiding any transcode. These params
// mirror @scrypted/webrtc's requiredVideoCodec / Opus so the downstream negotiation lines up.
const SUBSCRIBE_VIDEO_CODECS = [
    new RTCRtpCodecParameters({
        mimeType: 'video/H264',
        clockRate: 90000,
        rtcpFeedback: [
            { type: 'transport-cc' },
            { type: 'ccm', parameter: 'fir' },
            { type: 'nack' },
            { type: 'nack', parameter: 'pli' },
            { type: 'goog-remb' },
        ],
        parameters: 'level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f',
    }),
    // Accept RTX retransmissions. Without this, the SFU has no channel to answer our NACKs and
    // most upstream packet loss is unrecoverable (observed ~0.4% net video loss -> HomeKit frame
    // drops). LiveKit's payload type mapping is stable (H264 on 125, its rtx on 126/apt=125), and
    // werift keeps every remote rtx whose apt origin matches a local codec, so mirroring one pair
    // is enough to accept them all. payloadType MUST be explicit: werift's constructor rewrites
    // the apt parameter of any rtx codec it auto-assigns a payload type to.
    new RTCRtpCodecParameters({
        mimeType: 'video/rtx',
        clockRate: 90000,
        payloadType: 126,
        parameters: 'apt=125',
    }),
];
const SUBSCRIBE_AUDIO_CODECS = [
    new RTCRtpCodecParameters({
        mimeType: 'audio/opus',
        clockRate: 48000,
        channels: 2,
        payloadType: 111,
    }),
];
// Talk-back (microphone) is published with RED (RFC 2198 redundant Opus) as the primary codec,
// matching exactly what the SimpliSafe app publishes (track name "microphone", mimeType audio/red).
// The camera only plays audio published this way. werift auto-fills the red codec's parameters to
// `${payloadType+1}/${payloadType+1}`, so opus must sit at the red payloadType + 1 (110 -> 111), and
// werift's sender then RED-wraps the forwarded Opus payloads automatically.
const PUBLISH_AUDIO_CODECS = [
    new RTCRtpCodecParameters({
        mimeType: 'audio/red',
        clockRate: 48000,
        channels: 2,
        payloadType: 110,
    }),
    new RTCRtpCodecParameters({
        mimeType: 'audio/opus',
        clockRate: 48000,
        channels: 2,
        payloadType: 111,
    }),
];
import {
    AddTrackRequest,
    MuteTrackRequest,
    SessionDescription,
    SignalRequest,
    SignalResponse,
    SignalTarget,
    StreamState,
    TrackSource,
    TrackType,
    TrickleRequest,
} from '@livekit/protocol';
import type {
    RTCAVSignalingSetup,
    RTCSessionControl,
    RTCSignalingOptions,
    RTCSignalingSendIceCandidate,
    RTCSignalingSession,
} from '@scrypted/sdk';

export interface LiveKitDetails {
    liveKitURL: string;
    userToken: string;
}

export interface LiveViewResponse {
    liveKitDetails?: LiveKitDetails;
    cameraStatus?: string;
}

type ConsoleLike = Pick<Console, 'log' | 'warn' | 'error'>;

// Protocol/version advertised to the LiveKit server, mirroring livekit-client.
const LK_PROTOCOL = 15;
const LK_VERSION = '2.20.0';

// LiveKit's join response includes its TURN server, and @koush/ice's TurnClient keeps refreshing
// its allocation after pc.close() — every 10-minute session rollover leaks a refresh loop that
// spams unhandledRejection TransactionFailed indefinitely. Filtering TURN out was tried
// (2026-07-05) and BROKE streaming: the SimpliSafe SFU is not directly reachable, media goes via
// the relay, and the server drops the participant (signaling ws closes) when ICE cannot form. So
// TURN must stay on; the refresh leak needs fixing in werift instead.
const USE_TURN_SERVERS = true;

/**
 * Flatten LiveKit ICE servers (protobuf ICEServer with a `urls` array) into werift's expected
 * shape (one entry per url string).
 */
function normalizeIceServers(iceServers: any[] | undefined): any[] {
    if (!Array.isArray(iceServers))
        return [];
    const ret: any[] = [];
    for (const ice of iceServers) {
        const urls = ice?.urls ?? ice?.url;
        const credential = ice?.credential ?? ice?.password;
        const username = ice?.username;
        const push = (url: unknown) => {
            if (typeof url !== 'string')
                return;
            if (!USE_TURN_SERVERS && /^turns?:/i.test(url.trim()))
                return;
            ret.push({ urls: url, username, credential });
        };
        if (Array.isArray(urls)) {
            for (const url of urls)
                push(url);
        }
        else {
            push(urls);
        }
    }
    return ret;
}

const H264_START_CODE = Buffer.from([0x00, 0x00, 0x00, 0x01]);

/**
 * Reassembles the camera's H264 RTP into Annex-B access units and retains the most recent keyframe
 * (SPS + PPS + IDR). This lets the plugin produce a still from the already-flowing WebRTC video
 * without cold-starting a fresh stream — the slow, timeout-prone path that otherwise makes HomeKit
 * show "Snapshot Failed". werift's H264RtpPayload does not reassemble FU-A fragments (how keyframe
 * slices almost always arrive), so RFC 6184 depacketization is done here.
 */
class H264KeyframeCapturer {
    private sps?: Buffer;
    private pps?: Buffer;
    private auNals: Buffer[] = [];
    private auHasIdr = false;
    private auHasSps = false;
    private auHasPps = false;
    private auTimestamp?: number;
    private fuBuffer?: Buffer;
    private latest?: Buffer;

    get keyframe(): Buffer | undefined {
        return this.latest;
    }

    onRtp(rtp: RtpPacket): void {
        const buf = rtp.payload;
        if (!buf || buf.length < 1)
            return;

        // A change in RTP timestamp marks a new access unit; flush the previous one. (The marker bit
        // handled below is the primary boundary; this is a fallback when markers are unreliable.)
        const timestamp = rtp.header.timestamp;
        if (this.auTimestamp !== undefined && timestamp !== this.auTimestamp)
            this.finishAccessUnit();
        this.auTimestamp = timestamp;

        const nalType = buf[0] & 0x1f;
        if (nalType >= 1 && nalType <= 23) {
            // Single NAL unit packet.
            this.pushNal(buf);
        }
        else if (nalType === 24) {
            // STAP-A: one packet aggregating several NAL units (commonly SPS + PPS).
            let offset = 1;
            while (offset + 2 <= buf.length) {
                const size = buf.readUInt16BE(offset);
                offset += 2;
                if (size === 0 || offset + size > buf.length)
                    break;
                this.pushNal(buf.subarray(offset, offset + size));
                offset += size;
            }
        }
        else if (nalType === 28) {
            // FU-A: a single NAL unit fragmented across packets.
            if (buf.length < 2)
                return;
            const fuHeader = buf[1];
            const start = (fuHeader & 0x80) !== 0;
            const end = (fuHeader & 0x40) !== 0;
            const fragment = buf.subarray(2);
            if (start) {
                const nalHeader = (buf[0] & 0xe0) | (fuHeader & 0x1f);
                this.fuBuffer = Buffer.concat([Buffer.from([nalHeader]), fragment]);
            }
            else if (this.fuBuffer) {
                this.fuBuffer = Buffer.concat([this.fuBuffer, fragment]);
            }
            if (end && this.fuBuffer) {
                this.pushNal(this.fuBuffer);
                this.fuBuffer = undefined;
            }
        }
        // STAP-B / FU-B / MTAP are not used by these cameras and are ignored.

        if (rtp.header.marker)
            this.finishAccessUnit();
    }

    private pushNal(nal: Buffer): void {
        const type = nal[0] & 0x1f;
        if (type === 7) { this.sps = nal; this.auHasSps = true; }
        else if (type === 8) { this.pps = nal; this.auHasPps = true; }
        else if (type === 5) this.auHasIdr = true;
        this.auNals.push(nal);
    }

    private finishAccessUnit(): void {
        if (this.auHasIdr && this.auNals.length) {
            const parts: Buffer[] = [];
            // Ensure the still is decodable even if the camera sent parameter sets in an earlier AU.
            if (this.sps && !this.auHasSps) parts.push(H264_START_CODE, this.sps);
            if (this.pps && !this.auHasPps) parts.push(H264_START_CODE, this.pps);
            for (const nal of this.auNals) parts.push(H264_START_CODE, nal);
            this.latest = Buffer.concat(parts);
        }
        this.auNals = [];
        this.auHasIdr = false;
        this.auHasSps = false;
        this.auHasPps = false;
        this.fuBuffer = undefined;
        this.auTimestamp = undefined;
    }
}

/**
 * RTP sequence-continuity accounting for diagnosing packet loss. Tracks forward gaps (packets
 * skipped), late arrivals (retransmissions/reordering filling earlier gaps), and duplicates.
 * `lost` is net loss after late arrivals are credited back.
 */
class RtpSeqStats {
    received = 0;
    gapEvents = 0;
    lost = 0;
    reordered = 0;
    private expected?: number;

    onPacket(seq: number): void {
        this.received++;
        if (this.expected === undefined) {
            this.expected = (seq + 1) & 0xffff;
            return;
        }
        if (seq === this.expected) {
            this.expected = (seq + 1) & 0xffff;
            return;
        }
        const delta = (seq - this.expected) & 0xffff;
        if (delta < 0x8000) {
            // Jumped forward: delta packets were skipped.
            this.gapEvents++;
            this.lost += delta;
            this.expected = (seq + 1) & 0xffff;
        }
        else {
            // Behind the high-water mark: a late (retransmitted/reordered) packet filled a gap.
            this.reordered++;
            if (this.lost > 0)
                this.lost--;
        }
    }
}

interface LiveKitViewer {
    /** Negotiated codec parameters (stable across sessions — the payload-type mapping is forced). */
    videoCodec?: RTCRtpCodecParameters;
    audioCodec?: RTCRtpCodecParameters;
    /**
     * Expiry (unix seconds) of the token this session joined with. SimpliSafe's server enforces it:
     * media stops at exp and a leave follows. LiveKitCameraStream pre-warms a replacement session
     * shortly before this deadline and switches consumers over.
     */
    tokenExp?: number;
    /** False once the viewer is torn down or its current peer connection failed. */
    isHealthy: () => boolean;
    /** Register a callback fired exactly when the viewer is torn down (leave/expiry/failure). */
    onClosed: (cb: () => void) => void;
    close: () => void;
    /** The most recent decode-ready H264 keyframe (Annex-B SPS+PPS+IDR), if any has been seen. */
    getKeyframe: () => Buffer | undefined;
    /**
     * Lazily publish a single shared talk-back (microphone) track to LiveKit over this same
     * participant connection and return it. Callers write RTP into the returned track; it is
     * published only once and reused across all consumer sessions.
     */
    ensureMicTrack: () => Promise<MediaStreamTrack>;
    /** The published mic track, if ensureMicTrack has completed on this viewer. */
    getMicTrack: () => MediaStreamTrack | undefined;
    /**
     * Request exclusive use of the shared talk-back track for the calling session (identified by a
     * stable token). Returns true if this session owns the mic and may write RTP; false if another
     * session is currently talking. Unmutes on claim and re-mutes after the talker goes idle,
     * mirroring how the SimpliSafe app toggles mute per talk so the camera re-triggers playback.
     */
    claimMic: (token: object) => boolean;
    /**
     * Write a talk-back packet into the shared mic track, rewriting its sequence/timestamp to our own
     * monotonic counters so the stream stays continuous across consumer-session (source) switches.
     */
    writeMic: (rtp: RtpPacket) => void;
    /** True while a talk-back session currently owns the mic (and briefly after it goes idle). */
    isMicActive: () => boolean;
}

/**
 * Connect to LiveKit as a subscriber and return the negotiated peer connection plus the received
 * media tracks.
 */
/**
 * Rewrites RTP sequence numbers and timestamps so that packets from successive sources (the
 * subscriber peer connection is rebuilt on every session resume, with fresh SSRC/seq/ts bases)
 * form one continuous stream. Offsets are constant per source, so intra-source ordering, gaps,
 * and retransmissions are preserved; across a source switch the output continues just after the
 * previous source's last packet, advanced by wall-clock elapsed time.
 */
class RtpRebaser {
    private gen = -1;
    private seqOffset = 0;
    private tsOffset = 0;
    private lastOutSeq = 0;
    private lastOutTs = 0;
    private lastWallMs = 0;
    private started = false;

    constructor(private clockRate: number) {
    }

    rebase(gen: number, rtp: RtpPacket): RtpPacket {
        const header = rtp.header;
        if (gen !== this.gen) {
            this.gen = gen;
            if (this.started) {
                const elapsedMs = Math.max(20, Date.now() - this.lastWallMs);
                const tsAdvance = Math.round(elapsedMs * this.clockRate / 1000);
                // Margin past the last emitted seq guards against a slightly stale anchor (late
                // retransmits can move lastOutSeq backwards a few packets).
                this.seqOffset = (this.lastOutSeq + 16 - header.sequenceNumber) & 0xffff;
                this.tsOffset = ((this.lastOutTs + tsAdvance - header.timestamp) >>> 0);
            }
        }
        this.started = true;
        header.sequenceNumber = (header.sequenceNumber + this.seqOffset) & 0xffff;
        header.timestamp = (header.timestamp + this.tsOffset) >>> 0;
        this.lastOutSeq = header.sequenceNumber;
        this.lastOutTs = header.timestamp;
        this.lastWallMs = Date.now();
        return rtp;
    }
}

// Decode a JWT's payload without verifying (diagnostics only — identity/expiry of LiveKit tokens).
function jwtClaims(token: string): any {
    try {
        return JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString());
    }
    catch {
        return undefined;
    }
}

/**
 * RTP sinks a viewer delivers its received media into. Provided by LiveKitCameraStream, which owns
 * the stable consumer-facing relays and switches the active source viewer across session rollovers.
 */
interface ViewerSinks {
    video: (rtp: RtpPacket) => void;
    audio: (rtp: RtpPacket) => void;
}

async function startLiveKitViewer(details: LiveKitDetails, console: ConsoleLike, debug: () => boolean, sinks: ViewerSinks, signal?: AbortSignal): Promise<LiveKitViewer> {
    if (signal?.aborted)
        throw new Error('LiveKit stream closed.');
    const dlog = (...args: any[]) => { if (debug()) console.log(...args); };
    const joinClaims = jwtClaims(details.userToken);
    if (joinClaims)
        dlog(`SS:LiveKit join token claims sub=${joinClaims.sub} jti=${joinClaims.jti} room=${joinClaims.video?.room}`
            + ` nbf=${joinClaims.nbf} exp=${joinClaims.exp} ttl=${joinClaims.exp - joinClaims.nbf}s`);
    const base = details.liveKitURL.replace(/\/$/, '');
    const params = new URLSearchParams({
        access_token: details.userToken,
        auto_subscribe: '1',
        sdk: 'js',
        version: LK_VERSION,
        protocol: String(LK_PROTOCOL),
    });
    const url = `${base}/rtc?${params.toString()}`;

    dlog('SS:LiveKit connecting', base);
    const ws = new WebSocket(url);

    let pc: RTCPeerConnection | undefined;
    let videoTrack: MediaStreamTrack | undefined;
    let audioTrack: MediaStreamTrack | undefined;
    const keyframeCapturer = new H264KeyframeCapturer();
    const closedCallbacks: (() => void)[] = [];
    // Packet-loss diagnostics: sequence continuity at the earliest point we see LiveKit RTP.
    const videoStats = new RtpSeqStats();
    const audioStats = new RtpSeqStats();
    let nackSends = 0;
    let statsTimer: NodeJS.Timeout | undefined;
    let lastStatsLine = '';
    // Dead-window diagnostics: the upstream feed intermittently stops delivering video RTP for
    // multiple seconds (kills long-lived downstream sessions like HA/rebroadcast clients). Track
    // the last video packet arrival and log the exact start/end of any multi-second gap so it can
    // be correlated with signaling events (streamStateUpdate, mute, renegotiation) and pc state.
    const ts = () => new Date().toISOString().slice(11, 23);
    let lastVideoRtpMs = 0;
    let videoGapFlaggedAt = 0;
    let gapTimer: NodeJS.Timeout | undefined;
    const startStatsLogging = () => {
        if (statsTimer)
            return;
        statsTimer = setInterval(() => {
            const vidAge = lastVideoRtpMs ? Date.now() - lastVideoRtpMs : -1;
            const line = `SS:rtpstats video recv=${videoStats.received} lost=${videoStats.lost} gaps=${videoStats.gapEvents} late=${videoStats.reordered}`
                + ` | audio recv=${audioStats.received} lost=${audioStats.lost}`
                + ` | nackSends=${nackSends}`;
            if (line !== lastStatsLine) {
                lastStatsLine = line;
                dlog(`${line} | vidAge=${vidAge}ms at ${ts()}`);
            }
        }, 10_000);
        gapTimer = setInterval(() => {
            if (!lastVideoRtpMs || videoGapFlaggedAt)
                return;
            const silentMs = Date.now() - lastVideoRtpMs;
            if (silentMs > 1500) {
                videoGapFlaggedAt = lastVideoRtpMs;
                dlog(`SS:rtpgap video silent ${(silentMs / 1000).toFixed(1)}s at ${ts()}`
                    + ` (pc=${pc?.connectionState}/${pc?.iceConnectionState})`);
            }
        }, 500);
    };
    let pingTimer: NodeJS.Timeout | undefined;
    let remoteDescriptionSet = false;
    let closed = false;
    const pendingCandidates: RTCIceCandidate[] = [];

    // Publisher (outbound) peer connection state, created lazily when the first mic track is
    // published. LiveKit uses a separate publisher PC on the SAME signaling websocket/participant.
    let joinIceServers: any[] = [];
    let publisherPc: RTCPeerConnection | undefined;
    let publisherRemoteDescriptionSet = false;
    let publisherMicSender: any;
    const pendingPublisherCandidates: RTCIceCandidate[] = [];
    let micPublish: Promise<MediaStreamTrack> | undefined;
    let micTrackRef: MediaStreamTrack | undefined;

    // Mic mute state. The SimpliSafe app toggles its published microphone track muted<->unmuted per
    // talk; the camera keys its speaker off the unmute (mute->unmute) transition. We keep one
    // persistent published track and mute it after talk-back audio stops so the next talk unmutes
    // afresh — otherwise a permanently-unmuted track only triggers the camera the first time.
    //
    // There is ONE shared published mic track but potentially several consumer sessions (multiple
    // HomeKit devices). Only one may feed the track at a time: interleaving RTP from two sessions
    // (different SSRCs/timestamps) into the single sender corrupts the RED/sequence state and breaks
    // talk-back for everyone until the connection is torn down. `claimMic(token)` grants exclusive
    // ownership to the first talker; others are refused until the owner goes idle (inactivity).
    let micSid: string | undefined;
    let micMuted = false;
    let micOwner: object | undefined;
    let micMuteTimer: NodeJS.Timeout | undefined;
    const sendMute = (muted: boolean) => {
        if (!micSid)
            return;
        send({ case: 'mute', value: new MuteTrackRequest({ sid: micSid, muted }) });
        dlog('SS:LiveKit mic', muted ? 'muted (talk stop)' : 'unmuted (talk start)', micSid);
    };
    // Called on each inbound talk-back packet with the calling session's token. Returns true only if
    // this session owns the mic (and may write RTP). Unmutes on claim and arms an inactivity timer
    // that releases ownership + re-mutes shortly after audio stops.
    const claimMic = (token: object): boolean => {
        if (micOwner && micOwner !== token)
            return false;
        if (!micOwner) {
            micOwner = token;
            if (micMuted) {
                micMuted = false;
                sendMute(false);
            }
        }
        if (micMuteTimer)
            clearTimeout(micMuteTimer);
        micMuteTimer = setTimeout(() => {
            micOwner = undefined;
            micMuted = true;
            sendMute(true);
        }, 800);
        return true;
    };

    // werift never stops the TURN allocation-refresh loop or closes its UDP socket on pc.close()
    // (@koush/ice's TurnTransport has no close method, and TurnClient.refreshHandle is never
    // cancelled), so every closed session leaks a refresh loop that spams unhandledRejection
    // TransactionFailed once its allocation credentials lapse. Stop them explicitly.
    const stopTurnClients = (peer?: RTCPeerConnection) => {
        for (const ice of (peer as any)?.iceTransports ?? []) {
            for (const protocol of ice?.connection?.protocols ?? []) {
                const turn = protocol?.turn;
                if (!turn)
                    continue;
                try { turn.refreshHandle?.cancel?.(); } catch { /* ignore */ }
                // The cancelled refresh loop still completes its in-flight iteration (it re-checks
                // its flag only after the ~500s sleep), issuing one final REFRESH from a detached
                // async context. Left alone that request can only time out, surfacing as an
                // unhandledRejection TransactionTimeout minutes after every close; resolve it
                // immediately instead.
                try { turn.request = async () => []; } catch { /* ignore */ }
                // Stop the retry timers of transactions already in flight. Their promises are
                // never settled, which is rejection-free and GC-safe.
                try {
                    for (const transaction of Object.values(turn.transactions ?? {}))
                        (transaction as any)?.cancel?.();
                } catch { /* ignore */ }
                const transport = turn.transport;
                if (!transport)
                    continue;
                // Swap send out BEFORE closing the socket: pc.close() completes asynchronously
                // (DTLS close_notify, final RTCP), and any late send hitting the closed dgram
                // socket rejects uncaught ('Not running') from werift's send promise.
                try { transport.send = async () => { /* socket closed */ }; } catch { /* ignore */ }
                try { transport.close?.(); } catch { /* ignore */ }
            }
        }
    };

    const resetPublisher = (failedPc: RTCPeerConnection) => {
        // A late failure from a replaced publisher must not tear down its replacement.
        if (publisherPc !== failedPc)
            return;
        publisherPc = undefined;
        publisherMicSender = undefined;
        publisherRemoteDescriptionSet = false;
        pendingPublisherCandidates.length = 0;
        micTrackRef = undefined;
        micPublish = undefined;
        micSid = undefined;
        micOwner = undefined;
        micMuted = false;
        if (micMuteTimer)
            clearTimeout(micMuteTimer);
        stopTurnClients(failedPc);
        try { failedPc.close().catch(() => { /* ignore */ }); } catch { /* ignore */ }
    };

    const cleanup = () => {
        // Re-entrant: pc.close() below re-fires connectionStateChange('closed') into cleanup.
        if (closed)
            return;
        closed = true;
        if (pingTimer)
            clearInterval(pingTimer);
        if (statsTimer)
            clearInterval(statsTimer);
        if (gapTimer)
            clearInterval(gapTimer);
        if (micMuteTimer)
            clearTimeout(micMuteTimer);
        signal?.removeEventListener('abort', cleanup);
        try { ws.terminate(); } catch { /* ignore */ }
        // close() is asynchronous in werift; observe its rejection as well as synchronous errors.
        try { pc?.close().catch(() => { /* ignore */ }); } catch { /* ignore */ }
        stopTurnClients(pc);
        if (publisherPc)
            resetPublisher(publisherPc);
        for (const cb of closedCallbacks.splice(0)) {
            try { cb(); } catch { /* ignore */ }
        }
    };
    signal?.addEventListener('abort', cleanup, { once: true });
    ws.on('error', err => {
        dlog('SS:LiveKit websocket error.', err);
        cleanup();
    });

    const send = (message: SignalRequest['message']) => {
        if (ws.readyState !== WebSocket.OPEN)
            return;
        ws.send(new SignalRequest({ message }).toBinary());
    };

    const setupPeerConnection = (iceServers: any[]) => {
        pc = new RTCPeerConnection({
            iceServers: normalizeIceServers(iceServers),
            bundlePolicy: 'max-bundle',
            codecs: {
                video: SUBSCRIBE_VIDEO_CODECS,
                audio: SUBSCRIBE_AUDIO_CODECS,
            },
        });

        pc.onIceCandidate.subscribe(candidate => {
            if (!candidate?.candidate)
                return;
            send({
                case: 'trickle',
                value: new TrickleRequest({
                    candidateInit: JSON.stringify(candidate.toJSON()),
                    target: SignalTarget.SUBSCRIBER,
                }),
            });
        });

        pc.connectionStateChange.subscribe(state => {
            dlog(`SS:LiveKit subscriber pc ${state} at ${ts()}`);
            // A post-startup failure gets no leave message, so without this the viewer lingers as
            // a zombie: onClosed never fires, consumers hang on frozen video, and ensureViewer
            // keeps handing out the dead session.
            if (state === 'failed' || state === 'closed')
                cleanup();
        });
        pc.iceConnectionStateChange.subscribe(state =>
            dlog(`SS:LiveKit subscriber ice ${state} at ${ts()}`));

        const myPc = pc;
        pc.onTrack.subscribe(track => {
            if (track.kind === 'video') {
                videoTrack = track;
                track.onReceiveRtp.subscribe(rtp => {
                    const now = Date.now();
                    if (videoGapFlaggedAt) {
                        dlog(`SS:rtpgap video resumed after ${((now - videoGapFlaggedAt) / 1000).toFixed(1)}s at ${ts()}`);
                        videoGapFlaggedAt = 0;
                    }
                    lastVideoRtpMs = now;
                    videoStats.onPacket(rtp.header.sequenceNumber);
                    // Retain the latest keyframe (for on-demand snapshots), then hand the packet to
                    // the stream-level sink (which rebases seq/ts across session rollovers).
                    try { keyframeCapturer.onRtp(rtp); }
                    catch { /* ignore malformed packet */ }
                    sinks.video(rtp);
                });
                // Observe werift's NACK handler so the stats show whether retransmission requests
                // are actually being sent for the gaps we see.
                try {
                    const receiver = (myPc.getTransceivers() as any[])
                        .find(t => t?.receiver?.tracks?.includes?.(track) || t?.kind === 'video')?.receiver;
                    if (receiver) {
                        dlog('SS:rtpstats video nackEnabled=', !!receiver.nackEnabled);
                        receiver.nack?.onPacketLost?.subscribe?.(() => { nackSends++; });
                    }
                }
                catch (e) {
                    dlog('SS:rtpstats receiver introspection failed', e);
                }
                startStatsLogging();
            }
            else if (track.kind === 'audio') {
                audioTrack = track;
                track.onReceiveRtp.subscribe(rtp => {
                    audioStats.onPacket(rtp.header.sequenceNumber);
                    sinks.audio(rtp);
                });
                startStatsLogging();
            }
        });
    };

    await new Promise<void>((resolve, reject) => {
        let settled = false;
        const finish = (err?: Error) => {
            if (settled)
                return;
            settled = true;
            clearTimeout(timeout);
            ws.off('open', onOpen);
            ws.off('close', onClosed);
            const index = closedCallbacks.indexOf(onClosed);
            if (index >= 0)
                closedCallbacks.splice(index, 1);
            if (err) {
                cleanup();
                reject(err);
            } else {
                dlog('SS:LiveKit ws open');
                resolve();
            }
        };
        const onOpen = () => finish();
        const onClosed = () => finish(new Error('LiveKit signaling websocket closed before opening.'));
        const timeout = setTimeout(() => finish(new Error('LiveKit signaling websocket open timed out.')), 15000);
        closedCallbacks.push(onClosed);
        ws.once('open', onOpen);
        ws.once('close', onClosed);
        if (closed)
            onClosed();
    });

    const handleSignal = async (data: WebSocket.RawData) => {
        if (closed)
            return;
        let messageCase: string | undefined;
        let signalingPublisher: RTCPeerConnection | undefined;
        try {
            const bytes = data instanceof Buffer ? new Uint8Array(data)
                : data instanceof ArrayBuffer ? new Uint8Array(data)
                : new Uint8Array(data as any);
            const resp = SignalResponse.fromBinary(bytes);
            const msg = resp.message;
            messageCase = msg.case;

            switch (msg.case) {
                case 'join': {
                    const join = msg.value;
                    dlog('SS:LiveKit join subscriberPrimary=', join.subscriberPrimary,
                        'iceServers=', join.iceServers?.length, 'pingInterval=', join.pingInterval,
                        'sid=', join.participant?.sid);
                    joinIceServers = join.iceServers as any[];
                    setupPeerConnection(join.iceServers as any[]);
                    const intervalMs = (join.pingInterval || 30) * 1000;
                    pingTimer = setInterval(() => send({ case: 'ping', value: BigInt(Date.now()) }), intervalMs);
                    break;
                }
                case 'offer': {
                    if (!pc) {
                        console.warn('SS:LiveKit received offer before join; ignoring.');
                        break;
                    }
                    const offer = msg.value;
                    // Log the camera's offered H264 profiles so we can align werift's codec if the
                    // negotiation fails to match.
                    const h264 = (offer.sdp.match(/a=(rtpmap|fmtp):.*(H264|h264).*/g) || []).join(' | ');
                    if (h264)
                        dlog('SS:LiveKit server H264 offer:', h264);
                    // Loss diagnostics: does the server offer retransmission (rtx) / FEC, and does it
                    // pair ssrcs for it (ssrc-group FID)?
                    const resilience = (offer.sdp.match(/a=(rtpmap:\d+ (rtx|red|ulpfec|flexfec).*|fmtp:\d+ apt=\d+|ssrc-group:FID.*)/g) || []).join(' | ');
                    if (resilience)
                        dlog('SS:LiveKit server offer resilience:', resilience);
                    await pc.setRemoteDescription({ type: 'offer', sdp: offer.sdp });
                    remoteDescriptionSet = true;
                    for (const candidate of pendingCandidates.splice(0))
                        await pc.addIceCandidate(candidate).catch(() => { /* ignore */ });
                    const answer = await pc.createAnswer();
                    await pc.setLocalDescription(answer);
                    const answerVideo = (answer.sdp.match(/a=rtpmap:.*/g) || []).join(' | ');
                    if (answerVideo)
                        dlog('SS:LiveKit our answer rtpmap:', answerVideo);
                    send({
                        case: 'answer',
                        value: new SessionDescription({ type: 'answer', sdp: answer.sdp, id: offer.id }),
                    });
                    break;
                }
                case 'answer': {
                    // The server answers the offer we sent on the PUBLISHER peer connection when
                    // publishing the mic track. (The subscriber flow is the reverse: server offers.)
                    if (!publisherPc) {
                        console.warn('SS:LiveKit received answer with no publisher PC; ignoring.');
                        break;
                    }
                    const answer = msg.value;
                    signalingPublisher = publisherPc;
                    await signalingPublisher.setRemoteDescription({ type: 'answer', sdp: answer.sdp });
                    if (publisherPc !== signalingPublisher)
                        break;
                    publisherRemoteDescriptionSet = true;
                    for (const candidate of pendingPublisherCandidates.splice(0))
                        await publisherPc.addIceCandidate(candidate).catch(() => { /* ignore */ });
                    // werift derives the RED block payload type from the negotiated red fmtp, but
                    // LiveKit's answer leaves it empty -> redRedundantPayloadType=0 (falsy) -> the
                    // sender skips RED wrapping and ships raw Opus mislabelled as RED, which the camera
                    // can't decode. Force it to the Opus PT so werift actually builds RED packets.
                    if (publisherMicSender && !publisherMicSender.redRedundantPayloadType) {
                        publisherMicSender.redRedundantPayloadType = PUBLISH_AUDIO_CODECS[1].payloadType;
                        dlog('SS:LiveKit forced publisher RED redundant PT=', publisherMicSender.redRedundantPayloadType);
                    }
                    dlog('SS:LiveKit publisher answer applied.');
                    break;
                }
                case 'trickle': {
                    const init = JSON.parse(msg.value.candidateInit);
                    if (!init?.candidate)
                        break;
                    const candidate = new RTCIceCandidate({
                        candidate: init.candidate,
                        sdpMid: init.sdpMid,
                        sdpMLineIndex: init.sdpMLineIndex,
                    });
                    if (msg.value.target === SignalTarget.PUBLISHER) {
                        if (!publisherPc)
                            break;
                        if (publisherRemoteDescriptionSet)
                            await publisherPc.addIceCandidate(candidate).catch(() => { /* ignore */ });
                        else
                            pendingPublisherCandidates.push(candidate);
                        break;
                    }
                    if (!pc)
                        break;
                    if (remoteDescriptionSet)
                        await pc.addIceCandidate(candidate).catch(() => { /* ignore */ });
                    else
                        pendingCandidates.push(candidate);
                    break;
                }
                case 'trackPublished':
                    dlog('SS:LiveKit track published:', msg.value.cid, msg.value.track?.sid, msg.value.track?.type);
                    // Remember the mic track sid so we can mute/unmute it per talk session.
                    if (msg.value.track?.type === TrackType.AUDIO && msg.value.track?.sid)
                        micSid = msg.value.track.sid;
                    break;
                case 'leave': {
                    const l = msg.value;
                    dlog(`SS:LiveKit server requested leave. reason=${l.reason} action=${l.action}`
                        + ` canReconnect=${l.canReconnect} at ${ts()}`);
                    cleanup();
                    break;
                }
                case 'refreshToken': {
                    // The server refreshes the access token every ~5 minutes. Signaling-level resume
                    // with it is a dead end for us (the server demands an ICE restart + DTLS
                    // continuation werift can't do), so survival across the enforced 10-minute token
                    // expiry is handled by LiveKitCameraStream pre-warming a whole new session.
                    const claims = jwtClaims(msg.value);
                    if (claims)
                        dlog(`SS:LiveKit refreshToken claims sub=${claims.sub}`
                            + ` nbf=${claims.nbf} exp=${claims.exp} ttl=${claims.exp - claims.nbf}s at ${ts()}`);
                    break;
                }
                case 'streamStateUpdate':
                    // The SFU pausing our subscribed track (congestion control / publisher pause)
                    // stops video RTP entirely — the prime suspect for mid-stream dead windows.
                    for (const s of msg.value.streamStates ?? [])
                        dlog(`SS:LiveKit streamState ${s.trackSid}:`
                            + ` ${s.state === StreamState.PAUSED ? 'PAUSED' : 'ACTIVE'} at ${ts()}`);
                    break;
                case 'update':
                    // Participant updates carry per-track mute flags; a camera muting its video
                    // track mid-session is another dead-window candidate.
                    for (const p of msg.value.participants ?? []) {
                        const tracks = (p.tracks ?? [])
                            .map(t => `${t.sid}${t.muted ? ':muted' : ':live'}`)
                            .join(' ');
                        dlog(`SS:LiveKit participant ${p.identity} state=${p.state} tracks=[${tracks}] at ${ts()}`);
                    }
                    break;
                default:
                    if (msg.case && msg.case !== 'pong' && msg.case !== 'pongResp' && msg.case !== 'connectionQuality')
                        dlog('SS:LiveKit signal:', msg.case, 'at', ts());
                    break;
            }
        }
        catch (err) {
            console.warn('Failed to handle LiveKit signaling message.', err);
            // A failed offer exchange (e.g. werift crashing on an SFU renegotiation that adds an
            // m-line) leaves the server waiting for an answer it will never get; it kicks the
            // session seconds later regardless. Tear down now so the shared viewer resets and
            // consumers reconnect immediately instead of streaming into a doomed session.
            if (messageCase === 'offer') {
                console.warn('SS:LiveKit offer negotiation failed; restarting subscriber connection.');
                cleanup();
            }
            if (messageCase === 'answer' && signalingPublisher)
                resetPublisher(signalingPublisher);
        }
    };

    // Serialize signaling: LiveKit renegotiates by sending several offers (audio first, then
    // video). Processing them concurrently corrupts werift's signaling state and can drop the
    // video offer, so handle one message at a time.
    let signalQueue: Promise<void> = Promise.resolve();
    ws.on('message', (data: WebSocket.RawData) => {
        signalQueue = signalQueue.then(() => handleSignal(data));
    });
    ws.on('close', () => {
        dlog('SS:LiveKit ws closed.');
        // An unexpected websocket drop (network blip, server restart) must tear the viewer down so
        // consumers are notified and the next stream request builds a fresh session.
        cleanup();
    });

    // Wait for the subscriber peer connection to connect and deliver at least a video track.
    await new Promise<void>((resolve, reject) => {
        let settled = false;
        const subscriptions: (() => void)[] = [];
        const finish = (err?: Error) => {
            if (settled)
                return;
            settled = true;
            clearTimeout(timeout);
            clearInterval(poll);
            for (const dispose of subscriptions)
                dispose();
            const index = closedCallbacks.indexOf(onClosed);
            if (index >= 0)
                closedCallbacks.splice(index, 1);
            if (err) {
                cleanup();
                reject(err);
            } else {
                resolve();
            }
        };
        const onClosed = () => finish(new Error('LiveKit subscriber connection closed.'));
        const check = () => {
            if (pc?.connectionState === 'connected' && videoTrack)
                finish();
        };
        const timeout = setTimeout(() => finish(new Error('LiveKit subscriber connection timed out.')), 30000);
        const poll = setInterval(() => {
            if (pc) {
                subscriptions.push(pc.connectionStateChange.subscribe(state => {
                    if (state === 'failed' || state === 'closed')
                        finish(new Error(`LiveKit subscriber connection ${state}.`));
                    else
                        check();
                }).unSubscribe);
                subscriptions.push(pc.onTrack.subscribe(() => check()).unSubscribe);
                clearInterval(poll);
                check();
            }
        }, 100);
        closedCallbacks.push(onClosed);
        if (closed)
            onClosed();
    });

    // A single, persistent talk-back (microphone) track is published to LiveKit at most once per
    // connection and shared by every consumer session. Publishing per-session would add a new
    // transceiver and renegotiate the shared publisher each time, which corrupts it after the first
    // session (talk-back "works once then stops").
    //
    // Every consumer session's talk-back RTP is written into this one shared sender. Each HomeKit
    // talk session has its own SSRC/sequence/timestamp bases, and werift's sender passes the input
    // sequence/timestamp through (only offsetting the SSRC), so switching sources would make the
    // sequence jump backwards and the camera would discard the packets as stale. `writeMic` rewrites
    // every packet's sequence/timestamp to our own monotonic counters so the stream stays continuous
    // across source switches, regardless of which session is talking.
    let micSeq = Math.floor(Math.random() * 0xffff);
    let micTs = Math.floor(Math.random() * 0xffffffff);
    const writeMic = (rtp: RtpPacket): void => {
        if (!micTrackRef)
            return;
        rtp.header.sequenceNumber = micSeq;
        micSeq = (micSeq + 1) & 0xffff;
        rtp.header.timestamp = micTs;
        micTs = (micTs + 960) >>> 0; // 20ms @ 48kHz Opus
        micTrackRef.writeRtp(rtp);
    };
    const ensureMicTrack = (): Promise<MediaStreamTrack> => {
        if (closed)
            return Promise.reject(new Error('LiveKit stream closed.'));
        if (micPublish)
            return micPublish;
        if (!publisherPc) {
            publisherPc = new RTCPeerConnection({
                iceServers: normalizeIceServers(joinIceServers),
                bundlePolicy: 'max-bundle',
                codecs: { audio: PUBLISH_AUDIO_CODECS },
            });
            publisherPc.onIceCandidate.subscribe(candidate => {
                if (!candidate?.candidate)
                    return;
                send({
                    case: 'trickle',
                    value: new TrickleRequest({
                        candidateInit: JSON.stringify(candidate.toJSON()),
                        target: SignalTarget.PUBLISHER,
                    }),
                });
            });
            const createdPc = publisherPc;
            publisherPc.connectionStateChange.subscribe(state => {
                dlog('SS:LiveKit publisher connection state:', state);
                if (state === 'failed' || state === 'closed')
                    resetPublisher(createdPc);
            });
        }
        const publishingPc = publisherPc;
        micPublish = (async () => {
            const track = new MediaStreamTrack({ kind: 'audio', id: `mic-${Date.now()}` });
            const micTransceiver = publishingPc.addTransceiver(track, { direction: 'sendonly' });
            // The 'answer' handler force-enables RED wrapping on this sender once negotiation settles
            // (werift otherwise leaves redRedundantPayloadType=0 and sends raw Opus mislabelled as RED).
            publisherMicSender = micTransceiver.sender;

            // Announce the track to LiveKit, then negotiate: we (the client) offer on the PUBLISHER
            // target and the server answers (handled in the 'answer' case above).
            const cid = track.id!;
            send({
                case: 'addTrack',
                value: new AddTrackRequest({
                    cid,
                    // Match the SimpliSafe app's talk-back track exactly (name "microphone"); the
                    // camera keys its speaker playback off this convention.
                    name: 'microphone',
                    type: TrackType.AUDIO,
                    source: TrackSource.MICROPHONE,
                }),
            });

            const offer = await publishingPc.createOffer();
            if (closed || publisherPc !== publishingPc)
                throw new Error('LiveKit stream closed.');
            await publishingPc.setLocalDescription(offer);
            if (closed || publisherPc !== publishingPc)
                throw new Error('LiveKit stream closed.');
            send({
                case: 'offer',
                value: new SessionDescription({ type: 'offer', sdp: offer.sdp }),
            });
            dlog('SS:LiveKit publishing mic track cid=', cid);
            micTrackRef = track;
            return track;
        })();
        // Allow a retry on failure (e.g. transient publisher negotiation error).
        micPublish.catch(() => resetPublisher(publishingPc));
        return micPublish;
    };

    return {
        get videoCodec() { return videoTrack?.codec; },
        get audioCodec() { return audioTrack?.codec; },
        tokenExp: typeof joinClaims?.exp === 'number' ? joinClaims.exp : undefined,
        isHealthy: () => !closed && pc?.connectionState !== 'failed' && pc?.connectionState !== 'closed',
        onClosed: (cb: () => void) => {
            if (closed)
                cb();
            else
                closedCallbacks.push(cb);
        },
        close: cleanup,
        getKeyframe: () => keyframeCapturer.keyframe,
        ensureMicTrack,
        getMicTrack: () => micTrackRef,
        claimMic,
        writeMic,
        isMicActive: () => !!micOwner,
    };
}

/**
 * Minimal RTCSignalingSession wrapper around a werift peer connection, adapted from
 * @scrypted/webrtc's WeriftSignalingSession.
 */
class WeriftSignalingSession implements RTCSignalingSession {
    __proxy_props = { options: {} };
    options: RTCSignalingOptions = {};
    remoteDescription?: Promise<void>;

    constructor(public console: ConsoleLike, public pc: RTCPeerConnection) {
    }

    async getOptions(): Promise<RTCSignalingOptions> {
        return this.options;
    }

    async createLocalDescription(type: 'offer' | 'answer', setup: RTCAVSignalingSetup, sendIceCandidate: undefined | RTCSignalingSendIceCandidate): Promise<RTCSessionDescriptionInit> {
        this.pc.onIceCandidate.subscribe(candidate => {
            sendIceCandidate?.({
                candidate: candidate.candidate,
                sdpMid: candidate.sdpMid,
                sdpMLineIndex: candidate.sdpMLineIndex,
            });
        });

        if (type === 'offer') {
            const offer = await this.pc.createOffer();
            await this.pc.setLocalDescription(offer);
            return { type: offer.type, sdp: offer.sdp };
        }

        if (!sendIceCandidate)
            await this.remoteDescription;
        const answer = await this.pc.createAnswer();
        await this.pc.setLocalDescription(answer);
        return { type: answer.type, sdp: answer.sdp };
    }

    async setRemoteDescription(description: RTCSessionDescriptionInit, setup: RTCAVSignalingSetup): Promise<void> {
        this.remoteDescription = this.pc.setRemoteDescription(description as any);
        await this.remoteDescription;
    }

    async addIceCandidate(candidate: RTCIceCandidateInit): Promise<void> {
        await this.pc.addIceCandidate(new RTCIceCandidate(candidate as any));
    }
}

function createCandidateQueue(console: ConsoleLike, session: RTCSignalingSession) {
    let ready = false;
    let queue: RTCIceCandidateInit[] = [];
    const send = async (candidate: RTCIceCandidateInit) => {
        try {
            await session.addIceCandidate(candidate);
        }
        catch (e) {
            console.error('addIceCandidate error', e);
        }
    };
    return {
        flush() {
            ready = true;
            for (const candidate of queue)
                send(candidate);
            queue = [];
        },
        queueSendCandidate: async (candidate: RTCIceCandidateInit) => {
            if (!ready)
                queue.push(candidate);
            else
                send(candidate);
        },
    };
}

/**
 * Negotiate an offer/answer pair between two signaling clients. Adapted from
 * @scrypted/webrtc's connectRTCSignalingClients.
 */
async function connectRTCSignalingClients(
    console: ConsoleLike,
    offerClient: RTCSignalingSession,
    offerSetup: Partial<RTCAVSignalingSetup>,
    answerClient: RTCSignalingSession,
    answerSetup: Partial<RTCAVSignalingSetup>,
) {
    offerSetup.type = 'offer';
    answerSetup.type = 'answer';

    const answerQueue = createCandidateQueue(console, answerClient);
    const offerQueue = createCandidateQueue(console, offerClient);

    const offer = await offerClient.createLocalDescription('offer', offerSetup as RTCAVSignalingSetup, answerQueue.queueSendCandidate);
    await answerClient.setRemoteDescription(offer, answerSetup as RTCAVSignalingSetup);
    const answer = await answerClient.createLocalDescription('answer', answerSetup as RTCAVSignalingSetup, offerQueue.queueSendCandidate);
    await offerClient.setRemoteDescription(answer, offerSetup as RTCAVSignalingSetup);
    offerQueue.flush();
    answerQueue.flush();
}

/**
 * Manages a single shared LiveKit subscriber connection per camera and fans it out to multiple
 * Scrypted consumers.
 *
 * Scrypted requests a stream several times concurrently (console preview, rebroadcast, NVR, etc.),
 * each calling startRTCSignalingSession. If each opened its own LiveKit connection, they would all
 * join the same room with the SAME participant identity (from the user's token) — and LiveKit
 * disconnects the existing participant whenever another joins with a duplicate identity, so the
 * connections kick each other out (intermittent "connection failed" / black screen). Instead we
 * keep one upstream subscriber and bridge every consumer off its tracks, tearing the upstream down
 * only when the last consumer leaves.
 */
export class LiveKitCameraStream {
    private viewer?: LiveKitViewer;
    private viewerPromise?: Promise<LiveKitViewer>;
    private refcount = 0;
    private readonly abort = new AbortController();
    private readonly retiringViewers = new Map<LiveKitViewer, NodeJS.Timeout>();

    // Stable consumer-facing relays. Viewers (one per LiveKit session) push their received RTP
    // into these via per-viewer sinks; the rebasers keep sequence numbers/timestamps continuous
    // when the active session is swapped by a rollover, so consumers never renegotiate.
    readonly videoRelay = new MediaStreamTrack({ kind: 'video' });
    readonly audioRelay = new MediaStreamTrack({ kind: 'audio' });
    private readonly videoRebaser = new RtpRebaser(90000);
    private readonly audioRebaser = new RtpRebaser(48000);
    private genCounter = 0;
    private activeGen = 0;
    private rolloverTimer?: NodeJS.Timeout;
    private streamEndedCbs: (() => void)[] = [];
    // Outstanding device-level Intercom holds (acquireMicSink). These write to the mic track
    // directly without claiming it, so they count as talk-back activity for rollover deferral.
    private micSinkHolds = 0;

    constructor(
        private getDetails: (force?: boolean) => Promise<LiveKitDetails>,
        private console: ConsoleLike,
        private debug: () => boolean,
    ) {
    }

    private dlog(...args: any[]): void {
        if (this.debug())
            this.console.log(...args);
    }

    get videoCodec(): RTCRtpCodecParameters | undefined {
        return this.viewer?.videoCodec;
    }

    get audioCodec(): RTCRtpCodecParameters | undefined {
        return this.viewer?.audioCodec;
    }

    claimMic(token: object): boolean {
        return this.viewer?.claimMic(token) ?? false;
    }

    writeMic(rtp: RtpPacket): void {
        this.viewer?.writeMic(rtp);
    }

    async ensureMicTrack(): Promise<MediaStreamTrack> {
        const viewer = await this.ensureViewer();
        return viewer.ensureMicTrack();
    }

    getMicTrack(): MediaStreamTrack | undefined {
        return this.viewer?.getMicTrack();
    }

    /** Permanently dispose this camera, including attempts still fetching or joining. */
    close(): void {
        if (this.abort.signal.aborted)
            return;
        this.abort.abort();
        if (this.rolloverTimer)
            clearTimeout(this.rolloverTimer);
        for (const [viewer, timer] of this.retiringViewers) {
            clearTimeout(timer);
            viewer.close();
        }
        this.retiringViewers.clear();
        this.viewer?.close();
        this.viewer = undefined;
        this.viewerPromise = undefined;
        this.refcount = 0;
        this.micSinkHolds = 0;
        this.fireStreamEnded();
    }

    /**
     * Fired when the stream truly ends (active session died with no replacement). Returns an
     * unregister function so consumer sessions that end first don't accumulate here for the
     * stream's lifetime.
     */
    onStreamEnded(cb: () => void): () => void {
        this.streamEndedCbs.push(cb);
        return () => {
            const index = this.streamEndedCbs.indexOf(cb);
            if (index >= 0)
                this.streamEndedCbs.splice(index, 1);
        };
    }

    private fireStreamEnded(): void {
        for (const cb of this.streamEndedCbs.splice(0)) {
            try { cb(); } catch { /* ignore */ }
        }
    }

    /**
     * Per-viewer RTP sinks. The video sink of a NEWER generation activates that generation on its
     * first packet (the moment the pre-warmed replacement session delivers video); packets from
     * older generations are dropped from then on. Audio strictly follows the active generation so
     * the rebasers see clean source switches rather than interleaved sources.
     */
    private makeSinks(gen: number): ViewerSinks {
        return {
            video: rtp => {
                if (gen < this.activeGen)
                    return;
                if (gen > this.activeGen) {
                    this.activeGen = gen;
                    this.dlog(`SS:LiveKit rollover: video source switched to session gen ${gen}`);
                }
                this.videoRelay.writeRtp(this.videoRebaser.rebase(gen, rtp));
            },
            audio: rtp => {
                if (gen !== this.activeGen)
                    return;
                this.audioRelay.writeRtp(this.audioRebaser.rebase(gen, rtp));
            },
        };
    }

    /**
     * SimpliSafe's LiveKit server enforces the join token's 10-minute expiry (media stops at exp,
     * CONNECTION_TIMEOUT leave follows; signaling-level resume demands an ICE restart + DTLS
     * continuation werift cannot do). So shortly before expiry, pre-warm a complete replacement
     * session — a fresh live-view token joins as a distinct participant identity, so both sessions
     * briefly coexist — and cut consumers over on its first video packet.
     */
    private scheduleRollover(viewer: LiveKitViewer): void {
        if (this.rolloverTimer)
            clearTimeout(this.rolloverTimer);
        if (!viewer.tokenExp)
            return;
        const delay = viewer.tokenExp * 1000 - Date.now() - 45_000;
        if (delay <= 0)
            return;
        this.rolloverTimer = setTimeout(() => {
            this.rollover(viewer).catch(err =>
                this.dlog('SS:LiveKit rollover failed; session rides to expiry and self-heals.', err));
        }, delay);
        this.dlog(`SS:LiveKit rollover scheduled in ${Math.round(delay / 1000)}s`);
    }

    private async rollover(oldViewer: LiveKitViewer): Promise<void> {
        if (this.viewer !== oldViewer || this.refcount === 0)
            return;
        // Defer while talk-back is in progress — the shared mic track lives on the old session, so
        // rolling over mid-talk cuts it off. Re-check every couple seconds until a drop-dead point
        // that still leaves time to pre-warm the replacement before the server kills the old
        // session at token expiry (at which point the talk would die anyway).
        if (oldViewer.isMicActive() || this.micSinkHolds > 0) {
            const dropDeadMs = (oldViewer.tokenExp ?? 0) * 1000 - 12_000;
            if (Date.now() < dropDeadMs) {
                this.dlog('SS:LiveKit rollover deferred: talk-back in progress.');
                this.rolloverTimer = setTimeout(() => {
                    this.rollover(oldViewer).catch(err =>
                        this.dlog('SS:LiveKit rollover failed; session rides to expiry and self-heals.', err));
                }, 2000);
                return;
            }
            this.dlog('SS:LiveKit rollover proceeding despite active talk-back: token expiry imminent.');
        }
        this.dlog('SS:LiveKit rollover: pre-warming replacement session before token expiry.');
        const details = await this.getDetails();
        const next = await startLiveKitViewer(details, this.console, this.debug, this.makeSinks(++this.genCounter), this.abort.signal);
        if (this.viewer !== oldViewer || this.refcount === 0) {
            next.close();
            return;
        }
        this.viewer = next;
        this.viewerPromise = Promise.resolve(next);
        next.onClosed(() => {
            if (this.viewer === next) {
                this.viewer = undefined;
                this.viewerPromise = undefined;
                this.fireStreamEnded();
            }
        });
        this.scheduleRollover(next);
        // A device-level intercom may be mid-talk (rollover forced at the token drop-dead point);
        // re-publish the shared mic on the replacement so the intercom's per-packet track lookup
        // resumes flowing instead of writing into the old viewer's dead track.
        if (this.micSinkHolds > 0) {
            next.ensureMicTrack().catch(err =>
                this.dlog('SS:LiveKit mic re-publish after rollover failed.', err));
        }
        // Let the replacement deliver its first video (which flips the active source), then drop
        // the old session; closing it first would open a gap.
        this.retiringViewers.set(oldViewer, setTimeout(() => {
            this.retiringViewers.delete(oldViewer);
            try { oldViewer.close(); } catch { /* ignore */ }
        }, 2000));
    }

    /**
     * The latest H264 keyframe (Annex-B) from the active viewer, if one is currently connected.
     * Returns undefined when the camera is idle (no live video is flowing).
     */
    getKeyframe(): Buffer | undefined {
        return this.viewer?.getKeyframe();
    }

    /**
     * @param force ask the details supplier to bypass any active API backoff. Set for viewer
     * creation driven by a consumer actually asking for video, so a user pressing play retries now;
     * the scheduled rollover leaves it unset and respects the backoff.
     */
    private async ensureViewer(force = false): Promise<LiveKitViewer> {
        if (this.abort.signal.aborted)
            throw new Error('LiveKit stream closed.');
        if (this.viewer && this.viewer.isHealthy())
            return this.viewer;

        if (this.viewer) {
            // Unhealthy but not yet torn down: close it (which fires onClosed and clears
            // viewer/viewerPromise) so the request below builds a fresh session instead of being
            // handed the dead one via the stale viewerPromise.
            try { this.viewer.close(); } catch { /* ignore */ }
            this.viewer = undefined;
            this.viewerPromise = undefined;
        }

        if (!this.viewerPromise) {
            this.viewerPromise = (async () => {
                const details = await this.getDetails(force);
                const viewer = await startLiveKitViewer(details, this.console, this.debug, this.makeSinks(++this.genCounter), this.abort.signal);
                if (this.abort.signal.aborted) {
                    viewer.close();
                    throw new Error('LiveKit stream closed.');
                }
                this.dlog('SS:LiveKit subscriber connected; bridging to Scrypted.',
                    'video=', viewer.videoCodec?.mimeType ?? false,
                    'audio=', viewer.audioCodec?.mimeType ?? false);
                this.viewer = viewer;
                viewer.onClosed(() => {
                    if (this.viewer === viewer) {
                        this.viewer = undefined;
                        this.viewerPromise = undefined;
                        this.fireStreamEnded();
                    }
                });
                this.scheduleRollover(viewer);
                return viewer;
            })();
            this.viewerPromise.catch(() => { this.viewerPromise = undefined; });
        }
        return this.viewerPromise;
    }

    async startSession(session: RTCSignalingSession): Promise<RTCSessionControl> {
        await this.ensureViewer(true);
        if (this.abort.signal.aborted)
            throw new Error('LiveKit stream closed.');
        this.refcount++;
        let released = false;
        const release = () => {
            if (!released) {
                released = true;
                this.release();
            }
        };
        try {
            return await bridgeToScryptedSession(session, this, this.console, release);
        }
        catch (err) {
            release();
            throw err;
        }
    }

    /**
     * Acquire the shared talk-back sink for the device-level Intercom path (used by non-WebRTC
     * consumers). Ensures a connection exists (so talk-back works even if nothing is actively
     * viewing) and holds a refcount for the duration. Each write claims the current viewer's mic,
     * unmutes it and rewrites RTP through the same shared path as WebRTC talk-back. The sink
     * follows session rollovers and release drops its refcount.
     */
    async acquireMicSink(): Promise<{ writeRtp: (rtp: RtpPacket) => void; release: () => void }> {
        const viewer = await this.ensureViewer();
        if (this.abort.signal.aborted)
            throw new Error('LiveKit stream closed.');
        this.refcount++;
        this.micSinkHolds++;
        let released = false;
        const micToken = {};
        const release = () => {
            if (released)
                return;
            released = true;
            this.micSinkHolds = Math.max(0, this.micSinkHolds - 1);
            this.release();
        };
        try {
            await viewer.ensureMicTrack();
            return {
                writeRtp: rtp => {
                    const current = this.viewer;
                    if (released || !current?.claimMic(micToken))
                        return;
                    const track = current.getMicTrack();
                    if (!track) {
                        current.ensureMicTrack().catch(err =>
                            this.dlog('SS:LiveKit intercom mic publish failed.', err));
                        return;
                    }
                    rtp.header.payloadType = track.codec?.payloadType ?? 111;
                    current.writeMic(rtp);
                },
                release,
            };
        }
        catch (err) {
            release();
            throw err;
        }
    }

    private release(): void {
        this.refcount = Math.max(0, this.refcount - 1);
        if (this.refcount === 0) {
            if (this.rolloverTimer)
                clearTimeout(this.rolloverTimer);
            this.viewer?.close();
            this.viewer = undefined;
            this.viewerPromise = undefined;
        }
    }
}

async function bridgeToScryptedSession(
    session: RTCSignalingSession,
    stream: LiveKitCameraStream,
    console: ConsoleLike,
    onEnd: () => void,
): Promise<RTCSessionControl> {

    // Match the consumer peer connection's codecs to what LiveKit negotiated so RTP can be
    // forwarded without transcoding (payload types line up).
    const videoCodec = stream.videoCodec;
    const audioCodec = stream.audioCodec;
    const codecs: { video?: RTCRtpCodecParameters[]; audio?: RTCRtpCodecParameters[] } = {};
    if (videoCodec)
        codecs.video = [videoCodec];
    if (audioCodec)
        codecs.audio = [audioCodec];

    const consumerPc = new RTCPeerConnection({
        bundlePolicy: 'max-bundle',
        codecs,
    });

    // The relays outlive this session (they are camera-lifetime), so every subscription made here
    // must be disposed on session end — otherwise each session permanently leaks a per-packet
    // callback writing into its dead tracks.
    const sessionDisposers: (() => void)[] = [];
    let ended = false;
    const control = new SimplisafeRTCSessionControl(() => {
        ended = true;
        for (const dispose of sessionDisposers.splice(0)) {
            try { dispose(); } catch { /* ignore */ }
        }
        try { consumerPc.close().catch(() => { /* ignore */ }); } catch { /* ignore */ }
        onEnd();
    });

    // Outbound video, fed from the stream's stable relay (survives session rollovers).
    const videoOut = new MediaStreamTrack({ kind: 'video' });
    consumerPc.addTransceiver(videoOut, { direction: 'sendonly' });
    sessionDisposers.push(stream.videoRelay.onReceiveRtp.subscribe(rtp => videoOut.writeRtp(rtp)).unSubscribe);

    // Audio is bidirectional. We send the camera's audio to the consumer AND accept talk-back (the
    // viewer's microphone) on the same transceiver: Scrypted's WebRTC plugin implements HomeKit
    // two-way audio by pushing the mic audio back over THIS peer connection (it requests sendrecv),
    // not by calling the device's Intercom. Any inbound audio is forwarded up to the LiveKit
    // publisher so it reaches the camera.
    if (audioCodec) {
        const audioOut = new MediaStreamTrack({ kind: 'audio' });
        consumerPc.addTransceiver(audioOut, { direction: 'sendrecv' });
        sessionDisposers.push(stream.audioRelay.onReceiveRtp.subscribe(rtp => audioOut.writeRtp(rtp)).unSubscribe);
    }
    else {
        consumerPc.addTransceiver('audio', { direction: 'recvonly' });
    }

    // Forward inbound talk-back audio into the shared LiveKit mic track. The track is published once
    // (lazily, on first audio) and reused across every session, so re-publishing/renegotiation never
    // happens — that was corrupting the shared publisher after the first talk-back. Only the session
    // that currently owns the mic (claimMic) writes RTP: mixing two sessions into the one sender
    // corrupts it and breaks talk-back for everyone.
    let micStarting = false;
    const micToken = {};
    consumerPc.onTrack.subscribe(track => {
        if (track.kind !== 'audio')
            return;
        track.onReceiveRtp.subscribe(rtp => {
            // Take (or keep) exclusive ownership of the shared mic; bail if another session is talking.
            if (!stream.claimMic(micToken))
                return;
            if (ended)
                return;
            // A replacement viewer has its own publisher. Check that viewer's actual track,
            // rather than retaining a successful-publication flag from the previous session.
            if (!stream.getMicTrack() && !micStarting) {
                micStarting = true;
                stream.ensureMicTrack()
                    .catch(err => console.warn('SS:LiveKit talk-back publish failed.', err))
                    .finally(() => { micStarting = false; });
            }
            if (!stream.getMicTrack())
                return;
            // Forward into the shared mic track with monotonic sequence/timestamp rewriting.
            stream.writeMic(rtp);
        });
    });

    const weriftSession = new WeriftSignalingSession(console, consumerPc);
    const consumerSetup: Partial<RTCAVSignalingSetup> = {
        audio: { direction: 'sendrecv' },
        video: { direction: 'sendonly' },
    };
    const sessionSetup: Partial<RTCAVSignalingSetup> = {
        audio: { direction: 'sendrecv' },
        video: { direction: 'recvonly' },
    };

    consumerPc.connectionStateChange.subscribe(state => {
        if (state === 'failed' || state === 'closed')
            control.endSession().catch(() => { /* ignore */ });
    });
    // End the consumer session only when the stream truly ends (active session died with no
    // replacement) — NOT on session rollovers, which consumers ride through via the relays.
    sessionDisposers.push(stream.onStreamEnded(() => {
        control.endSession().catch(() => { /* ignore */ });
    }));

    try {
        // A consumer supplying its own offer must be the offering side.
        const options = session.options ?? await session.getOptions?.();
        if (ended)
            throw new Error('SimpliSafe consumer session ended during negotiation.');
        if (options?.offer)
            await connectRTCSignalingClients(console, session, sessionSetup, weriftSession, consumerSetup);
        else
            await connectRTCSignalingClients(console, weriftSession, consumerSetup, session, sessionSetup);
        if (ended)
            throw new Error('SimpliSafe consumer session ended during negotiation.');
    } catch (err) {
        await control.endSession();
        throw err;
    }

    return control;
}

/**
 * Returned to Scrypted's WebRTC plugin. Must be a class instance (not a plain object literal) so
 * Scrypted's RPC passes it by reference/proxy instead of trying to structured-clone its methods.
 */
class SimplisafeRTCSessionControl implements RTCSessionControl {
    private ended = false;

    constructor(private teardown: () => void) {
    }

    async getRefreshAt(): Promise<number | void> {
        // The shared stream owns token-expiry rollover for all consumers. Asking Scrypted to
        // refresh each consumer separately would unnecessarily renegotiate their peer connections.
        return undefined;
    }

    async extendSession(): Promise<void> {
    }

    async setPlayback(): Promise<void> {
    }

    async endSession(): Promise<void> {
        if (this.ended)
            return;
        this.ended = true;
        this.teardown();
    }
}

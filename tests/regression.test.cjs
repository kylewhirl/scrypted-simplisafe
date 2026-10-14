const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { EventEmitter } = require('node:events');
const ts = require('typescript');
// Load the SDK's generated runtime enums without initializing a Scrypted host.
const sdkTypes = {};
vm.runInNewContext(fs.readFileSync(path.resolve(__dirname, '../node_modules/@scrypted/sdk/dist/types/gen/index.js'), 'utf8'), { exports: sdkTypes });
const protocol = require('@livekit/protocol');

const quiet = { log() {}, warn() {}, error() {} };
class Signal {
    listeners = new Set();
    subscribe(fn) {
        this.listeners.add(fn);
        return { unSubscribe: () => this.listeners.delete(fn) };
    }
    emit(value) { for (const fn of [...this.listeners]) fn(value); }
}
class Track {
    onReceiveRtp = new Signal();
    constructor(options) { Object.assign(this, options); }
    writeRtp(packet) { this.onReceiveRtp.emit(packet); }
}
function clock() {
    const timers = new Map();
    const set = (fn, ms, repeat) => { const id = {}; timers.set(id, { fn, ms, repeat }); return id; };
    return {
        timers,
        setTimeout: (fn, ms) => set(fn, ms, false),
        setInterval: (fn, ms) => set(fn, ms, true),
        clearTimeout: id => timers.delete(id),
        clearInterval: id => timers.delete(id),
        fire(ms) {
            for (const [id, t] of [...timers]) {
                if (t.ms !== ms || !timers.has(id)) continue;
                if (!t.repeat) timers.delete(id);
                t.fn();
            }
        },
    };
}
function load(file, mocks, timer, extraExports = '') {
    const filename = path.resolve(__dirname, '..', 'src', file + '.ts');
    const code = ts.transpileModule(fs.readFileSync(filename, 'utf8') + extraExports, {
        compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS, esModuleInterop: true },
    }).outputText;
    const exports = {};
    vm.runInNewContext(code, {
        exports, require: name => name in mocks ? mocks[name] : require(name),
        Buffer, URL, URLSearchParams, process, console: quiet, AbortController,
        setTimeout: timer.setTimeout, clearTimeout: timer.clearTimeout,
        setInterval: timer.setInterval, clearInterval: timer.clearInterval,
    }, { filename });
    return exports;
}
function liveHarness() {
    const timer = clock();
    const sockets = [];
    const peers = [];
    class Socket extends EventEmitter {
        static OPEN = 1;
        static CONNECTING = 0;
        readyState = 0;
        sent = [];
        constructor(url) { super(); this.url = url; sockets.push(this); }
        send(data) { this.sent.push(data); }
        close() { this.readyState = 3; this.closed = true; this.emit('close'); }
        terminate() { this.close(); }
        open() { this.readyState = 1; this.emit('open'); }
        signal(message) { this.emit('message', Buffer.from(new protocol.SignalResponse({ message }).toBinary())); }
    }
    class Peer {
        connectionState = 'new';
        iceConnectionState = 'new';
        connectionStateChange = new Signal();
        iceConnectionStateChange = new Signal();
        onIceCandidate = new Signal();
        onTrack = new Signal();
        transceivers = [];
        constructor(config) { this.config = config; peers.push(this); }
        async close() { this.closed = true; this.connectionState = 'closed'; this.connectionStateChange.emit('closed'); }
        addTransceiver(track, options) { const t = { sender: {}, track, options }; this.transceivers.push(t); return t; }
        getTransceivers() { return this.transceivers; }
        async createOffer() { return { type: 'offer', sdp: '' }; }
        async createAnswer() { return { type: 'answer', sdp: '' }; }
        async setLocalDescription() {}
        async setRemoteDescription() {}
        async addIceCandidate() {}
    }
    const werift = {
        RTCPeerConnection: Peer, MediaStreamTrack: Track,
        RTCRtpCodecParameters: class { constructor(options) { Object.assign(this, options); } },
        RTCIceCandidate: class {}, RtpPacket: { deSerialize: b => b },
    };
    const lib = load('livekit', { ws: Socket, '@koush/werift': werift }, timer,
        '\nexport { startLiveKitViewer, bridgeToScryptedSession, H264KeyframeCapturer, RtpRebaser };');
    return { timer, sockets, peers, werift, ...lib };
}
const details = { liveKitURL: 'wss://fixture.invalid', userToken: 'fixture' };
const flush = async () => { for (let i = 0; i < 20; i++) await Promise.resolve(); };
async function connect(h, start) {
    const result = start();
    await flush();
    const ws = h.sockets.at(-1);
    ws.open();
    await flush();
    ws.signal({ case: 'join', value: new protocol.JoinResponse({ pingInterval: 30 }) });
    await flush();
    const peer = h.peers.at(-1);
    h.timer.fire(100);
    peer.connectionState = 'connected';
    peer.onTrack.emit(new Track({ kind: 'video', codec: { mimeType: 'video/H264' } }));
    peer.onTrack.emit(new Track({ kind: 'audio', codec: { mimeType: 'audio/opus' } }));
    peer.connectionStateChange.emit('connected');
    await flush();
    return result;
}

test('websocket open timeout tears down the failed attempt', async () => {
    const h = liveHarness();
    const pending = h.startLiveKitViewer(details, quiet, () => false, { video() {}, audio() {} });
    const rejected = assert.rejects(pending, /timed out/);
    h.timer.fire(15000);
    await rejected;
    assert.equal(h.sockets[0].closed, true);
    assert.equal(h.timer.timers.size, 0);
});
test('subscriber timeout without join clears polling and socket', async () => {
    const h = liveHarness();
    const pending = h.startLiveKitViewer(details, quiet, () => false, { video() {}, audio() {} });
    h.sockets[0].open(); await flush();
    const rejected = assert.rejects(pending, /timed out/);
    h.timer.fire(30000); await rejected;
    assert.equal(h.sockets[0].closed, true);
    assert.equal(h.timer.timers.size, 0);
});
test('subscriber timeout after join closes the peer and heartbeat', async () => {
    const h = liveHarness();
    const pending = h.startLiveKitViewer(details, quiet, () => false, { video() {}, audio() {} });
    h.sockets[0].open(); await flush();
    h.sockets[0].signal({ case: 'join', value: new protocol.JoinResponse({ pingInterval: 30 }) });
    await flush(); h.timer.fire(100);
    const rejected = assert.rejects(pending, /timed out/);
    h.timer.fire(30000); await rejected;
    assert.equal(h.peers[0].closed, true);
    assert.equal(h.timer.timers.size, 0);
});
test('early websocket close rejects immediately and clears timers', async () => {
    const h = liveHarness();
    const pending = h.startLiveKitViewer(details, quiet, () => false, { video() {}, audio() {} });
    const rejected = assert.rejects(pending, /closed/);
    h.sockets[0].close(); await rejected;
    assert.equal(h.timer.timers.size, 0);
});
test('device stream disposal cancels a pending join and prevents restart', async () => {
    const h = liveHarness();
    const stream = new h.LiveKitCameraStream(async () => details, quiet, () => false);
    const pending = stream.acquireMicSink();
    await flush();
    const rejected = assert.rejects(pending, /closed/);
    stream.close(); await rejected;
    assert.equal(h.sockets[0].closed, true);
    assert.equal(h.timer.timers.size, 0);
    await assert.rejects(stream.acquireMicSink(), /closed/);
    assert.equal(h.sockets.length, 1);
});
test('already connected video before polling completes startup and runtime error closes viewer', async () => {
    const h = liveHarness();
    const pending = h.startLiveKitViewer(details, quiet, () => false, { video() {}, audio() {} });
    h.sockets[0].open(); await flush();
    h.sockets[0].signal({ case: 'join', value: new protocol.JoinResponse({ pingInterval: 30 }) });
    await flush();
    h.peers[0].connectionState = 'connected';
    h.peers[0].onTrack.emit(new Track({ kind: 'video' }));
    h.timer.fire(100);
    const viewer = await pending;
    let closed = 0;
    viewer.onClosed(() => closed++);
    h.sockets[0].emit('error', Error('fixture network failure'));
    assert.equal(viewer.isHealthy(), false);
    assert.equal(h.peers[0].closed, true);
    assert.equal(closed, 1);
    assert.equal(h.timer.timers.size, 0);
});
test('consumer negotiation failure closes peer and unsubscribes RTP relays', async () => {
    const h = liveHarness();
    const stream = new h.LiveKitCameraStream(async () => details, quiet, () => false);
    let ends = 0;
    await assert.rejects(h.bridgeToScryptedSession({ getOptions: async () => { throw Error('fixture negotiation failure'); } }, stream, quiet, () => ends++), /fixture/);
    assert.equal(h.peers[0].closed, true);
    assert.equal(stream.videoRelay.onReceiveRtp.listeners.size, 0);
    assert.equal(stream.audioRelay.onReceiveRtp.listeners.size, 0);
    assert.equal(ends, 1);
});
test('asynchronous local SDP failure rejects negotiation and cleans up', async () => {
    const h = liveHarness();
    const stream = new h.LiveKitCameraStream(async () => details, quiet, () => false);
    h.werift.RTCPeerConnection.prototype.setLocalDescription = async () => { throw Error('fixture local SDP failure'); };
    const session = { options: { offer: { type: 'offer', sdp: '' } }, createLocalDescription: async () => ({ type: 'offer', sdp: '' }), setRemoteDescription: async () => {} };
    await assert.rejects(h.bridgeToScryptedSession(session, stream, quiet, () => {}), /local SDP failure/);
    assert.equal(h.peers[0].closed, true);
    assert.equal(stream.videoRelay.onReceiveRtp.listeners.size, 0);
});
test('one failed consumer negotiation preserves an existing viewer and its refcount', async () => {
    const h = liveHarness();
    const stream = new h.LiveKitCameraStream(async () => details, quiet, () => false);
    const session = { options: { offer: { type: 'offer', sdp: '' } }, createLocalDescription: async () => ({ type: 'offer', sdp: '' }), setRemoteDescription: async () => {} };
    const control = await connect(h, () => stream.startSession(session));
    await assert.rejects(stream.startSession({ getOptions: async () => { throw Error('fixture failed consumer'); } }), /fixture/);
    assert.equal(h.sockets[0].closed, undefined);
    assert.equal(h.peers[0].closed, undefined);
    assert.equal(stream.videoRelay.onReceiveRtp.listeners.size, 1);
    await control.endSession();
    assert.equal(h.sockets[0].closed, true);
    assert.equal(h.timer.timers.size, 0);
});
test('stream disposal closes active consumer, upstream, and relay subscriptions', async () => {
    const h = liveHarness();
    const stream = new h.LiveKitCameraStream(async () => details, quiet, () => false);
    const session = { options: { offer: { type: 'offer', sdp: '' } }, createLocalDescription: async () => ({ type: 'offer', sdp: '' }), setRemoteDescription: async () => {} };
    const control = await connect(h, () => stream.startSession(session));
    stream.close(); await control.endSession();
    assert.ok(h.peers.every(p => p.closed));
    assert.ok(h.sockets.every(s => s.closed));
    assert.equal(stream.videoRelay.onReceiveRtp.listeners.size, 0);
    assert.equal(stream.audioRelay.onReceiveRtp.listeners.size, 0);
    assert.equal(h.timer.timers.size, 0);
});
test('publisher failure closes failed peer and allows clean retry', async () => {
    const h = liveHarness();
    const viewer = await connect(h, () => h.startLiveKitViewer(details, quiet, () => false, { video() {}, audio() {} }));
    const Peer = h.werift.RTCPeerConnection;
    const originalOffer = Peer.prototype.createOffer;
    Peer.prototype.createOffer = async () => { throw Error('fixture publisher failure'); };
    await assert.rejects(viewer.ensureMicTrack(), /fixture/);
    assert.equal(h.peers[1].closed, true);
    assert.equal(viewer.getMicTrack(), undefined);
    Peer.prototype.createOffer = originalOffer;
    assert.ok(await viewer.ensureMicTrack());
    assert.equal(h.peers.length, 3);
    viewer.close();
    assert.ok(h.peers.every(p => p.closed));
    assert.equal(h.timer.timers.size, 0);
});
for (const failure of ['answer', 'connection']) {
    test(`publisher ${failure} failure clears the mic and republishes on retry`, async () => {
        const h = liveHarness();
        const viewer = await connect(h, () => h.startLiveKitViewer(details, quiet, () => false, { video() {}, audio() {} }));
        await viewer.ensureMicTrack();
        const publisher = h.peers[1];
        if (failure === 'answer') {
            publisher.setRemoteDescription = async () => { throw Error('fixture publisher answer failure'); };
            h.sockets[0].signal({ case: 'answer', value: new protocol.SessionDescription({ type: 'answer', sdp: '' }) });
            await flush();
        } else {
            publisher.connectionStateChange.emit('failed');
        }
        assert.equal(publisher.closed, true);
        assert.equal(viewer.getMicTrack(), undefined);
        await viewer.ensureMicTrack();
        assert.equal(h.peers.length, 3);
        viewer.close();
        assert.equal(h.timer.timers.size, 0);
    });
}
test('device mic sink shares ownership, unmutes after WebRTC, and rebases RTP', async () => {
    const h = liveHarness();
    const stream = new h.LiveKitCameraStream(async () => details, quiet, () => false);
    const sink = await connect(h, () => stream.acquireMicSink());
    const viewer = stream.viewer;
    const sent = [];
    viewer.getMicTrack().onReceiveRtp.subscribe(packet => sent.push({ ...packet.header }));
    h.sockets[0].signal({ case: 'trackPublished', value: new protocol.TrackPublishedResponse({ track: new protocol.TrackInfo({ sid: 'fixture-mic', type: protocol.TrackType.AUDIO }) }) });
    await flush();
    assert.equal(viewer.claimMic({}), true);
    viewer.writeMic({ header: { sequenceNumber: 1, timestamp: 1 } });
    sink.writeRtp({ header: { sequenceNumber: 500, timestamp: 500 } });
    assert.equal(sent.length, 1); // Another consumer owns the microphone.
    h.timer.fire(800);
    sink.writeRtp({ header: { sequenceNumber: 500, timestamp: 500 } });
    assert.equal(sent.length, 2);
    assert.equal(sent[1].sequenceNumber, (sent[0].sequenceNumber + 1) & 0xffff);
    assert.equal(sent[1].timestamp, (sent[0].timestamp + 960) >>> 0);
    const mutes = h.sockets[0].sent.map(bytes => protocol.SignalRequest.fromBinary(bytes).message).filter(m => m.case === 'mute').map(m => m.value.muted);
    assert.deepEqual(mutes, [true, false]);
    sink.release();
    assert.equal(h.timer.timers.size, 0);
});
test('late publisher negotiation rejection cannot clear its replacement', async () => {
    const h = liveHarness();
    const viewer = await connect(h, () => h.startLiveKitViewer(details, quiet, () => false, { video() {}, audio() {} }));
    await viewer.ensureMicTrack();
    const old = h.peers[1];
    let rejectAnswer;
    old.setRemoteDescription = () => new Promise((resolve, reject) => { rejectAnswer = reject; });
    h.sockets[0].signal({ case: 'answer', value: new protocol.SessionDescription({ type: 'answer', sdp: '' }) });
    await flush();
    old.connectionStateChange.emit('failed');
    const replacementTrack = await viewer.ensureMicTrack();
    rejectAnswer(Error('late old answer failure')); await flush();
    old.connectionStateChange.emit('closed');
    assert.equal(viewer.getMicTrack(), replacementTrack);
    assert.equal(h.peers[2].closed, undefined);
    viewer.close();
});
test('rollover retains the consumer and republishes its mic on the new viewer', async () => {
    const h = liveHarness();
    const stream = new h.LiveKitCameraStream(async () => details, quiet, () => false);
    const session = { options: { offer: { type: 'offer', sdp: '' } }, createLocalDescription: async () => ({ type: 'offer', sdp: '' }), setRemoteDescription: async () => {} };
    const control = await connect(h, () => stream.startSession(session));
    const consumer = h.peers[1];
    const incoming = new Track({ kind: 'audio' });
    consumer.onTrack.emit(incoming);
    const packet = () => ({ header: { sequenceNumber: 1, timestamp: 1 } });
    incoming.writeRtp(packet()); await flush();
    const firstMic = stream.getMicTrack();
    assert.ok(firstMic);
    await connect(h, () => stream.rollover(stream.viewer));
    assert.equal(stream.getMicTrack(), undefined);
    incoming.writeRtp(packet()); await flush();
    assert.ok(stream.getMicTrack());
    assert.notEqual(stream.getMicTrack(), firstMic);
    assert.equal(consumer.closed, undefined);
    h.timer.fire(2000);
    assert.equal(h.sockets[0].closed, true);
    await control.endSession();
    assert.ok(h.peers.every(p => p.closed));
    assert.ok(h.sockets.every(s => s.closed));
    assert.equal(h.timer.timers.size, 0);
});
test('WebRTC talk-back retries failed publication and republishes for replacement viewer', async () => {
    const h = liveHarness();
    const stream = new h.LiveKitCameraStream(async () => details, quiet, () => false);
    let activeTrack;
    let calls = 0;
    let packets = 0;
    stream.claimMic = () => true;
    stream.ensureMicTrack = async () => {
        if (++calls === 1) throw Error('temporary publisher failure');
        await Promise.resolve();
        activeTrack = {};
    };
    stream.getMicTrack = () => activeTrack;
    stream.writeMic = () => { if (activeTrack) packets++; };
    // An existing offer avoids exercising unrelated SDP generation in this fixture.
    const control = await h.bridgeToScryptedSession({ options: { offer: { type: 'offer', sdp: '' } }, createLocalDescription: async () => ({ type: 'offer', sdp: '' }), setRemoteDescription: async () => {} }, stream, quiet, () => {});
    const incoming = new Track({ kind: 'audio' });
    h.peers[0].onTrack.emit(incoming);
    incoming.writeRtp({}); await flush();
    incoming.writeRtp({}); await flush();
    incoming.writeRtp({});
    assert.equal(calls, 2);
    assert.equal(packets, 1);
    activeTrack = undefined; // Replacement viewer has not published a mic yet.
    incoming.writeRtp({}); await flush(); incoming.writeRtp({});
    assert.equal(calls, 3);
    assert.equal(packets, 2);
    await control.endSession();
});

function mainHarness() {
    const h = liveHarness();
    const children = [];
    const udp = [];
    const snapshots = [];
    class Base {
        console = quiet;
        storage = { getItem() { return null; }, setItem() {} };
        state = {};
        constructor(nativeId) { this.nativeId = nativeId; }
        get motionDetected() { return this.state.motionDetected; }
        set motionDetected(value) { this.state.motionDetected = value; }
        createMediaObject(data, mimeType) { return { data, mimeType }; }
    }
    const sdk = {
        ...sdkTypes, ScryptedDeviceBase: Base,
        default: {
            deviceManager: {}, systemManager: {},
            mediaManager: {
                createFFmpegMediaObject: async input => input,
                convertMediaObjectToJSON: async media => media,
                getFFmpegPath: async () => '/fixture/ffmpeg',
            },
        }, __esModule: true,
    };
    const main = load('main', {
        '@scrypted/sdk': sdk, './livekit': h, '@koush/werift': h.werift,
        '../package.json': require('../package.json'),
        'child_process': { spawn() { const cp = new EventEmitter(); cp.stderr = new EventEmitter(); cp.kill = () => { cp.killed = true; }; children.push(cp); return cp; } },
        dgram: { createSocket() { const socket = new EventEmitter(); socket.bind = (port, host, cb) => cb(); socket.address = () => ({ port: 12345 }); socket.close = () => { socket.closed = true; }; udp.push(socket); return socket; } },
        'jpeg-extract': async config => { snapshots.push(config); return Buffer.from('jpeg'); },
    }, h.timer, '\nexport { SimplisafeCamera, SimplisafeApi, deriveCameraNativeId, isLiveKitCameraDetails };');
    function camera(cameraDetails) {
        const c = new main.SimplisafeCamera('fixture-' + Math.random(), cameraDetails.uuid,
            { getAccessToken: async () => 'fixture-token' }, {}, () => false, () => {}, () => {});
        c.updateDetails(cameraDetails);
        return c;
    }
    return { ...h, ...main, camera, children, udp, snapshots };
}
const legacy = { uuid: 'fixture-uuid', name: 'Hall', model: 'SS001', status: 'online', supportedFeatures: { providers: { recording: 'simplisafe' } }, cameraSettings: { pictureQuality: '720p' } };
test('late exit from old intercom does not stop the replacement', async () => {
    const h = mainHarness();
    const c = h.camera({ ...legacy, supportedFeatures: { providers: { webrtc: 'kvs' } } });
    let releases = 0;
    c.liveKitStream = { acquireMicSink: async () => ({ release: () => releases++, writeRtp() {} }), close() {} };
    await c.startIntercom({ inputArguments: [] });
    await c.startIntercom({ inputArguments: [] });
    h.children[0].emit('exit', 0);
    await flush();
    assert.equal(h.children[1].killed, undefined);
    assert.equal(h.udp[1].closed, undefined);
    assert.equal(releases, 1);
    await c.stopIntercom(); c.dispose();
});
test('device disposal releases intercom resources and LiveKit stream', async () => {
    const h = mainHarness();
    const c = h.camera({ ...legacy, supportedFeatures: { providers: { webrtc: 'kvs' } } });
    let closed = 0;
    let releases = 0;
    c.liveKitStream = { acquireMicSink: async () => ({ release: () => releases++, writeRtp() {} }), close: () => closed++ };
    await c.startIntercom({ inputArguments: [] });
    c.dispose(); await flush();
    assert.equal(closed, 1);
    assert.equal(releases, 1);
    assert.equal(h.children[0].killed, true);
    assert.equal(h.udp[0].closed, true);
    c.dispose();
    assert.equal(closed, 1);
});
test('simultaneous intercom starts cancel the superseded request', async () => {
    const h = mainHarness();
    const c = h.camera({ ...legacy, supportedFeatures: { providers: { webrtc: 'kvs' } } });
    c.liveKitStream = { acquireMicSink: async () => ({ release() {}, writeRtp() {} }), close() {} };
    const first = c.startIntercom({ inputArguments: [] });
    const second = c.startIntercom({ inputArguments: [] });
    await assert.rejects(first, /cancelled/);
    await second;
    assert.equal(h.children.length, 1);
    c.dispose();
});
test('device UDP intercom forwards packets through the shared sink', async () => {
    const h = mainHarness();
    const c = h.camera({ ...legacy, supportedFeatures: { providers: { webrtc: 'kvs' } } });
    let packets = 0;
    c.liveKitStream = { acquireMicSink: async () => ({ release() {}, writeRtp: () => packets++ }), close() {} };
    await c.startIntercom({ inputArguments: [] });
    h.udp[0].emit('message', { header: { sequenceNumber: 1, timestamp: 1 } });
    assert.equal(packets, 1);
    c.dispose();
});
test('legacy SimpliCam and SS002 doorbell preserve FLV and verified hostname snapshots', async () => {
    const h = mainHarness();
    for (const info of [legacy, { ...legacy, model: 'SS002' }, { ...legacy, supportedFeatures: {} }]) {
        const c = h.camera(info);
        const stream = await c.getVideoStream();
        assert.equal(stream.container, 'flv');
        assert.ok(stream.inputArguments.includes('-tls_verify'));
        assert.equal(stream.inputArguments.at(-1), 'https://media.simplisafe.com/v1/fixture-uuid/flv?x=1280&audioEncoding=AAC');
        await c.takePicture();
        const snapshot = h.snapshots.at(-1);
        assert.equal(snapshot.url, 'https://media.simplisafe.com/v1/fixture-uuid/mjpg?x=1280&fr=1');
        assert.equal(snapshot.headers.Authorization, 'Bearer fixture-token');
        assert.equal(snapshot.strictSSL, undefined); // request's secure default is retained.
        c.dispose();
    }
});
test('discovery publishes legacy VideoCamera, new RTC/Intercom, and doorbell BinarySensor', async () => {
    const h = mainHarness();
    const p = Object.create(h.default.prototype);
    const published = [];
    p.cameraDetails = new Map();
    p.publishCameraMeta = async (id, metadata) => published.push(metadata);
    for (const info of [legacy, { ...legacy, model: 'SS002' }, { ...legacy, supportedFeatures: { providers: { webrtc: 'kvs' } } }]) {
        p.cameraDetails.set('fixture', info);
        await p.refreshDeviceDescriptor('fixture');
    }
    assert.ok(published[0].interfaces.includes('VideoCamera'));
    assert.ok(published[1].interfaces.includes('VideoCamera'));
    assert.ok(published[1].interfaces.includes('BinarySensor'));
    assert.ok(published[2].interfaces.includes('RTCSignalingChannel'));
    assert.ok(published[2].interfaces.includes('Intercom'));
    assert.ok(!published[2].interfaces.includes('VideoCamera'));
});
test('legacy and doorbell identifiers route motion/presses and reset state', async () => {
    const h = mainHarness();
    const p = Object.create(h.default.prototype);
    p.cameraDetails = new Map(); p.uuidToNativeId = new Map(); p.identifierToNativeIds = new Map();
    const info = { ...legacy, model: 'SS002', serialNumber: 'AA:BB:CC' };
    const id = h.deriveCameraNativeId(info);
    p.cameraDetails.set(id, info);
    p.associateUuidWithNativeId(info.uuid, id);
    p.registerCameraIdentifiers(id, info);
    for (const event of [{ sensorSerial: 'aa:bb:cc' }, { cameraUuid: info.uuid }, { internal: { mainCamera: 'AA:BB:CC' } }])
        assert.deepEqual([...p.resolveNativeIdsFromEvent(event)], [id]);
    const c = h.camera(info);
    c.handleMotionEvent({}); c.handleDoorbellEvent({});
    assert.equal(c.motionDetected, true); assert.equal(c.binaryState, true);
    assert.equal(c.state.motionDetected, true);
    assert.equal(Object.hasOwn(c, 'motionDetected'), false);
    h.timer.fire(5000);
    assert.equal(c.motionDetected, false); assert.equal(c.binaryState, false);
    p.unregisterCameraIdentifiers(id);
    assert.equal(p.identifierToNativeIds.size, 0);
    c.dispose();
});

function apiFixture(h) {
    const api = Object.create(h.SimplisafeApi.prototype);
    api.backoff = new Map(); api.liveViewRequests = new Map(); api.log = quiet;
    api.authManager = { tokenType: 'Bearer', refreshCredentials: async () => {} };
    api.getAccessToken = async () => 'fixture-token';
    return api;
}
function httpError(status, headers = {}) {
    return { isAxiosError: true, response: { status, statusText: 'fixture', headers, data: { message: 'fixture' } } };
}
test('app-hub throttling does not block legacy API and force bypass retries once', async () => {
    const h = mainHarness(); const api = apiFixture(h); let calls = 0;
    api.axios = { request: async config => {
        calls++;
        assert.equal(config.headers.Authorization, 'Bearer fixture-token');
        if (config.url.startsWith('https://app-hub')) throw httpError(429, { 'retry-after': '120' });
        return { data: 'legacy-ok' };
    } };
    const config = { url: 'https://app-hub.prd.aser.simplisafe.com/live-view' };
    await assert.rejects(api.request(config), /rate limited/);
    await assert.rejects(api.request(config), /backing off/);
    assert.equal(calls, 1);
    assert.equal(await api.request({ url: '/subscriptions/fixture' }), 'legacy-ok');
    await assert.rejects(api.request(config, { force: true }), /rate limited/);
    assert.equal(calls, 3);
});
test('401 refreshes once with new token; 403 and local auth failures do not throttle', async () => {
    const h = mainHarness(); const api = apiFixture(h); let calls = 0;
    api.authManager.refreshCredentials = async () => { api.getAccessToken = async () => 'new-fixture-token'; };
    api.axios = { request: async config => {
        if (++calls === 1) throw httpError(401);
        assert.equal(config.headers.Authorization, 'Bearer new-fixture-token');
        return { data: 'ok' };
    } };
    assert.equal(await api.request({ url: '/fixture' }), 'ok');
    assert.equal(calls, 2);
    api.axios.request = async () => { throw httpError(403); };
    await assert.rejects(api.request({ url: '/fixture' }), /403 Forbidden/);
    assert.equal(api.backoff.size, 0);
    api.getAccessToken = async () => { throw Error('fixture auth unavailable'); };
    await assert.rejects(api.request({ url: '/fixture' }), /auth unavailable/);
    assert.equal(api.backoff.size, 0);
});
test('overlapping live-view lookups share request and accept wrapped payload', async () => {
    const h = mainHarness(); const api = apiFixture(h); let calls = 0; let complete;
    api.subId = 'fixture-location'; api.getSubscription = async () => ({});
    api.request = async config => {
        calls++;
        assert.equal(config.url, 'https://app-hub.prd.aser.simplisafe.com/v2/cameras/fixture-uuid/fixture-location/live-view');
        return new Promise(resolve => { complete = resolve; });
    };
    const first = api.getLiveView('fixture-uuid'); const second = api.getLiveView('fixture-uuid');
    await flush(); complete({ data: { liveKitDetails: details } });
    assert.equal((await first).liveKitDetails, details);
    assert.equal((await second).liveKitDetails, details);
    assert.equal(calls, 1);
    assert.equal(api.liveViewRequests.size, 0);
});
test('snapshot keyframe reassembles STAP parameter sets and fragmented IDR', () => {
    const h = liveHarness(); const capturer = new h.H264KeyframeCapturer();
    const packet = (payload, timestamp, marker = false) => ({ payload: Buffer.from(payload), header: { timestamp, marker } });
    capturer.onRtp(packet([24, 0, 2, 0x67, 0x11, 0, 2, 0x68, 0x22], 1, true));
    capturer.onRtp(packet([0x7c, 0x85, 0x33], 2));
    capturer.onRtp(packet([0x7c, 0x45, 0x44], 2, true));
    assert.equal(capturer.keyframe.toString('hex'), '00000001671100000001682200000001653344');
});
test('RTP source switch preserves packet gaps and advances sequence and timestamp', () => {
    const h = liveHarness(); const rebaser = new h.RtpRebaser(90000);
    const packet = (seq, ts) => ({ header: { sequenceNumber: seq, timestamp: ts } });
    assert.equal(rebaser.rebase(1, packet(100, 1000)).header.sequenceNumber, 100);
    assert.equal(rebaser.rebase(1, packet(103, 4000)).header.sequenceNumber, 103);
    const next = rebaser.rebase(2, packet(10, 50));
    assert.equal(next.header.sequenceNumber, 119);
    assert.ok(next.header.timestamp >= 5800);
    const later = rebaser.rebase(2, packet(12, 3050));
    assert.equal(later.header.sequenceNumber, 121);
    assert.equal(later.header.timestamp - next.header.timestamp, 3000);
});

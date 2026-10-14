const { test } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

// These checks exercise the actual locked dependencies. They cover representative ICE/STUN and
// DTLS primitives, not a complete network handshake or a proof that every possible path is safe.
test('Werift ICE/STUN address paths do not use the advised ip.isPublic classifier', () => {
    const ip = require('ip');
    const original = ip.isPublic;
    ip.isPublic = () => { throw Error('advised classifier was invoked'); };
    try {
        const { getHostAddresses } = require('@koush/werift/lib/ice/src/ice');
        const { packXorAddress, unpackXorAddress } = require('@koush/werift/lib/ice/src/stun/attributes');
        assert.ok(Array.isArray(getHostAddresses(true, true)));
        const transaction = Buffer.alloc(12, 1);
        for (const address of ['192.0.2.10', '2001:db8::1']) {
            const packed = packXorAddress([address, 1234], transaction);
            const decoded = unpackXorAddress(packed, transaction);
            assert.equal(decoded[0], address);
            assert.equal(decoded[1], 1234);
        }
    } finally {
        ip.isPublic = original;
    }
});

test('Werift P256 key agreement and DTLS signatures do not use Elliptic ECDSA signing', async () => {
    const elliptic = require('elliptic');
    const original = elliptic.ec.prototype.sign;
    elliptic.ec.prototype.sign = () => { throw Error('advised ECDSA signer was invoked'); };
    try {
        const { generateKeyPair } = require('@koush/werift/lib/dtls/src/cipher/namedCurve');
        const { prfPreMasterSecret } = require('@koush/werift/lib/dtls/src/cipher/prf');
        const { NamedCurveAlgorithm, SignatureAlgorithm, HashAlgorithm } = require('@koush/werift/lib/dtls/src/cipher/const');
        const { CipherContext } = require('@koush/werift/lib/dtls/src/context/cipher');
        const curve = NamedCurveAlgorithm.secp256r1_23;
        const first = generateKeyPair(curve);
        const second = generateKeyPair(curve);
        assert.deepEqual(prfPreMasterSecret(first.publicKey, second.privateKey, curve),
            prfPreMasterSecret(second.publicKey, first.privateKey, curve));
        const signatureHash = { signature: SignatureAlgorithm.ecdsa_3, hash: HashAlgorithm.sha256_4 };
        const { certPem, keyPem } = await CipherContext.createSelfSignedCertificateWithKey(signatureHash, curve);
        const context = new CipherContext(1, certPem, keyPem, signatureHash);
        const data = Buffer.from('synthetic DTLS signature fixture');
        const signature = context.signatureData(data, 'sha256');
        assert.equal(crypto.verify('sha256', data, certPem, signature), true);
        // The server's separate signing path uses @fidm/x509 PrivateKey, backed by node:crypto.
        const serverSignature = context.localPrivateKey.sign(data, 'sha256');
        assert.equal(crypto.verify('sha256', data, certPem, serverSignature), true);
    } finally {
        elliptic.ec.prototype.sign = original;
    }
});

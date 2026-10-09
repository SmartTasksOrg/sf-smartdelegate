package dev.smartdelegate;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Hashing and Ed25519 in the formats every port shares: private keys are
 * base64 of the PKCS#8 (version 1) DER encoding, public keys base64 of the 32
 * raw bytes, and a key id is the first 16 hex characters of sha256(public).
 */
final class Crypto {
    private Crypto() {}

    static final byte[] PKCS8_PREFIX = hex("302e020100300506032b657004220420");
    static final byte[] SPKI_PREFIX = hex("302a300506032b6570032100");

    static byte[] hex(String s) {
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; i++) out[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        return out;
    }

    static String hex(byte[] b) {
        char[] out = new char[b.length * 2];
        for (int i = 0; i < b.length; i++) {
            out[2 * i] = Character.forDigit((b[i] >> 4) & 15, 16);
            out[2 * i + 1] = Character.forDigit(b[i] & 15, 16);
        }
        return new String(out);
    }

    static String sha256Hex(byte[] data) {
        try {
            return hex(MessageDigest.getInstance("SHA-256").digest(data));
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    static String sha256Hex(String s) {
        return sha256Hex(s.getBytes(StandardCharsets.UTF_8));
    }

    static String hashValue(Object v) {
        return sha256Hex(Json.canon(v));
    }

    static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    static String randomHex(int bytes) {
        byte[] b = new byte[bytes];
        new SecureRandom().nextBytes(b);
        return hex(b);
    }

    /** -> {private PKCS#8 base64, public raw base64} */
    static String[] keygen() {
        byte[] seed = new byte[32];
        new SecureRandom().nextBytes(seed);
        return new String[] {Base64.getEncoder().encodeToString(concat(PKCS8_PREFIX, seed)), Base64.getEncoder().encodeToString(publicFromSeed(seed))};
    }

    static byte[] seedOf(String privateB64) {
        byte[] der;
        try {
            der = Base64.getDecoder().decode(privateB64.strip());
        } catch (IllegalArgumentException e) {
            throw new EngineException("crypto", "private key is not base64 Ed25519 PKCS#8");
        }
        if (der.length != 48 || !java.util.Arrays.equals(java.util.Arrays.copyOf(der, 16), PKCS8_PREFIX))
            throw new EngineException("crypto", "private key is not base64 Ed25519 PKCS#8");
        return java.util.Arrays.copyOfRange(der, 16, 48);
    }

    static PrivateKey privateKey(String privateB64) {
        try {
            return KeyFactory.getInstance("Ed25519").generatePrivate(new PKCS8EncodedKeySpec(concat(PKCS8_PREFIX, seedOf(privateB64))));
        } catch (java.security.GeneralSecurityException e) {
            throw new EngineException("crypto", "private key is not Ed25519");
        }
    }

    static byte[] publicRaw(String publicB64) {
        try {
            byte[] raw = Base64.getDecoder().decode(publicB64.strip());
            if (raw.length != 32) throw new IllegalArgumentException();
            return raw;
        } catch (IllegalArgumentException e) {
            throw new EngineException("crypto", "public key is not base64 of 32 raw Ed25519 bytes");
        }
    }

    static PublicKey publicKey(byte[] raw) {
        try {
            return KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(concat(SPKI_PREFIX, raw)));
        } catch (java.security.GeneralSecurityException e) {
            throw new EngineException("crypto", "public key is not Ed25519");
        }
    }

    static String keyId(byte[] publicRaw) {
        return sha256Hex(publicRaw).substring(0, 16);
    }

    static byte[] sign(PrivateKey key, byte[] message) {
        try {
            Signature s = Signature.getInstance("Ed25519");
            s.initSign(key);
            s.update(message);
            return s.sign();
        } catch (java.security.GeneralSecurityException e) {
            throw new EngineException("crypto", "signing failed");
        }
    }

    static boolean verify(PublicKey key, byte[] message, byte[] signature) {
        try {
            Signature s = Signature.getInstance("Ed25519");
            s.initVerify(key);
            s.update(message);
            return s.verify(signature);
        } catch (java.security.GeneralSecurityException e) {
            return false;
        }
    }

    // The JDK can sign with an Ed25519 private key but offers no way to get
    // the public key back from it. This is the textbook derivation
    // (RFC 8032 section 5.1.5); it runs once at start-up, not per request.
    private static final BigInteger P = BigInteger.TWO.pow(255).subtract(BigInteger.valueOf(19));
    private static final BigInteger D = BigInteger.valueOf(-121665).multiply(BigInteger.valueOf(121666).modInverse(P)).mod(P);
    private static final BigInteger BX = new BigInteger("15112221349535400772501151409588531511454012693041857206046113283949847762202");
    private static final BigInteger BY = new BigInteger("46316835694926478169428394003475163141307993866256225615783033603165251855960");

    private static final BigInteger D2 = D.shiftLeft(1).mod(P);

    /**
     * Point addition in extended coordinates (X, Y, Z, T), RFC 8032 section
     * 5.1.4. The formula is complete: it also doubles. No inversion per step,
     * which is what made the affine form slow at start-up.
     */
    private static BigInteger[] add(BigInteger[] p, BigInteger[] q) {
        BigInteger a = p[1].subtract(p[0]).multiply(q[1].subtract(q[0])).mod(P);
        BigInteger b = p[1].add(p[0]).multiply(q[1].add(q[0])).mod(P);
        BigInteger c = p[3].multiply(D2).mod(P).multiply(q[3]).mod(P);
        BigInteger d = p[2].shiftLeft(1).multiply(q[2]).mod(P);
        BigInteger e = b.subtract(a), f = d.subtract(c), g = d.add(c), h = b.add(a);
        return new BigInteger[] {e.multiply(f).mod(P), g.multiply(h).mod(P), f.multiply(g).mod(P), e.multiply(h).mod(P)};
    }

    static byte[] publicFromSeed(byte[] seed) {
        byte[] h;
        try {
            h = MessageDigest.getInstance("SHA-512").digest(seed);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
        h[0] &= (byte) 248;
        h[31] &= 127;
        h[31] |= 64;
        byte[] be = new byte[32];
        for (int i = 0; i < 32; i++) be[i] = h[31 - i];
        BigInteger scalar = new BigInteger(1, be);
        BigInteger[] acc = {BigInteger.ZERO, BigInteger.ONE, BigInteger.ONE, BigInteger.ZERO};
        BigInteger[] base = {BX, BY, BigInteger.ONE, BX.multiply(BY).mod(P)};
        for (int i = 0; i < 255; i++) {
            if (scalar.testBit(i)) acc = add(acc, base);
            base = add(base, base);
        }
        BigInteger zinv = acc[2].modInverse(P);
        acc = new BigInteger[] {acc[0].multiply(zinv).mod(P), acc[1].multiply(zinv).mod(P)};
        byte[] y = acc[1].toByteArray();
        byte[] out = new byte[32];
        for (int i = 0; i < 32 && i < y.length; i++) out[i] = y[y.length - 1 - i];
        if (acc[0].testBit(0)) out[31] |= (byte) 0x80;
        return out;
    }
}

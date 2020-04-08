package com.github.netricecake.ecdh;

import java.security.InvalidParameterException;
import java.security.SecureRandom;

public class Curve25519 {

    private static long[] add(long[] in1, long[] in2) {
        long[] result = new long[10];

        for (int i = 0; i < 10; i++)
            result[i] = in1[i] + in2[i];

        return result;
    }

    private static long[] subtract(long[] in1, long[] in2) {
        long c;
        long[] result = new long[10];
        result[0] = (c = 0x7ffffda + in1[0] - in2[0]) & 0x3ffffff;

        for (int i = 1; i < 10; i++)
            if (i % 2 != 0)
                result[i] = (c = 0x3fffffe + in1[i] - in2[i] + (c >>> 26)) & 0x1ffffff;
            else
                result[i] = (c = 0x7fffffe + in1[i] - in2[i] + (c >>> 25)) & 0x3ffffff;

        result[0] += 19 * (c >>> 25);

        return result;
    }

    private static long[] multiply(long[] in1, long[] in2) {
        long[] result = new long[10];

        long[] r = {
                ((in1[0])) * (in2[0]),
                ((in1[0])) * (in2[1]) + ((in1[1])) * (in2[0]),
                2 * ((in1[1])) * (in2[1]) + ((in1[0])) * (in2[2]) + ((in1[2])) * (in2[0]),
                ((in1[1])) * (in2[2]) + ((in1[2])) * (in2[1]) + ((in1[0])) * (in2[3]) + ((in1[3])) * (in2[0]),
                ((in1[2])) * (in2[2]) + 2 * (((in1[1])) * (in2[3]) + ((in1[3])) * (in2[1])) + ((in1[0])) * (in2[4]) + ((in1[4])) * (in2[0]),
                ((in1[2])) * (in2[3]) + ((in1[3])) * (in2[2]) + ((in1[1])) * (in2[4]) + ((in1[4])) * (in2[1]) + ((in1[0])) * (in2[5]) + ((in1[5])) * (in2[0]),
                2 * (((in1[3])) * (in2[3]) + ((in1[1])) * (in2[5]) + ((in1[5])) * (in2[1])) + ((in1[2])) * (in2[4]) + ((in1[4])) * (in2[2]) + ((in1[0])) * (in2[6]) + ((in1[6])) * (in2[0]),
                ((in1[3])) * (in2[4]) + ((in1[4])) * (in2[3]) + ((in1[2])) * (in2[5]) + ((in1[5])) * (in2[2]) + ((in1[1])) * (in2[6]) + ((in1[6])) * (in2[1]) + ((in1[0])) * (in2[7]) + ((in1[7])) * (in2[0]),
                ((in1[4])) * (in2[4]) + 2 * (((in1[3])) * (in2[5]) + ((in1[5])) * (in2[3]) + ((in1[1])) * (in2[7]) + ((in1[7])) * (in2[1])) + ((in1[2])) * (in2[6]) + ((in1[6])) * (in2[2]) + ((in1[0])) * (in2[8]) + ((in1[8])) * (in2[0]),
                ((in1[4])) * (in2[5]) + ((in1[5])) * (in2[4]) + ((in1[3])) * (in2[6]) + ((in1[6])) * (in2[3]) + ((in1[2])) * (in2[7]) + ((in1[7])) * (in2[2]) + ((in1[1])) * (in2[8]) + ((in1[8])) * (in2[1]) + ((in1[0])) * (in2[9]) + ((in1[9])) * (in2[0]),
                2 * (((in1[5])) * (in2[5]) + ((in1[3])) * (in2[7]) + ((in1[7])) * (in2[3]) + ((in1[1])) * (in2[9]) + ((in1[9])) * (in2[1])) + ((in1[4])) * (in2[6]) + ((in1[6])) * (in2[4]) + ((in1[2])) * (in2[8]) + ((in1[8])) * (in2[2]),
                ((in1[5])) * (in2[6]) + ((in1[6])) * (in2[5]) + ((in1[4])) * (in2[7]) + ((in1[7])) * (in2[4]) + ((in1[3])) * (in2[8]) + ((in1[8])) * (in2[3]) + ((in1[2])) * (in2[9]) + ((in1[9])) * (in2[2]),
                ((in1[6])) * (in2[6]) + 2 * (((in1[5])) * (in2[7]) + ((in1[7])) * (in2[5]) + ((in1[3])) * (in2[9]) + ((in1[9])) * (in2[3])) + ((in1[4])) * (in2[8]) + ((in1[8])) * (in2[4]),
                ((in1[6])) * (in2[7]) + ((in1[7])) * (in2[6]) + ((in1[5])) * (in2[8]) + ((in1[8])) * (in2[5]) + ((in1[4])) * (in2[9]) + ((in1[9])) * (in2[4]),
                2 * (((in1[7])) * (in2[7]) + ((in1[5])) * (in2[9]) + ((in1[9])) * (in2[5])) + ((in1[6])) * (in2[8]) + ((in1[8])) * (in2[6]),
                ((in1[7])) * (in2[8]) + ((in1[8])) * (in2[7]) + ((in1[6])) * (in2[9]) + ((in1[9])) * (in2[6]),
                ((in1[8])) * (in2[8]) + 2 * (((in1[7])) * (in2[9]) + ((in1[9])) * (in2[7])),
                ((in1[8])) * (in2[9]) + ((in1[9])) * (in2[8]),
                2 * ((in1[9])) * (in2[9])
        };

        r[8] += (r[18] << 4) + (r[18] << 1) + r[18];
        r[7] += (r[17] << 4) + (r[17] << 1) + r[17];
        r[6] += (r[16] << 4) + (r[16] << 1) + r[16];
        r[5] += (r[15] << 4) + (r[15] << 1) + r[15];
        r[4] += (r[14] << 4) + (r[14] << 1) + r[14];
        r[3] += (r[13] << 4) + (r[13] << 1) + r[13];
        r[2] += (r[12] << 4) + (r[12] << 1) + r[12];
        r[1] += (r[11] << 4) + (r[11] << 1) + r[11];
        r[0] += (r[10] << 4) + (r[10] << 1) + r[10];

        r[10] = 0;

        long c;

        for (int i = 0; i < 10; i++)
            if(i % 2 == 0) {
                c = r[i] + (((r[i] >>> 32) >>> 31) >>> 6) >>> 26;
                r[i] -= c << 26;
                r[i + 1] += c;
            } else {
                c = r[i] + (((r[i] >>> 32) >>> 31) >>> 7) >>> 25;
                r[i] -= c << 25;
                r[i + 1] += c;
            }

        r[0] += (r[10] << 4) + (r[10] << 1) + r[10];

        r[10] = 0;

        c = r[0] + (((r[0] >>> 32) >>> 31) >>> 6) >>> 26;
        r[0] -= c << 26;
        r[1] += c;

        c = (r[1] + ((r[1] >>> 31) >>> 7)) >>> 25;
        r[1] -= c << 25;
        r[2] += c;

        System.arraycopy(r, 0, result,0, 10);

        return result;

    }

    private static long[] square(long[] in) {
        return square(in, 1);
    }

    private static long[] square(long[] in1, int in2) {

        long[] result = new long[10];
        System.arraycopy(in1, 0, result, 0, 10);

        do {
            long[] t = {
                    ((result[0])) * (result[0]),
                    2 * ((result[0])) * (result[1]),
                    2 * (((result[1])) * (result[1]) + ((result[0])) * (result[2])),
                    2 * (((result[1])) * (result[2]) + ((result[0])) * (result[3])),
                    ((result[2])) * (result[2]) + 4 * ((result[1])) * (result[3]) + 2 * ((result[0])) * (result[4]),
                    2 * (((result[2])) * (result[3]) + ((result[1])) * (result[4]) + ((result[0])) * (result[5])),
                    2 * (((result[3])) * (result[3]) + ((result[2])) * (result[4]) + ((result[0])) * (result[6]) + 2 * ((result[1])) * (result[5])),
                    2 * (((result[3])) * (result[4]) + ((result[2])) * (result[5]) + ((result[1])) * (result[6]) + ((result[0])) * (result[7])),
                    ((result[4])) * (result[4]) + 2 * (((result[2])) * (result[6]) + ((result[0])) * (result[8]) + 2 * (((result[1])) * (result[7]) + ((result[3])) * (result[5]))),
                    2 * (((result[4])) * (result[5]) + ((result[3])) * (result[6]) + ((result[2])) * (result[7]) + ((result[1])) * (result[8]) + ((result[0])) * (result[9])),
                    2 * (((result[5])) * (result[5]) + ((result[4])) * (result[6]) + ((result[2])) * (result[8]) + 2 * (((result[3])) * (result[7]) + ((result[1])) * (result[9]))),
                    2 * (((result[5])) * (result[6]) + ((result[4])) * (result[7]) + ((result[3])) * (result[8]) + ((result[2])) * (result[9])),
                    ((result[6])) * (result[6]) + 2 * (((result[4])) * (result[8]) + 2 * (((result[5])) * (result[7]) + ((result[3])) * (result[9]))),
                    2 * (((result[6])) * (result[7]) + ((result[5])) * (result[8]) + ((result[4])) * (result[9])),
                    2 * (((result[7])) * (result[7]) + ((result[6])) * (result[8]) + 2 * ((result[5])) * (result[9])),
                    2 * (((result[7])) * (result[8]) + ((result[6])) * (result[9])), ((result[8])) * (result[8]) + 4 * ((result[7])) * (result[9]),
                    2 * ((result[8])) * (result[9]),
                    2 * ((result[9])) * (result[9])
            };

            t[8] += (t[18] << 4) + (t[18] << 1) + t[18];
            t[7] += (t[17] << 4) + (t[17] << 1) + t[17];
            t[6] += (t[16] << 4) + (t[16] << 1) + t[16];
            t[5] += (t[15] << 4) + (t[15] << 1) + t[15];
            t[4] += (t[14] << 4) + (t[14] << 1) + t[14];
            t[3] += (t[13] << 4) + (t[13] << 1) + t[13];
            t[2] += (t[12] << 4) + (t[12] << 1) + t[12];
            t[1] += (t[11] << 4) + (t[11] << 1) + t[11];
            t[0] += (t[10] << 4) + (t[10] << 1) + t[10];

            t[10] = 0;

            long c;

            for (int i = 0; i < 10; i++)
                if(i % 2 == 0) {
                    c = t[i] + (((t[i] >>> 32) >>> 31) >>> 6) >>> 26;
                    t[i] -= c << 26;
                    t[i + 1] += c;
                } else {
                    c = t[i] + (((t[i] >>> 32) >>> 31) >>> 7) >>> 25;
                    t[i] -= c << 25;
                    t[i + 1] += c;
                }

            t[0] += (t[10] << 4) + (t[10] << 1) + t[10];

            t[10] = 0;

            c = t[0] + (((t[0] >>> 32) >>> 31) >>> 6) >>> 26;
            t[0] -= c << 26;
            t[1] += c;

            c = (t[1] + ((t[1] >>> 31) >>> 7)) >>> 25;
            t[1] -= c << 25;
            t[2] += c;

            System.arraycopy(t, 0, result,0, 10);

        } while (--in2 > 0);

        return result;
    }

    private static long[] mul121665(long[] in) {
        long c = 0;
        long[] result = new long[10];
        for (int i = 0; i < 10; i++)
            if (i % 2 == 0)
                result[i] = (c = in[i] * 121665 + (c >>> 25)) & 0x3ffffff;
            else
                result[i] = (c = in[i] * 121665 + (c >>> 26)) & 0x1ffffff;

        result[0] += 19 * (c >>> 25);

        return result;
    }

    private static byte[] scalarmult(long[] in1, long[] in2) {

        long[] t = {1, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        long[] u = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        long[] v = {1, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        long[] w = in2;
        long[] x;
        long[] y;
        long[] z;
        long[] a;
        long[] b;
        long[] c;

        int swapBit = 1;
        int b2;
        for (int i = 254; i-- > 2;) {
            x = add(w, v);
            v = subtract(w, v);
            y = add(t, u);
            u = subtract(t, u);
            t = multiply(y, v);
            u = multiply(x, u);
            z = add(t, u);
            u = square(subtract(t, u));
            t = square(z);
            u = multiply(u, in2);
            x = square(x);
            v = square(v);
            w = multiply(x, v);
            v = subtract(x, v);

            v = multiply(v, add(mul121665(v), x));

            b2 = (int) (in1[i >> 3] >> (i & 7)) & 1;
            long[][] j = new long[][][]{new long[][]{w, t, v, u}, new long[][]{t, w, u, v}}[b2 ^ swapBit];
            swapBit = b2;

            w = j[0];
            t = j[1];
            v = j[2];
            u = j[3];
        }

        for (int i = 0; i < 3; i++) {
            x = square(add(w, v));
            v = square(subtract(w, v));
            w = multiply(x, v);
            v = subtract(x, v);
            v = multiply(v, add(mul121665(v), x));
        }

        a = square(v);
        b = multiply(square(a, 2), v);
        a = multiply(b, a);
        b = multiply(square(a), b);
        b = multiply(square(b, 5), b);
        c = multiply(square(b, 10), b);
        b = multiply(square(multiply(square(c, 20), c), 10), b);
        c = multiply(square(b, 50), b);

        long[] r;

        r = multiply(w, multiply(square(multiply(square(multiply(square(c, 100), c), 50), b), 5), a));

        long op;

        long[] result = new long[10];
        result[0] = (op = r[0] + 0x4000000) & 0x3ffffff;

        for (int i = 1; i < 10; i++) {
            if (i % 2 != 0)
                result[i] = (op = r[i] + 0x1ffffff + (op >>> 26)) & 0x1ffffff;
            else
                result[i] = (op = r[i] + 0x3ffffff + (op >>> 25)) & 0x3ffffff;
        }

        return toByteArray(
                result[0]          | (result[1] << 26),
                (result[1] >>>  6) | (result[2] << 19),
                (result[2] >>> 13) | (result[3] << 13),
                (result[3] >>> 19) | (result[4] <<  6),
                 result[5]         | (result[6] << 25),
                (result[6] >>>  7) | (result[7] << 19),
                (result[7] >>> 13) | (result[8] << 12),
                (result[8] >>> 20) | (result[9] <<  6)
        );
    }

    private static byte[] toByteArray(long... a) {
        byte[] result = new byte[32];
        int c = 0;
        for (long i : a) {
            byte[] fBytes = {
                    (byte) ((i) & 0xff),
                    (byte) ((i >> 8) & 0xff),
                    (byte) ((i >> 16) & 0xff),
                    (byte) ((i >> 24) & 0xff),
            }; //Little endian
            System.arraycopy(fBytes, 0, result, c, 4);
            c += 4;
        }

        return result;
    }

    private static long[] byteArrayToLongArray(byte[] a) {
        long[] result = new long[a.length];

        for (int i = 0; i < a.length; i++)
            result[i] = a[i] & 0xff;

        return result;
    }

    //Return 32 bytes random key
    public static byte[] generateRandomKey() {
        byte[] r = new byte[32];
        new SecureRandom().nextBytes(r);
        return r;
    }

    public static byte[] publicKey(byte[] privateKey) throws InvalidParameterException {
        if (privateKey.length != 32) throw new InvalidParameterException("Private key must be 32 bytes.");

        long[] p = {9, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        long[] pk = byteArrayToLongArray(privateKey);

        pk[0] &= 0xf8;
        pk[31] &= 0x7f;
        pk[31] |= 0x40;

        return scalarmult(pk, p);
    }

    public static byte[] sharedSecret(byte[] privateKey, byte[] publicKey) {

        if (privateKey.length != 32) throw new InvalidParameterException("Private key must be 32 bytes.");

        if (publicKey.length != 32) throw new InvalidParameterException("Public key must be 32 bytes.");

        long[] p = {
                (((long) publicKey[0] & 0xff) |
                        ((long) publicKey[1] & 0xff) << 8 |
                        ((long) publicKey[2] & 0xff) << 16 |
                        ((long) publicKey[3] & 0xff) << 24) & 0x3ffffff,
                ((((long) publicKey[3] & 0xff) |
                        ((long) publicKey[4] & 0xff) << 8 |
                        ((long) publicKey[5] & 0xff) << 16 |
                        ((long) publicKey[6] & 0xff) << 24) >>> 2) & 0x1ffffff,
                ((((long) publicKey[6] & 0xff) |
                        ((long) publicKey[7] & 0xff) << 8 |
                        ((long) publicKey[8] & 0xff) << 16 |
                        ((long) publicKey[9] & 0xff) << 24) >>> 3) & 0x3ffffff,
                ((((long) publicKey[9] & 0xff) |
                        ((long) publicKey[10] & 0xff) << 8 |
                        ((long) publicKey[11] & 0xff) << 16 |
                        ((long) publicKey[12] & 0xff) << 24) >>> 5) & 0x1ffffff,
                ((((long) publicKey[12] & 0xff) |
                        ((long) publicKey[13] & 0xff) << 8 |
                        ((long) publicKey[14] & 0xff) << 16 |
                        ((long) publicKey[15] & 0xff) << 24) >>> 6) & 0x3ffffff,
                (((long) publicKey[16] & 0xff) |
                        ((long) publicKey[17] & 0xff) << 8 |
                        ((long) publicKey[18] & 0xff) << 16 |
                        ((long) publicKey[19] & 0xff) << 24) & 0x1ffffff,
                ((((long) publicKey[19] & 0xff) |
                        ((long) publicKey[20] & 0xff) << 8 |
                        ((long) publicKey[21] & 0xff) << 16 |
                        ((long) publicKey[22] & 0xff) << 24) >>> 1) & 0x3ffffff,
                ((((long) publicKey[22] & 0xff) |
                        ((long) publicKey[23] & 0xff) << 8 |
                        ((long) publicKey[24] & 0xff) << 16 |
                        ((long) publicKey[25] & 0xff) << 24) >>> 3) & 0x1ffffff,
                ((((long) publicKey[25] & 0xff) |
                        ((long) publicKey[26] & 0xff) << 8 |
                        ((long) publicKey[27] & 0xff) << 16 |
                        ((long) publicKey[28] & 0xff) << 24) >>> 4) & 0x3ffffff,
                ((((long) publicKey[28] & 0xff) |
                        ((long) publicKey[29] & 0xff) << 8 |
                        ((long) publicKey[30] & 0xff) << 16 |
                        ((long) publicKey[31] & 0xff) << 24) >>> 6) & 0x3ffffff
        };

        long[] pk = byteArrayToLongArray(privateKey);

        pk[0] &= 0xf8;
        pk[31] &= 0x7f;
        pk[31] |= 0x40;

        return scalarmult(pk, p);
    }

}

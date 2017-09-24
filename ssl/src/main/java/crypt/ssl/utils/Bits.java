package crypt.ssl.utils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;

public abstract class Bits {
    private Bits() {
    }

    // @formatter:off
    public static byte[] toBytes8 (int value) { return toBytes(value, 1); }
    public static byte[] toBytes16(int value) { return toBytes(value, 2); }
    public static byte[] toBytes32(int value) { return toBytes(value, 4); }
    // @formatter:on

    public static byte[] toBytes64(long value) {
        return new byte[]{
                (byte) (value >>> 56),
                (byte) (value >>> 48),
                (byte) (value >>> 40),
                (byte) (value >>> 32),
                (byte) (value >>> 24),
                (byte) (value >>> 16),
                (byte) (value >>> 8),
                (byte) (value)
        };
    }

    public static byte[] toBytes(int value, int size) {
        // Not very elegant, but code reuse is fantastic
        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        try {
            IO.writeInt(bos, value, size);
        } catch (IOException ignore) {
        }

        return bos.toByteArray();
    }

    public static byte[] toArray(ByteBuffer source) {
        byte[] bytes = IO.readBytes(source, source.remaining());
        source.rewind();

        return bytes;
    }

    public static byte[] concat(byte[]... arrays) {
        int totalLength = 0;
        for (byte[] array : arrays) {
            totalLength += array.length;
        }

        int offset = 0;
        byte[] concatenated = new byte[totalLength];

        for (byte[] array : arrays) {
            int length = array.length;
            System.arraycopy(array, 0, concatenated, offset, length);

            offset += length;
        }

        return concatenated;
    }
}

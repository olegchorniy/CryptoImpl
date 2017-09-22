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
}

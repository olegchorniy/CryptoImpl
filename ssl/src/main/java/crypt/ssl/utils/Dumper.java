package crypt.ssl.utils;

import java.io.IOException;
import java.nio.ByteBuffer;

public abstract class Dumper {

    private static final int OFFSET_BYTES = 2;
    private static final int OFFSET_WIDTH = OFFSET_BYTES * 2;

    private Dumper() {
    }

    public static String dumpToString(ByteBuffer buffer) {
        StringBuilder collector = new StringBuilder();

        try {
            dump(collector, buffer);
        } catch (IOException ignore) {
        }

        return collector.toString();
    }

    public static void dump(ByteBuffer buffer) throws IOException {
        dump(System.out, buffer, 16);
    }

    public static void dump(Appendable out, ByteBuffer buffer) throws IOException {
        dump(out, buffer, 16);
    }

    public static void dump(Appendable out, ByteBuffer buffer, int bytesPerRow) throws IOException {

        for (int offset = 0; buffer.hasRemaining(); offset += bytesPerRow) {

            out.append(Hex.toHex(offset, OFFSET_WIDTH)).append(":");

            for (int i = 0; i < bytesPerRow && buffer.hasRemaining(); i++) {
                out.append(" ").append(Hex.toHex(buffer.get()));
            }

            out.append(System.lineSeparator());
        }

        buffer.rewind();
    }
}

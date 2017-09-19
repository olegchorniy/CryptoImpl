package crypt.ssl.utils;

import org.apache.commons.lang3.StringUtils;

import java.io.IOException;
import java.nio.ByteBuffer;

public class Dumper {

    private static final int OFFSET_BYTES = 2;
    private static final int OFFSET_WIDTH = OFFSET_BYTES * 2;

    public static final int BYTES_PER_ROW_DEFAULT = 16;

    private int bytesPerRow = BYTES_PER_ROW_DEFAULT;
    private int leftIndent = 0;
    private Appendable out = System.out;

    public Dumper() {
    }

    public Dumper setBytesPerRow(int bytesPerRow) {
        this.bytesPerRow = bytesPerRow;
        return this;
    }

    public Dumper setLeftIndent(int leftIndent) {
        this.leftIndent = leftIndent;
        return this;
    }

    public Dumper setOut(Appendable out) {
        this.out = out;
        return this;
    }

    public void dump(ByteBuffer buffer) throws IOException {
        String indent = (leftIndent == 0) ? "" : StringUtils.repeat(' ', leftIndent);
        byte[] row = new byte[bytesPerRow];

        for (int offset = 0; ; offset += bytesPerRow) {

            int availableBytes = Math.min(bytesPerRow, buffer.limit() - buffer.position());
            if (availableBytes == 0) {
                break;
            }

            buffer.get(row, 0, availableBytes);

            // 1. line prefix: hexadecimal counter
            out.append(indent).append(Hex.toHex(offset, OFFSET_WIDTH)).append(":");

            // 2. hexadecimal values of bytes themselves
            for (int i = 0; i < availableBytes; i++) {
                out.append(' ').append(Hex.toHex(row[i]));
            }

            // 3. line suffix: ascii interpretation of byte values

            // we need to print 3 spaces instead of each missing byte
            // in a current row + 2 spaces to separate hex and ascii
            int spaces = (bytesPerRow - availableBytes) * 3 + 2;
            while (spaces-- > 0) {
                out.append(' ');
            }

            for (int i = 0; i < availableBytes; i++) {
                out.append(ascii(row[i]));
            }

            out.append(System.lineSeparator());
        }

        buffer.rewind();
    }

    private static char ascii(byte value) {
        return (value >= 0x20 && value <= 0x7E) ? (char) value : '.';
    }

    /* -------------------------------------------------------------------------------- */
    /* ------------ Convenient methods for the most common usage patterns. ------------ */
    /* -------------------------------------------------------------------------------- */

    public static String dumpToString(ByteBuffer buffer) {
        return dumpToString(0, buffer);
    }

    public static String dumpToString(int leftIndent, ByteBuffer buffer) {
        StringBuilder collector = new StringBuilder();

        try {
            new Dumper()
                    .setLeftIndent(leftIndent)
                    .setOut(collector)
                    .dump(buffer);
        } catch (IOException ignore) {
        }

        return collector.toString();
    }

    public static void dumpToStderr(ByteBuffer buffer) {
        try {
            new Dumper().setOut(System.err).dump(buffer);
        } catch (IOException ex) {
            ex.printStackTrace();
        }
    }

    public static void dumpToStdout(ByteBuffer buffer) {
        try {
            new Dumper().dump(buffer);
        } catch (IOException ex) {
            ex.printStackTrace();
        }
    }

    public static void dumpTo(Appendable out, ByteBuffer buffer) throws IOException {
        new Dumper().setOut(out).dump(buffer);
    }

    public static void dumpTo(Appendable out, ByteBuffer buffer, int bytesPerRow) throws IOException {
        new Dumper()
                .setOut(out)
                .setBytesPerRow(bytesPerRow)
                .dump(buffer);
    }
}

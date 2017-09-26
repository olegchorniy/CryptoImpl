package crypt.ssl.utils;

import crypt.ssl.TlsExceptions;
import crypt.ssl.messages.TlsEnum;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Collection;

public abstract class IO {

    private IO() {
    }

    /* -------------------------------------------------------- */
    /* --------------- Enum related IO methods ---------------- */
    /* -------------------------------------------------------- */

    public static <E extends Enum<E> & TlsEnum> void writeEnumConstants(OutputStream out, Collection<E> constants) throws IOException {
        for (E constant : constants) {
            writeEnum(out, constant);
        }
    }

    public static <E extends Enum<E> & TlsEnum> void writeEnum(OutputStream out, E constant) throws IOException {
        int size = TlsEnumUtils.getSize(constant.getDeclaringClass());
        int binValue = constant.getValue();

        writeInt(out, binValue, size);
    }

    public static <E extends Enum<E> & TlsEnum> E readEnum(ByteBuffer buffer, Class<E> enumClass) {
        int size = TlsEnumUtils.getSize(enumClass);
        int binValue = readInt(buffer, size);

        return TlsEnumUtils.getEnumConstant(enumClass, binValue);
    }

    public static <E extends Enum<E> & TlsEnum> E readEnum(InputStream in, Class<E> enumClass) throws IOException {
        int size = TlsEnumUtils.getSize(enumClass);
        int binValue = readInt(in, size);

        return TlsEnumUtils.getEnumConstant(enumClass, binValue);
    }


    /* --------------------------------------------------- */
    /* ---------------- Writing methods ------------------ */
    /* --------------------------------------------------- */

    // @formatter:off
    public static void writeInt8(OutputStream out, int value) throws IOException { writeInt(out, value, 1); }
    public static void writeInt16(OutputStream out, int value) throws IOException { writeInt(out, value, 2); }
    public static void writeInt24(OutputStream out, int value) throws IOException { writeInt(out, value, 3); }
    public static void writeInt32(OutputStream out, int value) throws IOException { writeInt(out, value, 4); }
    // @formatter:on

    public static void writeInt(OutputStream out, int value, int byteSize) throws IOException {
        for (int byteNum = byteSize - 1; byteNum >= 0; byteNum--) {
            int shift = byteNum * Byte.SIZE;
            byte byteVal = (byte) (value >> shift);

            out.write(byteVal);
        }
    }

    public static void writeBytes(OutputStream out, byte[] bytes) throws IOException {
        out.write(bytes);
    }

    public static void writeBytes(OutputStream out, ByteBuffer buffer) throws IOException {
        while (buffer.hasRemaining()) {
            out.write(buffer.get());
        }
    }

    public static void writeOpaque16(OutputStream out, byte[] opaque) throws IOException {
        writeInt16(out, opaque.length);
        writeBytes(out, opaque);
    }

    /* --------------------------------------------------- */
    /* ---------------- Reading methods ------------------ */
    /* --------------------------------------------------- */

    public static ByteBuffer readAsBuffer(ByteBuffer source, int length) {
        return ByteBuffer.wrap(readBytes(source, length));
    }

    public static byte[] readBytes(ByteBuffer source, int length) {
        byte[] bytes = new byte[length];
        source.get(bytes, 0, length);

        return bytes;
    }

    public static ByteBuffer readOrNullAsBuffer(InputStream in, int length) throws IOException {
        byte[] bytes = readOrNull(in, length);
        if (bytes == null) {
            return null;
        }

        return ByteBuffer.wrap(bytes);
    }

    public static ByteBuffer readAsBuffer(InputStream in, int length) throws IOException {
        return ByteBuffer.wrap(readBytes(in, length));
    }

    public static byte[] readOrNull(InputStream in, int bytesToRead) throws IOException {
        byte[] bytes = new byte[bytesToRead];

        int offset = 0;
        int length = bytesToRead;

        while (length != 0) {
            int read = in.read(bytes, offset, length);

            if (read == -1) {
                // EOF reached
                break;
            }

            offset += read;
            length -= read;
        }

        if (length != 0) {
            return null;
        }

        return bytes;
    }

    public static byte[] readBytes(InputStream in, int bytesToRead) throws IOException {
        byte[] bytes = readOrNull(in, bytesToRead);

        if (bytes == null) {
            throw TlsExceptions.eofException("EOF reached before " + bytesToRead + " bytes was read.");
        }

        return bytes;
    }

    // @formatter:off
    public static int readInt8(InputStream in) throws IOException { return readInt(in, 1);}
    public static int readInt16(InputStream in) throws IOException { return readInt(in, 2);}
    public static int readInt32(InputStream in) throws IOException { return readInt(in, 4);}
    // @formatter:on

    public static int readInt(InputStream in, int byteSize) throws IOException {
        int value = 0;

        for (int byteNum = byteSize - 1; byteNum >= 0; byteNum--) {
            int shift = byteNum * Byte.SIZE;
            int byteValue = checkForEOF(in.read());

            value |= (byteValue << shift);
        }

        return value;
    }

    public static int readInt8(ByteBuffer buffer) {
        return buffer.get() & 0xFF;
    }

    public static int readInt16(ByteBuffer buffer) {
        return buffer.getShort() & 0xFFFF;
    }

    public static int readInt24(ByteBuffer buffer) {
        return (readInt8(buffer) << 16) | readInt16(buffer);
    }

    public static int readInt32(ByteBuffer buffer) {
        return buffer.getInt();
    }

    public static int readInt(ByteBuffer buffer, int byteSize) {
        switch (byteSize) {
            case 1:
                return readInt8(buffer);
            case 2:
                return readInt16(buffer);
            case 3:
                return readInt24(buffer);
            case 4:
                return readInt32(buffer);
        }

        throw new IllegalArgumentException(
                "Illegal value of int size: \"" + byteSize + "\". " +
                        "Value should be between 1 and 4"
        );
    }

    public static BigInteger readBigInteger16(ByteBuffer buffer) {
        int length = IO.readInt16(buffer);
        byte[] mag = IO.readBytes(buffer, length);

        return new BigInteger(1, mag);
    }

    public static byte checkedReadByte(InputStream in) throws IOException {
        return (byte) checkForEOF(in.read());
    }

    private static int checkForEOF(int value) throws EOFException {
        if (value == -1) {
            throw TlsExceptions.eofException();
        }

        return value;
    }
}

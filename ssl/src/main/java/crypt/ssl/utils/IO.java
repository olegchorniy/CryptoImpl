package crypt.ssl.utils;

import crypt.ssl.TlsExceptions;
import crypt.ssl.messages.TlsEnum;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;

public abstract class IO {

    private IO() {
    }

    /* --------------- Enum related IO methods ---------------- */

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

    public static void writeInt(OutputStream out, int value, int byteSize) throws IOException {
        for (int byteNum = byteSize - 1; byteNum >= 0; byteNum--) {
            int shift = byteNum * Byte.SIZE;
            byte byteVal = (byte) (value >> shift);

            out.write(byteVal);
        }
    }

    public static byte[] readBytes(ByteBuffer source, int length) {
        byte[] bytes = new byte[length];
        source.get(bytes, 0, length);

        return bytes;
    }

    public static ByteBuffer readBytes(InputStream in, int length) throws IOException {
        byte[] bytes = new byte[length];
        int actuallyRead = in.read(bytes);

        if (actuallyRead != length) {
            throw TlsExceptions.eofException("Expected " + length + " bytes but only " + actuallyRead + " present");
        }

        return ByteBuffer.wrap(bytes);
    }

    // @formatter:off
    public static int readInt8(InputStream in) throws IOException { return readInt(in, 1);}
    public static int readInt16(InputStream in) throws IOException { return readInt(in, 2);}
    public static int readInt32(InputStream in) throws IOException { return readInt(in, 4);}

    //TODO: probably reimplement without using of loop
    public static int readInt8(ByteBuffer buffer) { return readInt(buffer, 1);}
    public static int readInt24(ByteBuffer buffer) { return readInt(buffer, 3);}
    // @formatter:on

    public static int readInt(ByteBuffer buffer, int byteSize) {
        int value = 0;

        for (int byteNum = byteSize - 1; byteNum >= 0; byteNum--) {
            value |= (buffer.get() << (byteNum * Byte.SIZE));
        }

        return value;
    }

    public static int readInt(InputStream in, int byteSize) throws IOException {
        int value = 0;

        for (int byteNum = byteSize - 1; byteNum >= 0; byteNum--) {
            int shift = byteNum * Byte.SIZE;
            int byteValue = checkForEOF(in.read());

            value |= (byteValue << shift);
        }

        return value;
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

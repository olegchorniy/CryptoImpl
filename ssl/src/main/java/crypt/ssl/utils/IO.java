package crypt.ssl.utils;

import crypt.ssl.TlsExceptions;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;

public abstract class IO {

    private IO() {
    }

    public static void writeInt(OutputStream out, int value, int byteSize) throws IOException {
        for (int byteNum = byteSize - 1; byteNum >= 0; byteNum--) {
            int shift = byteNum * Byte.SIZE;
            byte byteVal = (byte) (value >> shift);

            out.write(byteVal);
        }
    }

    public static ByteBuffer readBytes(InputStream in, int length) throws IOException {
        byte[] bytes = new byte[length];
        int actuallyRead = in.read(bytes);

        if (actuallyRead != length) {
            throw TlsExceptions.eofException("Expected " + length + " bytes but only " + actuallyRead + " present");
        }

        return ByteBuffer.wrap(bytes);
    }

    public static int readInt8(InputStream in) throws IOException { return readInt(in, 1);}
    public static int readInt16(InputStream in) throws IOException { return readInt(in, 2);}
    public static int readInt24(InputStream in) throws IOException { return readInt(in, 3);}
    public static int readInt32(InputStream in) throws IOException { return readInt(in, 4);}

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

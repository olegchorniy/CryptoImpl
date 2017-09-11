package crypt.ssl.utils;

import java.io.IOException;
import java.io.OutputStream;

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
}

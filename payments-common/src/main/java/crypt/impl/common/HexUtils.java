package crypt.impl.common;

import javax.xml.bind.DatatypeConverter;

public abstract class HexUtils {
    private HexUtils() {
    }

    public static byte[] fromHex(String hex) {
        return DatatypeConverter.parseHexBinary(hex);
    }

    public static String toHex(byte[] bytes) {
        return DatatypeConverter.printHexBinary(bytes);
    }
}

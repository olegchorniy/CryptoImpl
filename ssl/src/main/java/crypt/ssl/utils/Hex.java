package crypt.ssl.utils;

import org.apache.commons.lang3.StringUtils;

public abstract class Hex {

    private Hex() {
    }

    public static byte fromHex(String hex) {
        int value = Integer.parseInt(hex, 16);
        if (value < 0 || value > 255) {
            throw new NumberFormatException("Value out of range. Value:\"" + hex + "\"");
        }

        return (byte) value;
    }

    public static String toHex(byte value) {
        return toHex(value & 0xFF, 2);
    }

    public static String toHex(int value, int targetLength) {
        String hexValue = Integer.toHexString(value);
        return StringUtils.leftPad(hexValue, targetLength, '0');
    }
}

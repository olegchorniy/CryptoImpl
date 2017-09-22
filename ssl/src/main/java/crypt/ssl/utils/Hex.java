package crypt.ssl.utils;

import org.apache.commons.lang3.StringUtils;

import java.nio.ByteBuffer;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public abstract class Hex {

    private Hex() {
    }

    public static byte fromHex(String hex) {
        int value = Integer.parseInt(hex, 16);
        if (value < 0 || value > 255) {
            throw new NumberFormatException("Value is out of range. Value:\"" + hex + "\"");
        }

        return (byte) value;
    }

    public static String toHex(byte[] values) {
        return IntStream.range(0, values.length)
                .mapToObj(idx -> values[idx])
                .map(Hex::toHex)
                .collect(Collectors.joining(" "));
    }

    public static String toHex(ByteBuffer buffer) {
        StringBuilder hexBuilder = new StringBuilder();

        while (buffer.hasRemaining()) {

            if (hexBuilder.length() > 0) {
                hexBuilder.append(' ');
            }

            hexBuilder.append(toHex(buffer.get()));
        }

        buffer.rewind();

        return hexBuilder.toString();
    }

    public static String toHex(byte value) {
        return toHex(value & 0xFF, 2);
    }

    public static String toHex16(int value) {
        return toHex(value & 0xFFFF, 4);
    }

    public static String toHex32(int value) {
        return toHex(value, 8);
    }

    public static String toHex(int value, int targetLength) {
        String hexValue = Integer.toHexString(value);
        return StringUtils.leftPad(hexValue, targetLength, '0');
    }
}

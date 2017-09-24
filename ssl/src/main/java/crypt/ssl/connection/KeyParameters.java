package crypt.ssl.connection;

import crypt.ssl.utils.Hex;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class KeyParameters {

    private final byte[] macKey;
    private final byte[] encryptionKey;
    private final byte[] fixedIv;

    @Override
    public String toString() {
        return "KeyParameters(\n" +
                "\tmacKey: " + Hex.toHex(macKey) + ",\n" +
                "\tencryptionKey: " + Hex.toHex(encryptionKey) + ",\n" +
                "\tfixedIv: " + Hex.toHex(fixedIv) + ",\n" +
                ')';
    }
}

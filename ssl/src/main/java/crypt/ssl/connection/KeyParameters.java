package crypt.ssl.connection;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class KeyParameters {

    private final byte[] macKey;
    private final byte[] encryptionKey;
    private final byte[] fixedIv;
}

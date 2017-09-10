package crypt.ssl.messages.handshake;

import crypt.ssl.messages.Size;
import lombok.Getter;

@Getter
public enum HandshakeType {

    //@formatter:off

    HELLO_REQUEST       (0  /* 0x00 */),
    CLIENT_HELLO        (1  /* 0x01 */),
    SERVER_HELLO        (2  /* 0x02 */),
    CERTIFICATE         (11 /* 0x0B */),
    SERVER_KEY_EXCHANGE (12 /* 0x0C */),
    CERTIFICATE_REQUEST (13 /* 0x0D */),
    SERVER_HELLO_DONE   (14 /* 0x0E */),
    CERTIFICATE_VERIFY  (15 /* 0x0F */),
    CLIENT_KEY_EXCHANGE (16 /* 0x10 */),
    FINISHED            (20 /* 0x14 */);

    @Size(1)
    private final int value;

    HandshakeType(int value) {
        this.value = value;
    }

    //@formatter:on
}

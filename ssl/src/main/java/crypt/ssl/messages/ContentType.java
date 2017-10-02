package crypt.ssl.messages;

import crypt.ssl.utils.TlsEnumUtils;
import lombok.Getter;

@Getter
@Size(1)
public enum ContentType implements TlsEnum {

    //@formatter:off

    CHANGE_CIPHER_SPEC(20 /* 0x14 */),
    ALERT             (21 /* 0x15 */),
    HANDSHAKE         (22 /* 0x16 */),
    APPLICATION_DATA  (23 /* 0x17 */);

    private final int value;

    ContentType(int value) {
        this.value = value;
    }

    //@formatter:on

    @Override
    public String toString() {
        return TlsEnumUtils.toString(this);
    }
}

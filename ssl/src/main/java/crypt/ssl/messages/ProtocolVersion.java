package crypt.ssl.messages;

import crypt.ssl.utils.TlsEnumUtils;
import lombok.Getter;

@Getter
@Size(2)
public enum ProtocolVersion implements TlsEnum {

    SSLv30(3, 0),
    TLSv10(3, 1),
    TLSv11(3, 2),
    TLSv12(3, 3);

    private final int major;
    private final int minor;

    private final int value;

    ProtocolVersion(int major, int minor) {
        this.major = major;
        this.minor = minor;
        this.value = (major << 8) | minor;
    }

    @Override
    public String toString() {
        return TlsEnumUtils.toString(this);
    }
}

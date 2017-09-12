package crypt.ssl.messages;

import lombok.Getter;

@Getter
public enum ProtocolVersion implements TlsEnum {

    SSLv30(3, 0),
    TLSv10(3, 1),
    TLSv11(3, 2),
    TLSv12(3, 3);

    @Size(2)
    private final int value;

    ProtocolVersion(int major, int minor) {
        this.value = (major << 8) | minor;
    }

    public int getMajor() {
        return value >> 8;
    }

    public int getMinor() {
        return value & 0xFF;
    }
}

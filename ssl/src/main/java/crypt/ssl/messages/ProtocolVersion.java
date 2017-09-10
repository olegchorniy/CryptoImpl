package crypt.ssl.messages;

import lombok.Getter;

@Getter
public enum ProtocolVersion {

    SSLv30(3, 0),
    TLSv10(3, 1),
    TLSv11(3, 2),
    TLSv12(3, 3);

    @Size(1)
    private final int minor;

    @Size(1)
    private final int major;

    ProtocolVersion(int minor, int major) {
        this.minor = minor;
        this.major = major;
    }
}

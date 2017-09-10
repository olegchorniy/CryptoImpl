package crypt.ssl.messages.alert;

import crypt.ssl.messages.Size;
import crypt.ssl.messages.TlsEnum;
import lombok.Getter;

@Getter
public enum AlertDescription implements TlsEnum {

    // @formatter:off

    CLOSE_NOTIFY                (0),
    UNEXPECTED_MESSAGE          (10),
    BAD_RECORD_MAC              (20),
    DECRYPTION_FAILED_RESERVED  (21),
    RECORD_OVERFLOW             (22),
    DECOMPRESSION_FAILURE       (30),
    HANDSHAKE_FAILURE           (40),
    NO_CERTIFICATE_RESERVED     (41),
    BAD_CERTIFICATE             (42),
    UNSUPPORTED_CERTIFICATE     (43),
    CERTIFICATE_REVOKED         (44),
    CERTIFICATE_EXPIRED         (45),
    CERTIFICATE_UNKNOWN         (46),
    ILLEGAL_PARAMETER           (47),
    UNKNOWN_CA                  (48),
    ACCESS_DENIED               (49),
    DECODE_ERROR                (50),
    DECRYPT_ERROR               (51),
    EXPORT_RESTRICTION_RESERVED (60),
    PROTOCOL_VERSION            (70),
    INSUFFICIENT_SECURITY       (71),
    INTERNAL_ERROR              (80),
    USER_CANCELED               (90),
    NO_RENEGOTIATION            (100),
    UNSUPPORTED_EXTENSION       (110);

    // @formatter:on

    @Size(1)
    private final int value;

    AlertDescription(int value) {
        this.value = value;
    }
}

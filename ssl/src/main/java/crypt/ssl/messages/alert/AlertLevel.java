package crypt.ssl.messages.alert;

import crypt.ssl.messages.Size;
import crypt.ssl.messages.TlsEnum;
import lombok.Getter;

@Getter
@Size(1)
public enum AlertLevel implements TlsEnum {

    // @formatter:off
    WARNING (1),
    FATAL   (2);
    // @formatter:on

    private final int value;

    AlertLevel(int value) {
        this.value = value;
    }
};

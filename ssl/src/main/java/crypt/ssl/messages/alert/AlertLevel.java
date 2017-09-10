package crypt.ssl.messages.alert;

import crypt.ssl.messages.Size;
import crypt.ssl.messages.TlsEnum;
import lombok.Getter;

@Getter
public enum AlertLevel implements TlsEnum {

    // @formatter:off
    WARNING (1),
    FATAL   (2);
    // @formatter:on

    @Size(1)
    private final int value;

    AlertLevel(int value) {
        this.value = value;
    }
};

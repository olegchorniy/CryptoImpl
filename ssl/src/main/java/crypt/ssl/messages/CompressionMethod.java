package crypt.ssl.messages;

import crypt.ssl.utils.TlsEnumUtils;
import lombok.Getter;

@Getter
@Size(1)
public enum CompressionMethod implements TlsEnum {

    NULL(0);

    private final int value;

    CompressionMethod(int value) {
        this.value = value;
    }

    @Override
    public String toString() {
        return TlsEnumUtils.toString(this);
    }
}

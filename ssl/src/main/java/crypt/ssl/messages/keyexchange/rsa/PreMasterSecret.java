package crypt.ssl.messages.keyexchange.rsa;

import crypt.ssl.messages.ProtocolVersion;
import lombok.Builder;
import lombok.Getter;

@Builder
@Getter
public class PreMasterSecret {

    private ProtocolVersion version;
    private byte[] random;
}

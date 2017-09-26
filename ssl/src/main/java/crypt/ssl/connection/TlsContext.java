package crypt.ssl.connection;


import crypt.ssl.messages.ProtocolVersion;
import lombok.Getter;
import lombok.Setter;

import java.util.Random;

@Getter
@Setter
public class TlsContext {

    private Random random;
    private SecurityParameters securityParameters;
    private ProtocolVersion version;
}

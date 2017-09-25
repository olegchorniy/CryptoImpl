package crypt.ssl.connection;

import crypt.ssl.CipherSuite;
import crypt.ssl.messages.SessionId;
import lombok.*;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Session {

    private SessionId sessionId;
    private CipherSuite cipherSuite;
    private byte[] preMasterSecret;
}

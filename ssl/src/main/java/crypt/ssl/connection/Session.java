package crypt.ssl.connection;

import crypt.ssl.CipherSuite;
import crypt.ssl.messages.SessionId;
import crypt.ssl.utils.Hex;
import lombok.*;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Session {

    private SessionId sessionId;
    private CipherSuite cipherSuite;
    private byte[] masterSecret;

    @Override
    public String toString() {
        return "Session(" +
                "\n\tsessionId: " + sessionId +
                ",\n\tcipherSuite: " + cipherSuite +
                ",\n\tmasterSecret: " + Hex.toHex(masterSecret) +
                "\n)";
    }
}

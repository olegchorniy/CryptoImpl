package crypt.ssl.connection;

import crypt.ssl.CipherSuite;
import crypt.ssl.messages.RandomValue;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class SecurityParameters {

    private RandomValue clientRandom;
    private RandomValue serverRandom;
    private CipherSuite cipherSuite;
}

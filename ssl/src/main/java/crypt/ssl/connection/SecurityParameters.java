package crypt.ssl.connection;

import crypt.ssl.CipherSuite;
import crypt.ssl.messages.RandomValue;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class SecurityParameters {

    // The only value here which should be saved across several sessions (together with pre_master_secret and session_id)
    private CipherSuite cipherSuite;

    private RandomValue clientRandom;
    private RandomValue serverRandom;
    private byte[] masterSecret;
    private KeyParameters clientKeyParameters;
    private KeyParameters serverKeyParameters;
}

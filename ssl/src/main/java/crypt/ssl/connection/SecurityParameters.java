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
    private byte[] masterSecret;
    private KeyParameters clientKeyParameters;
    private KeyParameters serverKeyParameters;

    /*
      ConnectionEnd          entity;
    s PRFAlgorithm           prf_algorithm;
    s BulkCipherAlgorithm    bulk_cipher_algorithm;
    s CipherType             cipher_type;
    s uint8                  enc_key_length;
    s uint8                  block_length;
      uint8                  fixed_iv_length;
      uint8                  record_iv_length;
    s MACAlgorithm           mac_algorithm;
    s uint8                  mac_length;
    s uint8                  mac_key_length;
    - CompressionMethod      compression_algorithm;
      opaque                 master_secret[48];

    + opaque                 client_random[32];
    + opaque                 server_random[32];
     */
}

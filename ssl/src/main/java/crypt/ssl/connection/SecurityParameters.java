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

    /*
      ConnectionEnd          entity;
      PRFAlgorithm           prf_algorithm;
      BulkCipherAlgorithm    bulk_cipher_algorithm;
      CipherType             cipher_type;
      uint8                  enc_key_length;
      uint8                  block_length;
      uint8                  fixed_iv_length;
      uint8                  record_iv_length;
      MACAlgorithm           mac_algorithm;
      uint8                  mac_length;
      uint8                  mac_key_length;
      CompressionMethod      compression_algorithm;
      opaque                 master_secret[48];

      opaque                 client_random[32];
      opaque                 server_random[32];
     */
}

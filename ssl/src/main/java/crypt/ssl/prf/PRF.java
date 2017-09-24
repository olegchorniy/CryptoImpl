package crypt.ssl.prf;

public interface PRF {

    byte[] compute(byte[] secret, String asciiLabel, byte[] seed, int outputLength);
}

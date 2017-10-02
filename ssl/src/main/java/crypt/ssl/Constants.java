package crypt.ssl;

public abstract class Constants {
    private Constants() {
    }

    public static final String CA_CERTS = "C:\\Program Files\\Java\\jdk1.8.0_73\\jre\\lib\\security\\cacerts";
    public static final byte[] EMPTY = new byte[0];

    /* Log names */

    public static final String HANDSHAKE = "logger.handshake";
}

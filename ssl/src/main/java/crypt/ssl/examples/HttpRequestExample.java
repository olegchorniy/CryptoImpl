package crypt.ssl.examples;

import crypt.ssl.CipherSuite;
import crypt.ssl.connection.TlsConfigurer;
import crypt.ssl.connection.TlsConnection;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.*;
import java.security.Security;

public class HttpRequestExample {

    // @formatter:off
    private static final String REQUEST_PATTERN =
                    "GET %s HTTP/1.1\r\n" +
                    "Host: %s\r\n" +
                    "Accept: text/html, application/json\r\n" +
                    "Connection: close\r\n" +
                    "\r\n";
    // @formatter:on

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) throws Exception {
        simpleHttpRequest("habrahabr.ru", "/top/", 443);
        simpleHttpRequest("localhost", "/test", 8090);
    }

    public static void simpleHttpRequest(String host, String path, int port) throws IOException {

        TlsConfigurer configurer = TlsConfigurer.builder()
                .validateCertificates(false)
                .suite(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA)
                .build();

        try (TlsConnection connection = new TlsConnection(configurer)) {
            connection.connect(host, port);

            InputStream input = connection.getInput();
            OutputStream output = connection.getOutput();

            writeRequest(host, path, output);
            readResponse(input);
        }
    }

    private static void writeRequest(String host, String path, OutputStream out) throws IOException {
        out.write(String.format(REQUEST_PATTERN, path, host).getBytes());
    }

    private static void readResponse(InputStream in) throws IOException {
        // Just read characters from the input stream until connection is closed from the other side.
        try (Reader reader = new InputStreamReader(in)) {
            while (true) {
                int _char = reader.read();
                if (_char == -1) {
                    break;
                }

                System.out.print((char) _char);
            }
        }

        System.out.println();
    }
}

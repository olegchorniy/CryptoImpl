package crypt.ssl;

import crypt.ssl.connection.Session;
import crypt.ssl.connection.TlsConfigurer;
import crypt.ssl.connection.TlsConnection;
import crypt.ssl.utils.Hex;
import org.bouncycastle.crypto.tls.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.net.ssl.SSLSocketFactory;
import java.io.*;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Date;

public class SslTest {

    private static final Config LOCALHOST = new Config("localhost", "/test", 8090);
    private static final Config HABRAHABR = new Config("habrahabr.ru", "/");
    private static final Config YOUTUBE = new Config("www.youtube.com", "/");

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) throws Exception {
        //bcSslClient();
        newSslClient();
        //javaSSLEngine();
    }

    public static void javaSSLEngine() throws Exception {
        Config config = LOCALHOST;
        //Config config = HABRAHABR;

        String host = config.host;
        String path = config.path;
        int port = config.port;

        try (Socket socket = SSLSocketFactory.getDefault().createSocket(host, port)) {
            doSimpleHttpRequest(host, path, socket.getOutputStream(), socket.getInputStream());
        }
    }

    public static Session newSslClient() throws Exception {

        Config config = LOCALHOST;

        String host = config.host;
        String path = config.path;
        int port = config.port;

        TlsConfigurer configurer = TlsConfigurer.builder()
                .suite(CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA)
                .validateCertificates(false)
                .build();

        try (TlsConnection connection = new TlsConnection(configurer)) {
            connection.connect(host, port);

            doSimpleHttpRequest(host, path, connection.getOutput(), connection.getInput());

            return connection.getSession();
        }
    }

    public static void resumeSession(Session session) throws Exception {
        String host = "localhost";
        String path = "/test";
        int port = 8090;

        try (TlsConnection connection = new TlsConnection(session)) {
            connection.connect(host, port);

            doSimpleHttpRequest(host, path, connection.getOutput(), connection.getInput());
        }
    }

    public static void bcSslClient() throws Exception {
        /*String host = "localhost";
        int port = 8090;
        String path = "/test";*/

        String host = "www.youtube.com";
        String path = "/";
        int port = 443;

        socket(host, port, (in, out) -> {

            TlsClientProtocol tls = new TlsClientProtocol(in, out, new SecureRandom());

            tls.connect(new DefaultTlsClient() {

                @Override
                public int[] getCipherSuites() {
                    return new int[]{
                            CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA.getValue()
                    };
                }

                @Override
                public TlsAuthentication getAuthentication() throws IOException {
                    return new ServerOnlyTlsAuthentication() {
                        @Override
                        public void notifyServerCertificate(Certificate serverCertificate) throws IOException {
                        }
                    };
                }
            });

            doSimpleHttpRequest(host, path, tls.getOutputStream(), tls.getInputStream());

            tls.close();
        });
    }

    public static void runSimpleHttpRequest() throws IOException {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress("localhost", 8090));

            doSimpleHttpRequest("localhost", "/test", socket.getOutputStream(), socket.getInputStream());
        }
    }

    public static void doSimpleHttpRequest(Config config, OutputStream os, InputStream is) throws IOException {
        doSimpleHttpRequest(config.host, config.path, os, is);
    }

    public static void doSimpleHttpRequest(String host, String path, OutputStream os, InputStream is) throws IOException {
        /* Send request */

        String request = "GET " + path + " HTTP/1.1\r\n" +
                "Host: " + host + "\r\n" +
                "Accept: text/html, application/json\r\n" +
                /*"Keep-Alive: timeout=1\r\n" +
                "Connection: Keep-Alive\r\n" +*/
                "Connection: close\r\n" +
                "\r\n";

        os.write(request.getBytes());

        /* Receive response */
        try {
            textDump(is);
            //dump(is);
        } catch (Exception e) {
            e.printStackTrace();
            System.err.println(new Date());
        }
    }

    private static void textDump(InputStream is) throws IOException {
        try (Reader reader = new InputStreamReader(is)) {
            int value;

            while ((value = reader.read()) != -1) {
                System.out.print((char) value);
            }
        }

        System.out.println();
    }

    private static void socket(String host, int port, SocketIOConsumer ioConsumer) throws Exception {
        socket(new InetSocketAddress(host, port), ioConsumer);
    }

    private static void socket(InetSocketAddress address, SocketIOConsumer ioConsumer) throws Exception {
        try (Socket socket = new Socket()) {
            socket.connect(address);

            ioConsumer.consume(socket.getInputStream(), socket.getOutputStream());
        }
    }

    public static void dump(InputStream is) throws IOException {
        dump(is, 16);
    }

    public static void dump(InputStream is, int bytesPerRow) throws IOException {
        int value;
        int bytesRead = 0;

        while ((value = is.read()) != -1) {

            if (bytesRead % bytesPerRow == 0) {
                System.out.print(Hex.toHex(bytesRead, 6) + ":");
            }

            System.out.print(" " + Hex.toHex((byte) value));

            bytesRead++;

            if (bytesRead % bytesPerRow == 0) {
                System.out.println();
            }
        }
    }

    private interface SocketIOConsumer {
        void consume(InputStream is, OutputStream os) throws Exception;
    }

    private static class Config {
        final String host;
        final String path;
        final int port;

        private Config(String host, String path, int port) {
            this.host = host;
            this.path = path;
            this.port = port;
        }

        public Config(String host, String path) {
            this.host = host;
            this.path = path;
            this.port = 443;
        }
    }
}

package crypt.ssl;

import crypt.ssl.connection.MessageStream;
import crypt.ssl.connection.TlsConnection;
import crypt.ssl.encoding.KeyExchangeDecoder;
import crypt.ssl.encoding.TlsEncoder;
import crypt.ssl.keyexchange.DHEKeyExchange;
import crypt.ssl.messages.*;
import crypt.ssl.messages.CompressionMethod;
import crypt.ssl.messages.ContentType;
import crypt.ssl.messages.ProtocolVersion;
import crypt.ssl.messages.alert.Alert;
import crypt.ssl.messages.handshake.*;
import crypt.ssl.messages.keyexchange.dh.SignedDHParams;
import crypt.ssl.testing.DigitalSignatureTest;
import crypt.ssl.utils.CertificateDecoder;
import crypt.ssl.utils.Dumper;
import crypt.ssl.utils.Hex;
import org.bouncycastle.crypto.tls.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

import static org.bouncycastle.crypto.tls.CipherSuite.TLS_DHE_RSA_WITH_AES_128_GCM_SHA256;

public class SslTest {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) throws Exception {
        //sslPretendingServer();
        //sslClient();
        //bcSslClient();
        newSslClient();
    }

    public static void newSslClient() throws Exception {
        TlsConnection connection = new TlsConnection(Collections.singletonList(CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA));

        connection.connect(new InetSocketAddress("localhost", 8090));
    }

    public static void sslPretendingServer() throws IOException {
        try (ServerSocket serverSocket = new ServerSocket(5555)) {
            Socket client = serverSocket.accept();
            new Thread(() -> {
                try {
                    dump(client.getInputStream());
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }).start();
        }
    }

    public static void bcSslClient() throws Exception {
        String host = "localhost";
        int port = 8090;
        String path = "/test";

        socket(host, port, (in, out) -> {

            TlsClientProtocol tls = new TlsClientProtocol(in, out, new SecureRandom());

            tls.connect(new DefaultTlsClient() {

                @Override
                public int[] getCipherSuites() {
                    return new int[]{
                            TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
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

    public static void sslClient() throws Exception {
        String host = "localhost";
        int port = 8090;
        String path = "/test";

        socket(host, port, (in, out) -> {

            MessageStream stream = new MessageStream(in, out);
            stream.setRecordVersion(ProtocolVersion.TLSv12);

            /* Sending ClientHello */
            ClientHello clientHello = ClientHello.builder()
                    .clientVersion(ProtocolVersion.TLSv12)
                    .random(new RandomValue(gmt_unix_time(), not_random_bytes(28)))
                    .sessionId(SessionId.EMPTY)
                    .cipherSuite(CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA)
                    .compressionMethod(CompressionMethod.NULL)
                    .extensions(Extensions.empty())
                    .build();

            ByteBuffer clientHelloMessage = TlsEncoder.encode(clientHello);
            stream.writeMessage(ContentType.HANDSHAKE, clientHelloMessage);

            /* Looking what the server has sent us */
            ServerHello serverHello = (ServerHello) checkAlert(stream.readMessage());
            CertificateMessage certificateMessage = (CertificateMessage) checkAlert(stream.readMessage());
            ServerKeyExchange serverKeyExchange = (ServerKeyExchange) checkAlert(stream.readMessage());
            // ServerHelloDone
            System.out.println(stream.readMessage());

            /* ------- Parse certificate -------*/
            X509Certificate certificate = getServerCertificate(certificateMessage);

            /* ------- Verify signature on the server's parameters -------- */
            SignedDHParams dhkeParams = KeyExchangeDecoder.readDHKEParams(serverKeyExchange.getData());
            System.out.println(dhkeParams);

            System.out.println("Signature verification = " + DigitalSignatureTest.checkSignature(
                    dhkeParams,
                    certificate,
                    clientHello.getRandom(),
                    serverHello.getRandom()
            ));

            // To be able to read it one more time below
            serverKeyExchange.getData().rewind();

            /* ------- Establish common secret -------- */
            DHEKeyExchange dhExchange = new DHEKeyExchange(null);

            dhExchange.processServerCertificate(certificate);
            dhExchange.processServerKeyExchange(serverKeyExchange);

            byte[] exchangeKeys = dhExchange.generateClientKeyExchange();

            ByteBuffer clientKeyExchange = TlsEncoder.encode(new ClientKeyExchange(exchangeKeys));
            stream.writeMessage(ContentType.HANDSHAKE, clientKeyExchange);

            Dumper.dumpToStdout(dhExchange.generatePreMasterSecret());
        });
    }

    private static X509Certificate getServerCertificate(CertificateMessage certificateMessage) throws CertificateException {
        List<ASN1Certificate> certificates = certificateMessage.getCertificates();
        byte[] x509Certificate = certificates.get(0).getContent();

        return CertificateDecoder.decodeCertificate(x509Certificate);
    }

    private static TlsMessage checkAlert(TlsMessage message) {
        if (!(message instanceof Alert)) {
            return message;
        }

        Alert alert = (Alert) message;
        System.err.format("Alert:%n\tlevel: %s%n\tdescription: %s%n", alert.getLevel(), alert.getDescription());

        throw new RuntimeException();
    }

    public static int gmt_unix_time() {
        return (int) (System.currentTimeMillis() / 1000);
    }

    public static byte[] not_random_bytes(int length) {
        byte[] bytes = new byte[length];

        for (int i = 0; i < length; i++) {
            bytes[i] = (byte) i;
        }

        return bytes;
    }

    public static byte[] random_bytes(int length) {
        Random random = new Random();
        byte[] randomBytes = new byte[length];

        random.nextBytes(randomBytes);
        return randomBytes;
    }

    // @formatter:off
    public static byte[] int8(int value) { return toBytes(value, 1); }
    public static byte[] int16(int value) { return toBytes(value, 2); }
    public static byte[] int24(int value) { return toBytes(value, 3); }
    public static byte[] int32(int value) { return toBytes(value, 4); }
    // @formatter:on

    public static byte[] bytes(Object... values) {
        byte[][] bytes = Arrays.stream(values)
                .map(obj -> {
                    if (obj instanceof byte[]) {
                        return (byte[]) obj;
                    }

                    if (obj instanceof Integer) {
                        return int8((Integer) obj);
                    }

                    throw new IllegalArgumentException("Unexpected value: " + obj);
                })
                .toArray(byte[][]::new);

        return concat(bytes);
    }

    public static byte[] concat(byte[]... arrays) {
        int totalLength = 0;
        for (byte[] array : arrays) {
            totalLength += array.length;
        }

        byte[] allBytes = new byte[totalLength];
        int index = 0;

        for (byte[] array : arrays) {
            for (byte value : array) {
                allBytes[index++] = value;
            }
        }

        //dumpToStdout(allBytes);

        return allBytes;
    }

    public static byte[] toBytes(final int value, final int bytesToTake) {
        byte[] bytes = new byte[bytesToTake];

        for (int i = 0; i < bytesToTake; i++) {
            int shift = ((bytesToTake - 1 - i) * 8);
            bytes[i] = (byte) ((value >> shift) & 0xFF);
        }

        return bytes;
    }

    public static void runSimpleHttpRequest() throws IOException {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress("localhost", 8090));

            doSimpleHttpRequest("localhost", "/test", socket.getOutputStream(), socket.getInputStream());
        }
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

            System.out.println(new Date());
            printDataWhilePresent(is);
        } catch (Exception e) {
            e.printStackTrace();
            System.err.println(new Date());
        }
    }

    private static void printDataWhilePresent(InputStream is) throws IOException {
        int value;
        while ((value = is.read()) != -1) {
            System.out.print((char) value);
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

    private static void write(OutputStream os, String line) throws IOException {
        os.write(line.getBytes());
    }

    private static void write(OutputStream os, byte[] bytes) throws IOException {
        /*System.out.println("Length: " + bytes.length);
        Dumper.dumpToStdout(ByteBuffer.wrap(bytes));*/
        os.write(bytes);
    }

    private static void write(OutputStream os, int... bytes) throws IOException {
        for (int byteValue : bytes) {
            os.write(byteValue);
        }
    }

    private static void dump(byte[] bytes) {
        try (ByteArrayInputStream bis = new ByteArrayInputStream(bytes)) {
            dump(bis);
        } catch (IOException e) {
            // impossible
            e.printStackTrace();
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
}

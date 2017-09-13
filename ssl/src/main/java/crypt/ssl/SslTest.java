package crypt.ssl;

import crypt.ssl.encoding.TlsDecoder;
import crypt.ssl.messages.TlsMessage;
import crypt.ssl.messages.TlsRecord;
import crypt.ssl.messages.handshake.CertificateMessage;
import crypt.ssl.testing.RSAKeyDecoding;
import crypt.ssl.utils.CertificateDecoder;
import crypt.ssl.utils.Hex;
import org.bouncycastle.crypto.tls.*;

import java.io.*;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Random;

public class SslTest {

    public static void main(String[] args) throws IOException, CertificateException {
        //sslPretendingServer();
        sslClient();
    }

    public static void sslPretendingServer() throws IOException {
        try (ServerSocket serverSocket = new ServerSocket(5555)) {
            Socket client = serverSocket.accept();
            new Thread(() -> {
                try {
                    //dumpAscii(client.getInputStream());
                    dump(client.getInputStream());
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }).start();
        }
    }

    public static void bcSslClient() throws IOException {
        String host = "rutracker.org";
        int port = 443;
        String path = "/forum/index.php";

        socket(host, port, (in, out) -> {

            TlsClientProtocol tls = new TlsClientProtocol(in, out, new SecureRandom());

            tls.connect(new DefaultTlsClient() {

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

    public static void sslClient() throws IOException {
        String host = "localhost";
        int port = 8090;
        String path = "/test";

        socket(host, port, (in, out) -> {

            write(out, bytes(
                    22 /* Content Type = Handshake */,
                    3, 3, /* Protocol Version = TLS v 1.2*/
                    int16(45 /* TBD */), /* Length*//*

                    *//* -------------- Handshake Message ----------- */
                    1, /* Handshake type = ClientHello*/
                    int24(41 /* TBD */), /* Handshake message data length */

                    /* Client Hello */
                    3, 3, /* Protocol Version = TLS v 1.2*/

                    int32(gmt_unix_time()), random_bytes(28), /* Random */

                    0, /* Length of Session Id */

                    int16(2), /* Bytes in Cipher Suites */
                    int16(0xC02F), // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA

                    1, /* Number of compression methods */
                    0 /* Compression method */
            ));

            //dump(in);

            TlsRecord record = TlsDecoder.readRecord(in);

            List<TlsMessage> messages = record.getMessages();
            CertificateMessage certificateMessage = (CertificateMessage) messages.get(1);

            try {
                System.out.println(CertificateDecoder.decodeCertificate(certificateMessage.getCertificates().get(0).getContent()));
            } catch (CertificateException e) {
                e.printStackTrace();
            }
        });
    }

    public static int gmt_unix_time() {
        return (int) (System.currentTimeMillis() / 1000);
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

        //dump(allBytes);

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

    private static void socket(String host, int port, SocketIOConsumer ioConsumer) throws IOException {
        socket(new InetSocketAddress(host, port), ioConsumer);
    }

    private static void socket(InetSocketAddress address, SocketIOConsumer ioConsumer) throws IOException {
        try (Socket socket = new Socket()) {
            socket.connect(address);

            ioConsumer.consume(socket.getInputStream(), socket.getOutputStream());
        }
    }

    private static void write(OutputStream os, String line) throws IOException {
        os.write(line.getBytes());
    }

    private static void write(OutputStream os, byte[] bytes) throws IOException {
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

    public static void dump(InputStream is, int charsPerLine) throws IOException {
        int value;
        int charsRead = 0;

        while ((value = is.read()) != -1) {

            if (charsRead != 0) {
                System.out.print(" ");
            }

            System.out.print(Hex.toHex((byte) value));

            charsRead++;

            if (charsRead == charsPerLine) {
                System.out.println();
                charsRead = 0;
            }
        }
    }

    private static void dumpAscii(InputStream is) throws IOException {
        InputStreamReader reader = new InputStreamReader(is, StandardCharsets.US_ASCII);
        int value;

        while ((value = reader.read()) != -1) {
            System.out.print((char) value);
        }
    }


    private interface SocketIOConsumer {
        void consume(InputStream is, OutputStream os) throws IOException;
    }
}

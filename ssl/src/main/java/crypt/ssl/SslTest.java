package crypt.ssl;

import java.io.*;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Random;

public class SslTest {


    public static void main(String[] args) throws IOException {
        //sslServer();
        sslClient();
    }


    public static void sslServer() throws IOException {
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

    public static void sslClient() throws IOException {
        socket("localhost", 8090, (in, out) -> {

            write(out, bytes(
                    22 /* Content Type = Handshake */,
                    3, 3, /* Protocol Version = TLS v 1.2*/
                    int16(45 /* TBD */), /* Length*/

                    /* -------------- Handshake Message ----------- */
                    1, /* Handshake type = ClientHello*/
                    int24(41 /* TBD */), /* Handshake message data length */

                    /* Client Hello */
                    3, 3, /* Protocol Version = TLS v 1.2*/

                    int32(gmt_unix_time()), random_bytes(28), /* Random */

                    0, /* Length of Session Id */

                    int16(2), /* Bytes in Cipher Suites */
                    /*int16(0x00004C), // TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA */
                    int16(0xC02F), // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA

                    1, /* Number of compression methods */
                    0 /* Compression method */
                    /* int16(0) - should not be present */
            ));

            dump(in);
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

    public static void simpleHttpRequest() throws IOException {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress("localhost", 8090));

            /* Send request */
            String request = "GET /test HTTP/1.1\r\n" +
                    "Host: localhost:8090\r\n" +
                    "Accept: text/html, application/json\r\n" +
                    "Connection: close\r\n\r\n";

            socket.getOutputStream().write(request.getBytes());

            /* Receive response */
            String response = copyToString(socket.getInputStream(), StandardCharsets.UTF_8);
            System.out.println(response);
        }
    }

    public static String copyToString(InputStream in, Charset charset) throws IOException {
        StringBuilder out = new StringBuilder();
        InputStreamReader reader = new InputStreamReader(in, charset);
        char[] buffer = new char[8192];
        int bytesRead = -1;
        while ((bytesRead = reader.read(buffer)) != -1) {
            out.append(buffer, 0, bytesRead);
        }
        return out.toString();
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

    private static void dump(InputStream is) throws IOException {
        dump(is, 20);
    }

    private static void dump(InputStream is, int charsPerLine) throws IOException {
        int value;
        int charsRead = 0;

        while ((value = is.read()) != -1) {

            if (charsRead != 0) {
                System.out.print(" ");
            }

            System.out.print(hex(value));

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

    private static byte fromHex(String hex) {
        return Byte.parseByte(hex, 16);
    }

    private static String hex(int byteValue) {
        int intVal = byteValue & 0xFF;
        String hexValue = Integer.toHexString(intVal);
        if (intVal < 16) {
            hexValue = "0" + hexValue;
        }

        return hexValue;
    }

    private interface SocketIOConsumer {
        void consume(InputStream is, OutputStream os) throws IOException;
    }
}

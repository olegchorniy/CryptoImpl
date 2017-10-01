package crypt.ssl.testing;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Date;

public class ClientServerTest {

    private static final int PORT = 5555;

    public static void main(String[] args) throws IOException, InterruptedException {
        startServer();

        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress("localhost", PORT));

            Thread.sleep(1000);

            log("Dumping input data");
            SslTest.dump(socket.getInputStream(), 4);

            System.out.println(socket.getInputStream().read());

            log("Dumping finished");
        }
    }

    private static void startServer() {
        runInNewThread(() -> {
            try (ServerSocket serverSocket = new ServerSocket(PORT)) {
                Socket clientSocket = serverSocket.accept();
                OutputStream out = clientSocket.getOutputStream();

                out.write(0xCA);
                out.write(0xFE);
                out.write(0xBA);
                out.write(0xBE);

                out.close();

                sleep(5000);

                clientSocket.close();
                log("Client connection closed");

                sleep(2000);

            } catch (Exception e) {
                e.printStackTrace();
            }
        });
    }

    private static Thread runInNewThread(Runnable runnable) {
        Thread thread = new Thread(runnable);
        thread.start();
        return thread;
    }

    private static void sleep(int millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
    }

    private static void log(String string) {
        System.out.printf("[%s][%s]: %s%n", Thread.currentThread().getName(), new Date(), string);
    }
}

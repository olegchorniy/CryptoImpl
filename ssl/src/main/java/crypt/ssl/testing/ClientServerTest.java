package crypt.ssl.testing;

import crypt.ssl.SslTest;

import java.io.IOException;
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

            System.out.println("Dumping input data: " + new Date());
            SslTest.dump(socket.getInputStream());
        }
    }

    private static void startServer() {
        runInNewThread(() -> {
            try (ServerSocket serverSocket = new ServerSocket(PORT)) {
                Socket clientSocket = serverSocket.accept();
                clientSocket.getOutputStream().write(new byte[]{1, 2, 3, 4});
                clientSocket.close();

                System.err.println("Client connection closed: " + new Date());
            } catch (Exception e) {
                System.out.println(e);
            }
        });
    }

    private static Thread runInNewThread(Runnable runnable) {
        Thread thread = new Thread(runnable);
        thread.start();
        return thread;
    }
}

package crypt.ssl.exceptions;

public class NoCloseNotifyException extends TlsException {

    public NoCloseNotifyException() {
        super("No close_notify alert received before connection closed");
    }
}

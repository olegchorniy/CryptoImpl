package crypt.payments.broker.exceptions;

public class InvalidBrokerNameException extends RuntimeException {

    public InvalidBrokerNameException(String broker, String expectedBroker) {
        super("Broker name in the certificate doesn't match to the current broker name. " +
                "Certificate broker = " + broker + ", current broker = " + expectedBroker);
    }
}

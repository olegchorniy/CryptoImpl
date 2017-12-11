package crypt.payments.broker.service;

import crypt.payments.broker.exceptions.InvalidBrokerNameException;
import crypt.payments.certificates.Certificate;
import crypt.payments.certificates.UserCertificate;
import crypt.payments.exceptions.InvalidPaymentException;
import crypt.payments.exceptions.SignatureVerificationException;
import crypt.payments.exceptions.UserNotFoundException;
import crypt.payments.payword.Commitment;
import crypt.payments.payword.Payment;
import crypt.payments.payword.PaywordUtilities;
import crypt.payments.registration.RegistrationRequest;
import crypt.payments.registration.RegistrationResponse;
import crypt.payments.registration.User;
import crypt.payments.signatures.SignatureUtils;
import crypt.payments.signatures.rsa.RSAKeyFactory;
import crypt.payments.signatures.rsa.RSAKeyPair;
import crypt.payments.signatures.rsa.RSAPrivateKey;
import crypt.payments.signatures.rsa.RSAPublicKey;

import java.time.LocalDateTime;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

public class Broker {

    private static final int KEY_SIZE = 512;
    private static final int DEFAULT_BALANCE = 100;

    private final Certificate certificate;
    private final RSAPrivateKey signatureKey;
    private final String name;

    private final Map<UUID, User> users = new ConcurrentHashMap<>();

    public Broker(Certificate certificate, RSAPrivateKey signatureKey) {
        this.name = certificate.getSubjectName();
        this.certificate = certificate;
        this.signatureKey = signatureKey;
    }

    public void redeem(Commitment commitment, Payment payment) {
        UserCertificate certificate = commitment.getCertificate();

        byte[] root = commitment.getRoot();

        // 1. Verify payment itself
        if (!PaywordUtilities.verifyPayment(PaywordUtilities.PAYWORD_HASH, root, payment)) {
            throw new InvalidPaymentException(root, payment);
        }

        // 2. Verify user's signature on the commitment
        if (!SignatureUtils.verify(commitment, certificate)) {
            throw new SignatureVerificationException("Commitment signature verification failed");
        }

        // 3. Verify users certificate
        if (!this.name.equals(certificate.getBroker())) {
            throw new InvalidBrokerNameException(certificate.getBroker(), this.name);
        }

        if (!SignatureUtils.verify(certificate, this.certificate)) {
            throw new SignatureVerificationException("UserCertificate signature verification failed");
        }

        // 4. Transfer funds.

        int amount = payment.getIndex();
        UUID senderId = certificate.getUserId();
        UUID recipientId = commitment.getRecipientId();

        User sender = requireUser(senderId);
        User recipient = requireUser(recipientId);

        sender.setBalance(sender.getBalance() - amount);
        recipient.setBalance(recipient.getBalance() + amount);
    }

    private User requireUser(UUID id) {
        User user = this.users.get(id);
        if (user == null) {
            throw new UserNotFoundException(id);
        }

        return user;
    }

    public RegistrationResponse registerUser(RegistrationRequest request) {
        String userName = request.getName();
        boolean secure = request.isSecure();
        int port = request.getPort();
        String address = request.getAddress();

        RSAKeyPair keyPair = RSAKeyFactory.generateKeyPair(KEY_SIZE);
        RSAPublicKey publicKey = keyPair.getPublicKey();
        RSAPrivateKey privateKey = keyPair.getPrivateKey();

        LocalDateTime now = LocalDateTime.now();
        UUID userId = UUID.randomUUID();

        UserCertificate userCrt = new UserCertificate(this.name, userId, userName, now.plusDays(1), publicKey);
        SignatureUtils.sign(userCrt, this.signatureKey);

        User user = new User(DEFAULT_BALANCE, port, address, secure, now, userCrt);

        this.users.put(userId, user);

        return new RegistrationResponse(user, privateKey);
    }

    public List<User> getUsers() {
        return this.users.values()
                .stream()
                .sorted(Comparator.comparing(User::getRegistrationDate).reversed())
                .collect(Collectors.toList());
    }

    public Certificate getCertificate() {
        return certificate;
    }

    public int deleteUsers() {
        int size = this.users.size();
        this.users.clear();
        return size;
    }
}

package crypt.payments.broker.service;

import crypt.payments.certificates.Certificate;
import crypt.payments.certificates.UserCertificate;
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

    public RegistrationResponse registerUser(RegistrationRequest request) {
        String userName = request.getName();
        String address = request.getAddress();
        int port = request.getPort();

        RSAKeyPair keyPair = RSAKeyFactory.generateKeyPair(KEY_SIZE);
        RSAPublicKey publicKey = keyPair.getPublicKey();
        RSAPrivateKey privateKey = keyPair.getPrivateKey();

        LocalDateTime now = LocalDateTime.now();

        UserCertificate userCrt = new UserCertificate(this.name, userName, now.plusDays(1), publicKey);
        SignatureUtils.sign(userCrt, this.signatureKey);

        User user = new User(UUID.randomUUID(), DEFAULT_BALANCE, port, address, now, userCrt);

        this.users.put(user.getId(), user);

        return new RegistrationResponse(user, privateKey);
    }

    public List<User> getUsers() {
        return this.users.values()
                .stream()
                .sorted(Comparator.comparing(User::getRegistrationDate).reversed())
                .collect(Collectors.toList());
    }
}

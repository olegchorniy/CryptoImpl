package labs.crypto.impl.service;

import crypt.payments.certificates.Certificate;
import crypt.payments.exceptions.SignatureVerificationException;
import crypt.payments.registration.RegistrationRequest;
import crypt.payments.registration.RegistrationResponse;
import crypt.payments.registration.User;
import crypt.payments.signatures.SignatureUtils;
import crypt.payments.signatures.SignedData;
import crypt.payments.signatures.rsa.RSAPrivateKey;
import labs.crypto.impl.events.UserRegistrationEvent;
import labs.crypto.impl.exceptions.UserNotRegisteredException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;

@Service
public class UserService {

    private static final Logger logger = LoggerFactory.getLogger(UserService.class);

    private final BrokerService brokerService;
    private final HostInfoProvider hostInfoProvider;
    private final ApplicationEventPublisher eventPublisher;

    @Value("${payments.user-name}")
    private String userName;

    @Value("${payments.user-address:#{null}}")
    private String userAddress;

    private volatile User user;
    private volatile RSAPrivateKey privateKey;

    public UserService(BrokerService brokerService, HostInfoProvider hostInfoProvider, ApplicationEventPublisher eventPublisher) {
        this.brokerService = brokerService;
        this.hostInfoProvider = hostInfoProvider;
        this.eventPublisher = eventPublisher;
    }

    public void createAccount() {
        RegistrationRequest request = new RegistrationRequest(
                this.userName,
                this.hostInfoProvider.isSecure(),
                this.hostInfoProvider.getHttpPort(),
                this.userAddress
        );

        RegistrationResponse response = brokerService.register(request);
        User user = response.getUser();

        Certificate brokerCertificate = brokerService.getBrokerCertificate();

        if (!SignatureUtils.verify(user.getCertificate(), brokerCertificate)) {
            logger.error("Signature verification failure: registration response = {}, broker certificate = {}",
                    response, brokerCertificate);

            throw new SignatureVerificationException("Broker signature verification failed");
        }

        this.user = user;
        this.privateKey = response.getPrivateKey();

        this.eventPublisher.publishEvent(new UserRegistrationEvent(user));
    }

    public User getUser() {
        return this.user;
    }

    public void sign(SignedData tbsDate) {
        checkUserInitialized();

        SignatureUtils.sign(tbsDate, this.privateKey);
    }

    public void checkUserInitialized() {
        if (this.user == null) {
            throw new UserNotRegisteredException();
        }
    }
}

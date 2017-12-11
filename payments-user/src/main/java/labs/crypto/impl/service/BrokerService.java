package labs.crypto.impl.service;

import crypt.payments.certificates.Certificate;
import crypt.payments.payword.Commitment;
import crypt.payments.payword.Payment;
import crypt.payments.payword.RedeemRequest;
import crypt.payments.registration.RegistrationRequest;
import crypt.payments.registration.RegistrationResponse;
import crypt.payments.registration.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
public class BrokerService {

    private static final ParameterizedTypeReference<List<User>> users = new ParameterizedTypeReference<List<User>>() {
    };

    @Value("${payments.broker-address}")
    private String brokerAddress;

    private final RestTemplate rest;

    public BrokerService(RestTemplate rest) {
        this.rest = rest;
    }


    public String getBrokerAddress() {
        return this.brokerAddress;
    }

    public Certificate getBrokerCertificate() {
        String url = buildUrl("/api/certificate");
        return this.rest.getForObject(url, Certificate.class);
    }

    public RegistrationResponse register(RegistrationRequest request) {
        String url = buildUrl("/api/register");
        return this.rest.postForObject(url, request, RegistrationResponse.class);
    }

    public List<User> getRegisteredUsers() {
        String url = buildUrl("/api/users");
        return this.rest.exchange(url, HttpMethod.GET, null, users).getBody();
    }

    public void redeem(Commitment commitment, Payment lastPayment) {
        String url = buildUrl("/api/redeem");
        RedeemRequest request = new RedeemRequest(commitment, lastPayment);
        this.rest.postForObject(url, request, Void.class);
    }

    public Optional<User> getUserById(UUID id) {
        return this.getRegisteredUsers()
                .stream()
                .filter(u -> u.getCertificate().getUserId().equals(id))
                .findFirst();
    }

    private String buildUrl(String path) {
        return UriComponentsBuilder.fromUriString(this.brokerAddress)
                .path(path)
                .build()
                .encode()
                .toUriString();
    }
}

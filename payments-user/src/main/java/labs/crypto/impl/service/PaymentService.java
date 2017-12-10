package labs.crypto.impl.service;

import crypt.payments.payword.PaywordGenerator;
import crypt.payments.registration.User;
import labs.crypto.impl.events.UserRegistrationEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.UUID;

@Service
public class PaymentService {

    private final BrokerService brokerService;
    private final RestTemplate rest;

    private volatile User currentUser;

    public PaymentService(BrokerService brokerService, RestTemplate rest) {
        this.brokerService = brokerService;
        this.rest = rest;
    }

    @EventListener(UserRegistrationEvent.class)
    public void onUserRegistered(UserRegistrationEvent event) {
        // reset current state
        this.currentUser = (User) event.getSource();
    }

    public void startPaymentSession(UUID receiverId, int chainLength) {
        User receiver = this.brokerService.getUserById(receiverId)
                .orElseThrow(() -> new RuntimeException("Receiver not found: " + receiverId));

        String url = buildUrl(receiver, "/api/startSession");

        //new PaywordGenerator("SHA-256").cratePaywordChain(chainLength);

        //this.rest.postForObject()
    }

    private String buildUrl(User user, String path) {
        return UriComponentsBuilder.newInstance()
                .host(user.getAddress())
                .port(user.getPort())
                .path(path)
                .build()
                .encode()
                .toUriString();
    }
}

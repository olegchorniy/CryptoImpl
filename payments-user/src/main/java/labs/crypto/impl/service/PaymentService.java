package labs.crypto.impl.service;

import crypt.payments.exceptions.InvalidPaymentException;
import crypt.payments.payword.Commitment;
import crypt.payments.payword.Payment;
import crypt.payments.payword.PaywordUtilities;
import crypt.payments.registration.User;
import labs.crypto.impl.events.UserRegistrationEvent;
import labs.crypto.impl.exceptions.SessionNotFoundException;
import labs.crypto.impl.exceptions.UserNotFoundException;
import labs.crypto.impl.model.IncomingSession;
import labs.crypto.impl.model.OutgoingSession;
import labs.crypto.impl.model.rest.StartSessionResponse;
import labs.crypto.impl.model.rest.TransferRequest;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;

@Service
public class PaymentService {

    private final BrokerService brokerService;
    private final UserService userService;
    private final RestTemplate rest;

    private final Map<UUID, IncomingSession> incomingSessions = new ConcurrentHashMap<>();
    private final Map<UUID, OutgoingSession> outgoingSessions = new ConcurrentHashMap<>();
    private final AtomicInteger balance = new AtomicInteger(0);

    public PaymentService(BrokerService brokerService, UserService userService, RestTemplate rest) {
        this.brokerService = brokerService;
        this.userService = userService;
        this.rest = rest;
    }

    @EventListener(UserRegistrationEvent.class)
    public void onUserRegistered(UserRegistrationEvent event) {
        // reset current state
        this.incomingSessions.clear();
        this.outgoingSessions.clear();
        this.balance.set(((User) event.getSource()).getBalance());
    }

    /* --------------- Session managements methods ---------------- */

    public void startOutgoingSession(UUID receiverId, int chainLength) {
        this.userService.checkUserInitialized();

        User recipient = findOrThrowException(receiverId);
        chainLength = Math.min(chainLength, this.balance.get());

        // Generate paywords and commitment
        byte[][] paywords = PaywordUtilities.createPaywordChain(PaywordUtilities.PAYWORD_HASH, chainLength);
        Commitment commitment = createCommitment(recipient, paywords);

        // Send commitment to the remote user
        String url = buildUrlToUser(recipient, "/api/startSession");
        StartSessionResponse response = this.rest.postForObject(url, commitment, StartSessionResponse.class);

        // Create outgoing session object and store it
        UUID sessionId = response.getSessionId();
        OutgoingSession session = new OutgoingSession(sessionId, recipient, paywords);

        this.outgoingSessions.put(sessionId, session);

        // Refresh user balance
        this.balance.addAndGet(-chainLength);
    }

    public UUID startIncomingSession(Commitment commitment) {
        this.userService.checkUserInitialized();

        UUID userId = getUserId(commitment);

        // Finish existing session from the same user if any.
        findBy(this.incomingSessions, s -> getUserId(s.getCommitment()), userId).ifPresent(this::doFinishIncomingSession);

        // Create new incoming session
        UUID sessionId = UUID.randomUUID();
        IncomingSession session = new IncomingSession(sessionId, commitment);

        this.incomingSessions.put(sessionId, session);

        return sessionId;
    }


    public void finishOutgoingSession(UUID sessionId) {
        this.userService.checkUserInitialized();

        OutgoingSession session = requireSession(this.outgoingSessions, sessionId);
        User recipient = session.getRecipient();

        String url = buildUrlToUser(recipient, "/api/finish/{sessionId}");
        this.rest.postForObject(url, null, Void.class, sessionId);

        // Everything is ok, we can return unpaid paywords to the user's balance
        int unpaidPaywords = session.getPaywords().length - 1 - session.getLastPaymentIndex();
        this.balance.addAndGet(unpaidPaywords);
        this.outgoingSessions.remove(sessionId);
    }

    public void finishIncomingSession(UUID sessionId) {
        doFinishIncomingSession(requireSession(this.incomingSessions, sessionId));
    }

    private void doFinishIncomingSession(IncomingSession session) {
        // TODO: finish
        UUID sessionId = session.getSessionId();

        Commitment commitment = session.getCommitment();
        Payment lastPayment = session.getLastPayment();

        this.brokerService.redeem(commitment, lastPayment);

        // Update internal state
        this.balance.addAndGet(lastPayment.getIndex());
        this.incomingSessions.remove(sessionId);
    }

    private UUID getUserId(Commitment commitment) {
        return commitment.getCertificate().getUserId();
    }

    private Commitment createCommitment(User recipient, byte[][] paywords) {
        Commitment commitment = new Commitment();

        commitment.setCurrentDate(LocalDateTime.now());
        commitment.setRoot(paywords[0]);
        commitment.setRecipientId(recipient.getCertificate().getUserId());
        commitment.setCertificate(this.userService.getUser().getCertificate());

        this.userService.sign(commitment);

        return commitment;
    }

    /* --------------- Payment methods ---------------- */

    public void transferMoneyTo(UUID sessionId, int amount) {
        this.userService.checkUserInitialized();

        OutgoingSession session = requireSession(this.outgoingSessions, sessionId);

        User recipient = session.getRecipient();
        byte[][] paywords = session.getPaywords();
        int lastPaymentIndex = session.getLastPaymentIndex();

        /* Prepare next payment */
        int nextIndex = Math.min(lastPaymentIndex + amount, paywords.length - 1);
        byte[] nextPayword = paywords[nextIndex];
        Payment payment = new Payment(nextIndex, nextPayword);

        /* Send payment */
        String url = buildUrlToUser(recipient, "/api/transfer");
        this.rest.postForObject(url, new TransferRequest(sessionId, payment), Void.class);

        /* Update state */
        session.setLastPaymentIndex(nextIndex);
    }

    public void receiveMoneyFrom(UUID sessionId, Payment nextPayment) {
        this.userService.checkUserInitialized();

        IncomingSession session = requireSession(this.incomingSessions, sessionId);

        Payment lastPayment = session.getLastPayment();

        if (!PaywordUtilities.verifyPayment(PaywordUtilities.PAYWORD_HASH, lastPayment, nextPayment)) {
            throw new InvalidPaymentException(sessionId, lastPayment, nextPayment);
        }

        session.setLastPayment(lastPayment);
    }

    /* ---------------- Utilities ------------------ */

    private User findOrThrowException(UUID id) {
        return this.brokerService.getUserById(id).orElseThrow(() -> new UserNotFoundException(id));
    }

    private static <V> V requireSession(Map<UUID, V> map, UUID sessionId) {
        V session = map.get(sessionId);
        if (session == null) {
            throw new SessionNotFoundException(sessionId);
        }

        return session;
    }

    private String buildUrlToUser(User user, String path) {
        return UriComponentsBuilder.newInstance()
                .host(user.getAddress())
                .port(user.getPort())
                .path(path)
                .build()
                .encode()
                .toUriString();
    }

    private static <T, V> Optional<T> findBy(Map<?, T> elements, Function<? super T, V> fieldGetter, V value) {
        return elements.values()
                .stream()
                .filter(e -> Objects.equals(fieldGetter.apply(e), value))
                .findFirst();
    }
}
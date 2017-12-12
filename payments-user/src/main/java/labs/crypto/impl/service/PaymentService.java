package labs.crypto.impl.service;

import crypt.payments.exceptions.InvalidPaymentException;
import crypt.payments.exceptions.UserNotFoundException;
import crypt.payments.payword.Commitment;
import crypt.payments.payword.Payment;
import crypt.payments.payword.PaywordUtilities;
import crypt.payments.registration.User;
import labs.crypto.impl.events.UserRegistrationEvent;
import labs.crypto.impl.exceptions.SessionNotFoundException;
import labs.crypto.impl.model.IncomingSession;
import labs.crypto.impl.model.OutgoingSession;
import labs.crypto.impl.model.rest.StartSessionResponse;
import labs.crypto.impl.model.rest.TransferRequest;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.time.LocalDateTime;
import java.util.*;
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

    /* ------------------- Getters --------------------- */

    public Collection<IncomingSession> getIncomingSessions() {
        return incomingSessions.values();
    }

    public OutgoingSession getOutgoingSessionById(UUID sessionId) {
        return this.outgoingSessions.get(sessionId);
    }

    public OutgoingSession getOutgoingSessionByRecipient(UUID recipientId) {
        return outgoingSessions.values()
                .stream()
                .filter(session -> session.getRecipient().getCertificate().getUserId().equals(recipientId))
                .findFirst()
                .orElse(null);
    }

    public int getBalance() {
        return this.balance.get();
    }

    /* --------------- Session managements methods ---------------- */

    public UUID startOutgoingSession(UUID recipientId, int chainLength) {
        this.userService.checkUserInitialized();

        User recipient = findOrThrowException(recipientId);
        chainLength = Math.min(chainLength, this.balance.get());

        findBy(this.outgoingSessions, this::getUserId, recipientId).ifPresent(this::doFinishOutgoingSession);

        // Generate paywords and commitment
        byte[][] paywords = PaywordUtilities.createPaywordChain(PaywordUtilities.PAYWORD_HASH, chainLength);
        Commitment commitment = createCommitment(recipient, paywords);

        // Send commitment to the remote user
        String url = buildUrlToUser(recipient, "/api/session/start");
        StartSessionResponse response = this.rest.postForObject(url, commitment, StartSessionResponse.class);

        // Create outgoing session object and store it
        UUID sessionId = response.getSessionId();
        OutgoingSession session = new OutgoingSession(sessionId, recipient, paywords);

        this.outgoingSessions.put(sessionId, session);

        // Refresh user balance
        this.balance.addAndGet(-chainLength);

        return sessionId;
    }

    public UUID startIncomingSession(Commitment commitment) {
        this.userService.checkUserInitialized();

        //TODO: it would be great to check if the recipient id from the request is equal to our id
        //UUID recipientId = commitment.getRecipientId();

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

        String url = buildUrlToUser(recipient, "/api/session/finish/{sessionId}", sessionId);
        this.rest.postForObject(url, null, Void.class);

        // Everything is ok, we can return unpaid paywords to the user's balance
        doFinishOutgoingSession(session);
    }

    public void finishIncomingSession(UUID sessionId) {
        this.userService.checkUserInitialized();

        IncomingSession session = requireSession(this.incomingSessions, sessionId);

        // communicate to broker and update internal state
        doFinishIncomingSession(session);

        // notify user that session has been finished
        UUID senderId = session.getCommitment().getCertificate().getUserId();
        User sender = findOrThrowException(senderId);
        String url = buildUrlToUser(sender, "/api/session/finished/{sessionId}", sessionId);

        this.rest.postForObject(url, null, Void.class);
    }

    public void onOutgoingSessionFinished(UUID sessionId) {
        doFinishOutgoingSession(requireSession(this.outgoingSessions, sessionId));
    }

    public void onIncomingSessionFinished(UUID sessionId) {
        doFinishIncomingSession(requireSession(this.incomingSessions, sessionId));
    }

    /* ------------------ Methods which apply changes locally ----------------- */

    private void doFinishOutgoingSession(OutgoingSession session) {
        int unpaidPaywords = session.getPaywords().length - 1 - session.getLastPaymentIndex();
        this.balance.addAndGet(unpaidPaywords);
        this.outgoingSessions.remove(session.getSessionId());
    }

    private void doFinishIncomingSession(IncomingSession session) {
        Commitment commitment = session.getCommitment();
        Payment lastPayment = session.getLastPayment();

        if (lastPayment != null) {
            this.brokerService.redeem(commitment, lastPayment);
            this.balance.addAndGet(lastPayment.getIndex());
        }

        // Update internal state
        this.incomingSessions.remove(session.getSessionId());
    }

    private UUID getUserId(Commitment commitment) {
        return commitment.getCertificate().getUserId();
    }

    private UUID getUserId(OutgoingSession session) {
        return session.getRecipient().getCertificate().getUserId();
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

        if (lastPayment == null) {
            checkAgainstRoot(session, nextPayment);
        } else {
            checkAgainstPrevPayment(sessionId, lastPayment, nextPayment);
        }

        session.setLastPayment(nextPayment);
    }

    private void checkAgainstRoot(IncomingSession session, Payment nextPayment) {
        byte[] root = session.getCommitment().getRoot();
        if (!PaywordUtilities.verifyPayment(PaywordUtilities.PAYWORD_HASH, root, nextPayment)) {
            throw new InvalidPaymentException(root, nextPayment);
        }
    }

    private void checkAgainstPrevPayment(UUID sessionId, Payment lastPayment, Payment nextPayment) {
        if (!PaywordUtilities.verifyPayment(PaywordUtilities.PAYWORD_HASH, lastPayment, nextPayment)) {
            throw new InvalidPaymentException(sessionId, lastPayment, nextPayment);
        }
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

    private String buildUrlToUser(User user, String path, Object... uriVariables) {
        return UriComponentsBuilder.newInstance()
                .scheme(user.isSecure() ? "https" : "http")
                .host(user.getAddress())
                .port(user.getPort())
                .path(path)
                .buildAndExpand(uriVariables)
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
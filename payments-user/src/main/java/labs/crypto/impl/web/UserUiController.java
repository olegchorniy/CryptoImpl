package labs.crypto.impl.web;

import crypt.payments.certificates.Certificate;
import crypt.payments.certificates.UserCertificate;
import crypt.payments.payword.Commitment;
import crypt.payments.payword.Payment;
import crypt.payments.registration.User;
import crypt.payments.utils.HexUtils;
import labs.crypto.impl.model.OutgoingSession;
import labs.crypto.impl.model.RenderRequest;
import labs.crypto.impl.model.ui.*;
import labs.crypto.impl.service.BrokerService;
import labs.crypto.impl.service.PaymentService;
import labs.crypto.impl.service.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.Comparator;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

@Controller
@RequestMapping
public class UserUiController {

    private static final Logger logger = LoggerFactory.getLogger(UserUiController.class);

    private final PaymentService paymentService;
    private final UserService userService;
    private final BrokerService brokerService;

    public UserUiController(PaymentService paymentService, UserService userService, BrokerService brokerService) {
        this.paymentService = paymentService;
        this.userService = userService;
        this.brokerService = brokerService;
    }

    @GetMapping("/")
    public String index(@RequestParam(name = "recipient", required = false) UUID recipientId, Model model) {
        User user = this.userService.getUser();
        if (user != null) {
            UserCertificate userCertificate = user.getCertificate();

            UserModel userModel = new UserModel(
                    userCertificate.getUserId(),
                    userCertificate.getSubjectName(),
                    this.paymentService.getBalance()
            );

            model.addAttribute("user", userModel);
        }


        BrokerModel brokerModel = null;
        try {
            brokerModel = getBrokerModel(user);
        } catch (Exception e) {
            logger.error("Cant fetch broker", e);
        }

        model.addAttribute("broker", brokerModel);

        if (brokerModel != null) {
            if (recipientId != null) {
                model.addAttribute("recipient", makeRecipient(recipientId));
            }

            model.addAttribute("incomingSessions", makeIncomingSessions());
        }

        return "index";
    }

    private List<IncomingSessionModel> makeIncomingSessions() {
        return this.paymentService.getIncomingSessions()
                .stream()
                .map(session -> {
                    UUID sessionId = session.getSessionId();
                    Payment payment = session.getLastPayment();

                    Commitment commitment = session.getCommitment();
                    UserCertificate certificate = commitment.getCertificate();
                    SenderModel sender = new SenderModel(certificate.getUserId(), certificate.getSubjectName());


                    return new IncomingSessionModel(
                            sender,
                            sessionId,
                            payment == null ? 0 : payment.getIndex(),
                            HexUtils.toHex(commitment.getRoot())
                    );
                })
                .collect(Collectors.toList());
    }

    private BrokerModel getBrokerModel(User user) {
        String address = this.brokerService.getBrokerAddress();
        Certificate certificate = this.brokerService.getBrokerCertificate();

        List<Vendor> vendors = getVendors(user);

        return new BrokerModel(
                certificate.getSubjectName(),
                address,
                vendors
        );
    }

    private List<Vendor> getVendors(User user) {
        UUID userId = user == null ? null : user.getCertificate().getUserId();

        return this.brokerService.getRegisteredUsers()
                .stream()
                .map(this::makeVendor)
                .filter(v -> user == null || !v.getId().equals(userId))
                .sorted(Comparator.comparing(Vendor::getRegistrationDate).reversed())
                .collect(Collectors.toList());
    }

    private Vendor makeVendor(User user) {
        UserCertificate certificate = user.getCertificate();
        String address = userAddress(user);
        OutgoingSession session = this.paymentService.getOutgoingSessionByRecipient(certificate.getUserId());

        return new Vendor(
                certificate.getUserId(),
                certificate.getSubjectName(),
                address,
                user.getRegistrationDate(),
                session == null ? null : session.getSessionId()
        );
    }

    private RecipientModel makeRecipient(UUID vendorId) {
        return this.brokerService.getUserById(vendorId)
                .map(recipient -> {
                    UserCertificate certificate = recipient.getCertificate();

                    OutgoingSession session = this.paymentService.getOutgoingSessionByRecipient(vendorId);
                    OutgoingSessionModel sessionModel = session == null ? null : makeSessionModel(session);

                    return new RecipientModel(
                            vendorId,
                            certificate.getSubjectName(),
                            userAddress(recipient),
                            sessionModel
                    );
                })
                .orElse(null);
    }

    private OutgoingSessionModel makeSessionModel(OutgoingSession session) {
        UUID sessionId = session.getSessionId();

        int amount = session.getLastPaymentIndex();
        byte[][] paywords = session.getPaywords();

        List<PaywordModel> paywordsModel = IntStream.range(0, paywords.length)
                .mapToObj(i -> new PaywordModel(i <= amount, HexUtils.toHex(paywords[i])))
                .collect(Collectors.toList());

        return new OutgoingSessionModel(
                sessionId,
                amount,
                paywordsModel
        );
    }

    private String userAddress(User user) {
        return UriComponentsBuilder.newInstance()
                .scheme(user.isSecure() ? "https" : "http")
                .host(user.getAddress())
                .port(user.getPort())
                .build()
                .encode()
                .toUriString();
    }

    @PostMapping("/render")
    public String render(@RequestBody RenderRequest request, Model model) {
        model.addAllAttributes(request.getParams());
        return request.getTemplate();
    }
}

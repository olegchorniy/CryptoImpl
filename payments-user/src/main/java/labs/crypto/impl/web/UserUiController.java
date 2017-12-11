package labs.crypto.impl.web;

import crypt.payments.certificates.Certificate;
import crypt.payments.certificates.UserCertificate;
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
    public String index(@RequestParam(name = "session", required = false) UUID sessionId, Model model) {
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
            if (sessionId != null) {
                model.addAttribute("outgoingSession", getOutgoingSession(sessionId));
            }
        }

        return "index";
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

    private OutgoingSessionModel getOutgoingSession(UUID sessionId) {
        OutgoingSession session = this.paymentService.getOutgoingSessionById(sessionId);
        if (session == null) {
            return null;
        }

        return makeOutgoingSession(session);
    }

    private OutgoingSessionModel makeOutgoingSession(OutgoingSession session) {
        UUID sessionId = session.getSessionId();
        User recipient = session.getRecipient();
        UserCertificate certificate = recipient.getCertificate();

        RecipientModel recipientModel = new RecipientModel(certificate.getSubjectName(), userAddress(recipient));

        int amount = session.getLastPaymentIndex();
        byte[][] paywords = session.getPaywords();

        List<PaywordModel> paywordsModel = IntStream.range(0, paywords.length)
                .mapToObj(i -> new PaywordModel(i <= amount, HexUtils.toHex(paywords[i])))
                .collect(Collectors.toList());

        return new OutgoingSessionModel(
                sessionId,
                recipientModel,
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

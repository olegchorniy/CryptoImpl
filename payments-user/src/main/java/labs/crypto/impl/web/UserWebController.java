package labs.crypto.impl.web;

import labs.crypto.impl.service.BrokerService;
import labs.crypto.impl.service.PaymentService;
import labs.crypto.impl.service.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RequestMapping("/ui")
@RestController
public class UserWebController {

    private static final Logger logger = LoggerFactory.getLogger(UserWebController.class);

    private final PaymentService paymentService;
    private final UserService userService;
    private final BrokerService brokerService;

    public UserWebController(PaymentService paymentService, UserService userService, BrokerService brokerService) {
        this.paymentService = paymentService;
        this.userService = userService;
        this.brokerService = brokerService;
    }


    @GetMapping("/test")
    public String test() {
        System.out.println("test");
        return "OK";
    }

    /* ----------------------- Action endpoints ------------------- */

    @PostMapping("/register")
    @ResponseStatus(HttpStatus.OK)
    public void register() {
        this.userService.createAccount();
    }

    @PostMapping("/transfer")
    @ResponseStatus(HttpStatus.OK)
    public void transferMoney(@RequestParam("sessionId") UUID sessionId,
                              @RequestParam("amount") int amount) {
        this.paymentService.transferMoneyTo(sessionId, amount);
    }

    @PostMapping("/outgoing/start")
    @ResponseStatus(HttpStatus.OK)
    public void startSession(@RequestParam("recipientId") UUID recipientId,
                             @RequestParam("chainLength") int chainLength) {
        this.paymentService.startOutgoingSession(recipientId, chainLength);
    }

    @PostMapping("/outgoing/finish")
    @ResponseStatus(HttpStatus.OK)
    public void finishOutgoing(@RequestParam("sessionId") UUID sessionId) {
        this.paymentService.finishOutgoingSession(sessionId);
    }

    @PostMapping("/incoming/finish")
    @ResponseStatus(HttpStatus.OK)
    public void finishIncoming(@RequestParam("sessionId") UUID sessionId) {
        this.paymentService.finishIncomingSession(sessionId);
    }
}

package labs.crypto.impl.web;

import crypt.payments.payword.Commitment;
import labs.crypto.impl.model.rest.StartSessionResponse;
import labs.crypto.impl.model.rest.TransferRequest;
import labs.crypto.impl.service.PaymentService;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequestMapping("/api")
public class UserApiController {

    private final PaymentService paymentService;

    public UserApiController(PaymentService paymentService) {
        this.paymentService = paymentService;
    }

    @PostMapping("/session/start")
    public StartSessionResponse startSession(@RequestBody Commitment commitment) {
        UUID sessionId = this.paymentService.startIncomingSession(commitment);

        return new StartSessionResponse(sessionId);
    }

    @PostMapping("/session/finish/{sessionId}")
    public void finish(@PathVariable("sessionId") UUID sessionId) {
        this.paymentService.onIncomingSessionFinished(sessionId);
    }

    @PostMapping("/session/finished/{sessionId}")
    public void sessionFinished(@PathVariable("sessionId") UUID sessionId) {
        this.paymentService.onOutgoingSessionFinished(sessionId);
    }

    @PostMapping("/transfer")
    @ResponseStatus(HttpStatus.OK)
    public void transfer(@RequestBody TransferRequest request) {
        this.paymentService.receiveMoneyFrom(request.getSessionId(), request.getPayment());
    }
}

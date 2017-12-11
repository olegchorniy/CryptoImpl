package labs.crypto.impl.web;

import crypt.payments.payword.Commitment;
import labs.crypto.impl.model.rest.StartSessionResponse;
import labs.crypto.impl.model.rest.TransferRequest;
import labs.crypto.impl.service.PaymentService;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

import static org.springframework.web.bind.annotation.RequestMethod.POST;

@RestController
@RequestMapping("/api")
public class UserApiController {

    private final PaymentService paymentService;

    public UserApiController(PaymentService paymentService) {
        this.paymentService = paymentService;
    }

    @RequestMapping(path = "/startSession", method = POST)
    public StartSessionResponse startSession(@RequestBody Commitment commitment) {
        UUID sessionId = this.paymentService.startIncomingSession(commitment);

        return new StartSessionResponse(sessionId);
    }

    @RequestMapping(path = "/finish/{sessionId}", method = POST)
    public void finishSession(@PathVariable("sessionId") UUID sessionId) {
        this.paymentService.finishIncomingSession(sessionId);
    }

    @RequestMapping(path = "/finished/{sessionId}", method = POST)
    public void finishedSession(@PathVariable("sessionId") UUID sessionId) {
        this.paymentService.finishOutgoingSession(sessionId);
    }

    @RequestMapping("/transfer")
    @ResponseStatus(HttpStatus.OK)
    public void transfer(@RequestBody TransferRequest request) {
        this.paymentService.receiveMoneyFrom(request.getSessionId(), request.getPayment());
    }
}

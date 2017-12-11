package labs.crypto.impl.web;

import crypt.payments.payword.Commitment;
import labs.crypto.impl.model.rest.StartSessionResponse;
import labs.crypto.impl.model.rest.TransferRequest;
import labs.crypto.impl.service.PaymentService;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

@RestController
@RequestMapping("/api")
public class UserApiController {

    private final PaymentService paymentService;

    public UserApiController(PaymentService paymentService) {
        this.paymentService = paymentService;
    }

    @RequestMapping("/startSession")
    public StartSessionResponse startSession(@RequestBody Commitment commitment) {
        UUID sessionId = this.paymentService.startIncomingSession(commitment);

        return new StartSessionResponse(sessionId);
    }

    @RequestMapping("/transfer")
    @ResponseStatus(HttpStatus.OK)
    public void transfer(@RequestBody TransferRequest request) {
        this.paymentService.receiveMoneyFrom(request.getSessionId(), request.getPayment());
    }
}

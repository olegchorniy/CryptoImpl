package crypt.payments.broker.web;

import crypt.payments.broker.service.Broker;
import crypt.payments.certificates.Certificate;
import crypt.payments.payword.RedeemRequest;
import crypt.payments.registration.RegistrationRequest;
import crypt.payments.registration.RegistrationResponse;
import crypt.payments.registration.User;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.util.List;

import static org.springframework.web.bind.annotation.RequestMethod.GET;
import static org.springframework.web.bind.annotation.RequestMethod.POST;

@RequestMapping("/api")
@RestController
public class BrokerApiController {

    private final Broker broker;

    public BrokerApiController(Broker broker) {
        this.broker = broker;
    }

    /* --------------------- Auxiliary endpoints ------------------- */

    @RequestMapping(path = "/certificate", method = GET)
    public Certificate certificate() {
        return this.broker.getCertificate();
    }

    @RequestMapping(path = "/users", method = GET)
    public List<User> users() {
        return this.broker.getUsers();
    }

    /* --------------------- Main endpoints ------------------- */

    @RequestMapping(path = "/register", method = POST)
    public RegistrationResponse register(@RequestBody RegistrationRequest request, HttpServletRequest servletRequest) {
        if (request.getAddress() == null) {
            request.setAddress(servletRequest.getRemoteAddr());
        }

        return this.broker.registerUser(request);
    }

    @RequestMapping(path = "/redeem", method = POST)
    public void redeem(@RequestBody RedeemRequest request) {
        this.broker.redeem(request.getCommitment(), request.getPayment());
    }
}

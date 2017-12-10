package crypt.payments.broker.web;

import crypt.payments.broker.service.Broker;
import crypt.payments.registration.RegistrationRequest;
import crypt.payments.registration.RegistrationResponse;
import crypt.payments.registration.User;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RequestMapping("/api")
@RestController
public class ApiController {

    private final Broker broker;

    public ApiController(Broker broker) {
        this.broker = broker;
    }

    @RequestMapping(path = "/register", method = RequestMethod.POST)
    public RegistrationResponse register(@RequestBody RegistrationRequest request) {
        return this.broker.registerUser(request);
    }

    @RequestMapping(path = "/users", method = RequestMethod.GET)
    public List<User> users() {
        return this.broker.getUsers();
    }
}

package labs.crypto.impl.events;

import crypt.payments.registration.User;
import org.springframework.context.ApplicationEvent;

public class UserRegistrationEvent extends ApplicationEvent {

    public UserRegistrationEvent(User user) {
        super(user);
    }
}

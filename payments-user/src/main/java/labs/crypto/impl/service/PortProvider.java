package labs.crypto.impl.service;

import org.springframework.boot.context.embedded.EmbeddedServletContainerInitializedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Service;

@Service
public class PortProvider {

    private volatile int port;

    public int getHttpPort() {
        return this.port;
    }

    @EventListener(EmbeddedServletContainerInitializedEvent.class)
    public void onApplicationEvent(EmbeddedServletContainerInitializedEvent event) {
        this.port = event.getEmbeddedServletContainer().getPort();
    }
}

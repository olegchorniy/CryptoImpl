package labs.crypto.impl.service;

import org.apache.catalina.startup.Tomcat;
import org.springframework.boot.context.embedded.EmbeddedServletContainer;
import org.springframework.boot.context.embedded.EmbeddedServletContainerInitializedEvent;
import org.springframework.boot.context.embedded.tomcat.TomcatEmbeddedServletContainer;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Service;

@Service
public class HostInfoProvider {

    private volatile int port;
    private volatile boolean secure;

    public int getHttpPort() {
        return this.port;
    }

    public boolean isSecure() {
        return this.secure;
    }

    @EventListener(EmbeddedServletContainerInitializedEvent.class)
    public void onApplicationEvent(EmbeddedServletContainerInitializedEvent event) {
        EmbeddedServletContainer container = event.getEmbeddedServletContainer();
        this.port = container.getPort();

        // TODO: CHECK THIS!!!
        Tomcat tomcat = ((TomcatEmbeddedServletContainer) container).getTomcat();
        this.secure = tomcat.getConnector().getSecure();
    }
}

package crypt.payments.broker.configuration;

import com.google.gson.Gson;
import crypt.payments.broker.service.Broker;
import crypt.payments.certificates.Certificate;
import crypt.payments.signatures.SignatureUtils;
import crypt.payments.signatures.rsa.RSAKeyFactory;
import crypt.payments.signatures.rsa.RSAKeyPair;
import crypt.payments.signatures.rsa.RSAPrivateKey;
import crypt.payments.signatures.rsa.RSAPublicKey;
import crypt.payments.utils.GsonFactory;
import lombok.SneakyThrows;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;

import java.io.IOException;
import java.io.InputStreamReader;
import java.time.LocalDateTime;
import java.time.Month;

@Configuration
public class BrokerConfiguration {

    private static final Logger logger = LoggerFactory.getLogger(BrokerConfiguration.class);

    private static final String BROKER_NAME = "Lab_N3_Broker";

    @Bean
    public Broker broker() {
        Resource crtResource = new ClassPathResource("brokerCertificate.json");
        Resource privateKeyResource = new ClassPathResource("brokerPrivateKey.json");

        Broker broker;

        if (crtResource.exists() && privateKeyResource.exists()) {
            broker = deserializeBroker(crtResource, privateKeyResource);
            logger.info("Broker deserialized, certificate = {}", broker.getCertificate());
        } else {
            broker = newBroker();
            logger.info("New broker created, certificate = {}", broker.getCertificate());
        }

        return broker;
    }

    @SneakyThrows
    private Broker deserializeBroker(Resource certificateResource, Resource privateKeyResource) {
        Gson gson = GsonFactory.createGson();

        Certificate certificate = deserialize(gson, certificateResource, Certificate.class);
        RSAPrivateKey privateKey = deserialize(gson, privateKeyResource, RSAPrivateKey.class);

        return new Broker(certificate, privateKey);
    }

    private <T> T deserialize(Gson gson, Resource resource, Class<T> clazz) throws IOException {
        try (InputStreamReader reader = new InputStreamReader(resource.getInputStream())) {
            return gson.fromJson(reader, clazz);
        }
    }

    private Broker newBroker() {
        RSAKeyPair keyPair = RSAKeyFactory.generateKeyPair(512);
        RSAPublicKey publicKey = keyPair.getPublicKey();
        RSAPrivateKey privateKey = keyPair.getPrivateKey();

        Certificate certificate = new Certificate();
        certificate.setSubjectName(BROKER_NAME);
        certificate.setExpirationDate(LocalDateTime.of(2017, Month.DECEMBER.getValue(), 31, 23, 59));
        certificate.setPublicKey(publicKey);

        SignatureUtils.sign(certificate, privateKey);

        return new Broker(certificate, privateKey);
    }
}

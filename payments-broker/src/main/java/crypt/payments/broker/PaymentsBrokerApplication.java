package crypt.payments.broker;

import com.google.gson.*;
import crypt.payments.utils.GsonFactory;
import crypt.payments.utils.HexUtils;
import lombok.SneakyThrows;
import lombok.ToString;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import java.security.Security;
import java.util.UUID;

@SpringBootApplication
public class PaymentsBrokerApplication {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Bean
    public Gson gson() {
        return GsonFactory.createGson();
    }

    public static void main(String[] args) {
        SpringApplication.run(PaymentsBrokerApplication.class, args);
        //byteSeDeTest();
    }

    @SneakyThrows
    private static void byteSeDeTest() {
        JsonSerializer<byte[]> serializer = (bytes, type, context) -> new JsonPrimitive(HexUtils.toHex(bytes));
        JsonDeserializer<byte[]> deserializer = (bytesJson, type, context) -> HexUtils.fromHex(bytesJson.getAsString());

        Gson gson = new GsonBuilder()
                .registerTypeAdapter(byte[].class, serializer)
                .registerTypeAdapter(byte[].class, deserializer)
                .serializeNulls()
                .create();

        Test test = new Test();
        test.a = new byte[]{1, 2, 3, (byte) 0xFF, (byte) 0xAB};
        test.b = null;

        String json = gson.toJson(test);
        System.out.println(json);

        System.out.println(gson.fromJson(json, Test.class));
    }


    @ToString
    static class Test {
        byte[] a;
        byte[] b;

        UUID id = UUID.randomUUID();
    }
}

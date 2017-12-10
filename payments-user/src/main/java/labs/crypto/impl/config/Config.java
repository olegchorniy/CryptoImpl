package labs.crypto.impl.config;

import com.google.gson.Gson;
import crypt.payments.utils.GsonFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.converter.json.GsonHttpMessageConverter;
import org.springframework.web.client.RestTemplate;

import java.util.Collections;

@Configuration
public class Config {

    @Bean
    public Gson gson() {
        return GsonFactory.createGson();
    }

    @Bean
    public RestTemplate rest() {
        GsonHttpMessageConverter gsonConverter = new GsonHttpMessageConverter();
        gsonConverter.setGson(gson());

        RestTemplate rest = new RestTemplate();
        rest.setMessageConverters(Collections.singletonList(gsonConverter));

        return rest;
    }
}

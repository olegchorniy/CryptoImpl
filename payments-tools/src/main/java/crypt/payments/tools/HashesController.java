package crypt.payments.tools;

import crypt.payments.utils.HashUtils;
import crypt.payments.utils.HexUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@RequestMapping("/api")
public class HashesController {

    private static final Logger LOGGER = LoggerFactory.getLogger(HashesController.class);

    @RequestMapping("/hash")
    @ResponseBody
    public String hash(
            @RequestParam("data") String data,
            @RequestParam("alg") String algorithm
    ) {
        byte[] hex = HexUtils.fromHex(data);
        byte[] hash = HashUtils.hash(algorithm, hex);

        return HexUtils.toHex(hash);
    }
}

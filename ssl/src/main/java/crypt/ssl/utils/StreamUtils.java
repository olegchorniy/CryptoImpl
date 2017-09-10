package crypt.ssl.utils;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

public abstract class StreamUtils {

    private StreamUtils() {
    }

    public static String copyToAsciiString(InputStream in) throws IOException {
        return copyToString(in, StandardCharsets.US_ASCII);
    }

    public static String copyToUTF8String(InputStream in) throws IOException {
        return copyToString(in, StandardCharsets.UTF_8);
    }

    public static String copyToString(InputStream in, Charset charset) throws IOException {
        StringBuilder out = new StringBuilder();
        InputStreamReader reader = new InputStreamReader(in, charset);
        char[] buffer = new char[8192];
        int bytesRead = -1;

        while ((bytesRead = reader.read(buffer)) != -1) {
            out.append(buffer, 0, bytesRead);
        }

        return out.toString();
    }
}

package crypt.ssl.utils;

import java.util.Objects;

public abstract class Assert {

    private Assert() {
    }

    public static void assertNotNull(Object obj) {
        assertTrue(obj != null, "Object should not be null");
    }

    public static void assertEquals(Object left, Object right) {
        assertTrue(Objects.equals(left, right));
    }

    public static void assertTrue(boolean expression, String message) {
        if (!expression) {
            throw new IllegalStateException(message);
        }
    }

    public static void assertTrue(boolean expression) {
        assertTrue(expression, "[Assertion failed] - this state invariant must be true");
    }
}

package crypt.ssl.utils;

public abstract class Assert {

    private Assert() {
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

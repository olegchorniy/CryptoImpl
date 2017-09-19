package crypt.ssl.messages;

import crypt.ssl.utils.Hex;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class Extensions {

    static final Extensions EMPTY = new Extensions(Collections.emptyMap());

    private final Map<Integer, byte[]> table;

    private Extensions(Map<Integer, byte[]> table) {
        this.table = table;
    }

    public byte[] get(int type) {
        return table.get(type);
    }

    @Override
    public String toString() {
        return table.toString();
    }

    public static Extensions empty() {
        return EMPTY;
    }

    public static ExtensionsBuilder builder() {
        return new ExtensionsBuilder();
    }

    public static class ExtensionsBuilder {

        private final Map<Integer, byte[]> extensions;

        ExtensionsBuilder() {
            this.extensions = new HashMap<>();
        }

        public void add(int type, byte[] value) {
            byte[] oldValue;
            if ((oldValue = this.extensions.put(type, value)) != null) {
                throw new IllegalStateException("Duplicated extension of type '" + Hex.toHex16(type) + "'. " +
                        "Old value = " + Hex.toHex(oldValue) + ". " +
                        "New value = " + Hex.toHex(value) + ".");
            }
        }

        public Extensions build() {
            if (extensions.isEmpty()) {
                return EMPTY;
            }

            return new Extensions(Collections.unmodifiableMap(this.extensions));
        }
    }
}

package crypt.ssl.messages;

import crypt.ssl.utils.Hex;

import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.stream.Collectors;

public class Extensions implements Iterable<Extension> {

    static final Extensions EMPTY = new Extensions(Collections.emptyMap());

    private final Map<Integer, byte[]> table;

    private Extensions(Map<Integer, byte[]> table) {
        this.table = table;
    }

    public byte[] get(int type) {
        return table.get(type);
    }

    public int size() {
        return this.table.size();
    }

    public boolean isEmpty() {
        return this.table.isEmpty();
    }

    @Override
    public Iterator<Extension> iterator() {
        return this.table.entrySet()
                .stream()
                .map(extension -> new Extension(extension.getKey(), extension.getValue()))
                .collect(Collectors.toList())
                .iterator();
    }

    @Override
    public String toString() {
        return table.entrySet()
                .stream()
                .map(e -> Hex.toHex16(e.getKey()) + " : " + Hex.toHex(e.getValue()))
                .collect(Collectors.joining(",", "[", "]"));
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

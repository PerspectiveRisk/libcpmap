// Copyright (c) 2019-2020 Calum Ewart Hutton
// Distributed under the GNU General Public License v3.0+, see the accompanying
// file LICENSE or https://opensource.org/licenses/GPL-3.0.

package lib.chutchut.cpmap.payload.base;

import com.google.gson.ExclusionStrategy;
import com.google.gson.FieldAttributes;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import lib.chutchut.cpmap.util.Util;
import lib.chutchut.cpmap.vector.CPVector;


public abstract class Payload {

    private transient Map<String, String> templatePlaceholderMap;
    private static transient String templatePlaceholderPattern = "(\\[([A-Z]+)\\])";

    protected String name;
    protected String template;
    protected int type;

    public interface IPayload {
        void renderPlaceholder(String key);
        boolean isSupportedVector(CPVector vector);
    }

    protected abstract static class Builder {
        protected String name;
        protected String template;
        protected int type;
        protected CPVector vector;

        protected Builder(int type, String name, String template) {
            this.type = type;
            this.template = template;
            this.name = name;
        }

        protected Builder(Payload payload) {
            this.type = payload.type;
            this.template = payload.template;
            this.name = payload.name;
        }

        protected Builder(Payload payload, CPVector vector) {
            this.type = payload.type;
            this.template = payload.template;
            this.name = payload.name;
            this.vector = vector.copy();
        }

        public CPVector getVector() {
            return vector;
        }

        public void setVector(CPVector vector) {
            this.vector = vector;
        }

        public CPVector getRenderedVector() {
            if (vector != null) {
                return vector.getWithPayload(build());
            }
            return null;
        }

        public abstract Payload build();
    }

    public static ExclusionStrategy exclude = new ExclusionStrategy() {
        @Override
        public boolean shouldSkipField(FieldAttributes f) {
            return false;
        }

        @Override
        public boolean shouldSkipClass(Class<?> clazz) {
            // Exclude inner Builder and Payloads classes
            return clazz.isAssignableFrom(Builder.class) || clazz.getSimpleName().equals("Payloads");
        }
    };

    /*
     * Default constructor for Gson
     */
    protected Payload() {}

    protected Payload(int type, String name, String template) {
        this.type = type;
        this.name = name;
        this.template = template;
    }

    protected Payload(Builder baseBuilder) {
        this.type = baseBuilder.type;
        this.name = baseBuilder.name;
        this.template = baseBuilder.template;
    }

    public static String replaceTemplatePlaceholder(String template, String key, String replace) {
        if (template == null) {
            return null;
        }
        if (replace == null) {
            replace = "";
        }
        return template.replaceAll("(\\[" + key.toUpperCase() + "\\])", replace);
    }

    public int getType() {
        return type;
    }

    public String getTypeString() {
        return name;
    }

    public String getTemplate() {
        return template;
    }

    private Matcher getTemplateMatcher() {
        Pattern placeholderRegex = Pattern.compile(templatePlaceholderPattern);
        return placeholderRegex.matcher(template);
    }

    private Map<String, String> getPlaceholderMap() {
        if (templatePlaceholderMap == null) {
            templatePlaceholderMap = new HashMap<>();
        }
        return templatePlaceholderMap;
    }

    private ArrayList<String> getUnmappedPlaceholderKeys() {
        Set<String> differenceSet = new HashSet<>(getTemplatePlaceholderKeys());
        differenceSet.removeAll(new HashSet<>(getMappedPlaceholderKeys()));
        return new ArrayList<>(differenceSet);
    }

    private ArrayList<String> getMappedPlaceholderKeys() {
        return new ArrayList<>(getPlaceholderMap().keySet());
    }

    private ArrayList<String> getTemplatePlaceholderKeys() {
        ArrayList<String> keys = new ArrayList<>();
        Matcher matcher = getTemplateMatcher();
        while (matcher.find()) {
            keys.add(matcher.group(2));
        }
        return keys;
    }

    public boolean templateHasKey(String key) {
        return getTemplatePlaceholderKeys().contains(key.toUpperCase());
    }

    protected void setPlaceholder(String key, String val) {
        getPlaceholderMap().put(key, val);
    }

    public static boolean isLogicalExpression(String expr) {
        if (expr == null) {
            return false;
        }
        String[] opChars = new String[] {"<", ">", "=", "!"};
        for (String chr : opChars) {
            if (expr.contains(chr)) {
                return true;
            }
        }
        return false;
    }

    private String getPlaceholder(String key) {
        if (getPlaceholderMap().containsKey(key)) {
            return getPlaceholderMap().get(key);
        }
        return null;
    }

    private void callInterface() {
        // Ensure this object implements IPayload
        if (!(this instanceof IPayload)) {
            throw new RuntimeException("Payload object (" + getClass().getCanonicalName() + ") does not implement IPayload");
        }
        IPayload iface = (IPayload) this;
        // Map the placeholder keys to replacement values
        ArrayList<String> keys = getTemplatePlaceholderKeys();
        for (String key : keys) {
            iface.renderPlaceholder(key);
        }
    }

    protected String renderTemplate() {
        // Check the template has been set
        if (template == null || template.trim().length() == 0) {
            throw new RuntimeException("Payload template not set");
        }
        // (*Always!*) Call interface methods to set placeholder vars
        callInterface();
        // Check for unmapped placeholder vars and raise an exception if any found
        ArrayList<String> unmapped = getUnmappedPlaceholderKeys();
        if (unmapped.size() > 0) {
            String msg = "Unmapped placeholder keys found: " + Util.listToString(unmapped);
            throw new RuntimeException(msg);
        }
        // Use the mapped placeholder vars to render the payload template
        String payload = template;
        for (String key : getMappedPlaceholderKeys()) {
            payload = replaceTemplatePlaceholder(payload, key, getPlaceholder(key));
        }
        // Normalise spaces
        payload = payload.replaceAll("\\s+", " ");
        // Check for empty payload
        if (payload.trim().length() == 0) {
            throw new RuntimeException("Empty payload");
        }
        return payload;
    }

    public boolean endsWith(String end) {
        String trimmedPayload = getPayload().trim();
        return trimmedPayload.endsWith(end);
    }

    public boolean endsWithComment() {
        return endsWith("--") || endsWith("/*");
    }

    public String getPayload() {
        return renderTemplate();
    }

    @Override
    public String toString() {
        return getPayload();
    }

    @Override
    public int hashCode() {
        return Objects.hash(getPayload());
    }

    @Override
    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        } else if (obj == null) {
            return false;
        } else if (!(obj instanceof Payload)) {
            return false;
        }

        Payload otherPayload = (Payload) obj;
        return hashCode() == otherPayload.hashCode();
    }
}

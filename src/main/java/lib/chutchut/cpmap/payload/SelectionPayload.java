// Copyright (c) 2019-2020 Calum Ewart Hutton
// Distributed under the GNU General Public License v3.0+, see the accompanying
// file LICENSE or https://opensource.org/licenses/GPL-3.0.

package lib.chutchut.cpmap.payload;

import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import lib.chutchut.cpmap.payload.base.InjectionPayload;
import lib.chutchut.cpmap.util.Util;
import lib.chutchut.cpmap.vector.CPVector;

public class SelectionPayload extends InjectionPayload {

    public static final String NAME = "SELECTION";
    public static final int TYPE = 338;

    protected String input;
    protected String expectedOutput;
    protected String alias;
    protected int row;

    public static class Payloads {
        private static String[] templates = new String[]{
                " ([INPUT][LIMIT])[ALIAS] ",
        };

        public static Set<SelectionPayload> getDefault() {
            Map<String, String> inOutMap = new HashMap<>();
            inOutMap.put("'XXX'||'YYY'", "XXXYYY");
            return get(inOutMap);
        }

        public static Set<SelectionPayload> get(Map<String, String> inOuts) {
            LinkedHashSet<SelectionPayload> payloads = new LinkedHashSet<>();
            for (String tpl : templates) {
                for (Map.Entry<String, String> entry : inOuts.entrySet()) {
                    Builder builder = new Builder(TYPE, NAME, tpl);
                    builder.setInput(entry.getKey());
                    builder.setExpectedOutput(entry.getValue());
                    payloads.add(builder.build());
                }
            }
            return payloads;
        }
    }

    public static class Builder extends InjectionPayload.Builder {
        protected String input = "'XXX'||'YYY'";
        protected String expectedOutput = "XXXYYY";
        protected String alias;
        protected int row;

        public Builder(int type, String name, String template) {
            super(type, name, template);
        }

        public Builder(SelectionPayload payload, CPVector vector) {
            super(payload, vector);
            input = payload.input;
            expectedOutput = payload.expectedOutput;
            alias = payload.alias;
            row = payload.row;
        }

        public void setRow(int newRow) {
            row = newRow;
        }

        public void addRow() {
            row++;
        }

        public void setInput(String in) {
            input = in;
        }

        public void setExpectedOutput(String out) {
            expectedOutput = out;
        }

        public void setAlias(String al) {
            alias = al;
        }

        @Override
        public SelectionPayload build() {
            return new SelectionPayload(this);
        }
    }

    /*
     * Default constructor for Gson
     */
    protected SelectionPayload() {
        super();
    }

    public SelectionPayload(int type, String name, String template) {
        super(type, name, template);
    }

    protected SelectionPayload(Builder builder) {
        super(builder);
        input = builder.input;
        expectedOutput = builder.expectedOutput;
        alias = builder.alias;
        row = builder.row;
    }

    public String getInput() {
        return input;
    }

    public String getExpectedOutput() {
        return expectedOutput;
    }

    public String getAlias() {
        return alias;
    }

    public int getRow() {
        return row;
    }

    @Override
    public void renderPlaceholder(String key) {
        // Call parent to render base keys
        super.renderPlaceholder(key);
        switch (key) {
            case "INPUT":
                setPlaceholder(key, renderInput());
                break;
            case "LIMIT":
                setPlaceholder(key, renderLimit());
                break;
            case "ALIAS":
                setPlaceholder(key, renderAlias());
                break;
        }
    }

    @Override
    public boolean isSupportedVector(CPVector vector) {
        // Expect a non-null query vector which is *not*: PROJECTION, SORT_ORDER, CVALS_KEY
        return vector != null && vector.isQuery() && !Util.listContains(new int[] {CPVector.PROJECTION, CPVector.SORT_ORDER, CPVector.CVALS_KEY}, vector.getType());
    }

    private String renderInput() {
        return input;
    }

    private String renderLimit() {
        return row <= 0 ? "" : " LIMIT 1 OFFSET " + (row - 1);
    }

    private String renderAlias() {
        return alias != null ? " AS " + alias : "";
    }
}

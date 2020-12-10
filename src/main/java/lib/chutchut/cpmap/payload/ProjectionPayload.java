// Copyright (c) 2019-2020 Calum Ewart Hutton
// Distributed under the GNU General Public License v3.0+, see the accompanying
// file LICENSE or https://opensource.org/licenses/GPL-3.0.

package lib.chutchut.cpmap.payload;

import java.util.LinkedHashSet;
import java.util.Set;

import lib.chutchut.cpmap.payload.base.InjectionPayload;
import lib.chutchut.cpmap.vector.CPVector;

public class ProjectionPayload extends InjectionPayload {

    public static final String NAME = "PROJECTION";
    public static final int TYPE = 337;

    protected String table;

    public static class Payloads {
        private static String[] templates = new String[]{
                "[FIELD] [FROM] [TABLE] [WHERE] [ACOND] [EXTRA] --",
                "[FIELD] [FROM] [TABLE] [WHERE] [ACOND] [EXTRA] /*"
        };

        public static Set<ProjectionPayload> getDefault() {
            return get();
        }

        public static Set<ProjectionPayload> get() {
            LinkedHashSet<ProjectionPayload> payloads = new LinkedHashSet<>();
            for (String tpl : templates) {
                Builder builder = new Builder(TYPE, NAME, tpl);
                payloads.add(builder.build());
            }
            return payloads;
        }
    }

    public static class Builder extends InjectionPayload.Builder {
        protected String table = defaultTable;

        public Builder(int type, String name, String template) {
            super(type, name, template);
        }

        public Builder(ProjectionPayload payload, CPVector vector) {
            super(payload, vector);
            table = payload.table;
        }

        public void setTable(String tbl) {
            table = tbl;
        }

        @Override
        public ProjectionPayload build() {
            return new ProjectionPayload(this);
        }
    }

    /*
     * Default constructor for Gson
     */
    protected ProjectionPayload() {
        super();
    }

    public ProjectionPayload(int type, String name, String template) {
        super(type, name, template);
    }

    protected ProjectionPayload(Builder builder) {
        super(builder);
        table = builder.table;
    }

    public String getTable() {
        return table;
    }

    @Override
    public void renderPlaceholder(String key) {
        // Call parent to render base keys
        super.renderPlaceholder(key);
        switch (key) {
            case "TABLE":
                setPlaceholder(key, renderTable());
                break;
            case "FROM":
                setPlaceholder(key, renderFrom());
                break;
            case "WHERE":
                setPlaceholder(key, renderWhere());
                break;
        }
    }

    @Override
    public boolean isSupportedVector(CPVector vector) {
        // Expect non-null PROJECTION vector
        return vector != null && vector.getType() == CPVector.PROJECTION;
    }

    private String renderTable() {
        return table;
    }

    private String renderFrom() {
        return table == null ? "" : "FROM";
    }

    protected String renderWhere() {
        return getField() == null || !getField().toLowerCase().contains(" where ") ? "WHERE 1=1" : "";
    }
}

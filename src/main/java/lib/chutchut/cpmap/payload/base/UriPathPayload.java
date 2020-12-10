// Copyright (c) 2019-2020 Calum Ewart Hutton
// Distributed under the GNU General Public License v3.0+, see the accompanying
// file LICENSE or https://opensource.org/licenses/GPL-3.0.

package lib.chutchut.cpmap.payload.base;

import lib.chutchut.cpmap.vector.CPVector;

public abstract class UriPathPayload extends Payload implements Payload.IPayload {

    protected String targetPath;
    protected boolean encodeSlashes;

    public abstract static class Builder extends Payload.Builder {
        protected String targetPath = "/system/etc/hosts";
        protected boolean encodeSlashes;

        protected Builder(int type, String name, String template) {
            super(type, name, template);
        }

        protected Builder(UriPathPayload pathPayload, CPVector vector) {
            super(pathPayload, vector);
            targetPath = pathPayload.targetPath;
            encodeSlashes = pathPayload.encodeSlashes;
        }

        public void setTargetPath(String path) {
            targetPath = path;
        }

        public void setEncodeSlashes(boolean encode) {
            encodeSlashes = encode;
        }
    }

    /*
     * Default constructor for Gson
     */
    protected UriPathPayload() {
        super();
    }

    protected UriPathPayload(int type, String name, String template) {
        super(type, name, template);
    }

    protected UriPathPayload(Builder builder) {
        super(builder);
        targetPath = builder.targetPath;
        encodeSlashes = builder.encodeSlashes;
    }

    public String getTargetPath() {
        return targetPath;
    }

    protected boolean getEncodeSlashes() {
        return encodeSlashes;
    }

    private String encodePayloadSlashes(String input) {
        // Dont encode the first slash
        return "/" + input.substring(1).replace("/", "%2F");
    }

    @Override
    public void renderPlaceholder(String key) {
        switch (key) {
            case "PATH":
                setPlaceholder(key, renderTargetPath());
                break;
        }
    }

    private String renderTargetPath() {
        return targetPath;
    }

    @Override
    protected String renderTemplate() {
        String rendered = super.renderTemplate();
        if (encodeSlashes) {
            return encodePayloadSlashes(rendered);
        } else {
            return rendered;
        }
    }

}

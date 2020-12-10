// Copyright (c) 2019-2020 Calum Ewart Hutton
// Distributed under the GNU General Public License v3.0+, see the accompanying
// file LICENSE or https://opensource.org/licenses/GPL-3.0.

package lib.chutchut.cpmap.payload;

import java.util.LinkedHashSet;
import java.util.Set;

import lib.chutchut.cpmap.payload.base.InjectionPayload;
import lib.chutchut.cpmap.payload.base.Payload;
import lib.chutchut.cpmap.vector.CPVector;


public class HeuristicPayload extends InjectionPayload implements Payload.IPayload {

    public static final String NAME = "HEURISTIC";
    public static final int TYPE = 333;

    public static class Payloads {
        private static String[] templates = new String[] {
                "[FIELD][QUO]"
        };

        public static Set<HeuristicPayload> getDefault() {
            return get(new char[] {'\'', '"'});
        }

        public static Set<HeuristicPayload> get(char[] quotes) {
            LinkedHashSet<HeuristicPayload> payloads = new LinkedHashSet<>();
            for (String tpl : templates) {
                for (char quote : quotes) {
                    Builder builder = new Builder(TYPE, NAME, tpl);
                    builder.setQuoteChar(quote);
                    payloads.add(builder.build());
                }
            }
            return payloads;
        }
    }

    public static class Builder extends InjectionPayload.Builder {
        public Builder(int type, String name, String template) {
            super(type, name, template);
        }

        public Builder(HeuristicPayload payload, CPVector vector) {
            super(payload, vector);
        }

        @Override
        public HeuristicPayload build() {
            return new HeuristicPayload(this);
        }
    }

    /*
     * Default constructor for Gson
     */
    protected HeuristicPayload() {
        super();
    }

    protected HeuristicPayload(Builder builder) {
        super(builder);
    }

    @Override
    public boolean isSupportedVector(CPVector vector) {
        // All vectors supported
        return true;
    }
}

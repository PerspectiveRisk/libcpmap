// Copyright (c) 2019-2020 Calum Ewart Hutton
// Distributed under the GNU General Public License v3.0+, see the accompanying
// file LICENSE or https://opensource.org/licenses/GPL-3.0.

package lib.chutchut.cpmap.payload.base;

import android.content.ContentValues;

import java.util.ArrayList;
import java.util.Arrays;

import lib.chutchut.cpmap.payload.HeuristicPayload;
import lib.chutchut.cpmap.payload.UnionPayload;
import lib.chutchut.cpmap.util.Util;
import lib.chutchut.cpmap.vector.CPVector;


public abstract class InjectionPayload extends Payload implements Payload.IPayload {

    protected static transient String defaultField = "rowid";
    protected static transient String defaultTable = "android_metadata";

    protected String field;
    protected int lBrackets;
    protected int rBrackets;
    protected boolean encodePayload;
    protected Character quoteChar;
    protected String operator;
    protected String extra;
    protected String[] selectionArgs = new String[0];
    protected ArrayList<String[]> conditions = new ArrayList<>();

    public abstract static class Builder extends Payload.Builder {
        protected String field = defaultField;
        protected String operator = "AND";
        protected int lBrackets;
        protected int rBrackets;
        protected boolean encodePayload;
        protected Character quoteChar;
        protected String extra;
        protected String[] selectionArgs = new String[0];
        protected ArrayList<String[]> conditions = new ArrayList<>();

        protected Builder(int type, String name, String template) {
            super(type, name, template);
        }

        protected Builder(InjectionPayload injectionPayload, CPVector vector) {
            super(injectionPayload, vector);
            field = injectionPayload.field;
            operator = injectionPayload.operator;
            lBrackets = injectionPayload.lBrackets;
            rBrackets = injectionPayload.rBrackets;
            encodePayload = injectionPayload.encodePayload;
            quoteChar = injectionPayload.quoteChar;
            extra = injectionPayload.extra;
            selectionArgs = Arrays.copyOf(injectionPayload.selectionArgs, injectionPayload.selectionArgs.length);
            conditions = new ArrayList<>(injectionPayload.conditions);

            if (getVector() != null) {
                // Set selection args from InjectionPayloads
                if (!Util.nullOrEmpty(selectionArgs)) {
                    getVector().setSelection(selectionArgs);
                }

                // Set the payload field to the query param used in the injection if not set explicitly
                if (getVector().getQueryParamField() != null && (field == null || field.equals(defaultField))) {
                    field = getVector().getQueryParamField();
                }

                // Url-encode URI segment vectors
                if ((getVector().getType() == CPVector.URI_SEGMENT || getVector().getType() == CPVector.URI_ID) && injectionPayload.getType() != HeuristicPayload.TYPE) {
                    encodePayload = true;
                }

                // Also ensure UNION payloads in URI segment vectors are set with the appropriate table instead of field
                if (getVector().getType() == CPVector.URI_SEGMENT && injectionPayload.getType() == UnionPayload.TYPE && getVector().getTable() != null) {
                    field = getVector().getTable();
                }

                // Clear the field for uri id vectors
                if (getVector().getType() == CPVector.URI_ID) {
                    field = "";
                }
            }
        }

        public void setField(String fld) {
            field = fld;
        }

        public void setLBrackets(int lb) {
            lBrackets = lb;
        }

        public void setRBrackets(int rb) {
            rBrackets = rb;
        }

        public void setEncodePayload(boolean encode) {
            encodePayload = encode;
        }

        public void setQuoteChar(Character quote) {
            quoteChar = quote;
        }

        public void setOperator(String op) {
            operator = op;
        }

        public void setExtra(String ex) {
            extra = ex;
        }

        public void setSelectionArgs(String[] sargs) {
            selectionArgs = sargs;
        }

        public void addSelectionArg(String sarg) {
            String[] args = new String[selectionArgs.length + 1];
            // Copy existing array
            System.arraycopy(selectionArgs, 0, args, 0, selectionArgs.length);
            // Add new val to end
            args[args.length - 1] = sarg;
            selectionArgs = args;
        }

        public void removeSelectionArg() {
            // Remove the last argument if its not noll and empty
            if (!Util.nullOrEmpty(selectionArgs)) {
                String[] args = new String[selectionArgs.length - 1];
                // Copy existing array, minus 1
                System.arraycopy(selectionArgs, 0, args, 0, selectionArgs.length - 1);
                selectionArgs = args;
            }
        }

        public void setConditions(ArrayList<String[]> conds) {
            conditions = conds;
        }

        public void addPlaceholderCondition() {
            addCondition("'XXX'", "?");
        }

        public void addCondition(String left, String right) {
            conditions.add(new String[] {left, right});
        }

        public void removeCondition() {
            if (!Util.nullOrEmpty(conditions)) {
                conditions.remove(conditions.size() - 1);
            }
        }

        public void setBrackets(int num) {
            if (num >= 0) {
                lBrackets = num;
                rBrackets = num;
            }
        }

        public boolean handleWithoutRowid(CPVector vector) {
            String alternativeField = null;
            if (vector.getColsWithFilter("_id").size() > 0) {
                // Use the first id col
                alternativeField = vector.getColsWithFilter("_id").get(0);
            } else if (vector.getColsWithFilter("Id").size() > 0) {
                // Use the first id col
                alternativeField = vector.getColsWithFilter("Id").get(0);
            } else if (vector.getColsWithFilter("id").size() > 0) {
                // Use the first id col
                alternativeField = vector.getColsWithFilter("id").get(0);
            } else if (vector.getColsWithFilter(null).size() > 0) {
                // Use the first from vector query fields
                alternativeField = vector.getColsWithFilter(null).get(0);
            }
            if (alternativeField != null && !alternativeField.equals(field)) {
                field = alternativeField;
                return true;
            }
            return false;
        }
    }

    /*
     * Default constructor for Gson
     */
    protected InjectionPayload() {
        super();
    }

    protected InjectionPayload(int type, String name, String template) {
        super(type, name, template);
    }

    protected InjectionPayload(Builder builder) {
        super(builder);
        field = builder.field;
        operator = builder.operator;
        lBrackets = builder.lBrackets;
        rBrackets = builder.rBrackets;
        encodePayload = builder.encodePayload;
        quoteChar = builder.quoteChar;
        extra = builder.extra;
        selectionArgs = builder.selectionArgs;
        conditions = builder.conditions;
    }

    public String getField() {
        return field;
    }

    public static String getDefaultField() {
        return defaultField;
    }

    public static String getDefaultTable() {
        return defaultTable;
    }

    public static ContentValues getDummyValues() {
        // Dummy vals (use the field if set)
        ContentValues vals = new ContentValues();
        vals.put(defaultField, "123");
        return vals;
    }

    public int getLBrackets() {
        return lBrackets;
    }

    public int getRBrackets() {
        return rBrackets;
    }

    public boolean getEncodePayload() {
        return encodePayload;
    }

    public Character getQuoteChar() {
        return quoteChar;
    }

    public String getOperator() {
        return operator;
    }

    public String getExtra() {
        return extra;
    }

    public String[] getSelectionArgs() {
        return selectionArgs;
    }

    public ArrayList<String[]> getConditions() {
        return conditions;
    }
    
    protected String[] getBrackets(int num) {
        String lb = "";
        String rb = "";
        for (int i = 0; i < num; i++) {
            lb = lb + ")";
            rb = rb + "(";
        }
        return new String[] {lb, rb};
    }

    protected String[] getConditionArray(boolean bool) {
        if (bool) {
            return new String[] {"1", "1", "="};
        } else {
            return new String[] {"1", "2", "="};
        }
    }

    protected String getAdditionalCondition(boolean bool, String operator) {
        String condition = "";
        for (String[] aCond : conditions) {
            String logicalOp;
            if (aCond[0].equals(aCond[1])) {
                // Left and right operand are equal, so true operator should be equals
                if (bool) {
                    logicalOp = "=";
                } else {
                    logicalOp = "!=";
                }
            } else {
                // Left and right operand are not equal, so true operator should be not equals
                if (bool) {
                    logicalOp = "!=";
                } else {
                    logicalOp = "=";
                }
            }
            condition = condition + String.format(" %s %s %s %s", operator, aCond[0], logicalOp, aCond[1]);
        }
        return condition;
    }

    protected String getCondition(boolean bool) {
        // Dont quote the condition
        String[] cond = getConditionArray(bool);
        return String.format("%s=%s", cond[0], cond[1]);
    }

    protected String getRightCondition(boolean bool) {
        // Quote the condition if quote char is set
        if (quoteChar == null) {
            return getCondition(bool);
        }
        String[] cond = getConditionArray(bool);
        return String.format("%s%s%s=%s%s", quoteChar, cond[0], quoteChar, quoteChar, cond[1]);
    }

    protected String getLeftCondition(boolean bool) {
        // The left condition shouldnt be used on fields that are logical expressions
        if (isLogicalExpression(renderField())) {
            return null;
        }
        // Quote the condition if quote char is set
        if (quoteChar == null) {
            if (bool) {
                return " != -123";
            } else {
                return " = -123";
            }
        }
        if (bool) {
            return String.format("%s != -123", quoteChar);
        } else {
            return String.format("%s = -123", quoteChar);
        }
    }

    @Override
    public void renderPlaceholder(String key) {
        switch (key) {
            case "QUO":
                setPlaceholder(key, renderQuoteChar());
                break;
            case "LBR":
                setPlaceholder(key, renderLeftBracket());
                break;
            case "RBR":
                setPlaceholder(key, renderRightBracket());
                break;
            case "EXTRA":
                setPlaceholder(key, renderExtra());
                break;
            case "OP":
                setPlaceholder(key, renderOperator());
                break;
            case "FIELD":
                setPlaceholder(key, renderField());
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
        }
    }

    private String renderQuoteChar() {
        if (quoteChar != null) {
            return String.valueOf(quoteChar);
        } else {
            return "";
        }
    }

    private String renderLeftBracket() {
        String[] brackets = getBrackets(lBrackets);
        return brackets[0];
    }

    private String renderRightBracket() {
        String[] brackets = getBrackets(rBrackets);
        return brackets[1];
    }

    private String renderExtra() {
        return extra;
    }

    private String renderOperator() {
        return operator;
    }

    private String renderField() {
        return replaceTemplatePlaceholder(field, "ICOND", getCondition(true));
    }

    private String renderRightCondition() {
        return getRightCondition(true);
    }

    private String renderLeftCondition() {
        return getLeftCondition(true);
    }

    private String renderAdditionalConditions() {
        return getAdditionalCondition(true, operator);
    }

    @Override
    protected String renderTemplate() {
        String rendered = super.renderTemplate();
        if (encodePayload) {
            return Util.urlEncodeString(rendered);
        } else {
            return rendered;
        }
    }

}

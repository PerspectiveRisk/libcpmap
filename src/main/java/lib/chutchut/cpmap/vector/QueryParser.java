// Copyright (c) 2019-2020 Calum Ewart Hutton
// Distributed under the GNU General Public License v3.0+, see the accompanying
// file LICENSE or https://opensource.org/licenses/GPL-3.0.

package lib.chutchut.cpmap.vector;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import lib.chutchut.cpmap.util.Util;


public class QueryParser {

    private String TAG = "QueryParser";
    private String[] reserved = new String[] {"select", "from", "where", "limit", "offset", "and", "or", "as", "join", "inner", "outer"};

    private CPVector vector;
    private String query;

    public QueryParser(CPVector vector) {
        this.vector = vector;
        this.query = vector.getQuery();
    }

    public QueryParser(String query) {
        this.query = query;
    }

    public String getQuery() {
        return query;
    }

    private ArrayList<Column> getCols() {
        if (isCreate()) {
            return getCreateCols(query);
        } else {
            // Expect both vector and query to not be null
            if (vector != null && query != null) {
                if (vector.isQuery()) {
                    return getQueryCols(query);
                } else if (vector.isUpdate()) {
                    return getUpdateCols(query);
                }
            } else if (query != null) {
                // If only the query string was used to init the parser
                if (query.trim().toLowerCase().startsWith("select ")) {
                    // Query
                    return getQueryCols(query);
                } else {
                    // Update
                    return getUpdateCols(query);
                }
            }
        }
        return null;
    }

    private boolean isCreate() {
        return query != null && query.trim().toLowerCase().startsWith("create ");
    }

    public String getInjectionVectorAlias() {
        // If the injection vector placeholder () is not present return null
        if (!query.contains("<injection>")) {
            return null;
        }

        Pattern p = Pattern.compile("<injection>\\s+AS\\s+([\\w\\d_-]+)", Pattern.CASE_INSENSITIVE);
        Matcher matcher = p.matcher(query);
        while (matcher.find()) {
            return matcher.group(1);
        }
        return null;
    }

    private ArrayList<Column> getCreateCols(String query) {
        ArrayList<Column> cols = new ArrayList<>();
        // Strip any gravess
        query = query.replace("`", "");
        Pattern p1 = Pattern.compile("CREATE\\s+TABLE\\s+[\"']?\\w+[\"']?\\s*\\(((.|\\n)+)\\)", Pattern.CASE_INSENSITIVE);
        Matcher getCreateFields = p1.matcher(query);
        if (getCreateFields.find()) {
            String[] fieldSplit = getCreateFields.group(1).split(",");
            for (int i = 0; i < fieldSplit.length; i++) {
                String[] fieldElementSplit = fieldSplit[i].trim().split(" ");
                String fieldToAdd = fieldElementSplit[0];
                if (fieldToAdd.matches("^[0-9A-Za-z-_]+[0-9a-z-_]+$")) {
                    // Dont add ALL CAPS fields, they are probably keywords (i.e. UNIQUE)
                    // Also ignore fields with invalid chars
                    cols.add(new Column(null, fieldToAdd, null));
                }
            }
        }
        return cols;
    }

    private ArrayList<Column> getQueryCols(String query) {
        // Get last index of FROM, use for substr
        ArrayList<Column> cols = new ArrayList<>();
        int lastFromIndex = query.toLowerCase().lastIndexOf(" from");
        if (lastFromIndex > 0) {
            String select = query.substring(0, lastFromIndex);
            Pattern p = Pattern.compile("(([\\w\\d_]+)\\.)?([\\w\\d_]+)(\\s+AS\\s+([\\w\\d_]+))?");
            Matcher matcher = p.matcher(select);
            while (matcher.find()) {
                String parent = matcher.group(2);
                String name = matcher.group(3);
                String alias = matcher.group(5);
                if (Util.listContains(reserved, name.toLowerCase(), true) || name.matches("^\\d+$")) {
                    continue;
                }
                cols.add(new Column(parent, name, alias));
            }
        }
        return cols;
    }

    private ArrayList<Column> getUpdateCols(String query) {
        ArrayList<Column> cols = new ArrayList<>();
        Pattern p = Pattern.compile("([\\w\\d_]+)\\s*=");
        Matcher matcher = p.matcher(query);
        while (matcher.find()) {
            String name = matcher.group(1);
            if (Util.listContains(reserved, name.toLowerCase(), true) || name.matches("^\\d+$")) {
                continue;
            }
            cols.add(new Column(null, name, null));
        }
        return cols;
    }

    public boolean isWildcard() {
        Pattern matchWildcardPattern = Pattern.compile("SELECT\\s+\\*\\s+FROM\\s+([\\w-]+)\\s?", Pattern.CASE_INSENSITIVE);
        Matcher matchWildcardQuery = matchWildcardPattern.matcher(query);
        return matchWildcardQuery.find();
    }

    public ArrayList<String> getCols(String filter) {
        ArrayList<Column> cols = getCols();
        LinkedHashSet<String> strCols = new LinkedHashSet<>();
        if (cols != null) {
            for (Column col : cols) {
                if (filter == null || col.matchName(filter)) {
                    strCols.add(col.name);
                }
            }
        }
        return new ArrayList<>(strCols);
    }

    public String getFrom() {
        Pattern matchFromPattern = Pattern.compile("\\s+FROM\\s+([\\w-]+)\\s?", Pattern.CASE_INSENSITIVE);
        Matcher matchFromQuery = matchFromPattern.matcher(query);
        if (matchFromQuery.find()) {
            return matchFromQuery.group(1);
        }
        return null;
    }

    private class Column {
        private String parentTable;
        private String name;
        private String alias;

        public Column(String parent, String name, String alias) {
            this.parentTable = parent;
            this.name = name;
            this.alias = alias;
        }

        public boolean matchName(String filter) {
            if (this.alias == null) {
                return this.name.contains(filter);
            } else {
                return this.name.contains(filter) || this.alias.contains(filter);
            }
        }
    }

}

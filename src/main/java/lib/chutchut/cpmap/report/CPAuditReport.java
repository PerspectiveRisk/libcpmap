// Copyright (c) 2019-2020 Calum Ewart Hutton
// Distributed under the GNU General Public License v3.0+, see the accompanying
// file LICENSE or https://opensource.org/licenses/GPL-3.0.

package lib.chutchut.cpmap.report;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;

import lib.chutchut.cpmap.vector.CPVector;
import lib.chutchut.cpmap.vector.QueryParser;

public class CPAuditReport {

    private HashMap<Integer, HashSet<String>> vectorTables = new HashMap<>();
    private HashMap<String, String> vectorTableSql = new HashMap<>();

    /*
     * Default constructor for Gson
     */
    private CPAuditReport() {}

    public CPAuditReport(HashMap<Integer, HashSet<String>> vectorTables, HashMap<String, String> vectorTableSql) {
        this.vectorTables = vectorTables;
        this.vectorTableSql = vectorTableSql;
    }

    public void update(CPAuditReport auditReport) {
        if (auditReport != null) {
            for (int vHash : auditReport.getVectorTables().keySet()) {
                if (vectorTables.containsKey(vHash)) {
                    vectorTables.get(vHash).addAll(auditReport.getAccessibleTables(vHash));
                } else {
                    vectorTables.put(vHash, auditReport.getAccessibleTables(vHash));
                }
            }
        }
    }

    public HashMap<Integer, HashSet<String>> getVectorTables() {
        return vectorTables;
    }

    public HashSet<String> getAccessibleTables(int vHash) {
        if (vectorTables.containsKey(vHash)) {
            return vectorTables.get(vHash);
        }
        return null;
    }

    public HashSet<String> getAccessibleTables(CPVector vector) {
        return getAccessibleTables(getVectorKey(vector));
    }

    public HashSet<String> getAllAccessibleTables() {
        HashSet<String> allTables = new HashSet<>();
        for (HashSet<String> vTables : vectorTables.values()) {
            allTables.addAll(vTables);
        }
        return allTables;
    }

    public static int getVectorKey(CPVector vector) {
        // Define the vector key as the hashCode() of the vectors uri authority, falling back to the hashCode() of the vector in
        // the case of null authorities (unlikely?)
        return vector.getUri().getAuthority() != null ? vector.getUri().getAuthority().hashCode() : vector.hashCode();
    }

    public static String getVectorTableKey(int hash, String table) {
        return String.format("%s::%s", hash, table);
    }

    public static String getVectorTableKey(CPVector vector, String table) {
        return getVectorTableKey(getVectorKey(vector), table);
    }

    public ArrayList<String> getVectorTableFields(CPVector vector, String table) {
        String key = getVectorTableKey(vector, table);
        if (vectorTableSql.containsKey(key) && vectorTableSql.get(key) != null) {
            return new QueryParser(vectorTableSql.get(key)).getCols(null);
        }
        return null;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("All accessible tables:\n\n");
        for (String table : getAllAccessibleTables()) {
            sb.append("[TABLE]: " + table + "\n");
        }
        return sb.toString();
    }
}

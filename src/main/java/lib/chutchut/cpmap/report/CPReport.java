// Copyright (c) 2019-2020 Calum Ewart Hutton
// Distributed under the GNU General Public License v3.0+, see the accompanying
// file LICENSE or https://opensource.org/licenses/GPL-3.0.

package lib.chutchut.cpmap.report;

import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Set;

import lib.chutchut.cpmap.payload.BooleanBlindPayload;
import lib.chutchut.cpmap.payload.HeuristicPayload;
import lib.chutchut.cpmap.payload.PathTraversalPayload;
import lib.chutchut.cpmap.payload.ProjectionPayload;
import lib.chutchut.cpmap.payload.SelectionPayload;
import lib.chutchut.cpmap.payload.UnionPayload;
import lib.chutchut.cpmap.payload.base.Payload;
import lib.chutchut.cpmap.util.Util;
import lib.chutchut.cpmap.vector.CPExploit;
import lib.chutchut.cpmap.vector.CPVector;

public class CPReport {

    private CPReportTarget target;
    private String sqliteVersion;
    private LinkedHashSet<CPExploit> items = new LinkedHashSet<>();
    private CPAuditReport auditReport;

    /*
     * Default constructor for Gson
     */
    public CPReport() {}

    public CPReport(CPReportTarget target, LinkedHashSet<CPExploit> items, String sqliteVer) {
        this.target = target;
        this.items = items;
        this.sqliteVersion = sqliteVer;
    }

    public CPReport(CPReportTarget target, CPExploit item, String sqliteVer) {
        this.target = target;
        this.items = new LinkedHashSet<>();
        this.items.add(item);
        this.sqliteVersion = sqliteVer;
    }

    public static CPReport fromJson(String json) {
        try {
            return Util.getGson().fromJson(json, CPReport.class);
        } catch (Exception e) {
            return null;
        }
    }

    public LinkedHashSet<CPExploit> getItems() {
        return items;
    }

    public Set<Payload> getVectorPayloads(CPVector vector) {
        HashSet<Payload> vectorPayloads = new HashSet<>();
        for (CPExploit item : items) {
            if (item.getVector().equals(vector)) {
                vectorPayloads.addAll(item.getPayloads());
            }
        }
        return vectorPayloads;
    }

    public void addItem(CPExploit item) {
        this.items.add(item);
    }

    public CPReport getVectorReport(CPVector vector) {
        if (getVectors().contains(vector)) {
            return new CPReport(target, new CPExploit(vector, getVectorPayloads(vector)), sqliteVersion);
        }
        return null;
    }

    public CPReportTarget getTarget() {
        return target;
    }

    public String getSqliteVersion() {
        return sqliteVersion;
    }

    public void setSqliteVersion(String sqlite) {
        sqliteVersion = sqlite;
    }

    public CPAuditReport getAuditReport() {
        return auditReport;
    }

    public void setAuditReport(CPAuditReport aRep) {
        auditReport = aRep;
    }

    public boolean hasUpdateVectors() {
        for (CPExploit item : items) {
            if (item.getVector().isUpdate()) {
                return true;
            }
        }
        return false;
    }

    public boolean hasReadVectors() {
        for (CPExploit item : items) {
            if (item.getVector().isQuery()) {
                return true;
            }
        }
        return false;
    }

    public boolean hasInjectionPayloads() {
        for (CPExploit item : items) {
            for (Payload vectorPayload : item.getPayloads()) {
                if (isInjectionPayload(vectorPayload)) {
                    return true;
                }
            }
        }
        return false;
    }

    public static boolean isInjectionPayload(Payload payload) {
        return payload.getType() == BooleanBlindPayload.TYPE || payload.getType() == UnionPayload.TYPE || payload.getType() == ProjectionPayload.TYPE || payload.getType() == SelectionPayload.TYPE;
    }

    public boolean hasHeuristicPayloads() {
        for (CPExploit item : items) {
            for (Payload vectorPayload : item.getPayloads()) {
                if (isHeuristicPayload(vectorPayload)) {
                    return true;
                }
            }
        }
        return false;
    }

    public static boolean isHeuristicPayload(Payload payload) {
        return payload.getType() == HeuristicPayload.TYPE;
    }

    public boolean hasPathTraversalPayloads() {
        for (CPExploit item : items) {
            for (Payload vectorPayload : item.getPayloads()) {
                if (isPathTraversalPayload(vectorPayload)) {
                    return true;
                }
            }
        }
        return false;
    }

    public static boolean isPathTraversalPayload(Payload payload) {
        return payload.getType() == PathTraversalPayload.TYPE;
    }

    public boolean hasHeuristicOnly() {
        int numHeur = 0;
        int numOther = 0;
        for (CPExploit item : items) {
            for (Payload vectorPayload : item.getPayloads()) {
                if (isHeuristicPayload(vectorPayload)) {
                    numHeur++;
                } else {
                    numOther++;
                }
            }
        }
        return numHeur > 0 && numOther == 0;
    }

    public CPExploit getPathTraversalExploit() {
        for (CPExploit item : items) {
            for (Payload vectorPayload : item.getPayloads()) {
                if (isPathTraversalPayload(vectorPayload)) {
                    return new CPExploit(item.getVector(), vectorPayload);
                }
            }
        }
        return null;
    }

    public int numVectors() {
        return getVectors().size();
    }

    public HashSet<CPVector> getVectors() {
        HashSet<CPVector> vectors = new HashSet<>();
        for (CPExploit item : items) {
            vectors.add(item.getVector());
        }
        return vectors;
    }

    public int numPayloads() {
        int numPl = 0;
        for (CPExploit item : items) {
            numPl += item.getPayloads().size();
        }
        return numPl;
    }

    public boolean contains(CPExploit item) {
        return contains(item.getVector());
    }

    public boolean contains(CPVector vector) {
        return getVectorPayloads(vector).size() > 0;
    }

    public String toJson() {
        return Util.getGson().toJson(this);
    }

    public void update(CPReport report) {
        // Only update if they are equal (i.e. same pkg and version)
        if (!report.getTarget().getTargetPkg().equalsIgnoreCase(target.getTargetPkg()) || !report.getTarget().getVersion().equalsIgnoreCase(target.getVersion())) {
            return;
        }
        for (CPExploit item : report.getItems()) {
            if (!contains(item)) {
                // New vector
                items.add(item);
            }
        }
        if (report.sqliteVersion != null && sqliteVersion == null) {
            sqliteVersion = report.getSqliteVersion();
        }
        // Update the audit report
        if (auditReport != null) {
            auditReport.update(report.auditReport);
        } else {
            auditReport = report.auditReport;
        }
    }

    private static String loadReportAsString(CPReport report) {
        StringBuilder repString = new StringBuilder();
        boolean valid = true;
        if (report == null) {
            return repString.toString();
        }
        try {
            for (CPVector vector : report.getVectors()) {
                boolean definedPathPerms = vector.getRequiredPathPermission() == null
                        || (vector.getRequiredPathPermission() != null && !vector.getRequiredPathPermission().equals("n/a"));
                repString.append("Got vector: " + vector + "\n");
                if (vector.getProviderClass() != null) {
                    repString.append("Vulnerable provider: " + vector.getProviderClass() + "\n");
                }
                if (vector.getRequiredPermission() == null && !definedPathPerms) {
                    repString.append("Permission required: null\n");
                } else if (definedPathPerms) {
                    String pathPerm = vector.getRequiredPathPermission();
                    if (pathPerm == null) {
                        pathPerm = "null";
                    }
                    repString.append("Permission required (path): " + pathPerm + "\n");
                } else if (vector.getRequiredPermission() != null) {
                    repString.append("Permission required (provider): " + vector.getRequiredPermission() + "\n");
                }
                if (vector.getQuery() != null && vector.getTable() != null) {
                    repString.append("Original query: '" + vector.getQuery() + "' (table: " + vector.getTable() + ")\n");
                }
                for (Payload payload : report.getVectorPayloads(vector)) {
                    if (payload.getType() != HeuristicPayload.TYPE) {
                        repString.append(String.format("[%s]: %s\n", payload.getTypeString(), payload.getPayload()));
                    } else {
                        repString.append(String.format("[%s]: Positive heuristic result: (%s)\n", payload.getTypeString(), payload.getPayload()));
                    }
                }
                repString.append("\n");
            }
        } catch (RuntimeException re) {
            // Probably incompatible report JSON
            valid = false;
        }

        if (valid) {
            return repString.toString();
        } else {
            return "Incompatible JSON report, re-run the scan to generate a valid report";
        }
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder(loadReportAsString(this));
        if (auditReport != null && auditReport.getAllAccessibleTables().size() > 0) {
            sb.append("\nAudit report\n\n");
            sb.append(auditReport.toString());
            sb.append("\nAccessible tables per vector:\n\n");
            for (CPVector vector : getVectors()) {
                sb.append(vector.toString() + "\n");
                if (auditReport.getAccessibleTables(vector) != null) {
                    for (String table : auditReport.getAccessibleTables(vector)) {
                        sb.append("[TABLE]: " + table + "\n");
                    }
                } else {
                    sb.append("No accessible tables\n");
                }
                sb.append("\n");
            }
        }
        return sb.toString();
    }
}

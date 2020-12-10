// Copyright (c) 2019-2020 Calum Ewart Hutton
// Distributed under the GNU General Public License v3.0+, see the accompanying
// file LICENSE or https://opensource.org/licenses/GPL-3.0.

package lib.chutchut.cpmap.util;

import android.content.ContentValues;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.PathPermission;
import android.content.pm.ProviderInfo;
import android.net.Uri;
import android.os.PatternMatcher;
import android.util.Log;

import com.google.common.base.CaseFormat;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.concurrent.ThreadLocalRandom;

import lib.chutchut.cpmap.CPMap;
import lib.chutchut.cpmap.payload.adapter.PayloadAdapter;
import lib.chutchut.cpmap.payload.base.Payload;
import lib.chutchut.cpmap.report.CPReport;
import lib.chutchut.cpmap.report.CPReportTarget;
import lib.chutchut.cpmap.vector.CPVector;

public class Util {

    private static String TAG = "LibUtil";

    public static boolean listContains(List<String> strList, String search, boolean equals) {
        if (strList == null || search == null) {
            return false;
        }
        for (String item : strList) {
            if (!equals) {
                if (item.contains(search)) {
                    return true;
                }
            } else {
                if (item.equals(search)) {
                    return true;
                }
            }
        }
        return false;
    }

    public static boolean listContains(Set<String> strSet, String search, boolean equals) {
        if (strSet == null || search == null) {
            return false;
        }
        for (String item : strSet) {
            if (!equals) {
                if (item.contains(search)) {
                    return true;
                }
            } else {
                if (item.equals(search)) {
                    return true;
                }
            }
        }
        return false;
    }

    public static boolean listContains(Object[] strArr, String search, boolean equals) {
        if (strArr == null || search == null) {
            return false;
        }
        for (Object item : strArr) {
            if (!equals) {
                if (((String) item).contains(search)) {
                    return true;
                }
            } else {
                if (((String) item).equals(search)) {
                    return true;
                }
            }
        }
        return false;
    }

    public static boolean listContains(String[] strArr, String search, boolean equals) {
        if (strArr == null || search == null) {
            return false;
        }
        for (String item : strArr) {
            if (!equals) {
                if (item.contains(search)) {
                    return true;
                }
            } else {
                if (item.equals(search)) {
                    return true;
                }
            }
        }
        return false;
    }

    public static boolean listContains(ContentValues cVals, String search, boolean equals) {
        if (cVals == null || search == null) {
            return false;
        }
        for (String key : cVals.keySet()) {
            String item = (String) cVals.get(key);
            if (!equals) {
                if (item.contains(search)) {
                    return true;
                }
            } else {
                if (item.equals(search)) {
                    return true;
                }
            }
        }
        return false;
    }

    public static boolean listContains(int[] intArr, int search) {
        if (intArr == null || search == -1) {
            return false;
        }
        for (int item : intArr) {
            if (item == search) {
                return true;
            }
        }
        return false;
    }

    public static String listToString(String[] list) {
        if (list == null) {
            return "null";
        } else if (list.length == 0) {
            return "<empty>";
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < list.length; i++) {
            if (i > 0) {
                sb.append(", ");
            }
            sb.append(list[i]);
        }
        return sb.toString();
    }

    public static String listToString(ArrayList<String> list) {
        if (list == null) {
            return "null";
        } else if (list.size() == 0) {
            return "<empty>";
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < list.size(); i++) {
            if (i > 0) {
                sb.append(", ");
            }
            sb.append(list.get(i));
        }
        return sb.toString();
    }

    public static String listToString(ContentValues cVals) {
        if (cVals == null) {
            return "null";
        } else if (cVals.size() == 0) {
            return "<empty>";
        }
        StringBuilder sb = new StringBuilder();
        int count = 0;
        for (String key : cVals.keySet()) {
            if (count > 0) {
                sb.append(", ");
            }
            if (cVals.get(key) != null) {
                sb.append(key + ":" + cVals.get(key));
            } else {
                sb.append(key + ":null");
            }
            count++;
        }
        return sb.toString();
    }

    public static boolean nullOrEmpty(Object[] obj) {
        return obj == null || obj.length == 0;
    }

    public static boolean nullOrEmpty(List obj) {
        return obj == null || obj.size() == 0;
    }

    public static boolean nullOrEmpty(ContentValues obj) {
        return obj == null || obj.size() == 0;
    }

    public static void addToList(Set<String> list, String word) {
        if (word.length() < 3) {
            return;
        }
        list.add(word);
        list.add(word.toLowerCase());
    }

    public static String[] camelCaseToArray(String in) {
        return CaseFormat.UPPER_CAMEL.to(CaseFormat.LOWER_UNDERSCORE, in).split("_");
    }

    public static String getInstalledPkgVersion(Context context, String pkg) {
        try {
            PackageInfo packageInfo = context.getPackageManager().getPackageInfo(pkg, 0);
            if (packageInfo != null) {
                if (packageInfo.versionName != null) {
                    return packageInfo.versionName;
                } else {
                    return "null";
                }
            } else {
                return null;
            }
        } catch (PackageManager.NameNotFoundException nnfe) {
            return null;
        }
    }

    public static CPReportTarget getInstalledTarget(Context context, String pkg) {
        String targetVer = getInstalledPkgVersion(context, pkg);
        if (targetVer != null) {
            return new CPReportTarget(pkg, targetVer);
        } else {
            return null;
        }
    }

    public static String getReportBasePath(Context context) {
        return context.getExternalFilesDir(null) + "/reports";
    }

    public static Gson getGson() {
        GsonBuilder gsonBuilder = new GsonBuilder();
        gsonBuilder.registerTypeAdapter(Payload.class, new PayloadAdapter());
        // Make Gson process null vars
        gsonBuilder.serializeNulls();
        if (Payload.exclude != null) {
            gsonBuilder.addSerializationExclusionStrategy(Payload.exclude);
            gsonBuilder.addDeserializationExclusionStrategy(Payload.exclude);
        } else {
            Log.w(TAG, "Payload ExclusionStrategy is null");
        }
        return gsonBuilder.create();
    }

    public static ArrayList<CPReport> loadReports(Context context, String pkg) {
        ArrayList<CPReport> reports = new ArrayList<>();
        File pkgCacheDir = new File(getReportBasePath(context) + "/" + pkg);
        if (!pkgCacheDir.exists()) {
            return reports;
        }
        for (File reportFile : pkgCacheDir.listFiles()) {
            try {
                CPReport cpReport = loadReport(reportFile);
                if (cpReport != null) {
                    reports.add(cpReport);
                }
            } catch (Exception e) {
                Log.e(TAG, "Exception loading reports for package (" + pkg + "): " + e.getMessage());
            }
        }
        return reports;
    }

    public static String readFile(File file) {
        try {
            BufferedReader br = new BufferedReader(new FileReader(file));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) {
                sb.append(String.format("%s\n", line));
            }
            br.close();
            return sb.toString();
        } catch (Exception e) {
            Log.e(TAG, "Exception reading file: (" + file.getAbsolutePath() + "): " + e.getMessage());
        }
        return null;
    }

    public static String getAuthorityFromVector(CPVector vector) {
        String auth = vector.getUri().getAuthority();
        // Split on slash and return the first segment (because segments can be part of the authority?
        String[] authSplit = auth.split("/");
        return authSplit[0].replace(CPVector.injectionChar, "");
    }

    public static boolean pkgVersionisInstalled(Context context, String pkg, String version) {
        CPReportTarget installedTarget = Util.getInstalledTarget(context, pkg);
        return installedTarget != null && installedTarget.getVersion().equalsIgnoreCase(version);
    }

    public static CPReport loadReport(String jsonString) {
        if (jsonString != null && jsonString.trim().length() > 0) {
            CPReport cpReport = null;
            try {
                cpReport = getGson().fromJson(jsonString, CPReport.class);
            } catch (RuntimeException re) {
                Log.w(TAG, "RuntimeException deserialising CPReport JSON: " + re.getMessage());
            } catch (Exception e) {
                Log.w(TAG, "Exception deserialising CPReport JSON: " + e.getMessage());
            }
            return cpReport;
        }
        return null;
    }

    public static int getRandomInt() {
        return (int) (Math.random() * ((999999 - 111111) + 1)) + 111111;
    }

    public static int getRandomIntInRange(int min, int max) {
        return ThreadLocalRandom.current().nextInt(min, max + 1);
    }

    public static CPReport loadReport(File repFile) {
        if (repFile.exists()) {
            String jsonReportString = readFile(repFile);
            return loadReport(jsonReportString);
        }
        return null;
    }

    public static String loadReportJson(Context context, String pkg, String version) {
        return loadReportJson(new File(getReportPath(context, pkg, version)));
    }

    public static String loadReportJson(File repFile) {
        if (repFile.exists()) {
            return readFile(repFile);
        }
        return null;
    }

    public static String getSafeVersionString(String version) {
        return version.replaceAll("[^\\w-.]", "-");
    }

    public static boolean saveReport(Context context, CPReport report) {
        File pkgCacheDir = new File(getReportBasePath(context) + "/" + report.getTarget().getTargetPkg());
        // Check for dir and make it if it doesnt exist
        if (!pkgCacheDir.exists()) {
            boolean dirMade = pkgCacheDir.mkdirs();
            if (!dirMade) {
                Log.e(TAG, "Couldnt create cache directory for package: " + report.getTarget().getTargetPkg());
                return false;
            }
        }
        // If the report for the version exists already, update it
        CPReport existingReport = loadReport(context, report.getTarget().getTargetPkg(), report.getTarget().getVersion());
        if (existingReport != null) {
            existingReport.update(report);
            report = existingReport;
        }
        String jsonReport = report.toJson();
        try {
            // Always overwrite the existing file
            FileWriter fw = new FileWriter(new File(Util.getReportPath(context, report.getTarget().getTargetPkg(), report.getTarget().getVersion())), false);
            fw.write(jsonReport);
            fw.close();
            return true;
        } catch (IOException ioe) {
            Log.e(TAG, "IOException saving report: " + ioe.getMessage());
        }
        return false;
    }

    public static boolean deleteReport(Context context, String pkg, String version) {
        File repFile = new File(getReportPath(context, pkg, version));
        boolean status = false;
        if (repFile.exists()) {
            try {
                repFile.delete();
                status = true;
            } catch (Exception e) {
                Log.e(TAG, "Exception deleting report: " + e.getMessage());
            }
        }
        // If there are no more reports for the package, delete the base dir
        if (loadReports(context, pkg).size() == 0) {
            status = deleteDirectory(new File(getReportBasePath(context) + "/" + pkg));
        }
        return status;
    }

    public static boolean deleteAllReports(Context context, String pkg) {
        File reportBase = new File(getReportBasePath(context) + "/" + pkg);
        boolean status = false;
        if (reportBase.exists()) {
            try {
                status = deleteDirectory(reportBase);
            } catch (Exception e) {
                Log.e(TAG, "Exception deleting reports: " + e.getMessage());
            }
        }
        return status;
    }

    public static boolean deleteDirectory(File directoryToBeDeleted) {
        File[] allContents = directoryToBeDeleted.listFiles();
        if (allContents != null) {
            for (File file : allContents) {
                deleteDirectory(file);
            }
        }
        return directoryToBeDeleted.delete();
    }

    public static CPReport loadReport(Context context, String pkg, String version) {
        return loadReport(new File(getReportPath(context, pkg, version)));
    }

    public static String getTxtReportPath(Context context, String pkg, String version) {
        // Use the safe version string for the file path to avoid invalid chars
        version = getSafeVersionString(version);
        return getReportBasePath(context) + "/" + pkg + "/report-" + pkg + "-" + version + ".txt";
    }

    public static String getReportPath(Context context, String pkg, String version) {
        // Use the safe version string for the file path to avoid invalid chars
        version = getSafeVersionString(version);
        return getReportBasePath(context) + "/" + pkg + "/report-" + pkg + "-" + version + ".json";
    }

    public static boolean copyFile(String src, String dst) {
        File source = new File(src);
        File target = new File(dst);
        return copyFile(source, target);
    }

    public static boolean copyFile(InputStream src, String dst) {
        File target = new File(dst);
        return copyFile(src, target);
    }

    public static boolean copyFile(File src, File dst) {
        InputStream in;
        try {
            in = new FileInputStream(src);
            return copyFile(in, dst);
        } catch (IOException ioe) {
            Log.e(TAG, "IOException copying target file: " + ioe.getMessage());
        }
        return false;
    }

    public static boolean copyFile(InputStream in, File dst) {
        OutputStream out = null;
        try {
            out = new FileOutputStream(dst);
            byte[] buf = new byte[1024];
            int len;
            while ((len = in.read(buf)) > 0) {
                out.write(buf, 0, len);
            }
            return true;
        } catch (IOException ioe) {
            Log.e(TAG, "IOException copying target file: " + ioe.getMessage());
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
        return false;
    }

    public static boolean deleteFile(File target) {
        try {
            return target.delete();
        } catch (Exception e) {
            Log.e(TAG,"Exception deleting file: " + e.getMessage());
        }
        return false;
    }

    public static boolean copyBytesToFile(byte[] src, File dst) {
        InputStream in = new ByteArrayInputStream(src);
        return copyFile(in, dst);
    }

    public static String readStreamToString(InputStream in) {
        ByteArrayOutputStream out = null;
        try {
            out = new ByteArrayOutputStream();
            byte[] buf = new byte[1024];

            int len;
            while((len = in.read(buf)) > 0) {
                out.write(buf, 0, len);
            }
            return new String(out.toByteArray());
        } catch (IOException var6) {
            Log.e(TAG, "IOException reading target file: " + var6.getMessage());
            return null;
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
            }
        }
    }

    public static boolean hasPermission(Context context, String perm) {
        return context.getPackageManager().checkPermission(perm, context.getPackageName()) == PackageManager.PERMISSION_GRANTED;
    }

    public static HashSet<String> getPathPermissions(ProviderInfo providerInfo) {
        HashSet<String> pathPerms = new HashSet<>();
        if (!nullOrEmpty(providerInfo.pathPermissions)) {
            for (PathPermission pathPerm : providerInfo.pathPermissions) {
                String readPerm = pathPerm.getReadPermission();
                String writePerm = pathPerm.getWritePermission();
                if (readPerm != null) {
                    pathPerms.add(readPerm);
                }
                if (writePerm != null) {
                    pathPerms.add(writePerm);
                }
            }
        }
        return pathPerms;
    }

    public static String getPathPermission(ProviderInfo providerInfo, boolean forRead, Uri uri) {
        if (!Util.nullOrEmpty(providerInfo.pathPermissions)) {
            for (PathPermission pathPerm : providerInfo.pathPermissions) {
                PatternMatcher matcher = new PatternMatcher(pathPerm.getPath(), pathPerm.getType());
                if (matcher.match(uri.getPath())) {
                    if (forRead) {
                        return pathPerm.getReadPermission();
                    } else {
                        return pathPerm.getWritePermission();
                    }
                }
            }
        }
        // Undefined
        return "n/a";
    }

    public static String[] getRowsAsStringArr(ArrayList<String[]> rows) {
        return getRowsAsString(rows).split("\n");
    }

    public static String getRowsAsString(ArrayList<String[]> rows) {
        StringBuilder sb = new StringBuilder();
        if (!Util.nullOrEmpty(rows)) {
            for (String[] row : rows) {
                for (String field : row) {
                    sb.append(field);
                    sb.append(" | ");
                }
                sb.append("\n");
            }
        }
        return sb.toString();
    }

    public static String getPackageNameByAuthority(String authority, Context context) {
        String pkgName = null;
        ProviderInfo pInfo = getProviderInfoByAuthority(authority, context);
        if (pInfo != null && pInfo.applicationInfo != null) {
            pkgName = pInfo.applicationInfo.packageName;
        }
        return pkgName;
    }

    public static PackageInfo getPackageInfo(Context context, String pkg) {
        try {
            return context.getPackageManager().getPackageInfo(pkg, getPmFlags());
        } catch (PackageManager.NameNotFoundException nnfe) {
            Log.e(TAG, "NameNotFoundException: " + nnfe.getMessage());
        }
        return null;
    }

    public static String urlEncodeString(String in) {
        try {
            String encodedVal = URLEncoder.encode(in, "UTF-8");
            // Replace spaces encoded to + to %20 (+ is not decoded in the query)
            return encodedVal.replace("+", "%20");
        } catch (UnsupportedEncodingException uee) {
            Log.e(TAG, "UnsupportedEncodingException: " + uee.getMessage());
        }
        // Fallback to the original value
        return in;
    }

    public static Set<String> getRandomSet(Set<String> strings, int num) {
        if (strings.size() < num) {
            return strings;
        }

        Set<String> tmpList = new HashSet<>();
        int numStrings = strings.size();
        String[] apkStringsArr = strings.toArray(new String[0]);
        // Choose strings at random
        while (tmpList.size() < num) {
            int rand = new Random().nextInt(numStrings);
            tmpList.add(apkStringsArr[rand]);
        }

        return tmpList;
    }

    public static ProviderInfo getProviderInfoFromPackageInfo(PackageInfo pkgInfo, String authority) {
        if (pkgInfo != null && pkgInfo.providers != null) {
            for (ProviderInfo prov : pkgInfo.providers) {
                if (prov.authority != null) {
                    if (!prov.authority.contains(";") && prov.authority.equalsIgnoreCase(authority)) {
                        return prov;
                    } else if (prov.authority.contains(";")) {
                        // Split on semi colon and check each authority
                        String authSplit[] = prov.authority.split(";");
                        for (String subAuth : authSplit) {
                            if (authority.equalsIgnoreCase(subAuth)) {
                                return prov;
                            }
                        }
                    }
                }
            }
        }
        return null;
    }

    public static int getPmFlags() {
        return PackageManager.GET_META_DATA
                |PackageManager.GET_PROVIDERS
                |PackageManager.GET_RESOLVED_FILTER
                |PackageManager.GET_INTENT_FILTERS
                |PackageManager.GET_PERMISSIONS
                |PackageManager.GET_URI_PERMISSION_PATTERNS;
    }

    public static ProviderInfo getProviderInfoByAuthority(String authority, Context context) {
        return context.getPackageManager().resolveContentProvider(authority, getPmFlags());
    }

    public static boolean isAvailableProvider(Context context, ProviderInfo pInfo) {
        // Skip internal/android providers
        if (Util.listContains(CPMap.androidProviders, pInfo.name, true)) {
            return false;
        }
        // Skip unexported/disabled providers
        if (!pInfo.exported || !pInfo.enabled) {
            return false;
        }

        if (pInfo.readPermission == null || pInfo.writePermission == null) {
            // If provider has null read/write perms
            return true;
        } else if (hasPermission(context, pInfo.readPermission) || hasPermission(context, pInfo.writePermission)) {
            // If current app context has requested read/write perms
            return true;
        } else if (pInfo.pathPermissions != null) {
            // If provider has unprotected path perms
            for (PathPermission pathPerm : pInfo.pathPermissions) {
                if (pathPerm.getReadPermission() == null || hasPermission(context, pathPerm.getReadPermission())) {
                    return true;
                }
                if (pathPerm.getWritePermission() == null || hasPermission(context, pathPerm.getWritePermission())) {
                    return true;
                }
            }
        }
        return false;
    }

    public static ArrayList<ProviderInfo> getAvailableProviders(String pkg, Context context, ArrayList<String> onlyProv, ArrayList<String> skipProv) {
        ArrayList<ProviderInfo> providers = new ArrayList<>();
        PackageInfo pkgInfo;
        try {
            pkgInfo = context.getPackageManager().getPackageInfo(pkg, getPmFlags());
        } catch (PackageManager.NameNotFoundException nnfe) {
            Log.w(TAG, "NameNotFoundException for requested package: " + pkg);
            return null;
        }
        if (!Util.nullOrEmpty(pkgInfo.providers)) {
            for (ProviderInfo pInfo : pkgInfo.providers) {
                // Skip/filter based on options
                if ((onlyProv != null && !onlyProv.contains(pInfo.name)) || (skipProv != null && skipProv.contains(pInfo.name))) {
                    continue;
                }

                if (isAvailableProvider(context, pInfo)) {
                    providers.add(pInfo);
                }
            }
        }
        return providers;
    }

    public static boolean hasAvailableProviders(String pkg, Context context, ArrayList<String> onlyProv, ArrayList<String> skipProv) {
        return getAvailableProviders(pkg, context, onlyProv, skipProv).size() > 0;
    }

    public static boolean isValidUri(Context context, Uri uri) {
        return context.getContentResolver().getType(uri) != null;
    }

    public static void addDiscoveredUriForPkg(Context context, String pkg, String uri) {
        if (pkg != null) {
            SharedPreferences sharedPref = context.getSharedPreferences("discovery_scan",0);
            SharedPreferences.Editor editor = sharedPref.edit();
            String prefKey = pkg + "_discovered_uris";
            // Create a new set from the shared prefs set
            Set<String> uriSet = new HashSet<>(sharedPref.getStringSet(prefKey, new HashSet<String>()));
            uriSet.add(uri);
            editor.putStringSet(prefKey, uriSet);
            editor.apply();
        }
    }

    public static boolean compareUriPaths(Uri first, Uri second) {
        /*
         * Compare Uris paths by path segments. Ignore query params
         */
        List<String> firstSegments = first.getPathSegments();
        List<String> secondSegments = second.getPathSegments();
        if (firstSegments.size() != secondSegments.size()) {
            return false;
        }

        // Path segments must be in the same order
        for (int i = 0; i < firstSegments.size(); i++) {
            if (!firstSegments.get(i).equals(secondSegments.get(i))) {
                return false;
            }
        }

        return true;
    }

    public static HashSet<Uri> getDiscoveredUrisOnly(Context context) {
        HashMap<String, Set<String>> discovered = getDiscoveredUris(context);
        HashSet<Uri> uris = new HashSet<>();
        for (Set<String> pkgUris : discovered.values()) {
            for (String pkgUriStr : pkgUris) {
                uris.add(Uri.parse(pkgUriStr));
            }
        }
        return uris;
    }

    public static HashMap<String, Set<String>> getDiscoveredUris(Context context) {
        HashMap<String, Set<String>> discovered = new HashMap<>();
        SharedPreferences sharedPref = context.getSharedPreferences("discovery_scan",0);
        Map<String, ?> prefMap = sharedPref.getAll();
        for (String key : prefMap.keySet()) {
            if (key.endsWith("_discovered_uris")) {
                String pkg = key.replace("_discovered_uris", "");
                // Create a new set from the shared prefs set
                Set<String> uris = new HashSet<>(sharedPref.getStringSet(key, new HashSet<String>()));
                discovered.put(pkg, uris);
            }
        }
        return discovered;
    }

    public static void setDiscoveredUris(Context context, HashMap<String, Set<String>> discovered) {
        SharedPreferences sharedPref = context.getSharedPreferences("discovery_scan",0);
        SharedPreferences.Editor edit = sharedPref.edit();
        for (String key : discovered.keySet()) {
            edit.putStringSet(key + "_discovered_uris", discovered.get(key));
        }
        edit.apply();
    }

    public static Set<Uri> getDiscoveredUrisForPkg(Context context, String pkg) {
        SharedPreferences sharedPref = context.getSharedPreferences("discovery_scan",0);
        // Create a new set from the shared prefs set
        Set<String> pkgDiscUriStr = new HashSet<>(sharedPref.getStringSet(pkg + "_discovered_uris", new HashSet<String>()));
        Set<Uri> pkgDiscUri = new HashSet<>();
        for (String dUri : pkgDiscUriStr) {
            pkgDiscUri.add(Uri.parse(dUri));
        }
        return pkgDiscUri;
    }

    public static String getHashStr(Object ... objs) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < objs.length; i++) {
            if (i > 0) {
                sb.append("::");
            }
            if (objs[i] != null) {
                if (objs[i] instanceof Object[]) {
                    // Use the Arrays.deepHashCode() method
                    sb.append(Arrays.deepHashCode((Object[]) objs[i]));
                } else {
                    sb.append(objs[i].hashCode());
                }
            } else {
                sb.append(-1);
            }
        }
        return sb.toString();
    }

    public static String getHumanDateDiff(Date startDate, Date endDate) {
        // From: https://www.mkyong.com/java/java-time-elapsed-in-days-hours-minutes-seconds/
        long different = endDate.getTime() - startDate.getTime();
        long secondsInMilli = 1000;
        long minutesInMilli = secondsInMilli * 60;
        long hoursInMilli = minutesInMilli * 60;
        long daysInMilli = hoursInMilli * 24;

        long elapsedDays = different / daysInMilli;
        different = different % daysInMilli;

        long elapsedHours = different / hoursInMilli;
        different = different % hoursInMilli;

        long elapsedMinutes = different / minutesInMilli;
        different = different % minutesInMilli;

        long elapsedSeconds = different / secondsInMilli;

        StringBuilder sb = new StringBuilder();
        if (elapsedDays > 0) {
            sb.append(elapsedDays + " day(s), ");
        }
        if (elapsedHours > 0) {
            sb.append(elapsedHours + " hour(s), ");
        }
        if (elapsedMinutes > 0) {
            sb.append(elapsedMinutes + " minute(s), ");
        }
        sb.append(elapsedSeconds + " second(s)");
        return sb.toString();
    }
}
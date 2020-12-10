// Copyright (c) 2019-2020 Calum Ewart Hutton
// Distributed under the GNU General Public License v3.0+, see the accompanying
// file LICENSE or https://opensource.org/licenses/GPL-3.0.

package lib.chutchut.cpmap.util;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.PathPermission;
import android.content.pm.PermissionInfo;
import android.content.pm.ProviderInfo;
import android.util.Log;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;


public class ProviderPermissionCollector {

    private Context context;
    private String targetPkg;
    private boolean ignoreGrantedPerms = false;
    private boolean ignoreManifestPerms = false;
    private Map<String, PermissionInfo[]> declaredPerms = new HashMap<>();
    private Map<String, HashSet<CollectedPermission>> reqPerms = new HashMap<>();
    private Map<String, ProviderInfo[]> providers = new HashMap<>();

    public static class CollectedPermission {

        public enum Op {
            READ,
            WRITE
        }
        private String providerName;
        private String authority;
        private Op operation;
        private String permission;
        private String protectionLevel;
        private String path;
        private int type;

        private CollectedPermission(ProviderInfo providerInfo, Op op, String perm, String protection, String path, int type) {
            this.providerName = providerInfo.name;
            this.authority = providerInfo.authority;
            this.operation = op;
            this.permission = perm;
            this.protectionLevel = protection;
            this.path = path;
            this.type = type;
        }

        public Op getOperation() {
            return operation;
        }

        public String getPath() {
            return path;
        }

        public String getPermission() {
            return permission;
        }

        public String getProtectionLevel() {
            return protectionLevel;
        }

        public String getProviderName() {
            return providerName;
        }

        public int getType() {
            return type;
        }

        public String getAuthority() {
            return authority;
        }

        public boolean isPathPerm() {
            return this.path != null;
        }

        public boolean isNullPerm() {
            return permission == null;
        }
    }

    public ProviderPermissionCollector(Context context) {
        this.context = context;
    }

    public ProviderPermissionCollector(Context context, String pkg, boolean ignoreGrantedPerms, boolean ignoreManifestPerms) {
        this.context = context;
        this.targetPkg = pkg;
        this.ignoreGrantedPerms = ignoreGrantedPerms;
        this.ignoreManifestPerms = ignoreManifestPerms;
    }

    public ProviderInfo getProviderInfo(String pkg, String provider) {
        if (providers.containsKey(pkg)) {
            for (ProviderInfo pInfo : providers.get(pkg)) {
                if (pInfo.name.equals(provider)) {
                    return pInfo;
                }
            }
        }
        return null;
    }

    private String getPermLevelString(int permLevel) {
        switch (permLevel) {
            default:
                return "UNKNOWN";
            case 0:
                return "NORMAL";
            case 1:
                return "DANGEROUS";
            case 2:
                return "SIGNATURE";
            case 3:
                return "SIGNATURE_OR_SYSTEM";
        }
    }

    private boolean isAcquirable(int permLevel) {
        // Acquirable if protection level is normal or dangerous
        return permLevel == 0 || permLevel == 1;
    }

    private PermissionInfo getDeclaredPermission(String perm) {
        for (PermissionInfo[] decPerms : declaredPerms.values()) {
            if (decPerms != null) {
                for (PermissionInfo permInfo : decPerms) {
                    if (permInfo.name.equalsIgnoreCase(perm)) {
                        return permInfo;
                    }
                }
            }
        }
        try {
            // Fallback to looking up the perm ino using the package manager
            return context.getPackageManager().getPermissionInfo(perm, 0);
        } catch (PackageManager.NameNotFoundException nnfe) {
            Log.e("ProvPermCollector", "NameNotFoundException: " + nnfe.getMessage());
        }
        return null;
    }

    private boolean canAcquirePermission(String perm) {
        PermissionInfo permInfo = getDeclaredPermission(perm);
        return permInfo != null && isAcquirable(permInfo.protectionLevel);
    }

    public boolean hasAquirableNonNullPermission(HashSet<CollectedPermission> collected) {
        for (CollectedPermission permission : collected) {
            if (!permission.isNullPerm() && canAcquirePermission(permission.getPermission())) {
                return true;
            }
        }
        return false;
    }

    private boolean hasPermissionToCollect(Context context, String perm) {
        return !Util.hasPermission(context, perm) || ignoreGrantedPerms;
    }

    private boolean hasNoManifestPermission(List<String> manifestPerms, String perm) {
        return !manifestPerms.contains(perm) || ignoreManifestPerms;
    }

    private List<String> getPackageManifestPermissions() {
        try {
            PackageInfo pkgInfo = context.getPackageManager().getPackageInfo(context.getPackageName(), PackageManager.GET_PERMISSIONS);
            if (!Util.nullOrEmpty(pkgInfo.requestedPermissions)) {
                return Arrays.asList(pkgInfo.requestedPermissions);
            }
        } catch (PackageManager.NameNotFoundException nnfe) {
            Log.e("PermissionCollector", String.format("Exception collecting missing provider permissions from target package (%s): %s", targetPkg, nnfe.getMessage()));
        }
        return new ArrayList<>();
    }

    public Map<String, HashSet<CollectedPermission>> collect() {
        HashSet<String> pkgs = new HashSet<>();
        HashSet<PackageInfo> pkginfos = new HashSet<>();
        if (targetPkg == null) {
            pkginfos.addAll(context.getPackageManager().getInstalledPackages(PackageManager.GET_PROVIDERS | PackageManager.GET_PERMISSIONS));
        } else {
            try {
                PackageInfo pkgInfo = context.getPackageManager().getPackageInfo(targetPkg, PackageManager.GET_PROVIDERS | PackageManager.GET_PERMISSIONS);
                pkginfos.add(pkgInfo);
            } catch (PackageManager.NameNotFoundException nnfe) {
                Log.e("ProvPermCollector", "NameNotFoundException: " + nnfe.getMessage());
                return null;
            }
        }

        for (PackageInfo packageInfo : pkginfos) {
            String pkg = packageInfo.packageName;
            // Add all declared perms regardless of target
            declaredPerms.put(pkg, packageInfo.permissions);

            if (!Util.nullOrEmpty(packageInfo.providers)) {
                // Only interested in packages with providers
                pkgs.add(pkg);
                providers.put(pkg, packageInfo.providers);
            }
        }

        List<String> manifestPerms = getPackageManifestPermissions();
        for (String pkg : pkgs) {
            HashSet<CollectedPermission> requestedPerms = new HashSet<>();
            for (ProviderInfo providerInfo : providers.get(pkg)) {

                // If the provider is not available for whatever reason, skip it
                if (!Util.isAvailableProvider(context, providerInfo)) {
                    continue;
                }

                PermissionInfo readPermInfo = null;
                PermissionInfo writePermInfo = null;
                String readPermString = providerInfo.readPermission;
                String writePermString = providerInfo.writePermission;

                if (readPermString != null) {
                    readPermInfo = getDeclaredPermission(readPermString);
                }
                if (writePermString != null) {
                    writePermInfo = getDeclaredPermission(writePermString);
                }

                // Check context does not have permission, and it has not already been requested in the manifest, and it can be acquired
                if (readPermString == null || (hasPermissionToCollect(context, readPermString) && hasNoManifestPermission(manifestPerms, readPermString) && canAcquirePermission(readPermString))) {
                    if (readPermInfo != null) {
                        requestedPerms.add(new CollectedPermission(providerInfo, CollectedPermission.Op.READ, readPermString, getPermLevelString(readPermInfo.protectionLevel), null, -1));
                    } else {
                        requestedPerms.add(new CollectedPermission(providerInfo, CollectedPermission.Op.READ, readPermString, getPermLevelString(-1), null, -1));
                    }
                }
                if (writePermString == null || (hasPermissionToCollect(context, writePermString) && hasNoManifestPermission(manifestPerms, writePermString) && canAcquirePermission(writePermString))) {
                    if (writePermInfo != null) {
                        requestedPerms.add(new CollectedPermission(providerInfo, CollectedPermission.Op.WRITE, writePermString, getPermLevelString(writePermInfo.protectionLevel), null, -1));
                    } else {
                        requestedPerms.add(new CollectedPermission(providerInfo, CollectedPermission.Op.WRITE, writePermString, getPermLevelString(-1), null, -1));
                    }
                }

                // Check path permissions
                if (providerInfo.pathPermissions != null) {
                    for (PathPermission pathPermission : providerInfo.pathPermissions) {

                        PermissionInfo readPathPermInfo = null;
                        PermissionInfo writePathPermInfo = null;
                        String readPathPermString = pathPermission.getReadPermission();
                        String writePathPermString = pathPermission.getWritePermission();
                        String path = pathPermission.getPath();

                        if (readPathPermString != null) {
                            readPathPermInfo = getDeclaredPermission(readPathPermString);
                        }
                        if (writePathPermString != null) {
                            writePathPermInfo = getDeclaredPermission(writePathPermString);
                        }

                        if (readPathPermString == null || (hasPermissionToCollect(context, readPathPermString) && hasNoManifestPermission(manifestPerms, readPathPermString) && canAcquirePermission(readPathPermString))) {
                            if (readPathPermInfo != null) {
                                requestedPerms.add(new CollectedPermission(providerInfo, CollectedPermission.Op.READ, readPathPermString, getPermLevelString(readPathPermInfo.protectionLevel), path, pathPermission.getType()));
                            } else {
                                requestedPerms.add(new CollectedPermission(providerInfo, CollectedPermission.Op.READ, readPathPermString, getPermLevelString(-1), path, pathPermission.getType()));
                            }
                        }
                        if (writePathPermString == null || (hasPermissionToCollect(context, writePathPermString) && hasNoManifestPermission(manifestPerms, writePathPermString) && canAcquirePermission(writePathPermString))) {
                            if (writePathPermInfo != null) {
                                requestedPerms.add(new CollectedPermission(providerInfo, CollectedPermission.Op.WRITE, writePathPermString, getPermLevelString(writePathPermInfo.protectionLevel), path, pathPermission.getType()));
                            } else {
                                requestedPerms.add(new CollectedPermission(providerInfo, CollectedPermission.Op.WRITE, writePathPermString, getPermLevelString(-1), path, pathPermission.getType()));
                            }
                        }
                    }
                }
            }

            reqPerms.put(pkg, requestedPerms);
        }

        if (!reqPerms.isEmpty()) {
            return reqPerms;
        } else {
            return null;
        }
    }

}

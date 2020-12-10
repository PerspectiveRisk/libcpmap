// Copyright (c) 2019-2020 Calum Ewart Hutton
// Distributed under the GNU General Public License v3.0+, see the accompanying
// file LICENSE or https://opensource.org/licenses/GPL-3.0.

package lib.chutchut.cpmap.report;

import android.os.Bundle;

import lib.chutchut.cpmap.util.Util;


public class CPReportTarget {

    private String targetPkg;
    private String version;

    /*
     * Default constructor for Gson
     */
    public CPReportTarget() {}

    public CPReportTarget(String target, String version) {
        this.targetPkg = target;
        this.version = version;
    }

    public static CPReportTarget fromJson(String json) {
        try {
            return Util.getGson().fromJson(json, CPReportTarget.class);
        } catch (Exception e) {
            return null;
        }
    }

    public String getTargetPkg() {
        return targetPkg;
    }

    public String getVersion() {
        return version;
    }

    public String toString() {
        return this.getTargetPkg() + " (" + this.getVersion() + ")";
    }

    public String toJson() {
        return Util.getGson().toJson(this);
    }

    public Bundle toBundle() {
        Bundle bundle = new Bundle();
        bundle.putString("target_pkg", targetPkg);
        bundle.putString("target_version", version);
        return bundle;
    }

    public static CPReportTarget fromBundle(Bundle data) {
        if (data != null && data.containsKey("target_pkg") && data.containsKey("target_version")) {
            return new CPReportTarget(data.getString("target_pkg"), data.getString("target_version"));
        }
        return null;
    }
}

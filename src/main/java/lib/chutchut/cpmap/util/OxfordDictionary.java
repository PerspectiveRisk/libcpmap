// Copyright (c) 2019-2020 Calum Ewart Hutton
// Distributed under the GNU General Public License v3.0+, see the accompanying
// file LICENSE or https://opensource.org/licenses/GPL-3.0.

package lib.chutchut.cpmap.util;

import android.content.Context;
import android.util.Log;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.HashSet;

public class OxfordDictionary {

    private static String TAG = "OxfordDictionary";

    private boolean isInit = false;
    private boolean strictEquals = false;
    private Context context;
    private HashSet<String> words = new HashSet<>();

    public OxfordDictionary(Context context) {
        this.context = context;
        init();
    }

    private void init() {
        try {
            InputStream is = context.getAssets().open("ox3000-5000.txt");
            BufferedReader br = new BufferedReader(new InputStreamReader(is));
            String line;
            while ((line = br.readLine()) != null) {
                words.add(line);
            }
            Log.i(TAG, "Initialised dictionary with " + words.size() + " words");
            isInit = true;
        } catch (IOException ioe) {
            Log.e(TAG, "IOException in init(): " + ioe.getMessage());
        }
    }

    public boolean isInitialised() {
        return isInit;
    }

    private boolean innerContains(String word) {
        return Util.listContains(words, word, strictEquals);
    }

    public boolean contains(String word) {
        // Check for the word in the list
        if (innerContains(word)) {
            return true;
        }

        // Split on camelcase
        String[] subWords = Util.camelCaseToArray(word);
        if (subWords.length > 1) {
            for (String subWord : subWords) {
                if (contains(subWord)) {
                    return true;
                }
            }
        }

        // Split on - _ / and space
        if (word.contains("/")) {
            // Split on /
            for (String slashSplit : word.split("/")) {
                if (contains(slashSplit)) {
                    return true;
                }
            }
        } else if (word.contains(" ")) {
            // Split on space
            for (String spaceSplit : word.split(" ")) {
                if (contains(spaceSplit)) {
                    return true;
                }
            }
        }  else if (word.contains("_")) {
            // Split on underscore
            for (String underSplit : word.split("_")) {
                if (contains(underSplit)) {
                    return true;
                }
            }
        }  else if (word.contains("-")) {
            // Split on dash
            for (String dashSplit : word.split("-")) {
                if (contains(dashSplit)) {
                    return true;
                }
            }
        }

        return false;
    }

}

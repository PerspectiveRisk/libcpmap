# CPMap

CPMap is an Android module for detecting and exploiting local SQL Injection vulnerabilities in Android Content Providers.

## Features

The main features of the module are:

- Supports several injection vectors:
	- Content URI id (read/update)
  	- Content URI segment (read/update)
  	- Projection (read)
  	- Sort order (read, cannot be used for dumping)
  	- Where clause (read/update)
  	- Content Values key (update)
  	- Query parameter key (read/update)
  	- Query parameter value (read/update)

- Supports several payloads
	- Heuristic (error-based)
  	- Boolean blind 
  	- Projection
  	- Selection 
  	- UNION 
  	- Path-traversal

- Can be used in a targeted, or zero-knowledge discovery mode
	- Targeted mode will validate and use the provided injection vectors/report object
  	- Discovery mode will perform the following actions to determine valid Content Provider URI's to exploit
    	- Examine package metadata (i.e. other application components defined in the manifest), and attempt to extract strings from the target packages APK (DEX files) 
    	- Gathered metadata and strings are checked for full Content URI's, and used to generate a wordlist
    	- The module attempts to generate Content URIs using the wordlist, which are in turn validated by attempting to query or update the generated URI

- Dump data from vulnerable Content Providers using arbitrary SQL queries

- Access module log and the underlying query log via listener interfaces 

- If vulnerable Content Providers are found, the module produces a report which can be stored as a JSON string for ease of storage and collaboration

## Installation

Build the project into an Android module, or add as a git submodule:


```bash
git submodule add https://github.com/PerspectiveRisk/libcpmap.git
```

Include in the apps build.gradle file:


```gradle
dependencies {
    implementation project(path: ':libcpmap')
```

## Usage

Use either the targeted or discovery mode constructor to instantiate the main CPMap object where most core functionality resides. Options to control the behaviour of the module can be provided via the second parameter of the constructor, a Bundle.

### Permissions

Before your test app can interact with another apps Content Providers it must have permission to do so. Separate permissions can be required for read (i.e. query) or write (i.e. update, insert, delete) operations.

Null permissions are automatically acquired by the test app, all others must be explicitly acquired by being defined in the test apps manifest, and then depending on protection level, also acquired at runtime.

You can check the target apps Content Provider permissions by examining the target apps manifest, or using the ProviderPermissionCollector object, i.e.


```Java
ProviderPermissionCollector providerPermissionCollector = new ProviderPermissionCollector(this, targetPkg, false, false);
Map<String, HashSet<ProviderPermissionCollector.CollectedPermission>> permMap = providerPermissionCollector.collect();
if (permMap != null && permMap.containsKey(targetPkg)) {
    for (ProviderPermissionCollector.CollectedPermission colPerm : permMap.get(targetPkg)) {
        // Skip null perms
        if (colPerm.getPermission() == null) {
            continue;
        }
        System.out.println(String.format("Got acquirable permission: %s for provider: %s. Protection: %s (%s)", colPerm.getPermission(), colPerm.getProviderName(), colPerm.getProtectionLevel(), colPerm.getOperation()));
    }
}
```

Once acquirable permissions have been determined (if any), list them in the test apps manifest i.e.


```XML
<uses-permission android:name="android.permission.READ_CONTACTS" />
<uses-permission android:name="android.permission.READ_SMS" />
<uses-permission android:name="com.google.android.ims.providers.ACCESS_DATA" />
```

### Options

- dump_payload (String) - use a specific type of payload for dumping
- dump_vector (String) - use a specific type of vector for dumping
- dump_table (String) - only dump data from a specific table
- dump_order (String) - ORDER BY statement for dumping
- dump_limit (Integer) - maximum number of rows to dump 
- no_cache (Boolean) - if true, do not attempt to read cached data from internal storage
- heuristic_detection (Boolean) - if true, use heuristic detection logic
- blind_detection (Boolean) - if true, use boolean blind detection logic
- providers (ArrayList<String>) - list of providers for audit/dumping 
- skip (ArrayList<String>) - list of providers to exclude from audit/dumping 
- permissions (ArrayList<String>) - list of permissions for audit
- vectors (ArrayList<String>) - list of vectors for audit
- payloads (ArrayList<String>) - list of payloads for audit
- refresh_cache (Boolean) - if true, force refresh of cached data
- hide_cached_vector_output (Boolean) - if true, do not output summary of cached data in log output
- no_duplicate_vectors (Boolean) - if true, skip vectors that are similar to those already identified during audit
- use_dictionary_filter (Boolean) - if true, filter wordlist by checking for 'real' words 
- max_words (Integer) - mavimum number of words to generate for the bruteforce wordlist 
- max_depth (Integer) - mavimum depth of bruteforce logic 
- apk_path (String) - absolute path to APK file to use during audit

### Targeted


```Java
List<String> uris = ArrayList<>();
uris.add("content://my.target.pkg/content/provider/1");
CPMap cpm = new CPMap(context, new Bundle(), uris);

// Load existing report
CPReport report = Util.loadReport(new File("/sdcard/report.json"));
CPMap cpm = new CPMap(context, new Bundle(), report);
```

### Discovery


```Java
CPMap cpm = new CPMap(context, new Bundle(), "my.target.pkg");
```

### Audit

Use the map() method to audit the target package using the provided URI's or discovery mode logic. If vulnerable Content Providers are identified, a CPReport object is returned


```Java
CPReport report = cpm.map();
```

### Dump

Use the dump() method to retrieve data from vulnerable Content Providers


```Java
ArrayList<String[]> rows = cpm.dump("SELECT DISTINCT tbl_name FROM sqlite_master");
```

### Listeners

Register listeners on the CPMap object to access additional data, i.e. the underlying module and query log


```Java
cpm.setLogListener(logListener);
cpm.setQueryListener(logListener);
cpm.setDumpListener(logListener);
```

### Threading 

Its hard to tell how long an audit or dump will take, so its important to run each of these operations on a background thread to prevent locking the main Android UI thread. An example of using the module with an AsyncTask is shown below


```Java
public class TestActivity extends AppCompatActivity {

    private Button btnExec;
    private TextView tvLogOutput;

    private String TAG = "TestActivity";

    private class MapAsync extends AsyncTask<String, Void, Void> implements CPMap.CPMapLogListener {

        private Context context;
        private String pkg;

        public MapAsync(Context ctx, String pkg) {
            this.context = ctx;
            this.pkg = pkg;
        }

        @Override
        protected void onPreExecute() {
            tvLogOutput.setText("");
            btnExec.setEnabled(false);
        }

        @Override
        protected void onPostExecute(Void result) {
            btnExec.setEnabled(true);
        }

        @Override
        protected Void doInBackground(String ... params) {
            CPMap cpm = new CPMap(context, new Bundle(), pkg);
            cpm.setLogListener(this);
            cpm.map();
            return null;
        }

        @Override
        public void onLogInf(String s) {
            logFromThread("I/" + s);
        }

        @Override
        public void onLogWarn(String s) {
            logFromThread("W/" + s);
        }

        @Override
        public void onLogErr(String s) {
            logFromThread("E/" + s);
        }
    }

    private void logFromThread(final String msg) {
        try {
            runOnUiThread(new Runnable() {
                @Override
                public void run() {
                    tvLogOutput.append(msg + "\n");
                }
            });
            Log.i(TAG, msg);
        } catch (Exception e) {
            Log.e(TAG, "Exception writing log text from thread");
        }
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_test);

        btnExec = findViewById(R.id.execBtn);
        tvLogOutput = findViewById(R.id.logOutputTv);

        btnExec.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                MapAsync mapAsync = new MapAsync(getApplicationContext(), "my.target.pkg");
                mapAsync.execute();
            }
        });
    }
}
```

## License
[GPL v3.0+](https://opensource.org/licenses/GPL-3.0)
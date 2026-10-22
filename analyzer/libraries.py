"""Third-party library detection from class package names in DEX files."""
import re
from collections import Counter
 
CLASS_RE = re.compile(rb"L([a-zA-Z][\w]*(?:/[\w$]+)+);")
 
# package prefix (slash form) -> (library name, category)
KNOWN_LIBRARIES = {
    "androidx/": ("AndroidX", "framework"),
    "kotlin/": ("Kotlin stdlib", "framework"),
    "kotlinx/": ("Kotlinx", "framework"),
    "com/google/android/material/": ("Material Components", "framework"),
    "com/google/gson/": ("Gson", "framework"),
    "okhttp3/": ("OkHttp", "network"),
    "okio/": ("Okio", "network"),
    "retrofit2/": ("Retrofit", "network"),
    "com/squareup/": ("Square libraries", "network"),
    "com/bumptech/glide/": ("Glide", "framework"),
    "com/google/firebase/": ("Firebase", "analytics"),
    "com/google/android/gms/": ("Google Play Services", "framework"),
    "com/facebook/": ("Facebook SDK", "ads_tracking"),
    "com/google/android/gms/ads/": ("Google Ads", "ads_tracking"),
    "com/unity3d/ads/": ("Unity Ads", "ads_tracking"),
    "com/applovin/": ("AppLovin", "ads_tracking"),
    "com/appsflyer/": ("AppsFlyer", "ads_tracking"),
    "com/adjust/": ("Adjust", "ads_tracking"),
    "com/onesignal/": ("OneSignal", "ads_tracking"),
    "com/flurry/": ("Flurry", "analytics"),
    "com/mixpanel/": ("Mixpanel", "analytics"),
    "io/sentry/": ("Sentry", "analytics"),
    "io/reactivex/": ("RxJava", "framework"),
    "org/apache/http/": ("Apache HTTP (legacy)", "network"),
    "com/jcraft/jsch/": ("JSch (SSH)", "network"),
}
 
 
def detect_libraries(apk):
    counts = Counter()
    for dex in apk.get_all_dex():
        for m in CLASS_RE.findall(dex):
            path = m.decode("utf-8", "ignore") + "/"
            # longest matching prefix wins
            best = None
            for prefix in KNOWN_LIBRARIES:
                if path.startswith(prefix) and (best is None or len(prefix) > len(best)):
                    best = prefix
            if best:
                counts[best] += 1
    libs = [
        {"name": KNOWN_LIBRARIES[p][0], "category": KNOWN_LIBRARIES[p][1],
         "package": p.rstrip("/").replace("/", "."), "classes": n}
        for p, n in counts.items()
    ]
    return sorted(libs, key=lambda x: -x["classes"])
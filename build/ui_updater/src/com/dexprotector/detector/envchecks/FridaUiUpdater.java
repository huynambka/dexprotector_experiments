package com.dexprotector.detector.envchecks;

import android.app.Activity;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;
import android.widget.TextView;
import java.lang.ref.WeakReference;
import java.util.UUID;

public final class FridaUiUpdater {
    private static Handler handler;
    private static Runnable runnable;
    private static WeakReference<Activity> activityRef;

    public static synchronized void start(Activity activity) {
        if (activity == null || handler != null) return;
        activityRef = new WeakReference<>(activity);
        handler = new Handler(Looper.getMainLooper());
        runnable = new Runnable() {
            @Override public void run() {
                try { updateOnce(); } catch (Throwable ignored) {}
                Handler h = handler;
                if (h != null) h.postDelayed(this, 2000L);
            }
        };
        handler.post(runnable);
    }

    public static synchronized void stop() {
        if (handler != null && runnable != null) handler.removeCallbacks(runnable);
        handler = null;
        runnable = null;
        activityRef = null;
    }

    private static void updateOnce() {
        WeakReference<Activity> ref = activityRef;
        Activity activity = ref == null ? null : ref.get();
        if (activity == null) { stop(); return; }
        TextView tv = (TextView) activity.findViewById(0x7f06004f);
        if (tv == null) return;
        String androidId = "<android_id>";
        try { androidId = Settings.Secure.getString(activity.getContentResolver(), "android_id"); } catch (Throwable ignored) {}
        String nl = "\n";
        StringBuilder sb = new StringBuilder();
        sb.append(nl).append(System.currentTimeMillis()).append(nl);
        sb.append("androidId: ").append(androidId).append(nl);
        sb.append("sessionId: ").append(UUID.randomUUID().toString()).append(nl);
        sb.append("xposed: false").append(nl);
        sb.append("customFirmware: false").append(nl);
        sb.append("debugger: false").append(nl);
        sb.append("emulator: false").append(nl);
        sb.append("manualInstall: false").append(nl);
        sb.append("root: false").append(nl);
        tv.setText(sb.toString());
    }
}

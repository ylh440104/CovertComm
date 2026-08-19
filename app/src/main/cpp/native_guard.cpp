#include <jni.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <dlfcn.h>
#include <dirent.h>
#include <pthread.h>
#include <android/log.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <sys/prctl.h>
#include <linux/fs.h>

#define TAG "CVMil"
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

static volatile int g_active = 0;
static volatile int g_purged = 0;
static unsigned char g_scramble[128] = {0};
static volatile int g_scramble_ready = 0;

static void mem_wipe(volatile unsigned char *p, size_t n) {
    if (!p || !n) return;
    for (size_t i = 0; i < n; i++) p[i] = 0;
    __asm__ volatile("dmb sy" : : : "memory");
    memset((void*)p, 0, n);
    __asm__ volatile("dmb sy" : : : "memory");
    for (size_t i = 0; i < n; i++) p[i] = 0xFF;
    __asm__ volatile("dmb sy" : : : "memory");
    for (size_t i = 0; i < n; i++) p[i] = 0;
    __asm__ volatile("dmb sy" : : : "memory");
}

static void die() {
    g_active = 0;
    _exit(1);
}

static void urandom(unsigned char *b, size_t n) {
    if (!b || !n) return;
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) { LOGE("FATAL: no urandom"); die(); }
    size_t t = 0;
    while (t < n) {
        ssize_t r = read(fd, b + t, n - t);
        if (r <= 0) { close(fd); LOGE("FATAL: urandom read fail"); die(); }
        t += r;
    }
    close(fd);
}

static void purge_all(JNIEnv *env) {
    if (g_purged) return;
    g_purged = 1;
    g_active = 0;
    LOGE("PURGE: destroying all data");

    jclass activityThread = env->FindClass("android/app/ActivityThread");
    if (activityThread) {
        jmethodID current = env->GetStaticMethodID(activityThread, "currentActivityThread", "()Landroid/app/ActivityThread;");
        jmethodID getApp = env->GetMethodID(activityThread, "getApplication", "()Landroid/app/Application;");
        if (current && getApp) {
            jobject at = env->CallStaticObjectMethod(activityThread, current);
            if (at) {
                jobject app = env->CallObjectMethod(at, getApp);
                if (app) {
                    jclass ctx = env->GetObjectClass(app);
                    jmethodID getDir = env->GetMethodID(ctx, "getFilesDir", "()Ljava/io/File;");
                    jmethodID getCache = env->GetMethodID(ctx, "getCacheDir", "()Ljava/io/File;");
                    jmethodID getCodeCache = env->GetMethodID(ctx, "getCodeCacheDir", "()Ljava/io/File;");
                    jmethodID getDataDir = env->GetMethodID(ctx, "getDataDir", "()Ljava/io/File;");
                    jmethodID getPath = env->GetMethodID(ctx, "getAbsolutePath", "()Ljava/lang/String;");
                    jmethodID fileList = env->GetMethodID(ctx, "fileList", "()[Ljava/lang/String;");
                    jmethodID deleteFile = env->GetMethodID(ctx, "deleteFile", "(Ljava/lang/String;)Z");

                    jobject dirs[] = {NULL, NULL, NULL, NULL};
                    jmethodID getters[] = {getDir, getCache, getCodeCache, getDataDir};
                    for (int i = 0; i < 4; i++) {
                        if (getters[i]) dirs[i] = env->CallObjectMethod(app, getters[i]);
                    }

                    for (int p = 0; p < 3; p++) {
                        for (int i = 0; i < 4; i++) {
                            if (!dirs[i]) continue;
                            jstring path = (jstring)env->CallObjectMethod(dirs[i], getPath);
                            if (!path) continue;
                            const char *pstr = env->GetStringUTFChars(path, NULL);
                            if (!pstr) continue;
                            char cmd[4096];
                            int fd = open("/dev/urandom", O_RDONLY);
                            unsigned char rbuf[65536];
                            if (fd >= 0) {
                                for (int pass = 0; pass < 3; pass++) {
                                    snprintf(cmd, sizeof(cmd), "find %s -type f 2>/dev/null", pstr);
                                    FILE *fp = popen(cmd, "r");
                                    if (fp) {
                                        char fpath[4096];
                                        while (fgets(fpath, sizeof(fpath), fp)) {
                                            fpath[strcspn(fpath, "\n")] = 0;
                                            int ff = open(fpath, O_WRONLY);
                                            if (ff >= 0) {
                                                for (int k = 0; k < 5; k++) {
                                                    size_t written = 0;
                                                    while (written < sizeof(rbuf)) {
                                                        ssize_t nr = read(fd, rbuf, sizeof(rbuf) - written);
                                                        if (nr <= 0) break;
                                                        written += nr;
                                                    }
                                                    write(ff, rbuf, sizeof(rbuf));
                                                    fsync(ff);
                                                }
                                                close(ff);
                                            }
                                        }
                                        pclose(fp);
                                    }
                                }
                                close(fd);
                            }
                            snprintf(cmd, sizeof(cmd), "rm -rf %s/* 2>/dev/null; rm -rf %s/.* 2>/dev/null", pstr, pstr);
                            system(cmd);
                            snprintf(cmd, sizeof(cmd), "fstrim %s 2>/dev/null", pstr);
                            system(cmd);
                            env->ReleaseStringUTFChars(path, pstr);
                        }
                    }
                }
            }
        }
    }
    LOGE("PURGE: complete");
    syscall(__NR_exit_group, 137);
    _exit(137);
}

static int is_uid_zero() {
    return getuid() == 0 || getgid() == 0 || geteuid() == 0 || getegid() == 0;
}

static void check_root() {
    const char *paths[] = {
        "/system/app/Superuser.apk", "/system/etc/init.d", "/system/xbin/daemonsu",
        "/system/xbin/su", "/system/bin/su", "/sbin/su", "/su/bin/su",
        "/data/local/xbin/su", "/data/local/bin/su", "/magisk", "/sbin/magisk",
        "/data/adb/magisk", "/data/adb/ksu", "/data/adb/ap", "/data/adb/modules",
        "/system/lib/libsu.so", "/system/lib64/libsu.so",
        NULL
    };
    struct stat st;
    for (int i = 0; paths[i]; i++) {
        if (stat(paths[i], &st) == 0) { LOGE("root file: %s", paths[i]); die(); }
    }
    int fd = open("/system/build.prop", O_RDONLY);
    if (fd >= 0) {
        char buf[1024];
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (n > 0) {
            buf[n] = 0;
            char *p = strstr(buf, "ro.debuggable");
            if (p) { p += 13; while (*p == '=') p++; if (*p == '1') { LOGE("debuggable"); die(); } }
            p = strstr(buf, "ro.build.tags");
            if (p) { p += 13; while (*p == '=') p++; if (strncmp(p, "release-keys", 12)) { LOGE("tags"); die(); } }
        }
    }
}

static void check_capture() {
    if (getenv("http_proxy") || getenv("HTTPS_PROXY") || getenv("ALL_PROXY") || getenv("NO_PROXY")) {
        LOGE("proxy detected"); die();
    }
    int fd = open("/proc/net/tcp", O_RDONLY);
    if (fd >= 0) {
        char buf[4096];
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (n > 0) {
            buf[n] = 0;
            char *line = buf;
            while ((line = strstr(line, "\n"))) {
                line++;
                unsigned int port = 0;
                if (sscanf(line, "%*d: %*X:%X", &port) >= 1) {
                    if (port == 8080 || port == 8888 || port == 3128 || port == 8889 || port == 9090 || port == 27042 || port == 27047) {
                        LOGE("proxy/capture port %d", port); die();
                    }
                }
            }
        }
    }
    fd = open("/proc/net/route", O_RDONLY);
    if (fd >= 0) {
        char buf[1024];
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (n > 0) {
            buf[n] = 0;
            int routes = 0;
            char *p = buf;
            while ((p = strstr(p, "\n"))) { routes++; p++; }
            if (routes > 5) { LOGE("vpn/tunnel routes"); die(); }
        }
    }
    fd = open("/proc/self/maps", O_RDONLY);
    if (fd >= 0) {
        char buf[4096];
        ssize_t n = read(fd, buf, sizeof(buf) - 1);
        close(fd);
        if (n > 0) {
            buf[n] = 0;
            const char *bad[] = {
                "frida", "gdb", "lldb", "strace", "rr", "inject", "substrate", "cydia",
                "xposed", "edxp", "lsposed", "riru", "zygisk", "valgrind", "hook",
                "FRIDA", "frida-", "frida_", "libfrida", "frida-agent", "frida-gadget",
                "tcpdump", "tshark", "wireshark", "mitmproxy", "charles", "burp",
                "dnspy", "de4dot", "apktool", "jadx", "dex2jar", "jd-gui",
                NULL
            };
            for (int i = 0; bad[i]; i++) {
                if (strstr(buf, bad[i])) { LOGE("detected: %s", bad[i]); die(); }
            }
        }
    }
}

static void *monitor_thread(void *arg) {
    JNIEnv *env = (JNIEnv*)arg;
    while (g_active) {
        struct timespec ts;
        ts.tv_sec = 0;
        ts.tv_nsec = 500000000;
        nanosleep(&ts, NULL);
        if (!g_active) break;
        check_capture();
        check_root();
    }
    return NULL;
}

static void init_scramble() {
    if (g_scramble_ready) return;
    urandom(g_scramble, 128);
    g_scramble_ready = 1;
}

extern "C" {

JNIEXPORT void JNICALL
Java_com_covertcomm_app_security_NativeGuard_initAntiDebug(JNIEnv *env, jobject thiz) {
    if (g_active) return;
    g_active = 1;
    if (is_uid_zero()) { LOGE("uid zero"); die(); }
    check_root();
    check_capture();
    prctl(PR_SET_PDEATHSIG, SIGKILL);
    pthread_t t;
    JavaVM *vm = NULL;
    env->GetJavaVM(&vm);
    pthread_create(&t, NULL, monitor_thread, (void*)env);
    pthread_detach(t);
}

JNIEXPORT void JNICALL
Java_com_covertcomm_app_security_NativeGuard_initScramble(JNIEnv *env, jobject thiz) {
    init_scramble();
}

JNIEXPORT void JNICALL
Java_com_covertcomm_app_security_NativeGuard_purge(JNIEnv *env, jobject thiz) {
    purge_all(env);
}

JNIEXPORT jbyteArray JNICALL
Java_com_covertcomm_app_security_NativeGuard_secureWipe(JNIEnv *env, jobject thiz, jbyteArray data) {
    if (!data) return NULL;
    jsize len = env->GetArrayLength(data);
    if (len <= 0) return data;
    jboolean is_copy;
    jbyte *b = env->GetByteArrayElements(data, &is_copy);
    if (!b) return data;
    mem_wipe((unsigned char*)b, len);
    if (is_copy) env->ReleaseByteArrayElements(data, b, 0);
    else {
        env->ReleaseByteArrayElements(data, b, JNI_COMMIT);
        mem_wipe((unsigned char*)b, len);
        env->ReleaseByteArrayElements(data, b, JNI_ABORT);
    }
    return data;
}

JNIEXPORT jbyteArray JNICALL
Java_com_covertcomm_app_security_NativeGuard_secureRandomBytes(JNIEnv *env, jobject thiz, jint length) {
    if (length <= 0 || length > 65536) return env->NewByteArray(0);
    jbyteArray r = env->NewByteArray(length);
    if (!r) return NULL;
    jbyte *b = env->GetByteArrayElements(r, NULL);
    if (!b) return NULL;
    urandom((unsigned char*)b, length);
    env->ReleaseByteArrayElements(r, b, 0);
    return r;
}

JNIEXPORT jstring JNICALL
Java_com_covertcomm_app_security_NativeGuard_getNativeVersion(JNIEnv *env, jobject thiz) {
    return env->NewStringUTF("cvmil-v3");
}

JNIEXPORT jbyteArray JNICALL
Java_com_covertcomm_app_security_NativeGuard_xorEncrypt(JNIEnv *env, jobject thiz, jbyteArray data, jbyteArray key) {
    if (!data || !key) return data;
    jsize dl = env->GetArrayLength(data);
    jsize kl = env->GetArrayLength(key);
    if (dl <= 0 || kl <= 0) return data;
    jbyte *d = env->GetByteArrayElements(data, NULL);
    jbyte *k = env->GetByteArrayElements(key, NULL);
    if (!d || !k) return data;
    for (jsize i = 0; i < dl; i++) d[i] ^= k[i % kl];
    env->ReleaseByteArrayElements(data, d, 0);
    env->ReleaseByteArrayElements(key, k, JNI_ABORT);
    return data;
}

JNIEXPORT jbyteArray JNICALL
Java_com_covertcomm_app_security_NativeGuard_splitKey(JNIEnv *env, jobject thiz, jbyteArray key) {
    if (!key) return NULL;
    jsize len = env->GetArrayLength(key);
    if (len <= 0) return NULL;
    if (!g_scramble_ready) init_scramble();
    jbyteArray r = env->NewByteArray(len);
    if (!r) return NULL;
    jbyte *s = env->GetByteArrayElements(key, NULL);
    jbyte *d = env->GetByteArrayElements(r, NULL);
    if (!s || !d) return NULL;
    for (jsize i = 0; i < len; i++) d[i] = s[i] ^ g_scramble[i % 128];
    mem_wipe((unsigned char*)s, len);
    env->ReleaseByteArrayElements(key, s, JNI_ABORT);
    env->ReleaseByteArrayElements(r, d, 0);
    return r;
}

JNIEXPORT jbyteArray JNICALL
Java_com_covertcomm_app_security_NativeGuard_unscrambleKey(JNIEnv *env, jobject thiz, jbyteArray scrambled) {
    if (!scrambled) return NULL;
    jsize len = env->GetArrayLength(scrambled);
    if (len <= 0) return NULL;
    if (!g_scramble_ready) init_scramble();
    jbyteArray r = env->NewByteArray(len);
    if (!r) return NULL;
    jbyte *s = env->GetByteArrayElements(scrambled, NULL);
    jbyte *d = env->GetByteArrayElements(r, NULL);
    if (!s || !d) return NULL;
    for (jsize i = 0; i < len; i++) d[i] = s[i] ^ g_scramble[i % 128];
    env->ReleaseByteArrayElements(r, d, 0);
    env->ReleaseByteArrayElements(scrambled, s, JNI_ABORT);
    return r;
}

JNIEXPORT jbyteArray JNICALL
Java_com_covertcomm_app_security_NativeGuard_aesEncrypt(JNIEnv *env, jobject thiz, jbyteArray pt, jbyteArray key) {
    if (!pt || !key) return NULL;
    jsize pl = env->GetArrayLength(pt);
    jsize kl = env->GetArrayLength(key);
    if (pl <= 0 || kl < 32) return NULL;
    jbyte *p = env->GetByteArrayElements(pt, NULL);
    jbyte *k = env->GetByteArrayElements(key, NULL);
    if (!p || !k) return NULL;
    jsize ol = pl + 16;
    jbyteArray r = env->NewByteArray(ol);
    jbyte *o = env->GetByteArrayElements(r, NULL);
    if (!o) return NULL;
    for (jsize i = 0; i < pl; i++) o[i] = p[i] ^ k[i % 32];
    for (jsize i = 0; i < 16; i++) o[pl + i] = (jbyte)(rand() & 0xFF);
    mem_wipe((unsigned char*)p, pl);
    env->ReleaseByteArrayElements(pt, p, JNI_ABORT);
    env->ReleaseByteArrayElements(key, k, JNI_ABORT);
    env->ReleaseByteArrayElements(r, o, 0);
    return r;
}

JNIEXPORT jbyteArray JNICALL
Java_com_covertcomm_app_security_NativeGuard_aesDecrypt(JNIEnv *env, jobject thiz, jbyteArray ct, jbyteArray key) {
    if (!ct || !key) return NULL;
    jsize cl = env->GetArrayLength(ct);
    jsize kl = env->GetArrayLength(key);
    if (cl <= 16 || kl < 32) return NULL;
    jbyte *c = env->GetByteArrayElements(ct, NULL);
    jbyte *k = env->GetByteArrayElements(key, NULL);
    if (!c || !k) return NULL;
    jsize pl = cl - 16;
    jbyteArray r = env->NewByteArray(pl);
    jbyte *o = env->GetByteArrayElements(r, NULL);
    if (!o) return NULL;
    for (jsize i = 0; i < pl; i++) o[i] = c[i] ^ k[i % 32];
    env->ReleaseByteArrayElements(r, o, 0);
    env->ReleaseByteArrayElements(ct, c, JNI_ABORT);
    env->ReleaseByteArrayElements(key, k, JNI_ABORT);
    return r;
}

JNIEXPORT jint JNICALL
Java_com_covertcomm_app_security_NativeGuard_integrityCheck(JNIEnv *env, jobject thiz) {
    return 1;
}

} // extern "C"
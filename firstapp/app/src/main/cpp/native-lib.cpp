#include <jni.h>
#include <string>
#include <android/log.h>

#include "spdlog/spdlog.h"
#include "spdlog/sinks/sink.h"
#include "spdlog/sinks/android_sink.h"
#include "mbedtls/des.h"

#define LOGI(...) ((void)__android_log_print(ANDROID_LOG_INFO, "some-tag", __VA_ARGS__))
#define LOGW(...) ((void)__android_log_print(ANDROID_LOG_WARN, "some-tag", __VA_ARGS__))
#define LOGE(...) ((void)__android_log_print(ANDROID_LOG_ERROR, "some-tag", __VA_ARGS__))
#define LOGD(...) ((void)__android_log_print(ANDROID_LOG_DEBUG, "jpw", __VA_ARGS__))

#define SLOGD(...) ((void)logger->info( __VA_ARGS__))


std::shared_ptr<spdlog::logger> logger = spdlog::android_logger_mt("android", "jpw");

int cnt = 0;

extern "C" JNIEXPORT jstring JNICALL
Java_ru_bmstu_iu3_firstapp_MainActivity_stringFromJNI(
        JNIEnv *env,
        jobject /* this */) {
    std::string hello = "Hello from C++";
    LOGD("We are inside stringFromJni function %d", 2020);
    SLOGD("Hello from spdlog {}", cnt++);
    return env->NewStringUTF(hello.c_str());
}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_ru_bmstu_iu3_firstapp_MainActivity_des(
        JNIEnv *env, jobject, jbyteArray key, jbyteArray data)
    {
        mbedtls_des3_context des;

        jbyte *  pkey = env->GetByteArrayElements(key, nullptr);
        jsize ksz = env->GetArrayLength(key);

        jbyte *  pdata = env->GetByteArrayElements(data, nullptr);
        jsize dsz = env->GetArrayLength(data);
        jsize rsz = dsz % 8;
        jbyte  * buf = new jbyte[dsz + 8 - rsz];
        //Padding
        for (int i = 0; i < 8 - rsz; i++) buf[dsz + rsz + i] = (jbyte)rsz;
        std::copy(pdata, pdata + dsz, buf);
	    mbedtls_des3_init(&des);
	    mbedtls_des3_set2key_enc( &des, (const unsigned char *)pkey);
	    mbedtls_des3_crypt_ecb( &des, (const unsigned char *)buf, (unsigned char *)buf);
	    mbedtls_des3_free( &des );
        jbyteArray  out = env->NewByteArray(dsz + 8 - rsz);
        env->SetByteArrayRegion(out, 0, dsz, buf);
        delete [] buf;
        env->ReleaseByteArrayElements(key, pkey, 0);
        env->ReleaseByteArrayElements(data, pdata, 0);
        return out;
}

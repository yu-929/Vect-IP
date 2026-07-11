#include <jni.h>
#include "libvect.h"

JNIEXPORT jint JNICALL
Java_com_vect_app_VectBridge_startServer(JNIEnv *env, jclass clazz, jint port) {
    return (jint)StartVectServer((int)port);
}
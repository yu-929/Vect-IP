package com.vect.app

object VectBridge {
    init {
        System.loadLibrary("vect")
        System.loadLibrary("vectbridge")
    }

    external fun startServer(port: Int): Int
}
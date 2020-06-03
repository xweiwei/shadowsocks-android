package com.github.shadowsocks.utils

import android.content.Context
import android.util.Base64
import android.util.Log
import android.widget.Toast
import java.io.*
import java.lang.AssertionError
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.Socket
import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.security.SecureRandom
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import javax.net.ssl.*
import javax.security.auth.x500.X500Principal
import kotlin.concurrent.thread

const val TAG:String = "Cert"


fun toast(context: Context, msg: String?) {
    Log.d("TOAST", msg)
    Toast.makeText(context, msg, Toast.LENGTH_LONG).show()
}

//fun hasCert(context: Context): Boolean {
//    copyCerts(context)
//    val ret = File("/system/etc/security/cacerts/c8750f0d.0").exists()
//    Log.d("TAT", "cert exists?$ret")
//    return ret
//}

fun hasCert(certDir: File): Boolean {
    val cert = getCert(certDir) ?: return false
    val loadCert = File("/system/etc/security/cacerts/${cert.name}")
    if (!loadCert.exists()) {
        return false
    }

    return cert.toMD5() == loadCert.toMD5()
}

fun hasCert(context: Context, host: String, port: Int): Boolean {
    return hasCert(getCertDir(context, host, port))
}

fun File.toMD5(): String {
    var md5 = MessageDigest.getInstance("MD5")
    val fin = FileInputStream(this)
    var len = -1
    val buffer = ByteArray(1024)
    while (fin.read(buffer).also { len = it } != -1) {
        md5.digest(buffer, 0, len)
    }
    fin.close()
    val bytes = md5.digest()
    return bytes.toHex()
}

fun ByteArray.toHex(): String {
    return joinToString("") { "%02x".format(it) }
}

internal class ReadCert constructor(certDir: File): X509TrustManager {

    private val mCertDir = certDir


    @Throws(CertificateException::class)
    override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {
    }

    @Throws(CertificateException::class)
    override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
        println("check server" +  chain!!.size)
        for (cert in chain!!) {
            Log.d(TAG, cert!!.subjectDN.toString())
            if (cert.subjectDN.equals(cert.issuerDN)) {
                Log.d(TAG, cert!!.subjectDN.toString())
                saveCert(cert, mCertDir)
            }
        }
    }

    override fun getAcceptedIssuers(): Array<X509Certificate>? {
        return null
    }
}


fun X509_NAME_hash(principal: X500Principal): Int {
    return X509_NAME_hash(principal, "SHA1")
}

fun X509_NAME_hash_old(principal: X500Principal): Int {
    return X509_NAME_hash(principal, "MD5")
}

fun X509_NAME_hash(principal: X500Principal, algorithm: String): Int {
    return try {
        val digest: ByteArray = MessageDigest.getInstance(algorithm).digest(principal.getEncoded())
        var offset = 0
        (digest[offset++].toInt() and 0xff shl 0 or (digest[offset++].toInt() and 0xff shl 8)
                or (digest[offset++].toInt() and 0xff shl 16) or (digest[offset].toInt() and 0xff shl 24))
    } catch (e: NoSuchAlgorithmException) {
        throw AssertionError(e)
    }
}

fun saveCert(cert: X509Certificate, certDir: File): Boolean {
    val name = "%08x.0".format(X509_NAME_hash_old(cert.subjectX500Principal))
    Log.d(TAG, "saveCert name $name")
    val certFile = File(certDir, name)
    if (certFile.exists()) {
        certFile.delete()
    }
    val fos = FileOutputStream(certFile)
    fos.write("-----BEGIN CERTIFICATE-----\n".toByteArray())
    fos.write(Base64.encode(cert.encoded, Base64.DEFAULT))
    fos.write("\n-----END CERTIFICATE-----".toByteArray())
    fos.close()
    return true
}


fun getCertDir(context: Context, host: String, port: Int): File {
    val certDir = File(context.filesDir, "certs/$host/$port")
    if (!certDir.exists()) {
        certDir.mkdirs()
    }
    return certDir
}

fun getCert(dir:File): File? {
    var l = dir.listFiles()
    return when {
        l == null -> {
            null
        }
        l.size == 1 -> {
            l[0]
        }
        else -> {
            for (f in l) {
                f.delete()
            }
            null
        }
    }
}

fun downloadCert(host: String, port: Int, certDir: File) {
    try {
        val sc = SSLContext.getInstance("SSL")
        sc.init(null, arrayOf<TrustManager>(ReadCert(certDir)), SecureRandom())

        val sslsocketfactory: SSLSocketFactory = sc.socketFactory as SSLSocketFactory
        val socket = Socket(
                Proxy(
                        Proxy.Type.SOCKS,
                        InetSocketAddress(host, port)
                ))
        socket.soTimeout = 2000
        socket.connect(InetSocketAddress("mi.com", 443), 2000)
        val sslsocket: SSLSocket = sslsocketfactory
                .createSocket(socket, "mi.com", 443, true) as SSLSocket

        sslsocket.startHandshake()
        sslsocket.close()
        socket.close()
    } catch (e: Exception) {
        e.printStackTrace()
    }
}

fun loadCert(context: Context, host: String, port: Int, download: Boolean = false) {
    val certDir = getCertDir(context, host, port)
    if (download || getCert(certDir) == null) {
        toast(context, "下载证书")

        thread { downloadCert(host, port, certDir) }.join(3000)
    }

    val cert = getCert(certDir)
    if (cert == null) {
        toast(context, "证书导入失败")
        return
    }

    if (hasCert(certDir)) {
        toast(context, "证书已导入")
        return
    }

    loadCert(context, cert.path)

    if (hasCert(certDir)) {
        toast(context, "证书导入成功")
    } else {
        toast(context, "证书导入失败")
    }
}

fun loadCert(context: Context, cert: String) {
    try {
        val tmpDir = "/data/local/tmp/"
        val fakeCertDir: String = "$tmpDir/cacerts/"
        var p = Runtime.getRuntime().exec("su -c ls")
        p.waitFor()
        if (p.exitValue() == 0) {
            p = Runtime.getRuntime().exec("su")
            val os = p.outputStream
            val cmd = "umount /system/etc/security/cacerts;cp -pR /system/etc/security/cacerts " + tmpDir +
                    ";cp " + cert + " " + fakeCertDir +
                    ";chmod -R 755 " + fakeCertDir +
                    ";chcon -R `ls -Z /system/etc/security/cacerts | head -n1 | cut -d \" \" -f 1 ` " + fakeCertDir +
                    ";mount " + fakeCertDir + " /system/etc/security/cacerts/;exit"
            Log.d(TAG, "cmd $cmd")
            os.write(cmd.toByteArray())
            os.flush()
            os.close()
            p.waitFor()
            return
        }
    } catch (e: Exception) {
        e.printStackTrace()
    }
    toast(context, "请授予ROOT权限")
}

fun unloadCert(context: Context, host: String, port: Int) {
    var p = Runtime.getRuntime().exec("su")
    val os = p.outputStream
    val cmd = "umount /system/etc/security/cacerts;exit\n"
    Log.d(TAG, "cmd $cmd")
    os.write(cmd.toByteArray())
    os.flush()
    os.close()
    p.waitFor()

    if (hasCert(context, host, port)) {
        toast(context, "证书卸载失败")
    } else {
        toast(context, "证书卸载成功")
    }
    return
}


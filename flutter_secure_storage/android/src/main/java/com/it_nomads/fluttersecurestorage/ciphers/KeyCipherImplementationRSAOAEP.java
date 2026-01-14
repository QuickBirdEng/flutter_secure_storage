package com.it_nomads.fluttersecurestorage.ciphers;

import android.content.Context;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;

import androidx.annotation.RequiresApi;

import com.it_nomads.fluttersecurestorage.FlutterSecureStorageConfig;

import java.math.BigInteger;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.util.Calendar;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.security.auth.x500.X500Principal;

class KeyCipherImplementationRSAOAEP extends KeyCipherImplementationRSA18 {

    public KeyCipherImplementationRSAOAEP(Context context, FlutterSecureStorageConfig config) throws Exception {
        super(context, config);
    }

    @Override
    protected String createKeyAlias() {
        // Backward compatibility: use original key name for default config
        if ("FlutterSecureStorage".equals(config.getSharedPreferencesName())) {
            return context.getPackageName() + ".FlutterSecureStoragePluginKeyOAEP";
        }

        String configId = config.getSharedPreferencesName() + "_" + config.getSharedPreferencesKeyPrefix();
        return context.getPackageName() + ".FlutterSecureStoragePluginKeyOAEP_" + configId;
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    @Override
    protected AlgorithmParameterSpec makeAlgorithmParameterSpec(Context context, Calendar start, Calendar end, boolean isStrongBoxBacked) {
        final KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(keyAlias, KeyProperties.PURPOSE_DECRYPT | KeyProperties.PURPOSE_ENCRYPT)
                .setCertificateSubject(new X500Principal("CN=" + keyAlias))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setBlockModes(KeyProperties.BLOCK_MODE_ECB)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                .setCertificateSerialNumber(BigInteger.valueOf(1))
                .setCertificateNotBefore(start.getTime())
                .setCertificateNotAfter(end.getTime());
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && isStrongBoxBacked) {
            builder.setIsStrongBoxBacked(true);
        }
        return builder.build();
    }

    @Override
    protected Cipher getRSACipher() throws Exception {
        return Cipher.getInstance("RSA/ECB/OAEPPadding", "AndroidKeyStoreBCWorkaround");
    }

    protected AlgorithmParameterSpec getAlgorithmParameterSpec() {
        return new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT);
    }
}

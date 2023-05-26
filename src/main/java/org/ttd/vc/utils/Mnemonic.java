package org.ttd.vc.utils;

/*
This code was taken from
https://github.com/algorand/java-algorand-sdk/blob/develop/src/main/java/com/algorand/algosdk/mnemonic/Mnemonic.java
 */

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Objects;

public class Mnemonic {
    private static final int BITS_PER_WORD = 11;
    private static final int CHECKSUM_LEN_WORDS = 1;
    private static final int KEY_LEN_BYTES = 32;
    private static final int MNEM_LEN_WORDS = 25;
    private static final int PADDING_ZEROS = 8;
    private static final String CHECKSUM_ALG = "SHA-512/256";
    private static final String MNEMONIC_DELIM = " ";

    public Mnemonic() {
    }

    public static String fromKey(byte[] key) {
        Objects.requireNonNull(key, "key must not be null");
        if (key.length != 32) {
            throw new IllegalArgumentException("key length must be 32 bytes");
        } else {
            String chkWord = checksum(key);
            int[] uint11Arr = toUintNArray(key);
            String[] words = applyWords(uint11Arr);
            return mnemonicToString(words, chkWord);
        }
    }

    public static byte[] toKey(String mnemonicStr) throws GeneralSecurityException {
        Objects.requireNonNull(mnemonicStr, "mnemonic must not be null");
        String[] mnemonic = mnemonicStr.split(" ");
        if (mnemonic.length != 25) {
            throw new IllegalArgumentException("mnemonic does not have enough words");
        } else {
            int numWords = 24;
            int[] uint11Arr = new int[numWords];

            int w;
            for(w = 0; w < numWords; ++w) {
                uint11Arr[w] = -1;
            }

            for(w = 0; w < Wordlist.RAW.length; ++w) {
                for(int i = 0; i < numWords; ++i) {
                    if (Wordlist.RAW[w].equals(mnemonic[i])) {
                        uint11Arr[i] = w;
                    }
                }
            }

            for(w = 0; w < numWords; ++w) {
                if (uint11Arr[w] == -1) {
                    throw new IllegalArgumentException("mnemonic contains word that is not in word list");
                }
            }

            byte[] b = toByteArray(uint11Arr);
            if (b.length != 33) {
                throw new GeneralSecurityException("wrong key length");
            } else if (b[32] != 0) {
                throw new GeneralSecurityException("unexpected byte from key");
            } else {
                byte[] bCopy = Arrays.copyOf(b, 32);
                String chkWord = checksum(bCopy);
                if (!chkWord.equals(mnemonic[24])) {
                    throw new GeneralSecurityException("checksum failed to validate");
                } else {
                    return Arrays.copyOf(b, 32);
                }
            }
        }
    }

    protected static String checksum(byte[] data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-512/256");
            digest.update(Arrays.copyOf(data, data.length));
            byte[] d = digest.digest();
            d = Arrays.copyOfRange(d, 0, 2);
            return applyWord(toUintNArray(d)[0]);
        } catch (NoSuchAlgorithmException var3) {
            throw new RuntimeException(var3);
        }
    }

    private static int[] toUintNArray(byte[] arr) {
        int buffer = 0;
        int numBits = 0;
        int[] out = new int[(arr.length * 8 + 11 - 1) / 11];
        int j = 0;

        for(int i = 0; i < arr.length; ++i) {
            int v = arr[i];
            if (v < 0) {
                v += 256;
            }

            buffer |= v << numBits;
            numBits += 8;
            if (numBits >= 11) {
                out[j] = buffer & 2047;
                ++j;
                buffer >>= 11;
                numBits -= 11;
            }
        }

        if (numBits != 0) {
            out[j] = buffer & 2047;
        }

        return out;
    }

    private static byte[] toByteArray(int[] arr) {
        int buffer = 0;
        int numBits = 0;
        byte[] out = new byte[(arr.length * 11 + 8 - 1) / 8];
        int j = 0;

        for(int i = 0; i < arr.length; ++i) {
            buffer |= arr[i] << numBits;

            for(numBits += 11; numBits >= 8; numBits -= 8) {
                out[j] = (byte)(buffer & 255);
                ++j;
                buffer >>= 8;
            }
        }

        if (numBits != 0) {
            out[j] = (byte)(buffer & 255);
        }

        return out;
    }

    private static String applyWord(int iN) {
        return Wordlist.RAW[iN];
    }

    private static String[] applyWords(int[] arrN) {
        String[] ret = new String[arrN.length];

        for(int i = 0; i < arrN.length; ++i) {
            ret[i] = applyWord(arrN[i]);
        }

        return ret;
    }

    private static String mnemonicToString(String[] mnemonic, String checksum) {
        StringBuilder s = new StringBuilder();

        for(int i = 0; i < mnemonic.length; ++i) {
            if (i > 0) {
                s.append(" ");
            }

            s.append(mnemonic[i]);
        }

        s.append(" ");
        s.append(checksum);
        return s.toString();
    }
}

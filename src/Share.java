//Modified Coda Hale implementation for secret sharing (open source)

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.util.Map;
import java.util.HashMap;
import java.util.Objects;
import java.util.StringJoiner;
import java.io.*;
import java.lang.*;
import java.util.Base64;
import javax.crypto.spec.*;

import javax.crypto.*;
import java.security.*;

import javax.crypto.Cipher;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.Map;


public class Share {

    //This implements an (n,k) secret sharing scheme, n miners and k shares required for reconstruction
    private final SecureRandom random;
    private final int n;
    private final int k;
    public byte[][] privateKeys;
    public byte[][] publicKeys;

    public Share(SecureRandom random, int n, int k) {
        this.random = random;
        //We implement with k = n/2
        checkArgument(k > 1, "K must be > 1");
        checkArgument(n >= k, "N must be >= K");
        checkArgument(n <= 255, "N must be <= 255");
        this.n = n;
        this.k = k;
    }

    //This function splits the secret key (input with byte[] type)
    // into shares. These are then passed into the smart contract.

    public Map<Integer, byte[]> split(byte[] secret) {
        // generate part values
        final byte[][] values = new byte[n][secret.length];
        for (int i = 0; i < secret.length; i++) {
            // for each byte, generate a random polynomial, p
            final byte[] p = GF256.generate(random, k - 1, secret[i]);
            for (int x = 1; x <= n; x++) {
                // each part's byte is p(partId)
                values[x - 1][i] = GF256.eval(p, (byte) x);
            }
        }

        // return as a set of objects
        final Map<Integer, byte[]> parts = new HashMap<>(n());
        for (int i = 0; i < values.length; i++) {
            parts.put(i + 1, values[i]);
        }
        return parts;
    }

    /**
     * Joins the given parts to recover the original secret.
     *
     *
     * @param parts a map of part IDs to part values
     * @return the original secret
     * @throws IllegalArgumentException if {@code parts} is empty or contains values of varying
     *     lengths
     */
    public byte[] join(Map<Integer, byte[]> parts) {
        checkArgument(parts.size() > 0, "No parts provided");
        final int[] lengths = parts.values().stream().mapToInt(v -> v.length).distinct().toArray();
        checkArgument(lengths.length == 1, "Varying lengths of part values");
        final byte[] secret = new byte[lengths[0]];
        for (int i = 0; i < secret.length; i++) {
            final byte[][] points = new byte[parts.size()][2];
            int j = 0;
            for (Map.Entry<Integer, byte[]> part : parts.entrySet()) {
                points[j][0] = part.getKey().byteValue();
                points[j][1] = part.getValue()[i];
                j++;
            }
            secret[i] = GF256.interpolate(points);
        }
        return secret;
    }

    /**
     * The number of parts the scheme will generate when splitting a secret.
     *
     * @return {@code N}
     */
    public int n() {
        return n;
    }

    /**
     * The number of parts the scheme will require to re-create a secret.
     *
     * @return {@code K}
     */
    public int k() {
        return k;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof Share)) {
            return false;
        }
        final Share scheme = (Share) o;
        return n == scheme.n && k == scheme.k && Objects.equals(random, scheme.random);
    }

    @Override
    public int hashCode() {
        return Objects.hash(random, n, k);
    }

    @Override
    public String toString() {
        return new StringJoiner(", ", Share.class.getSimpleName() + "[", "]")
                .add("random=" + random)
                .add("n=" + n)
                .add("k=" + k)
                .toString();
    }

    private static void checkArgument(boolean condition, String message) {
        if (!condition) {
            throw new IllegalArgumentException(message);
        }
    }

    //Stackoverflow saviour help with fixing AES 256 key length parameter issues
    //https://stackoverflow.com/questions/6481627/java-security-illegal-key-size-or-default-parameters
    // The following function is taken from a response on that thread.

    public static void fixKeyLength() {
        String errorString = "Failed manually overriding key-length permissions.";
        int newMaxKeyLength;
        try {
            if ((newMaxKeyLength = Cipher.getMaxAllowedKeyLength("AES")) < 256) {
                Class c = Class.forName("javax.crypto.CryptoAllPermissionCollection");
                Constructor con = c.getDeclaredConstructor();
                con.setAccessible(true);
                Object allPermissionCollection = con.newInstance();
                Field f = c.getDeclaredField("all_allowed");
                f.setAccessible(true);
                f.setBoolean(allPermissionCollection, true);

                c = Class.forName("javax.crypto.CryptoPermissions");
                con = c.getDeclaredConstructor();
                con.setAccessible(true);
                Object allPermissions = con.newInstance();
                f = c.getDeclaredField("perms");
                f.setAccessible(true);
                ((Map) f.get(allPermissions)).put("*", allPermissionCollection);

                c = Class.forName("javax.crypto.JceSecurityManager");
                f = c.getDeclaredField("defaultPolicy");
                f.setAccessible(true);
                Field mf = Field.class.getDeclaredField("modifiers");
                mf.setAccessible(true);
                mf.setInt(f, f.getModifiers() & ~Modifier.FINAL);
                f.set(null, allPermissions);

                newMaxKeyLength = Cipher.getMaxAllowedKeyLength("AES");
            }
        } catch (Exception e) {
            throw new RuntimeException(errorString, e);
        }
        if (newMaxKeyLength < 256)
            throw new RuntimeException(errorString); // hack failed
    }

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidAlgorithmParameterException {

        //Load in and read the CSV file with data, convert into a byte array

        File file = new File("src/Mar_13_Temperature_Data.csv");
        byte[] bArray = new byte[(int) file.length()];

        FileInputStream fs = new FileInputStream(file);
        fs.read(bArray);
        fs.close();

        //Fix AES Encryption Length: (function above the main)
        fixKeyLength();

        //Key Generation Process:
        SecureRandom rand = new SecureRandom();
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(256, rand);
        SecretKey secretKey = generator.generateKey();

        //File Encryption Process:

        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] byteCipherText = cipher.doFinal(bArray);


        //String converted = new String(bArray);
        //System.out.println(converted);
        //System.out.println(byteCipherText);
        //System.out.println(bArray);


        //Secret Sharing Implementation:
        //Returns a map (parts) from miner number to polynomial evaluated at random point

        Share share = new Share(new SecureRandom(), 6, 4);
        byte[] secret = secretKey.getEncoded();
        Map<Integer,byte[]> parts1 = share.split(secret);

        //Make a copy to test the public key encryption:
        Map<Integer,byte[]> parts = parts1;


        // Create public keys and perform miner public key encryption of shares for storage on Ethereum
        //Hardcode public/private keys for testing purposes in this implementation.

        //initialize public/private key arrays:
        //eventually we scrape the blockchain for these public keys so that each miner is able
        //to use their own private key to decrypt.

        PrivateKey[] privateKeys = new PrivateKey[share.n];
        PublicKey[] publicKeys = new PublicKey[share.n];

        for (int i=0; i<share.n; i++) {
            KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
            g.initialize(2048, new SecureRandom());
            KeyPair keypair = g.generateKeyPair();
            PublicKey publicKey = keypair.getPublic();
            PrivateKey privateKey = keypair.getPrivate();

            //The following code populates arrays of public/private keys simulating the miners
            publicKeys[i] = publicKey;
            privateKeys[i] = privateKey;
        }

        //System.out.println(publicKeys);
        //System.out.println(privateKeys);

        //TO DO:
        //Now encrypt each of the shares using the miner public keys, and replace the corresponding
        //mapping in the parts map.

        for (int i=0; i<share.n; i++) {
            byte[] value = parts.get(i);
            Cipher encryptCipher = Cipher.getInstance("RSA");
            encryptCipher.init(Cipher.ENCRYPT_MODE, publicKeys[i]);
            byte[] cipherTexti = encryptCipher.doFinal(value);
            parts.replace(i, cipherTexti);
        }

        //AFTER DATA RETRIEVAL:
        //Require an added check here for which k public keys we get back in reconstruction,
        //but this suffices for testing purposes

        for (int i=0; i<share.n; i++) {
            Cipher decrypted = Cipher.getInstance("RSA");
            decrypted.init(Cipher.DECRYPT_MODE, privateKeys[i]);
            byte[] val = parts.get(i);
            byte[] newValue = decrypted.doFinal(val);
            //In final implementation it may make more sense to create a new mapping of size k (n/2)
            parts.replace(i,newValue);
        }

        //Key Recovery:
        //Convert back to SecretKey type
        byte[] recovered = share.join(parts);
        SecretKey secretKey1 = new SecretKeySpec(recovered, 0, recovered.length, "AES");

        //System.out.println(new String(recovered, StandardCharsets.UTF_8));
        //System.out.println(parts);

        //File Decryption Process:

        Cipher dcipher = Cipher.getInstance("AES");
        dcipher.init(Cipher.DECRYPT_MODE, secretKey1);
        byte[] bytePlainText = dcipher.doFinal(byteCipherText);
        String out = new String(bytePlainText);
        System.out.println(out);

        System.out.println("Hello");

    }
}
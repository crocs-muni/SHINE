package tests;

import cz.muni.fi.crocs.rcard.client.CardType;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.*;
import org.testng.Assert;
import shine.Consts;

import java.security.NoSuchAlgorithmException;
import java.util.Random;
import java.security.MessageDigest;

import java.math.BigInteger;

public class AppletTest extends BaseTest {
    ProtocolManager pm;
    MessageDigest hasher;
    Random rng;

    public AppletTest() throws NoSuchAlgorithmException {
        hasher = MessageDigest.getInstance("SHA-256");
        rng = new Random();
        rng.setSeed(0);
        setCardType(CardType.JCARDSIMLOCAL);
    }

    @BeforeEach
    public void setUpMethod() throws Exception {
        pm = new ProtocolManager(connect());
    }

    @AfterEach
    public void tearDownMethod() throws Exception {
        pm.disconnect();
    }

    public ECPoint keygen(int groupSize, ECPoint[] publicKeys) throws Exception {
        BigInteger[] privateKeys = new BigInteger[groupSize - 1];
        if(publicKeys == null || publicKeys.length != groupSize - 1) {
            publicKeys = new ECPoint[groupSize - 1];
        }
        for(int i = 0; i < groupSize - 1; ++i) {
            privateKeys[i] = new BigInteger(256, rng);
            publicKeys[i] = pm.generator.multiply(privateKeys[i]);
        }

        byte[] commitment = pm.keygenInitialize(groupSize);
        pm.keygenAddCommitment(0, commitment);
        for(int i = 0; i < groupSize - 1; ++i) {
            pm.keygenAddCommitment(i + 1, hasher.digest(publicKeys[i].getEncoded(false)));
        }

        ECPoint key = pm.keygenReveal();
        ECPoint expected = key;
        pm.keygenAddKey(0, key);
        for(int i = 0; i < groupSize - 1; ++i) {
            pm.keygenAddKey(i + 1, publicKeys[i]);
            expected = expected.add(publicKeys[i]);
        }
        ECPoint groupKey = pm.keygenFinalize();
        Assert.assertEquals(expected, groupKey);
        return groupKey;
    }

    public ECPoint keygen(int groupSize) throws Exception {
        return keygen(groupSize, null);
    }

    public BigInteger computeChallenge(ECPoint nonce, ECPoint publicKey, byte[] message) {
        hasher.reset();
        hasher.update(nonce.getEncoded(false));
        hasher.update(publicKey.getEncoded(false));
        hasher.update(message);
        return new BigInteger(1, hasher.digest());
    }

    @Test
    public void testKeygen() throws Exception {
        for(int i = 1; i <= Consts.MAX_PARTIES; ++i)
            keygen(i);
    }

    @Test
    public void testSign() throws Exception {
        ECPoint[] publicKeys = new ECPoint[2];
        ECPoint groupKey = keygen(3, publicKeys);
        ECPoint cardKey = groupKey;
        for(ECPoint publicKey : publicKeys) {
            cardKey = cardKey.subtract(publicKey);
        }

        short counter = 1;
        byte[] message = new byte[32];
        byte[] keyBuffer = new byte[64];

        ECPoint nonce = pm.getNonce(counter);
        byte[] encryptedNonce = pm.cacheNonce(counter + 1);
        BigInteger signature = pm.signReveal(counter, nonce, message, keyBuffer);
        BigInteger challenge = computeChallenge(nonce, groupKey, message);
        Assert.assertEquals(pm.generator.multiply(signature), cardKey.multiply(challenge).add(nonce));

        pm.revealNonce(counter + 1);

        byte[] nonceBytes = new byte[65];
        nonceBytes[0] = 0x04;
        System.arraycopy(encryptedNonce, 0, nonceBytes, 1, 64);
        for(int i = 0; i < 64; ++i) {
            nonceBytes[i + 1] ^= keyBuffer[i];
        }
        nonce = pm.curve.decodePoint(nonceBytes);

        signature = pm.sign(counter + 1, nonce, message);
        challenge = computeChallenge(nonce, groupKey, message);
        Assert.assertEquals(pm.generator.multiply(signature), cardKey.multiply(challenge).add(nonce));
    }
}

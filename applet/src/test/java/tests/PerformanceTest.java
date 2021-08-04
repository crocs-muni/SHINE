package tests;

import cz.muni.fi.crocs.rcard.client.CardManager;
import cz.muni.fi.crocs.rcard.client.CardType;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.Test;
import org.testng.Assert;

import java.io.FileWriter;
import java.io.PrintWriter;

public class PerformanceTest extends BaseTest {

    ProtocolManager pm;
    PrintWriter file;

    long REPEAT = 100;

    @Test
    public void PerformanceMeasurement() throws Exception {
        new PerformanceTest().run();
    }

    public void run() throws Exception {
        setCardType(CardType.JCARDSIMLOCAL);
        pm = new ProtocolManager(connect());
        file = new PrintWriter(new FileWriter("measurement.csv", true));

        debugInitialize();
        for(int i = 0; i < REPEAT; ++i) {
            //measureKeygen(1);
            measureSign(2 * i);
        }

        file.close();
        pm.disconnect();
    }

    public void measureKeygen(int groupSize) throws Exception {
        byte[] commitment = pm.keygenInitialize(groupSize);
        file.printf("KeygenInitialize;%d;%d\n", groupSize, pm.getLastOperationTime());
        for(int i = 0; i < groupSize; ++i) {
            pm.keygenAddCommitment(i, commitment);
            file.printf("KeygenAddCommitment;%d;%d\n", groupSize, pm.getLastOperationTime());
        }
        ECPoint key = pm.keygenReveal();
        file.printf("KeygenReveal;%d;%d\n", groupSize, pm.getLastOperationTime());
        for(int i = 0; i < groupSize; ++i) {
            pm.keygenAddKey(i, key);
            file.printf("KeygenAddKey;%d;%d\n", groupSize, pm.getLastOperationTime());
        }
        ECPoint groupkey = pm.keygenFinalize();
        file.printf("KeygenFinalize;%d;%d\n", groupSize, pm.getLastOperationTime());
    }

    public void debugInitialize() throws Exception {
        pm.debugSetGroupKey(pm.debugKeygen(), 1);
    }

    public void measureSign(int counter) throws Exception {
        byte[] message = new byte[32];
        byte[] keyBuffer = new byte[64];

        ECPoint nonce = pm.getNonce(counter);
        file.printf("GetNonce;%d\n", pm.getLastOperationTime());
        byte[] encryptedNonce = pm.cacheNonce(counter + 1);
        file.printf("CacheNonce;%d\n", pm.getLastOperationTime());
        pm.signReveal(counter, nonce, message, keyBuffer, false);
        file.printf("SignReveal;%d\n", pm.getLastOperationTime());
        pm.revealNonce(counter + 1);
        file.printf("RevealNonce;%d\n", pm.getLastOperationTime());

        byte[] nonceBytes = new byte[65];
        nonceBytes[0] = 0x04;
        System.arraycopy(encryptedNonce, 0, nonceBytes, 1, 64);
        for(int i = 0; i < 64; ++i) {
            nonceBytes[i + 1] ^= keyBuffer[i];
        }
        nonce = pm.curve.decodePoint(nonceBytes);

        pm.sign(counter + 1, nonce, message, false);
        file.printf("Sign;%d\n", pm.getLastOperationTime());
    }
}
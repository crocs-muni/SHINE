package tests;

import cz.muni.fi.crocs.rcard.client.CardType;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.jupiter.api.*;

public class AppletTest extends BaseTest {
    ProtocolManager pm;

    public AppletTest() {
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

    public ECPoint keygen(int groupSize) throws Exception {
        byte[] commitment = pm.keygenInitialize(groupSize);
        for(int i = 0; i < groupSize; ++i) {
            pm.keygenAddCommitment(i, commitment);
        }
        ECPoint key = pm.keygenReveal();
        for(int i = 0; i < groupSize; ++i) {
            pm.keygenAddKey(i, key);
        }
        return pm.keygenFinalize();
    }

    @Test
    public void testKeygen() throws Exception {
        keygen(1);
    }

    @Test
    public void testSign() throws Exception {
        keygen(1);

        short counter = 1;
        byte[] message = new byte[32];
        byte[] keyBuffer = new byte[64];

        ECPoint nonce = pm.getNonce(counter);
        byte[] encryptedNonce = pm.cacheNonce(counter + 1);
        pm.signReveal(counter, nonce, message, keyBuffer);
        pm.revealNonce(counter + 1);

        byte[] nonceBytes = new byte[65];
        nonceBytes[0] = 0x04;
        System.arraycopy(encryptedNonce, 0, nonceBytes, 1, 64);
        for(int i = 0; i < 64; ++i) {
            nonceBytes[i + 1] ^= keyBuffer[i];
        }
        nonce = pm.curve.decodePoint(nonceBytes);

        pm.sign(counter + 1, nonce, message);
    }
}

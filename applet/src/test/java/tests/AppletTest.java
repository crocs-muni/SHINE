package tests;

import mpcapplet.Consts;
import cardTools.RunConfig;
import mpcapplet.jcmathlib.SecP256r1;
import org.bouncycastle.math.ec.ECPoint;
import org.junit.Assert;
import org.junit.jupiter.api.*;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

public class AppletTest extends BaseTest {

    private ProtocolManager pm;

    public AppletTest() {
        setCardType(RunConfig.CARD_TYPE.JCARDSIMLOCAL);
    }

    @BeforeEach
    public void setUpMethod() throws Exception {
        pm = connect();
    }

    @AfterEach
    public void tearDownMethod() throws Exception {
        pm.disconnect(true);
    }

    private ResponseAPDU sendAPDU(int cla, int ins, int p1, int p2) throws Exception {
        return sendAPDU(cla, ins, p1, p2, null);
    }

    private ResponseAPDU sendAPDU(int cla, int ins, int p1, int p2, byte[] data) throws Exception {
        final CommandAPDU cmd = new CommandAPDU(cla, ins, p1, p2, data);
        return pm.transmit(cmd);
    }

    @Test
    public void testInfo() throws Exception {
        byte[] resp = sendAPDU(Consts.CLA_MPCAPPLET, Consts.INS_GET_INFO, 0, 0).getData();
        Assert.assertArrayEquals("MPCApplet 0.1.0".getBytes(StandardCharsets.UTF_8), resp);
    }

    @Test
    public void testIdentitySecret() throws Exception {
        byte[] sk = pm.debugIdentity();
        boolean zero = true;
        for (int i = 0; i < SecP256r1.COORD_SIZE; ++i) {
            if (sk[i] != 0x00) {
                zero = false;
                break;
            }
        }
        Assert.assertFalse(zero);
    }

    @Test
    public void testIdentityKey() throws Exception {
        BigInteger priv = new BigInteger(1, pm.debugIdentity());
        ECPoint publicKey = pm.generator.multiply(priv);
        Assert.assertTrue(publicKey.equals(pm.getIdentity()));
    }
}

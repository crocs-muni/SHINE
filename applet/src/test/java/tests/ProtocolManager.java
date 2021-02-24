package tests;

import cardTools.CardManager;
import mpcapplet.Consts;
import mpcapplet.jcmathlib.SecP256r1;
import org.testng.Assert;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Arrays;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

public class ProtocolManager extends CardManager {

    ECNamedCurveParameterSpec params;
    ECCurve curve;
    ECPoint generator;
    long lastOperationTime;

    public ProtocolManager(boolean bDebug, byte[] appletAID) {
        super(bDebug, appletAID);
        params = ECNamedCurveTable.getParameterSpec("secp256r1");
        curve = params.getCurve();
        generator = curve.decodePoint(SecP256r1.G);
    }

    private ResponseAPDU sendAPDU(int cla, int ins, int p1, int p2) throws Exception {
        return sendAPDU(cla, ins, p1, p2, null);
    }

    private ResponseAPDU sendAPDU(int cla, int ins, int p1, int p2, byte[] data) throws Exception {
        final CommandAPDU cmd = new CommandAPDU(cla, ins, p1, p2, data);
        return transmit(cmd);
    }

    public long getLastOperationTime() {
        return lastOperationTime;
    }

    public static void checkLength(ResponseAPDU apdu, int length) {
        Assert.assertNotNull(apdu);
        Assert.assertEquals(0x9000, apdu.getSW());
        Assert.assertEquals(apdu.getData().length, length);
    }

    public byte[] debugIdentity() throws Exception {
        ResponseAPDU resp = sendAPDU(Consts.CLA_MPCAPPLET, Consts.INS_DEBUG_IDENTITY, 0, 0);
        lastOperationTime = getLastTransmitTime();
        checkLength(resp, SecP256r1.COORD_SIZE);
        return resp.getData();
    }

    public ECPoint getIdentity() throws Exception {
        ResponseAPDU resp = sendAPDU(Consts.CLA_MPCAPPLET, Consts.INS_GET_IDENTITY, 0, 0);
        lastOperationTime = getLastTransmitTime();
        checkLength(resp, SecP256r1.POINT_SIZE);
        Assert.assertEquals(resp.getData()[0], 0x04);
        return curve.decodePoint(resp.getData());
    }
}

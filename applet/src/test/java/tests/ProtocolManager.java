package tests;

import cardTools.CardManager;
import mpcapplet.Consts;
import mpcapplet.jcmathlib.SecP256r1;
import org.junit.jupiter.api.Assertions;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.math.BigInteger;
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
        Assertions.assertNotNull(apdu);
        Assertions.assertEquals(0x9000, apdu.getSW());
        Assertions.assertEquals(apdu.getData().length, length);
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
        Assertions.assertEquals(resp.getData()[0], 0x04);
        return curve.decodePoint(resp.getData());
    }

    public byte[] keygenInitialize(int groupSize) throws Exception {
        ResponseAPDU resp = sendAPDU(Consts.CLA_MULTISCHNORR, Consts.INS_KEYGEN_INITIALIZE, groupSize, 0);
        lastOperationTime = getLastTransmitTime();
        checkLength(resp, 32);
        return resp.getData();
    }

    public void keygenAddCommitment(int idx, byte[] commitment) throws Exception {
        ResponseAPDU resp = sendAPDU(Consts.CLA_MULTISCHNORR, Consts.INS_KEYGEN_ADD_COMMITMENT, idx, 0, commitment);
        lastOperationTime = getLastTransmitTime();
        checkLength(resp, 0);
    }

    public ECPoint keygenReveal() throws Exception {
        ResponseAPDU resp = sendAPDU(Consts.CLA_MULTISCHNORR, Consts.INS_KEYGEN_REVEAL, 0, 0);
        lastOperationTime = getLastTransmitTime();
        checkLength(resp, SecP256r1.POINT_SIZE);
        return curve.decodePoint(resp.getData());
    }

    public void keygenAddKey(int idx, ECPoint partialPublicKey) throws Exception {
        ResponseAPDU resp = sendAPDU(Consts.CLA_MULTISCHNORR, Consts.INS_KEYGEN_ADD_KEY, idx, 0, partialPublicKey.getEncoded(false));
        lastOperationTime = getLastTransmitTime();
        checkLength(resp, 0);
    }

    public ECPoint keygenFinalize() throws Exception {
        ResponseAPDU resp = sendAPDU(Consts.CLA_MULTISCHNORR, Consts.INS_KEYGEN_FINALIZE, 0, 0);
        lastOperationTime = getLastTransmitTime();
        checkLength(resp, SecP256r1.POINT_SIZE);
        return curve.decodePoint(resp.getData());
    }

    public ECPoint getNonce(int counter) throws Exception {
        ResponseAPDU resp = sendAPDU(Consts.CLA_MULTISCHNORR, Consts.INS_GET_NONCE, counter & 0xff, (counter >> 8) & 0xff);
        lastOperationTime = getLastTransmitTime();
        checkLength(resp, 65);
        return curve.decodePoint(resp.getData());
    }

    public BigInteger sign(int counter, ECPoint groupNonce, byte[] message) throws Exception {
        byte[] data = new byte[SecP256r1.POINT_SIZE + message.length];
        System.arraycopy(groupNonce.getEncoded(false), 0, data, 0, SecP256r1.POINT_SIZE);
        System.arraycopy(message, 0, data, SecP256r1.POINT_SIZE, message.length);

        ResponseAPDU resp = sendAPDU(Consts.CLA_MULTISCHNORR, Consts.INS_SIGN, counter & 0xff, (counter >> 8) & 0xff, data);
        lastOperationTime = getLastTransmitTime();
        checkLength(resp, 32);
        return new BigInteger(1, resp.getData());
    }
}

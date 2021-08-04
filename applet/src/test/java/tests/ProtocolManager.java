package tests;

import cz.muni.fi.crocs.rcard.client.CardManager;
import shine.Consts;
import shine.jcmathlib.SecP256k1;
import org.junit.jupiter.api.Assertions;

import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.math.BigInteger;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

public class ProtocolManager {
    CardManager cm;

    ECNamedCurveParameterSpec params;
    ECCurve curve;
    ECPoint generator;
    long lastOperationTime;

    public ProtocolManager(CardManager cm) {
        this.cm = cm;
        params = ECNamedCurveTable.getParameterSpec("secp256k1");
        curve = params.getCurve();
        generator = curve.decodePoint(SecP256k1.G);
    }

    private ResponseAPDU sendAPDU(int cla, int ins, int p1, int p2) throws Exception {
        return sendAPDU(cla, ins, p1, p2, null);
    }

    private ResponseAPDU sendAPDU(int cla, int ins, int p1, int p2, byte[] data) throws Exception {
        final CommandAPDU cmd = new CommandAPDU(cla, ins, p1, p2, data);
        return cm.transmit(cmd);
    }

    public long getLastOperationTime() {
        return lastOperationTime;
    }

    public static void checkLength(ResponseAPDU apdu, int length) {
        Assertions.assertNotNull(apdu);
        Assertions.assertEquals(0x9000, apdu.getSW());
        Assertions.assertEquals(apdu.getData().length, length);
    }

    public byte[] keygenInitialize(int groupSize) throws Exception {
        ResponseAPDU resp = sendAPDU(Consts.CLA_SHINE, Consts.INS_KEYGEN_INITIALIZE, groupSize, 0);
        lastOperationTime = cm.getLastTransmitTime();
        checkLength(resp, 32);
        return resp.getData();
    }

    public void keygenAddCommitment(int idx, byte[] commitment) throws Exception {
        ResponseAPDU resp = sendAPDU(Consts.CLA_SHINE, Consts.INS_KEYGEN_ADD_COMMITMENT, idx, 0, commitment);
        lastOperationTime = cm.getLastTransmitTime();
        checkLength(resp, 0);
    }

    public ECPoint keygenReveal() throws Exception {
        ResponseAPDU resp = sendAPDU(Consts.CLA_SHINE, Consts.INS_KEYGEN_REVEAL, 0, 0);
        lastOperationTime = cm.getLastTransmitTime();
        checkLength(resp, SecP256k1.POINT_SIZE);
        return curve.decodePoint(resp.getData());
    }

    public void keygenAddKey(int idx, ECPoint partialPublicKey) throws Exception {
        ResponseAPDU resp = sendAPDU(Consts.CLA_SHINE, Consts.INS_KEYGEN_ADD_KEY, idx, 0, partialPublicKey.getEncoded(false));
        lastOperationTime = cm.getLastTransmitTime();
        checkLength(resp, 0);
    }

    public ECPoint keygenFinalize() throws Exception {
        ResponseAPDU resp = sendAPDU(Consts.CLA_SHINE, Consts.INS_KEYGEN_FINALIZE, 0, 0);
        lastOperationTime = cm.getLastTransmitTime();
        checkLength(resp, SecP256k1.POINT_SIZE);
        return curve.decodePoint(resp.getData());
    }

    public ECPoint getNonce(int counter) throws Exception {
        ResponseAPDU resp = sendAPDU(Consts.CLA_SHINE, Consts.INS_GET_NONCE, counter & 0xff, (counter >> 8) & 0xff);
        lastOperationTime = cm.getLastTransmitTime();
        checkLength(resp, 65);
        return curve.decodePoint(resp.getData());
    }

    public byte[] cacheNonce(int counter) throws Exception {
        ResponseAPDU resp = sendAPDU(Consts.CLA_SHINE, Consts.INS_CACHE_NONCE, counter & 0xff, (counter >> 8) & 0xff);
        lastOperationTime = cm.getLastTransmitTime();
        checkLength(resp, 64);
        return resp.getData();
    }

    public byte[] revealNonce(int counter) throws Exception {
        ResponseAPDU resp = sendAPDU(Consts.CLA_SHINE, Consts.INS_REVEAL_NONCE, counter & 0xff, (counter >> 8) & 0xff);
        lastOperationTime = cm.getLastTransmitTime();
        checkLength(resp, 64);
        return resp.getData();
    }

    public BigInteger sign(int counter, ECPoint groupNonce, byte[] message, boolean bip) throws Exception {
        byte[] data = new byte[SecP256k1.POINT_SIZE + message.length];
        System.arraycopy(groupNonce.getEncoded(false), 0, data, 0, SecP256k1.POINT_SIZE);
        System.arraycopy(message, 0, data, SecP256k1.POINT_SIZE, message.length);

        ResponseAPDU resp = sendAPDU(Consts.CLA_SHINE, bip ? Consts.INS_SIGN_BIP : Consts.INS_SIGN, counter & 0xff, (counter >> 8) & 0xff, data);
        lastOperationTime = cm.getLastTransmitTime();
        checkLength(resp, 32);
        return new BigInteger(1, resp.getData());
    }

    public BigInteger signReveal(int counter, ECPoint groupNonce, byte[] message, byte[] keyBuffer, boolean bip) throws Exception {
        byte[] data = new byte[SecP256k1.POINT_SIZE + message.length];
        System.arraycopy(groupNonce.getEncoded(false), 0, data, 0, SecP256k1.POINT_SIZE);
        System.arraycopy(message, 0, data, SecP256k1.POINT_SIZE, message.length);

        ResponseAPDU resp = sendAPDU(Consts.CLA_SHINE, bip ? Consts.INS_SIGN_BIP_REVEAL : Consts.INS_SIGN_REVEAL, counter & 0xff, (counter >> 8) & 0xff, data);
        lastOperationTime = cm.getLastTransmitTime();
        checkLength(resp, 32 + 64);
        byte[] signature = new byte[32];
        System.arraycopy(resp.getData(), 0, signature, 0, 32);
        System.arraycopy(resp.getData(), 32, keyBuffer, 0, 64);
        return new BigInteger(1, signature);
    }

    public ECPoint debugKeygen() throws Exception {
        ResponseAPDU resp = sendAPDU(Consts.CLA_SHINE, Consts.INS_DEBUG_KEYGEN, 0, 0);
        lastOperationTime = cm.getLastTransmitTime();
        checkLength(resp, 65);
        return curve.decodePoint(resp.getData());
    }

    public BigInteger debugPrivate() throws Exception {
        ResponseAPDU resp = sendAPDU(Consts.CLA_SHINE, Consts.INS_DEBUG_PRIVATE, 0, 0);
        lastOperationTime = cm.getLastTransmitTime();
        checkLength(resp, 32);
        return new BigInteger(1, resp.getData());
    }

    public ECPoint debugGroupKey() throws Exception {
        ResponseAPDU resp = sendAPDU(Consts.CLA_SHINE, Consts.INS_DEBUG_GROUPKEY, 0, 0);
        lastOperationTime = cm.getLastTransmitTime();
        checkLength(resp, 65);
        return curve.decodePoint(resp.getData());
    }

    public void debugSetGroupKey(ECPoint groupKey) throws Exception {
        ResponseAPDU resp = sendAPDU(Consts.CLA_SHINE, Consts.INS_DEBUG_SET_GROUPKEY, 0, 0, groupKey.getEncoded(false));
        lastOperationTime = cm.getLastTransmitTime();
        checkLength(resp, 0);
    }

    public void disconnect() throws CardException {
        cm.disconnect(true);
        cm = null;
    }
}

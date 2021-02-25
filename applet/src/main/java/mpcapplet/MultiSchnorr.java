package mpcapplet;

import javacard.framework.*;

import mpcapplet.jcmathlib.*;

import javax.print.attribute.standard.MediaSize;

public class MultiSchnorr {
    private MPCApplet ctx;

    private Bignat groupSecret;
    private ECPoint groupKey;
    private short groupSize;

    private byte[] commitments = new byte[(short) (SecP256r1.POINT_SIZE * Consts.MAX_PARTIES)];
    private byte commitmentCounter = 0;
    private byte revealCounter = 0;
    private short nonceCounter = 0;

    private Bignat signature;

    public MultiSchnorr(MPCApplet ctx) {
        this.ctx = ctx;
        groupSecret = new Bignat(SecP256r1.COORD_SIZE, JCSystem.MEMORY_TYPE_PERSISTENT, ctx.ecc.bnh);
        groupKey = new ECPoint(ctx.curve, ctx.ecc.ech);
        signature = new Bignat(SecP256r1.COORD_SIZE, JCSystem.MEMORY_TYPE_PERSISTENT, ctx.ecc.bnh);
    }

    public void process(APDU apdu) {
        switch(apdu.getBuffer()[ISO7816.OFFSET_INS]) {
            case Consts.INS_KEYGEN_INITIALIZE:
                keygenInitialize(apdu);
                break;
            case Consts.INS_KEYGEN_ADD_COMMITMENT:
                keygenAddCommitment(apdu);
                break;
            case Consts.INS_KEYGEN_REVEAL:
                keygenReveal(apdu);
                break;
            case Consts.INS_KEYGEN_ADD_KEY:
                keygenAddKey(apdu);
                break;
            case Consts.INS_KEYGEN_FINALIZE:
                keygenFinalize(apdu);
                break;
            case Consts.INS_GET_NONCE:
                getNonce(apdu);
                break;
            case Consts.INS_SIGN:
                sign(apdu);
                break;

            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private void keygenInitialize(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        groupSize = apduBuffer[ISO7816.OFFSET_P1];
        ctx.random.generateData(ctx.ramArray, (short) 0, (short) 32);
        groupSecret.set_from_byte_array((short) 0, ctx.ramArray, (short) 0, (short) 32);
        groupKey.setW(SecP256r1.G, (short) 0, SecP256r1.POINT_SIZE);
        groupKey.multiplication(groupSecret);
        groupKey.getW(ctx.ramArray, (short) 0);
        ctx.hasher.reset();
        ctx.hasher.doFinal(ctx.ramArray, (short) 0, SecP256r1.POINT_SIZE, apduBuffer, (short) 0);
        Util.arrayFillNonAtomic(commitments, (short) 0, (short) (ctx.curve.POINT_SIZE * Consts.MAX_PARTIES), (byte) 0x00);
        commitmentCounter = 0;
        revealCounter = 0;
        apdu.setOutgoingAndSend((short) 0, (short) 32);
    }

    private void keygenAddCommitment(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        short p1 = apduBuffer[ISO7816.OFFSET_P1];
        Util.arrayCopyNonAtomic(apduBuffer, ISO7816.OFFSET_CDATA, commitments, (short) (ctx.curve.POINT_SIZE * p1), ctx.curve.POINT_SIZE);
        ++commitmentCounter;
        apdu.setOutgoingAndSend((short) 0, (short) 0);
    }

    private void keygenReveal(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        groupKey.getW(apduBuffer, (short) 0);
        apdu.setOutgoingAndSend((short) 0, ctx.curve.POINT_SIZE);
    }

    private void keygenAddKey(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        short p1 = apduBuffer[ISO7816.OFFSET_P1];
        ctx.hasher.reset();
        ctx.hasher.doFinal(apduBuffer, ISO7816.OFFSET_CDATA, ctx.curve.POINT_SIZE, ctx.ramArray, (short) 0);
        if(Util.arrayCompare(ctx.ramArray, (short) 0, commitments, (short) (ctx.curve.POINT_SIZE * p1), ctx.curve.POINT_SIZE) != 0) {
            // TODO check failed
        }
        Util.arrayFillNonAtomic(commitments, (short) (ctx.curve.POINT_SIZE * p1), ctx.curve.POINT_SIZE, (byte) 0x00);
        ctx.tmpKey.setW(apduBuffer, ISO7816.OFFSET_CDATA, ctx.curve.POINT_SIZE);
        if(revealCounter == 0) {
            // TODO can be avoided by not sending card's public key
            groupKey.copy(ctx.tmpKey);
        } else {
            groupKey.add(ctx.tmpKey);
        }
        ++revealCounter;
        apdu.setOutgoingAndSend((short) 0, (short) 0);
    }

    private void keygenFinalize(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        groupKey.getW(apduBuffer, (short) 0);
        apdu.setOutgoingAndSend((short) 0, ctx.curve.POINT_SIZE);
    }

    private void getNonce(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        short counter = (short) (apduBuffer[ISO7816.OFFSET_P1] | (apduBuffer[ISO7816.OFFSET_P2] >> 8));
        if(counter > nonceCounter) {
            // TODO fail
        }
        nonceCounter = counter;
        prf(counter);
        ctx.tmpSecret.set_from_byte_array((short) 0, ctx.ramArray, (short) 0, (short) (SecP256r1.KEY_LENGTH / 8));
        ctx.tmpKey.setW(ctx.curve.G, (short) 0, ctx.curve.POINT_SIZE);
        ctx.tmpKey.multiplication(ctx.tmpSecret);
        ctx.tmpKey.getW(apduBuffer, (short) 0);
        apdu.setOutgoingAndSend((short) 0, ctx.curve.POINT_SIZE);
    }

    private void sign(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        short counter = (short) (apduBuffer[ISO7816.OFFSET_P1] | (apduBuffer[ISO7816.OFFSET_P2] >> 8));
        ctx.hasher.reset();
        groupKey.getW(ctx.ramArray, (short) 0);
        ctx.hasher.update(ctx.ramArray, (short) 0, ctx.curve.POINT_SIZE);
        ctx.hasher.update(apduBuffer, ISO7816.OFFSET_CDATA, ctx.curve.POINT_SIZE);
        ctx.hasher.doFinal(apduBuffer, (short) (ISO7816.OFFSET_CDATA + ctx.curve.POINT_SIZE), (short) 32, ctx.ramArray, (short) 0);
        ctx.tmpSecret.set_from_byte_array((short) 0, ctx.ramArray, (short) 0, ctx.hasher.getLength());
        signature.mod_mult(ctx.tmpSecret, groupSecret, ctx.curveOrder);
        prf(counter);
        ctx.tmpSecret.set_from_byte_array((short) 0, ctx.ramArray, (short) 0, ctx.hasher.getLength());
        signature.mod_add(ctx.tmpSecret, ctx.curveOrder);
        signature.copy_to_buffer(apduBuffer, (short) 0);
        apdu.setOutgoingAndSend((short) 0, (short) (ctx.curve.KEY_LENGTH / 8));
    }

    private void prf(short counter) {
        ctx.hasher.reset();
        ctx.hasher.update(ctx.identitySecret.as_byte_array(), (short) 0, (short) (SecP256r1.KEY_LENGTH / 8));
        ctx.ramArray[0] = (byte) (counter & 0xff);
        ctx.ramArray[1] = (byte) ((counter >> 8) & 0xff);
        ctx.hasher.doFinal(ctx.ramArray, (short) 0, (short) 2, ctx.ramArray, (short) 0);
    }
}

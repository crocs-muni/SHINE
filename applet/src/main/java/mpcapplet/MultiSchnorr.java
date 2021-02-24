package mpcapplet;

import javacard.framework.*;

import mpcapplet.jcmathlib.*;

public class MultiSchnorr {
    private MPCApplet ctx;

    private Bignat groupSecret;
    private ECPoint groupKey;
    private short groupSize;

    private byte[] commitments;
    private byte commitmentCounter;
    private byte revealCounter;

    public MultiSchnorr(MPCApplet ctx) {
        this.ctx = ctx;
        groupSecret = new Bignat(SecP256r1.COORD_SIZE, JCSystem.MEMORY_TYPE_PERSISTENT, ctx.ecc.bnh);
        groupKey = new ECPoint(ctx.curve, ctx.ecc.ech);
        commitments = new byte[(short) (SecP256r1.POINT_SIZE * Consts.MAX_PARTIES)];
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
}

package shine;

import javacard.framework.*;
import javacard.security.CryptoException;
import javacard.security.MessageDigest;
import javacard.security.RandomData;
import shine.jcmathlib.*;

public class Shine extends Applet
{
    public final byte[] ramArray = JCSystem.makeTransientByteArray((short) 65, JCSystem.CLEAR_ON_DESELECT);
    public final RandomData random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
    public final MessageDigest hasher = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);

    public ResourceManager rm;
    public ECCurve curve;

    public BigNat identitySecret, tmpSecret, groupSecret, signature;
    public ECPoint identityKey, tmpKey, groupKey;

    private short groupSize;

    private byte[] commitments;
    private byte commitmentCounter = 0;
    private byte revealCounter = 0;
    private short nonceCounter = 0;

    private final boolean debug = true;
    private boolean initialized = false;

    public static void install(byte[] bArray, short bOffset, byte bLength)
    {
        new Shine(bArray, bOffset, bLength);
    }

    public Shine(byte[] buffer, short offset, byte length)
    {
        OperationSupport.getInstance().setCard(OperationSupport.SIMULATOR);
        register();
}

    public void process(APDU apdu)
    {
        if (selectingApplet()) // ignore selection command
            return;

        if(apdu.getBuffer()[ISO7816.OFFSET_CLA] != Consts.CLA_SHINE)
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);

        try {
            switch(apdu.getBuffer()[ISO7816.OFFSET_INS]) {
                case Consts.INS_INITIALIZE:
                    initialize(apdu);
                    break;
                case Consts.INS_INFO:
                    getInfo(apdu);
                    break;
                case Consts.INS_IDENTITY:
                    getIdentity(apdu);
                    break;

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
                case Consts.INS_CACHE_NONCE:
                    cacheNonce(apdu);
                    break;
                case Consts.INS_REVEAL_NONCE:
                    revealNonce(apdu);
                    break;
                case Consts.INS_SIGN:
                    sign(apdu, false, false);
                    break;
                case Consts.INS_SIGN_REVEAL:
                    sign(apdu, true, false);
                    break;
                case Consts.INS_SIGN_BIP:
                    sign(apdu, false, true);
                    break;
                case Consts.INS_SIGN_BIP_REVEAL:
                    sign(apdu, true, true);
                    break;

                case Consts.INS_DEBUG_KEYGEN:
                    debugKeygen(apdu);
                    break;
                case Consts.INS_DEBUG_PRIVATE:
                    debugPrivate(apdu);
                    break;
                case Consts.INS_DEBUG_GROUPKEY:
                    debugGroupKey(apdu);
                    break;
                case Consts.INS_DEBUG_SET_GROUPKEY:
                    debugSetGroupKey(apdu);
                    break;

                default:
                    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            }
        } catch (ISOException e) {
            throw e; // Our exception from code, just re-emit
        } catch (ArrayIndexOutOfBoundsException e) {
            ISOException.throwIt(Consts.SW_ArrayIndexOutOfBoundsException);
        } catch (ArithmeticException e) {
            ISOException.throwIt(Consts.SW_ArithmeticException);
        } catch (ArrayStoreException e) {
            ISOException.throwIt(Consts.SW_ArrayStoreException);
        } catch (NullPointerException e) {
            ISOException.throwIt(Consts.SW_NullPointerException);
        } catch (NegativeArraySizeException e) {
            ISOException.throwIt(Consts.SW_NegativeArraySizeException);
        } catch (CryptoException e) {
            ISOException.throwIt((short) (Consts.SW_CryptoException_prefix | e.getReason()));
        } catch (SystemException e) {
            ISOException.throwIt((short) (Consts.SW_SystemException_prefix | e.getReason()));
        } catch (PINException e) {
            ISOException.throwIt((short) (Consts.SW_PINException_prefix | e.getReason()));
        } catch (TransactionException e) {
            ISOException.throwIt((short) (Consts.SW_TransactionException_prefix | e.getReason()));
        } catch (CardRuntimeException e) {
            ISOException.throwIt((short) (Consts.SW_CardRuntimeException_prefix | e.getReason()));
        } catch (Exception e) {
            ISOException.throwIt(Consts.SW_Exception);
        }
    }

    public boolean select() {
        if(initialized)
            curve.updateAfterReset();
        return true;
    }

    public void deselect() {}

    private void initialize(APDU apdu) {
        if(initialized)
            ISOException.throwIt(Consts.E_ALREADY_INITIALIZED);

        rm = new ResourceManager((short) 256);
        curve = new ECCurve(SecP256k1.p, SecP256k1.a, SecP256k1.b, SecP256k1.G, SecP256k1.r, rm);

        identitySecret = new BigNat(curve.COORD_SIZE, JCSystem.MEMORY_TYPE_PERSISTENT, rm);
        identityKey = new ECPoint(curve);

        tmpSecret = new BigNat(curve.COORD_SIZE, JCSystem.MEMORY_TYPE_PERSISTENT, rm);
        tmpKey = new ECPoint(curve);

        groupSecret = new BigNat(curve.COORD_SIZE, JCSystem.MEMORY_TYPE_PERSISTENT, rm);
        groupKey = new ECPoint(curve);

        signature = new BigNat(curve.COORD_SIZE, JCSystem.MEMORY_TYPE_PERSISTENT, rm);

        commitments = new byte[(short) (curve.POINT_SIZE * Consts.MAX_PARTIES)];

        random.generateData(ramArray, (short) 0, (short) 32);
        identitySecret.fromByteArray(ramArray, (short) 0, (short) 32);
        identityKey.setW(curve.G, (short) 0, (short) curve.G.length);
        identityKey.multiplication(identitySecret);

        initialized = true;

        apdu.setOutgoing();
    }

    private void getInfo(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        byte[] msg = {(byte) 0x53, (byte) 0x48, (byte) 0x49, (byte) 0x4e, (byte) 0x45}; // SHINE
        Util.arrayCopyNonAtomic(msg, (short) 0, apduBuffer, (short) 0, (short) msg.length);
        apdu.setOutgoingAndSend((short) 0, (short) msg.length);
    }

    private void getIdentity(APDU apdu) {
        if(!initialized)
            ISOException.throwIt(Consts.E_UNINITIALIZED);

        byte[] apduBuffer = apdu.getBuffer();
        identityKey.getW(apduBuffer, (short) 0);
        apdu.setOutgoingAndSend((short) 0, curve.POINT_SIZE);
    }

    private void keygenInitialize(APDU apdu) {
        if(!initialized)
            ISOException.throwIt(Consts.E_UNINITIALIZED);

        byte[] apduBuffer = apdu.getBuffer();
        groupSize = apduBuffer[ISO7816.OFFSET_P1];
        random.generateData(ramArray, (short) 0, (short) 32);
        groupSecret.fromByteArray(ramArray, (short) 0, (short) 32);
        groupKey.setW(curve.G, (short) 0, curve.POINT_SIZE);
        groupKey.multiplication(groupSecret);
        groupKey.getW(ramArray, (short) 0);
        hasher.reset();
        hasher.doFinal(ramArray, (short) 0, curve.POINT_SIZE, apduBuffer, (short) 0);
        Util.arrayFillNonAtomic(commitments, (short) 0, (short) (curve.COORD_SIZE * Consts.MAX_PARTIES), (byte) 0x00);
        commitmentCounter = 0;
        revealCounter = 0;
        nonceCounter = 0;
        apdu.setOutgoingAndSend((short) 0, curve.COORD_SIZE);
    }

    private void keygenAddCommitment(APDU apdu) {
        if(!initialized)
            ISOException.throwIt(Consts.E_UNINITIALIZED);

        byte[] apduBuffer = apdu.getBuffer();
        short p1 = apduBuffer[ISO7816.OFFSET_P1];
        Util.arrayCopyNonAtomic(apduBuffer, ISO7816.OFFSET_CDATA, commitments, (short) (curve.COORD_SIZE * p1), curve.COORD_SIZE);
        ++commitmentCounter;
        apdu.setOutgoingAndSend((short) 0, (short) 0);
    }

    private void keygenReveal(APDU apdu) {
        if(!initialized)
            ISOException.throwIt(Consts.E_UNINITIALIZED);

        byte[] apduBuffer = apdu.getBuffer();
        if(commitmentCounter != groupSize) {
            ISOException.throwIt(Consts.E_COMMITMENT_NUMBER);
        }
        groupKey.getW(apduBuffer, (short) 0);
        apdu.setOutgoingAndSend((short) 0, curve.POINT_SIZE);
    }

    private void keygenAddKey(APDU apdu) {
        if(!initialized)
            ISOException.throwIt(Consts.E_UNINITIALIZED);

        byte[] apduBuffer = apdu.getBuffer();
        short p1 = apduBuffer[ISO7816.OFFSET_P1];
        hasher.reset();
        hasher.doFinal(apduBuffer, ISO7816.OFFSET_CDATA, curve.POINT_SIZE, ramArray, (short) 0);
        if(Util.arrayCompare(ramArray, (short) 0, commitments, (short) (curve.COORD_SIZE * p1), curve.COORD_SIZE) != 0) {
            ISOException.throwIt(Consts.E_COMMITMENT_CHECK_FAILED);
        }
        Util.arrayFillNonAtomic(commitments, (short) (curve.COORD_SIZE * p1), curve.COORD_SIZE, (byte) 0x00);
        tmpKey.setW(apduBuffer, ISO7816.OFFSET_CDATA, curve.POINT_SIZE);
        if(revealCounter == 0) {
            groupKey.copy(tmpKey);
        } else {
            groupKey.add(tmpKey);
        }
        ++revealCounter;
        apdu.setOutgoingAndSend((short) 0, (short) 0);
    }

    private void keygenFinalize(APDU apdu) {
        if(!initialized)
            ISOException.throwIt(Consts.E_UNINITIALIZED);

        byte[] apduBuffer = apdu.getBuffer();
        groupKey.getW(apduBuffer, (short) 0);
        if(revealCounter != groupSize) {
            ISOException.throwIt(Consts.E_KEY_NUMBER);
        }
        apdu.setOutgoingAndSend((short) 0, curve.POINT_SIZE);
    }

    private void getNonce(APDU apdu) {
        if(!initialized)
            ISOException.throwIt(Consts.E_UNINITIALIZED);

        byte[] apduBuffer = apdu.getBuffer();
        short counter = (short) (((short) apduBuffer[ISO7816.OFFSET_P1] & 0xff) | (((short) apduBuffer[ISO7816.OFFSET_P2] & 0xff) << 8));
        checkCounter(counter);
        if(counter < nonceCounter) {
            ISOException.throwIt(Consts.E_USED_NONCE);
        }
        nonceCounter = counter;
        prf(counter);
        tmpSecret.fromByteArray(ramArray, (short) 0, (short) (curve.KEY_BIT_LENGTH / 8));
        tmpKey.setW(curve.G, (short) 0, curve.POINT_SIZE);
        tmpKey.multiplication(tmpSecret);
        tmpKey.getW(apduBuffer, (short) 0);
        apdu.setOutgoingAndSend((short) 0, curve.POINT_SIZE);
    }

    private void cacheNonce(APDU apdu) {
        if(!initialized)
            ISOException.throwIt(Consts.E_UNINITIALIZED);

        byte[] apduBuffer = apdu.getBuffer();
        short counter = (short) (((short) apduBuffer[ISO7816.OFFSET_P1] & 0xff) | (((short) apduBuffer[ISO7816.OFFSET_P2] & 0xff) << 8));
        checkCounter(counter);
        prf(counter);
        tmpSecret.fromByteArray(ramArray, (short) 0, (short) (curve.KEY_BIT_LENGTH / 8));
        tmpKey.setW(curve.G, (short) 0, curve.POINT_SIZE);
        tmpKey.multiplication(tmpSecret);
        tmpKey.getW(apduBuffer, (short) 0);
        kdf(ramArray, (short) 0);
        for(short i = 0; i < curve.POINT_SIZE; ++i) {
            apduBuffer[(short) (i + 1)] ^= ramArray[i];
        }
        apdu.setOutgoingAndSend((short) 1, (short) (curve.POINT_SIZE - 1));
    }

    private void revealNonce(APDU apdu) {
        if(!initialized)
            ISOException.throwIt(Consts.E_UNINITIALIZED);

        byte[] apduBuffer = apdu.getBuffer();
        short counter = (short) (((short) apduBuffer[ISO7816.OFFSET_P1] & 0xff) | (((short) apduBuffer[ISO7816.OFFSET_P2] & 0xff) << 8));
        checkCounter(counter);
        if(counter < nonceCounter) {
            ISOException.throwIt(Consts.E_USED_NONCE);
        }
        nonceCounter = counter;
        prf(counter);
        kdf(ramArray, (short) 0);
        Util.arrayCopyNonAtomic(ramArray, (short) 0, apduBuffer, (short) 0, (short) 64);
        apdu.setOutgoingAndSend((short) 0, (short) 64);
    }

    private void sign(APDU apdu, boolean reveal, boolean bip) {
        if(!initialized)
            ISOException.throwIt(Consts.E_UNINITIALIZED);

        byte[] apduBuffer = apdu.getBuffer();
        short counter = (short) (((short) apduBuffer[ISO7816.OFFSET_P1] & 0xff) | (((short) apduBuffer[ISO7816.OFFSET_P2] & 0xff) << 8));
        checkCounter(counter);
        if(counter < nonceCounter) {
            ISOException.throwIt(Consts.E_USED_NONCE);
        }
        nonceCounter = (short) (counter + 1);
        if(bip) {
            signBIP(counter, apduBuffer, ISO7816.OFFSET_CDATA, apduBuffer, (short) (ISO7816.OFFSET_CDATA + curve.POINT_SIZE));
        } else {
            signSchnorr(counter, apduBuffer, ISO7816.OFFSET_CDATA, apduBuffer, (short) (ISO7816.OFFSET_CDATA + curve.POINT_SIZE));
        }
        signature.copyToByteArray(apduBuffer, (short) 0);

        if(reveal) {
            prf(nonceCounter);
            kdf(ramArray, (short) 0);
            Util.arrayCopyNonAtomic(ramArray, (short) 0, apduBuffer, (short) (curve.KEY_BIT_LENGTH / 8), (short) 64);
            apdu.setOutgoingAndSend((short) 0, (short) (curve.KEY_BIT_LENGTH / 8 + 64));
        } else {
            apdu.setOutgoingAndSend((short) 0, (short) (curve.KEY_BIT_LENGTH / 8));
        }
    }

    private void prf(short counter) {
        hasher.reset();
        identitySecret.copyToByteArray(ramArray, (short) 0);
        hasher.update(ramArray, (short) 0, (short) (curve.KEY_BIT_LENGTH / 8));
        ramArray[0] = (byte) (counter & 0xff);
        ramArray[1] = (byte) ((counter >> 8) & 0xff);
        hasher.doFinal(ramArray, (short) 0, (short) 2, ramArray, (short) 0);
    }

    private void kdf(byte[] secret, short offset) {
        hasher.reset();
        hasher.doFinal(secret, offset, (short) 32, ramArray, (short) 0);
        hasher.reset();
        hasher.doFinal(ramArray, (short) 0, (short) 32, ramArray, (short) 32);
    }

    private void signSchnorr(short counter, byte[] nonceBuffer, short nonceOffset, byte[] messageBuffer, short messageOffset) {
        hasher.reset();
        hasher.update(nonceBuffer, nonceOffset, curve.POINT_SIZE);
        groupKey.getW(ramArray, (short) 0);
        hasher.update(ramArray, (short) 0, curve.POINT_SIZE);
        hasher.doFinal(messageBuffer, messageOffset, (short) 32, ramArray, (short) 0);
        signature.fromByteArray(ramArray, (short) 0, hasher.getLength());
        signature.modMult(groupSecret, curve.rBN);
        prf(counter);
        tmpSecret.fromByteArray(ramArray, (short) 0, hasher.getLength());
        signature.modAdd(tmpSecret, curve.rBN);
    }

    private void signBIP(short counter, byte[] nonceBuffer, short nonceOffset, byte[] messageBuffer, short messageOffset) {
        hasher.reset();
        hasher.update(Consts.TAG_CHALLENGE, (short) 0, (short) Consts.TAG_CHALLENGE.length);
        hasher.update(Consts.TAG_CHALLENGE, (short) 0, (short) Consts.TAG_CHALLENGE.length);
        hasher.update(nonceBuffer, (short) (nonceOffset + 1), curve.COORD_SIZE);
        groupKey.getW(ramArray, (short) 0);
        hasher.update(ramArray, (short) 1, curve.COORD_SIZE);
        hasher.doFinal(messageBuffer, messageOffset, (short) 32, ramArray, (short) 0);
        signature.fromByteArray(ramArray, (short) 0, hasher.getLength());
        signature.modMult(groupSecret, curve.rBN);
        if (!groupKey.isYEven()) {
            signature.modNegate(curve.rBN);
        }
        prf(counter);
        tmpSecret.fromByteArray(ramArray, (short) 0, hasher.getLength());
        if ((nonceBuffer[(short) (nonceOffset + curve.POINT_SIZE - 1)] & (byte) 0x01) == 0) {
            signature.modAdd(tmpSecret, curve.rBN);
        } else {
            signature.modSub(tmpSecret, curve.rBN);
        }
    }

    private void debugKeygen(APDU apdu) {
        if(!initialized)
            ISOException.throwIt(Consts.E_UNINITIALIZED);
        if (!debug)
            ISOException.throwIt(Consts.E_DEBUG_DISABLED);

        byte[] apduBuffer = apdu.getBuffer();
        groupSize = apduBuffer[ISO7816.OFFSET_P1];
        revealCounter = commitmentCounter = (byte) groupSize;
        nonceCounter = 0;
        random.generateData(ramArray, (short) 0, (short) 32);
        groupSecret.fromByteArray(ramArray, (short) 0, (short) 32);
        groupKey.setW(curve.G, (short) 0, curve.POINT_SIZE);
        groupKey.multiplication(groupSecret);
        groupKey.getW(apduBuffer, (short) 0);
        apdu.setOutgoingAndSend((short) 0, curve.POINT_SIZE);
    }

    private void debugPrivate(APDU apdu) {
        if(!initialized)
            ISOException.throwIt(Consts.E_UNINITIALIZED);
        if (!debug)
            ISOException.throwIt(Consts.E_DEBUG_DISABLED);

        byte[] apduBuffer = apdu.getBuffer();
        groupSecret.fromByteArray(ramArray, (short) 0, (short) 32);
        groupSecret.copyToByteArray(apduBuffer, (short) 0);
        apdu.setOutgoingAndSend((short) 0, groupSecret.length());
    }

    private void debugGroupKey(APDU apdu) {
        if(!initialized)
            ISOException.throwIt(Consts.E_UNINITIALIZED);
        if (!debug)
            ISOException.throwIt(Consts.E_DEBUG_DISABLED);

        groupKey.getW(apdu.getBuffer(), (short) 0);
        apdu.setOutgoingAndSend((short) 0, curve.POINT_SIZE);
    }

    private void debugSetGroupKey(APDU apdu) {
        if(!initialized)
            ISOException.throwIt(Consts.E_UNINITIALIZED);
        if (!debug)
            ISOException.throwIt(Consts.E_DEBUG_DISABLED);

        groupKey.setW(apdu.getBuffer(), ISO7816.OFFSET_CDATA, curve.POINT_SIZE);
        apdu.setOutgoing();
    }

    private void checkCounter(short counter) {
        if(counter < 0) {
            ISOException.throwIt(Consts.E_INVALID_COUNTER);
        }
        if(counter >= 32766) {
            ISOException.throwIt(Consts.E_DEPLETED_COUNTER);
        }
    }
}

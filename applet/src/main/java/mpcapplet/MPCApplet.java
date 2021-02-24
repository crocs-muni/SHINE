package mpcapplet;

import javacard.framework.*;
import javacard.security.CryptoException;
import javacard.security.MessageDigest;
import javacard.security.RandomData;
import mpcapplet.jcmathlib.*;

public class MPCApplet extends Applet implements MultiSelectable
{
    private byte[] ramArray = JCSystem.makeTransientByteArray((short) 65, JCSystem.CLEAR_ON_DESELECT);
    private RandomData random;
    private MessageDigest hasher;

    private ECConfig ecc;
    private ECCurve curve;
    private Bignat curveOrder;

    private Bignat identitySecret;
    private ECPoint identityKey;


    public static void install(byte[] bArray, short bOffset, byte bLength)
    {
        new MPCApplet(bArray, bOffset, bLength);
    }

    public MPCApplet(byte[] buffer, short offset, byte length)
    {
        random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        hasher = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);

        ecc = new ECConfig((short) 256);
        ecc.bnh.bIsSimulator = true;

        curve = new ECCurve(true, SecP256r1.p, SecP256r1.a, SecP256r1.b, SecP256r1.G, SecP256r1.r);
        curveOrder = new Bignat(SecP256r1.COORD_SIZE, JCSystem.MEMORY_TYPE_PERSISTENT, ecc.bnh);
        curveOrder.from_byte_array(SecP256r1.r);

        identitySecret = new Bignat(SecP256r1.COORD_SIZE, JCSystem.MEMORY_TYPE_PERSISTENT, ecc.bnh);
        identityKey = new ECPoint(curve, ecc.ech);

        // generate identity
        random.generateData(ramArray, (short) 0, (short) 32);
        identitySecret.set_from_byte_array((short) 0, ramArray, (short) 0, (short) 32);
        identityKey.setW(SecP256r1.G, (short) 0, SecP256r1.POINT_SIZE);
        identityKey.multiplication(identitySecret);

        register();
    }

    public void process(APDU apdu)
    {
        if (selectingApplet()) // ignore selection command
            return;

        byte[] apduBuffer = apdu.getBuffer();
        try {
            if (apduBuffer[ISO7816.OFFSET_CLA] == Consts.CLA_MPCAPPLET) {
                switch(apduBuffer[ISO7816.OFFSET_INS]) {
                    case Consts.INS_GET_INFO:
                        getInfo(apdu);
                        break;
                    case Consts.INS_GET_IDENTITY:
                        getIdentity(apdu);
                        break;

                    case Consts.INS_DEBUG_IDENTITY:
                        debugIdentity(apdu);
                        break;

                    default:
                        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                }
            } else {
                ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
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

    public boolean select(boolean b) {
        ecc.refreshAfterReset();
        return true;
    }

    public void deselect(boolean b) {}

    private void getInfo(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        byte[] msg = {0x4d, 0x50, 0x43, 0x41, 0x70, 0x70, 0x6c, 0x65, 0x74, 0x20, 0x30, 0x2e, 0x31, 0x2e, 0x30}; // MPCApplet 0.1.0
        Util.arrayCopyNonAtomic(msg, (short) 0, apduBuffer, (short) 0, (short) msg.length);
        apdu.setOutgoingAndSend((short) 0, (short) msg.length);
    }

    private void getIdentity(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        identityKey.getW(apduBuffer, (short) 0);
        apdu.setOutgoingAndSend((short) 0, SecP256r1.POINT_SIZE);
    }

    private void debugIdentity(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        Util.arrayCopyNonAtomic(identitySecret.as_byte_array(), (short) 0, apduBuffer, (short) 0, (short) (SecP256r1.KEY_LENGTH / 8));
        apdu.setOutgoingAndSend((short) 0, (short) (SecP256r1.KEY_LENGTH / 8));
    }
}
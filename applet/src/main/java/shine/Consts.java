package shine;

public class Consts {
    public static final byte MAX_PARTIES = 4;

    public static final byte CLA_MPCAPPLET = (byte) 0xC0;
    public static final byte INS_GET_INFO = (byte) 0xF0;
    public static final byte INS_GET_IDENTITY = (byte) 0xF1;

    public static final byte CLA_SHINE = (byte) 0xC1;
    public static final byte INS_KEYGEN_INITIALIZE = (byte) 0xC0;
    public static final byte INS_KEYGEN_ADD_COMMITMENT = (byte) 0xC1;
    public static final byte INS_KEYGEN_REVEAL = (byte) 0xC2;
    public static final byte INS_KEYGEN_ADD_KEY = (byte) 0xC3;
    public static final byte INS_KEYGEN_FINALIZE = (byte) 0xC4;
    public static final byte INS_GET_NONCE = (byte) 0xC5;
    public static final byte INS_CACHE_NONCE = (byte) 0xC7;
    public static final byte INS_REVEAL_NONCE = (byte) 0xC8;
    public static final byte INS_SIGN = (byte) 0xC6;
    public static final byte INS_SIGN_REVEAL = (byte) 0xC9;

    static final short E_COMMITMENT_CHECK_FAILED = (short) 0xc100;
    static final short E_USED_NONCE = (short) 0xc101;
    static final short E_COMMITMENT_NUMBER = (short) 0xc102;
    static final short E_KEY_NUMBER = (short) 0xc103;

    final static short SW_Exception = (short) 0xff01;
    final static short SW_ArrayIndexOutOfBoundsException = (short) 0xff02;
    final static short SW_ArithmeticException = (short) 0xff03;
    final static short SW_ArrayStoreException = (short) 0xff04;
    final static short SW_NullPointerException = (short) 0xff05;
    final static short SW_NegativeArraySizeException = (short) 0xff06;
    final static short SW_CryptoException_prefix = (short) 0xf100;
    final static short SW_SystemException_prefix = (short) 0xf200;
    final static short SW_PINException_prefix = (short) 0xf300;
    final static short SW_TransactionException_prefix = (short) 0xf400;
    final static short SW_CardRuntimeException_prefix = (short) 0xf500;
}
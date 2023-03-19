package shine;

public class Consts {
    public static final byte MAX_PARTIES = 4;

    public static final byte CLA_SHINE = (byte) 0x00;
    public static final byte INS_INFO = (byte) 0xf0;
    public static final byte INS_IDENTITY = (byte) 0xf1;
    public static final byte INS_INITIALIZE = (byte) 0xf2;

    public static final byte INS_DEBUG_KEYGEN = (byte) 0xd0;
    public static final byte INS_DEBUG_PRIVATE = (byte) 0xd1;
    public static final byte INS_DEBUG_GROUPKEY = (byte) 0xd2;
    public static final byte INS_DEBUG_SET_GROUPKEY = (byte) 0xd3;

    public static final byte INS_KEYGEN_INITIALIZE = (byte) 0x01;
    public static final byte INS_KEYGEN_ADD_COMMITMENT = (byte) 0x02;
    public static final byte INS_KEYGEN_REVEAL = (byte) 0x03;
    public static final byte INS_KEYGEN_ADD_KEY = (byte) 0x04;
    public static final byte INS_KEYGEN_FINALIZE = (byte) 0x05;
    public static final byte INS_GET_NONCE = (byte) 0x06;
    public static final byte INS_CACHE_NONCE = (byte) 0x07;
    public static final byte INS_REVEAL_NONCE = (byte) 0x08;
    public static final byte INS_SIGN = (byte) 0x09;
    public static final byte INS_SIGN_REVEAL = (byte) 0x0a;
    public static final byte INS_SIGN_BIP = (byte) 0x0b;
    public static final byte INS_SIGN_BIP_REVEAL = (byte) 0x0c;

    public static final byte[] TAG_CHALLENGE = {(byte) 0x7b, (byte) 0xb5, (byte) 0x2d, (byte) 0x7a, (byte) 0x9f, (byte) 0xef, (byte) 0x58, (byte) 0x32, (byte) 0x3e, (byte) 0xb1, (byte) 0xbf, (byte) 0x7a, (byte) 0x40, (byte) 0x7d, (byte) 0xb3, (byte) 0x82, (byte) 0xd2, (byte) 0xf3, (byte) 0xf2, (byte) 0xd8, (byte) 0x1b, (byte) 0xb1, (byte) 0x22, (byte) 0x4f, (byte) 0x49, (byte) 0xfe, (byte) 0x51, (byte) 0x8f, (byte) 0x6d, (byte) 0x48, (byte) 0xd3, (byte) 0x7c};

    static final short E_COMMITMENT_CHECK_FAILED = (short) 0xc100;
    static final short E_USED_NONCE = (short) 0xc101;
    static final short E_COMMITMENT_NUMBER = (short) 0xc102;
    static final short E_KEY_NUMBER = (short) 0xc103;
    static final short E_DEBUG_DISABLED = (short) 0xc104;
    static final short E_ALREADY_INITIALIZED = (short) 0xc105;
    static final short E_UNINITIALIZED = (short) 0xc106;
    static final short E_INVALID_COUNTER = (short) 0xc107;
    static final short E_DEPLETED_COUNTER = (short) 0xc108;

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

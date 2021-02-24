package mpcapplet;

public class Consts {
    public static final byte CLA_MPCAPPLET = (byte) 0xC0;

    public static final byte INS_GET_INFO = (byte) 0xF0;
    public static final byte INS_GET_IDENTITY = (byte) 0xF1;

    public static final byte INS_DEBUG_IDENTITY = (byte) 0xD1;

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

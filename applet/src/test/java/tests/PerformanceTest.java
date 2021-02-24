package tests;

import cardTools.RunConfig;

import java.io.FileWriter;
import java.io.PrintWriter;

public class PerformanceTest extends BaseTest {

    ProtocolManager pm;
    PrintWriter file;

    long REPEAT = 1;

    public static void main(String[] args) throws Exception {
        new PerformanceTest().run();
    }

    public void run() throws Exception {
        setCardType(RunConfig.CARD_TYPE.JCARDSIMLOCAL);
        pm = connect();
        file = new PrintWriter(new FileWriter("measurement.csv", true));

        for(int i = 0; i < REPEAT; ++i) {
            measureIdentitySecret();
            measureIdentityKey();
        }

        file.close();
        pm.disconnect(true);
    }

    public void measureIdentitySecret() throws Exception {
        pm.debugIdentity();
        file.printf("IdentitySecret;%d\n", pm.getLastOperationTime());
    }

    public void measureIdentityKey() throws Exception {
        pm.getIdentity();
        file.printf("IdentityKey;%d\n", pm.getLastOperationTime());
    }
}

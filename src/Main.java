import java.util.Arrays;
public class Main {

    public static void main(String[] args) {
        byte[] key = {0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
            0x00, (byte) 0xFF, (byte) 0xEE,
            (byte) 0xDD, (byte) 0xCC, (byte) 0xBB, (byte) 0xAA, (byte) 0x99,
            (byte) 0x88,
            (byte) 0xEF, (byte) 0xCD, (byte) 0xAB, (byte) 0x89, 0x67, 0x45, 0x23,
            0x01,
            0x10, 0x32, 0x54, 0x76, (byte) 0x98, (byte) 0xBA, (byte) 0xDC, (byte)
            0xFE};
        byte[] data = {(byte) 0xEF, (byte) 0xCD, (byte) 0xAD,
            (byte) 0xCC, 0x67, 0x45, 0x23, 0x01,
            0x10, 0x32, 0x54, 0x76, (byte) 0x98, (byte) 0xBF, (byte) 0xDC, (byte)
            0xFE};
        System.out.println(Arrays.toString(data));
        ChipperGost34_12_2015 kuznechik = ChipperGost34_12_2015.getInstance(key, data);
        byte[] encrypted = kuznechik.encryptCTR(data);
        System.out.println(Arrays.toString(encrypted));
        byte[] decrypted = kuznechik.decryptCTR(encrypted);
        System.out.println(Arrays.toString(decrypted));
    }
}
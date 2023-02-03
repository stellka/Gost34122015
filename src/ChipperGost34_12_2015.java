import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HashSet;
import java.util.Set;

public class ChipperGost34_12_2015 {
    private byte[] key;
    private byte[] iVector;
    private byte[][] roundConsts = new byte[32][16];
    private byte[][] roundKeys = new byte[10][16];
    private int stopCTR;
    private Set<byte[]> T;
    private static ChipperGost34_12_2015 instance;

    public static ChipperGost34_12_2015 getInstance(byte[] key, byte[] iVector) {
        if (instance == null)
            instance = new ChipperGost34_12_2015(key, iVector);
        return instance;
    }

    private ChipperGost34_12_2015(byte[] key, byte[] iVector) {
        if (key.length != 32 || iVector.length != 16)
            throw new IllegalArgumentException("Wrong size of key or iVector");
        this.key = key;
        this.iVector = iVector;
        byte[] leftPart = new byte[16];
        byte[] rightPart = new byte[16];
        System.arraycopy(this.key, 0, leftPart, 0, 16);
        System.arraycopy(this.key, 16, rightPart, 0, 16);
        initRoundKeys(leftPart, rightPart);
    }

    //длина блока данных
    private final int BLOCK_SIZE_BYTES = 16;
    //таблица для нелинейного биективного преобразования
    private final byte[] Pi = {
            (byte) 0xFC, (byte) 0xEE, (byte) 0xDD, 0x11, (byte) 0xCF, 0x6E, 0x31, 0x16,
            (byte) 0xFB, (byte) 0xC4, (byte) 0xFA, (byte) 0xDA, 0x23, (byte) 0xC5,
            0x04, 0x4D,
            (byte) 0xE9, 0x77, (byte) 0xF0, (byte) 0xDB, (byte) 0x93, 0x2E, (byte)
            0x99, (byte) 0xBA,
            0x17, 0x36, (byte) 0xF1, (byte) 0xBB, 0x14, (byte) 0xCD, 0x5F, (byte) 0xC1,
            (byte) 0xF9, 0x18, 0x65, 0x5A, (byte) 0xE2, 0x5C, (byte) 0xEF, 0x21,
            (byte) 0x81, 0x1C, 0x3C, 0x42, (byte) 0x8B, 0x01, (byte) 0x8E, 0x4F,
            0x05, (byte) 0x84, 0x02, (byte) 0xAE, (byte) 0xE3, 0x6A, (byte) 0x8F,
            (byte) 0xA0,
            0x06, 0x0B, (byte) 0xED, (byte) 0x98, 0x7F, (byte) 0xD4, (byte) 0xD3, 0x1F,
            (byte) 0xEB, 0x34, 0x2C, 0x51, (byte) 0xEA, (byte) 0xC8, 0x48, (byte) 0xAB,
            (byte) 0xF2, 0x2A, 0x68, (byte) 0xA2, (byte) 0xFD, 0x3A, (byte) 0xCE,
            (byte) 0xCC,
            (byte) 0xB5, 0x70, 0x0E, 0x56, 0x08, 0x0C, 0x76, 0x12,
            (byte) 0xBF, 0x72, 0x13, 0x47, (byte) 0x9C, (byte) 0xB7, 0x5D, (byte) 0x87,
            0x15, (byte) 0xA1, (byte) 0x96, 0x29, 0x10, 0x7B, (byte) 0x9A, (byte) 0xC7,
            (byte) 0xF3, (byte) 0x91, 0x78, 0x6F, (byte) 0x9D, (byte) 0x9E, (byte)
            0xB2, (byte) 0xB1,
            0x32, 0x75, 0x19, 0x3D, (byte) 0xFF, 0x35, (byte) 0x8A, 0x7E,
            0x6D, 0x54, (byte) 0xC6, (byte) 0x80, (byte) 0xC3, (byte) 0xBD, 0x0D, 0x57,
            (byte) 0xDF, (byte) 0xF5, 0x24, (byte) 0xA9, 0x3E, (byte) 0xA8, (byte)
            0x43, (byte) 0xC9,
            (byte) 0xD7, 0x79, (byte) 0xD6, (byte) 0xF6, 0x7C, 0x22, (byte) 0xB9, 0x03,
            (byte) 0xE0, 0x0F, (byte) 0xEC, (byte) 0xDE, 0x7A, (byte) 0x94, (byte)
            0xB0, (byte) 0xBC,
            (byte) 0xDC, (byte) 0xE8, 0x28, 0x50, 0x4E, 0x33, 0x0A, 0x4A,
            (byte) 0xA7, (byte) 0x97, 0x60, 0x73, 0x1E, 0x00, 0x62, 0x44,
            0x1A, (byte) 0xB8, 0x38, (byte) 0x82, 0x64, (byte) 0x9F, 0x26, 0x41,
            (byte) 0xAD, 0x45, 0x46, (byte) 0x92, 0x27, 0x5E, 0x55, 0x2F,
            (byte) 0x8C, (byte) 0xA3, (byte) 0xA5, 0x7D, 0x69, (byte) 0xD5, (byte)
            0x95, 0x3B,
            0x07, 0x58, (byte) 0xB3, 0x40, (byte) 0x86, (byte) 0xAC, 0x1D, (byte) 0xF7,
            0x30, 0x37, 0x6B, (byte) 0xE4, (byte) 0x88, (byte) 0xD9, (byte) 0xE7,
            (byte) 0x89,
            (byte) 0xE1, 0x1B, (byte) 0x83, 0x49, 0x4C, 0x3F, (byte) 0xF8, (byte) 0xFE,
            (byte) 0x8D, 0x53, (byte) 0xAA, (byte) 0x90, (byte) 0xCA, (byte) 0xD8,
            (byte) 0x85, 0x61,
            0x20, 0x71, 0x67, (byte) 0xA4, 0x2D, 0x2B, 0x09, 0x5B,
            (byte) 0xCB, (byte) 0x9B, 0x25, (byte) 0xD0, (byte) 0xBE, (byte) 0xE5,
            0x6C, 0x52,
            0x59, (byte) 0xA6, 0x74, (byte) 0xD2, (byte) 0xE6, (byte) 0xF4, (byte)
            0xB4, (byte) 0xC0,
            (byte) 0xD1, 0x66, (byte) 0xAF, (byte) 0xC2, 0x39, 0x4B, 0x63, (byte) 0xB6
    };

    //таблица для нелинейного биективного преобразования для расшифрования
    private final byte[] rPi = {
            (byte) 0xA5, 0x2D, 0x32, (byte) 0x8F, 0x0E, 0x30, 0x38, (byte) 0xC0,
            0x54, (byte) 0xE6, (byte) 0x9E, 0x39, 0x55, 0x7E, 0x52, (byte) 0x91,
            0x64, 0x03, 0x57, 0x5A, 0x1C, 0x60, 0x07, 0x18,
            0x21, 0x72, (byte) 0xA8, (byte) 0xD1, 0x29, (byte) 0xC6, (byte) 0xA4, 0x3F,
            (byte) 0xE0, 0x27, (byte) 0x8D, 0x0C, (byte) 0x82, (byte) 0xEA, (byte)
            0xAE, (byte) 0xB4,
            (byte) 0x9A, 0x63, 0x49, (byte) 0xE5, 0x42, (byte) 0xE4, 0x15, (byte) 0xB7,
            (byte) 0xC8, 0x06, 0x70, (byte) 0x9D, 0x41, 0x75, 0x19, (byte) 0xC9,
            (byte) 0xAA, (byte) 0xFC, 0x4D, (byte) 0xBF, 0x2A, 0x73, (byte) 0x84,
            (byte) 0xD5,
            (byte) 0xC3, (byte) 0xAF, 0x2B, (byte) 0x86, (byte) 0xA7, (byte) 0xB1,
            (byte) 0xB2, 0x5B,
            0x46, (byte) 0xD3, (byte) 0x9F, (byte) 0xFD, (byte) 0xD4, 0x0F, (byte)
            0x9C, 0x2F,
            (byte) 0x9B, 0x43, (byte) 0xEF, (byte) 0xD9, 0x79, (byte) 0xB6, 0x53, 0x7F,
            (byte) 0xC1, (byte) 0xF0, 0x23, (byte) 0xE7, 0x25, 0x5E, (byte) 0xB5, 0x1E,
            (byte) 0xA2, (byte) 0xDF, (byte) 0xA6, (byte) 0xFE, (byte) 0xAC, 0x22,
            (byte) 0xF9, (byte) 0xE2,
            0x4A, (byte) 0xBC, 0x35, (byte) 0xCA, (byte) 0xEE, 0x78, 0x05, 0x6B,
            0x51, (byte) 0xE1, 0x59, (byte) 0xA3, (byte) 0xF2, 0x71, 0x56, 0x11,
            0x6A, (byte) 0x89, (byte) 0x94, 0x65, (byte) 0x8C, (byte) 0xBB, 0x77, 0x3C,
            0x7B, 0x28, (byte) 0xAB, (byte) 0xD2, 0x31, (byte) 0xDE, (byte) 0xC4, 0x5F,
            (byte) 0xCC, (byte) 0xCF, 0x76, 0x2C, (byte) 0xB8, (byte) 0xD8, 0x2E, 0x36,
            (byte) 0xDB, 0x69, (byte) 0xB3, 0x14, (byte) 0x95, (byte) 0xBE, 0x62,
            (byte) 0xA1,
            0x3B, 0x16, 0x66, (byte) 0xE9, 0x5C, 0x6C, 0x6D, (byte) 0xAD,
            0x37, 0x61, 0x4B, (byte) 0xB9, (byte) 0xE3, (byte) 0xBA, (byte) 0xF1,
            (byte) 0xA0,
            (byte) 0x85, (byte) 0x83, (byte) 0xDA, 0x47, (byte) 0xC5, (byte) 0xB0,
            0x33, (byte) 0xFA,
            (byte) 0x96, 0x6F, 0x6E, (byte) 0xC2, (byte) 0xF6, 0x50, (byte) 0xFF, 0x5D,
            (byte) 0xA9, (byte) 0x8E, 0x17, 0x1B, (byte) 0x97, 0x7D, (byte) 0xEC, 0x58,
            (byte) 0xF7, 0x1F, (byte) 0xFB, 0x7C, 0x09, 0x0D, 0x7A, 0x67,
            0x45, (byte) 0x87, (byte) 0xDC, (byte) 0xE8, 0x4F, 0x1D, 0x4E, 0x04,
            (byte) 0xEB, (byte) 0xF8, (byte) 0xF3, 0x3E, 0x3D, (byte) 0xBD, (byte)
            0x8A, (byte) 0x88,
            (byte) 0xDD, (byte) 0xCD, 0x0B, 0x13, (byte) 0x98, 0x02, (byte) 0x93,
            (byte) 0x80,
            (byte) 0x90, (byte) 0xD0, 0x24, 0x34, (byte) 0xCB, (byte) 0xED, (byte)
            0xF4, (byte) 0xCE,
            (byte) 0x99, 0x10, 0x44, 0x40, (byte) 0x92, 0x3A, 0x01, 0x26,
            0x12, 0x1A, 0x48, 0x68, (byte) 0xF5, (byte) 0x81, (byte) 0x8B, (byte) 0xC7,
            (byte) 0xD6, 0x20, 0x0A, 0x08, 0x00, 0x4C, (byte) 0xD7, 0x74
    };

    //линейное преобразование в поле Галуа
    private final byte[] lVector = {
            1, (byte) 148, 32, (byte) 133, 16, (byte) 194, (byte) 192, 1,
            (byte) 251, 1, (byte) 192, (byte) 194, 16, (byte) 133, 32, (byte) 148
    };

    //Наложение раундового ключа 〖𝑘∈𝑉〗_128  на блок данных
    private byte[] XOR(byte[] left, byte[] right) {
        byte[] result = new byte[BLOCK_SIZE_BYTES];
        for (int i = 0; i < result.length; i++)
            result[i] = (byte) (left[i] ^ right[i]);
        return result;
    }

    //Замена байтов в блоке данных
    private byte[] S(byte[] input) {
        byte[] output = new byte[input.length];
        for (int i = 0; i < BLOCK_SIZE_BYTES; i++) {
            int data = input[i];
            if (data < 0)
                data += 256;
            output[i] = Pi[data];
        }
        return output;
    }
//Перемешивание блока данных
    private byte multiplicationGF(byte left, byte right) {
        byte result = 0;
        byte hBit;
        for (int i = 0; i < 8; i++) {
            if ((right & 1) == 1)
                result ^= left;
            hBit = (byte) (left & 0x80);
            left <<= 1;
            if (hBit < 0)
                left ^= 0xC3;
            right >>= 1;
        }
        return result;
    }
//𝑅(𝑎)=𝑅(𝑎_15 ||…||𝑎_0 )=𝑙(𝑎_15 ||𝑎_14 ||…||𝑎_0 ) 〖||𝑎〗_15 ||…||𝑎_1
    private byte[] R(byte[] input) {
        byte a15 = 0;
        byte[] output = new byte[16];
        for (int i = 15; i >= 0; i--) {
            if (i == 0)
                output[15] = input[i];
            else
                output[i - 1] = input[i];
            a15 ^= multiplicationGF(input[i], lVector[i]);
        }
        output[15] = a15;
        return output;
    }

    //𝐿(𝑎)=𝑅^16 (𝑎)
    private byte[] L(byte[] input) {
        byte[] output = input;
        for (int i = 0; i < 16; i++)
            output = R(output);
        return output;
    }

    //𝑆^(−1) для расшифрования
    private byte[] rS(byte[] input) {
        byte[] output = new byte[input.length];
        for (int i = 0; i < BLOCK_SIZE_BYTES; i++) {
            int data = input[i];
            if (data < 0)
                data += 256;
            output[i] = rPi[data];
        }
        return output;
    }

    //R^(−1) для расшифрования
    private byte[] rR(byte[] input) {
        byte a0 = input[15];
        byte[] output = new byte[16];
        for (int i = 1; i < 16; i++) {
            output[i] = input[i - 1];
            a0 ^= multiplicationGF(output[i], lVector[i]);
        }
        output[0] = a0;
        return output;
    }

    //L^(−1) для расшифрования
    private byte[] rL(byte[] input) {
        byte[] output = input;
        for (int i = 0; i < 16; i++)
            output = rR(output);
        return output;
    }

    //Вычисление раундовых констант
    private void initRoundConsts() {
        byte[][] roundNum = new byte[32][16];
        for (int i = 0; i < 32; i++) {
//            for (int j = 0; j < BLOCK_SIZE_BYTES; j++)
//                roundNum[i][j] = 0;
            roundNum[i][0] = (byte) (i + 1);
        }
        for (int i = 0; i < 32; i++)
            roundConsts[i] = L(roundNum[i]);
    }

    //преобразование 8-разрядной строки в элемент поля Галуа.
    //𝛷𝛹		композиция отображений 𝛷 и 𝛹
    private byte[][] FeistelRound(byte[] inLeft, byte[] inRight, byte[] roundC) {
        byte[] temp;
        temp = XOR(inLeft, roundC);
        temp = S(temp);
        temp = L(temp);
        byte[] outLeft = XOR(temp, inRight);
        byte[][] result = new byte[2][];
        result[0] = outLeft;
        result[1] = inLeft;
        return result;
    }

    //Вычисление первых двух раундовых ключей как двух частей ключа шифрования
    private void initRoundKeys(byte[] left, byte[] right) {
        byte[][] curRound = new byte[2][];
        initRoundConsts();
        roundKeys[0] = left;
        roundKeys[1] = right;
        curRound[0] = left;
        curRound[1] = right;
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 8; j++)
                curRound = FeistelRound(curRound[0], curRound[1], roundConsts[j + 8 *
                        i]);
            roundKeys[2 * i + 2] = curRound[0];
            roundKeys[2 * i + 3] = curRound[1];
        }
    }

    //наложение ключей и шифрование одного блока данных
    byte[] encrypt(byte[] inputBlock) {
        byte[] outputBlock = inputBlock;
        for (int i = 0; i < 9; i++) {
            outputBlock = XOR(outputBlock, roundKeys[i]);
            outputBlock = S(outputBlock);
            outputBlock = L(outputBlock);
        }
        outputBlock = XOR(outputBlock, roundKeys[9]);
        return outputBlock;
    }
    //расшифрование одного блока данных
    byte[] decrypt(byte[] inputBlock) {
        byte[] outputBlock = inputBlock;
        outputBlock = XOR(outputBlock, roundKeys[9]);
        for (int i = 8; i >= 0; i--) {
            outputBlock = rL(outputBlock);
            outputBlock = rS(outputBlock);
            outputBlock = XOR(outputBlock, roundKeys[i]);
        }
        return outputBlock;
    }



    //потоковое шифрование
    public byte[] encryptCTR(byte[] input) {
        stopCTR = input.length;
        int size = blocksCeiling(input);
        byte[][] inputBlocks = splitData(input);
        initT(size);
        byte[][] O = generateO();
        byte[][] outputBlocks = new byte[size][16];
        for (int i = 0; i < size; i++)
            outputBlocks[i] = XOR(inputBlocks[i], O[i]);
        return concatData(outputBlocks);
    }

    //потоковое расшифрование
    public byte[] decryptCTR(byte[] input) {
        int size = blocksCeiling(input);
        byte[][] inputBlocks = splitData(input);
        byte[][] O = generateO();
        byte[][] outputBlocks = new byte[size][16];
        for (int i = 0; i < size; i++)
            outputBlocks[i] = XOR(inputBlocks[i], O[i]);
        byte[] temp = concatData(outputBlocks);
        byte[] output = new byte[stopCTR];
        System.arraycopy(temp, 0, output, 0, stopCTR);
        return output;
    }

    private byte[][] generateO() {
        byte[][] O = new byte[T.size()][16];
        int i = 0;
        for (byte[] t : T)
            O[i++] = encrypt(t);
        return O;
    }

    private void initT(int size) {
        T = new HashSet<>(size);
        try {
            while (T.size() != size) {
                byte[] randomBytes = new byte[16];
                SecureRandom.getInstance("SHA1PRNG").nextBytes(randomBytes);
                T.add(randomBytes);
            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    private byte[][] splitData(byte[] input) {
        int size = blocksCeiling(input);
        byte[][] output = new byte[size][16];
        for (int i = 0, j = 0, k = 0; k < input.length; k++, j++) {
            if (j == 16) {
                i++;
                j = 0;
            }
            output[i][j] = input[k];
        }
        return output;
    }

    //конкатенация строк 𝐴,𝐵∈𝑉^∗
    private byte[] concatData(byte[][] input) {
        byte[] output = new byte[input.length * BLOCK_SIZE_BYTES];
        for (int i = 0, j = 0, k = 0; k < output.length; k++, j++) {
            if (j == 16) {
                i++;
                j = 0;
            }
            output[k] = input[i][j];
        }
        return output;
    }

    private int blocksCeiling(byte[] input) {
        int result = input.length / BLOCK_SIZE_BYTES;
        if (input.length % BLOCK_SIZE_BYTES != 0)
            result++;
        return result;
    }
}
package edu.boudoux.des;


import org.junit.Test;

import java.util.*;
import java.util.function.Function;

import static edu.boudoux.des.DataEncryptionStandard._des;
import static java.lang.Integer.parseInt;

public class DataEncryptionStandardTests {

    static byte[][] generalPermutationCases = {
            {127, 127, 127, 127, 127, 127, 127, 127},
            {8, 7, 6, 5, 4, 3, 2, 1},
            {0, 1, 2, 3, 4, 5, 6, 7},
            {1, 1, 1, 1, 1, 1, 1, 1},
            {0, 0, 0, 0, 0, 0, 0, 0},
            {-128, -128, -128, -128, -128, -128, -128, -128},
            {2, 2, 2, 2, 2, 2, 2, 2},
            {-2, -1, 0, 1, -2, -1, 0, 1},
            {-127, -126, -125, -124, -123, -122, -121, -120}
    };

    static byte[][] expansionPermutationCases = {
            {127, 127, 127, 127},
            {8, 7, 6, 5},
            {4, 3, 2, 1},
            {0, 1, 2, 3},
            {4, 5, 6, 7},
            {1, 1, 1, 1},
            {0, 0, 0, 0},
            {-128, -128, -128, -128},
            {2, 2, 2, 2},
            {-2, -1, 0, 1},
            {-127, -126, -125, -124}
    };


    @Test
    public void fullTest() {
        testEncryptionDecryption("12345678", "Ÿ \u077A \u30A1 \u30A4");

        runTests(
                DataEncryptionStandardTests::applyKeyPermutationChoice1_Tests
                ,DataEncryptionStandardTests::applyKeyPermutationChoice2_Tests
                ,DataEncryptionStandardTests::initialPermutation_Tests
                ,DataEncryptionStandardTests::finalPermutation_Tests
                ,DataEncryptionStandardTests::expansionPermutation_Tests
                ,DataEncryptionStandardTests::pBoxPermutation_Tests
                ,DataEncryptionStandardTests::padding_Tests
                ,DataEncryptionStandardTests::createBlocks_Tests
                ,DataEncryptionStandardTests::splitKey_Tests
                ,DataEncryptionStandardTests::applyLeftRotation_Tests
                ,DataEncryptionStandardTests::joinKeyHalves_Tests
                ,DataEncryptionStandardTests::keyTransformation_Tests
                ,DataEncryptionStandardTests::xorWithKey_Tests
                ,DataEncryptionStandardTests::substitutionBoxPermutation_Tests
                ,DataEncryptionStandardTests::applyFunctionF_Tests
                ,DataEncryptionStandardTests::processRound_Tests
                ,DataEncryptionStandardTests::initialFinalPermutationReversion_Tests
                ,DataEncryptionStandardTests::keyTransformationAfterSixteenRotations_Test
                ,DataEncryptionStandardTests::validationTest // disabled
        );
    }

    /**
     * Permutates using string manipulation, rather than bit manipulation. This kind of manipulation is easier to implement
     * than using bit manipulation, but it is slower. By having this returning the correct information we can verify if
     * that other implementations match the result of this method.
     *
     * @param value
     * @param permutationArray
     * @return
     */
    private static byte[] testUtilsPermutation(byte[] value, byte[][] permutationArray) {
        char[] bitString = stringifyBits(value).toCharArray();
        char[] resultingChar = new char[permutationArray.length * permutationArray[0].length];

        int valuesBitLength = value.length * 8;
        int currentBit = 0;
        for(byte[] permutationToDo: permutationArray)
            for(int idx = 0; idx < permutationToDo.length; idx++, currentBit++)
                resultingChar[currentBit] = bitString[valuesBitLength - permutationToDo[idx]];

        String bits = new String(resultingChar);
        byte[] result = new byte[permutationArray.length];
        int bitsLength = permutationArray[0].length;
        for(int i = 0, row = 0; i < permutationArray.length * bitsLength; i += bitsLength, row++)
            result[row] = (byte) Integer.parseInt(bits.substring(i, i + bitsLength), 2);

        return result;
    }

    private static String stringifyBits(byte[] value) {
        String[] result = new String[value.length];

        for (int i = 0; i < value.length; i++) {
            result[i] = Integer.toBinaryString(value[i]);

            if(result[i].length() < 8)
                result[i] = String.format("%8s", result[i]).replaceAll(" ", "0");
            else if(result[i].length() > 8)
                result[i] = result[i].substring(result[i].length() - 8);
        }

        return String.join("", result);
    }

    public static void testPermutation(String methodName, byte[][] permutationCases, byte[][] permutationArray, Function<byte[], byte[]> function) {
        byte[] result;
        byte[] expectedResult;
        int failures = 0;
        for (int idx = 0; idx < permutationCases.length; idx++) {
            result = function.apply(permutationCases[idx]);
            expectedResult = testUtilsPermutation(permutationCases[idx], permutationArray);
            if(! Arrays.equals(result, expectedResult)) {
                failures++;
                System.out.printf("%s failed for case '%d' (%s) - result: %s, expected: %s%n", methodName, idx, Arrays.toString(permutationCases[idx]), Arrays.toString(result), Arrays.toString(expectedResult));
            }
        }

        if(failures == 0)
            System.out.printf("Tests passed for '%s'\n", methodName);
    }

    private static void testEncryptionDecryption(String keyPass, String plainText) {
        byte[] keyPassBytes = keyPass.getBytes();
        byte[] plainTextBytes = plainText.getBytes();

        byte[] encryptedBytes = _des(plainTextBytes, keyPassBytes, DataEncryptionStandard.Operation.ENCRYPT);
        byte[] decryptedBytes = _des(encryptedBytes, keyPassBytes, DataEncryptionStandard.Operation.DECRYPT);

        String plainTextDecrypted = new String(decryptedBytes);
        System.out.printf("\nPlain text: '%s', Encrypted value (B64): %s, Decrypted value: '%s'\n", new String(plainTextBytes),
                new String(Base64.getEncoder().encode(encryptedBytes)), plainTextDecrypted);

        System.out.printf("Encrypted value: '%s'\n", new String(encryptedBytes));

        if(! Arrays.equals(decryptedBytes, plainTextBytes))
            System.err.println("\n'testEncryptionDecryption' failed");
        else
            System.out.println("\nTests passed for 'testEncryptionDecryption'");
    }

    /**
     * The validation test was mentioned in the paper "TESTING IMPLEMENTATIONS OF DES" by Ronald L. Rivest, 1985. See it
     * in the file 'DES-Maintenance test-Rivest-1985.txt'.
     *
     * See also:
     *  https://descsrc.nist.gov/csrc/media/publications/fips/46/3/archive/1999-10-25/documents/fips46-3.pdf
     */
    private static void validationTest() {
        final byte[] FINAL_RESULT = new byte[] { (byte) parseInt("1B", 16), (byte) parseInt("1A", 16), (byte) parseInt("2D", 16),
                (byte) parseInt("DB", 16), (byte) parseInt("4C", 16), (byte) parseInt("64", 16),
                (byte) parseInt("24", 16), (byte) parseInt("38", 16) };

        byte[] result = new byte[] { (byte) parseInt("94", 16), (byte) parseInt("74", 16), (byte) parseInt("B8", 16),
                (byte) parseInt("E8", 16), (byte) parseInt("C7", 16), (byte) parseInt("3B", 16),
                (byte) parseInt("CA", 16), (byte) parseInt("7D", 16) };

        for(int i = 0; i < 16; i++) {
            if (i % 2 == 0)
                result = DataEncryptionStandard._des(result, result, DataEncryptionStandard.Operation.ENCRYPT, false);
            else
                result = DataEncryptionStandard._des(result, result, DataEncryptionStandard.Operation.DECRYPT, false);
        }

        if(! Arrays.equals(result, FINAL_RESULT)) {
            System.err.println("validationTest failed!");
        } else {
            System.out.println("Tests passed for 'validationTest'");
        }
    }

    private static String getHex(byte[] value) {
        StringBuilder result = new StringBuilder();

        for (byte b : value) {
            String hex = Integer.toHexString(b);

            if (hex.length() == 1) hex = "0" + hex;

            result.append(hex.length() > 2 ? hex.substring(hex.length() - 2) : hex);
        }

        return result.toString().toUpperCase();
    }

    private static void keyTransformationAfterSixteenRotations_Test() {
        byte[] key = DataEncryptionStandard.applyKeyPermutationChoice1("12345678".getBytes());
        byte[] transformedKey = key;
        for(int i = 1; i <= 16; i++) {
            transformedKey = DataEncryptionStandard.keyTransformation(i, transformedKey);
        }

        if(! Arrays.equals(transformedKey, key))
            System.err.println("keyTransformationAfterSixteenRotations_Test failed");
        else
            System.out.println("Tests passed for 'keyTransformationAfterSixteenRotations_Test'");
    }

    private static void initialFinalPermutationReversion_Tests() {
        boolean failed = false;
        for(byte[] block: generalPermutationCases) {
            byte[] revertedBlock = DataEncryptionStandard.finalPermutation(DataEncryptionStandard.initialPermutation(block));

            if(! Arrays.equals(revertedBlock, block)) {
                failed = true;
                System.err.printf("initialFinalPermutationReversion_Tests failed (result: %s, expected: %s)\n", Arrays.toString(revertedBlock), Arrays.toString(block));
            }
        }

        if(! failed)
            System.out.println("Tests passed for 'initialFinalPermutationReversion_Tests'");
    }

    private static void runTests(Runnable... methods) {
        for (Runnable testMethod: methods) {
            testMethod.run();
        }
    }

    public static void padding_Tests() {
        List<byte[]> casesList = new ArrayList<>();

        for(byte i = 0; i < 127; i++) {
            byte[] testCase = new byte[i + 1];
            for (int j = 0; j < i + 1; j++) {
                testCase[j] = 1;
            }

            casesList.add(testCase);
        }

        int failures = 0;
        for (byte[] caseItem : casesList) {
            int reminder = caseItem.length % 8;
            int paddingLength = reminder == 0 ? 8 : 8 - reminder;

            int totalLength = caseItem.length + paddingLength;
            byte[] value = DataEncryptionStandard.padding(caseItem);

            if (totalLength != value.length || value[value.length - 1] != paddingLength) {
                failures++;
                System.out.printf("padding_Tests failed (result: %d, expected: %d)\n", value.length, totalLength);
            }
        }

        if(failures == 0)
            System.out.println("Tests passed for 'padding_Tests'");
    }

    public static void createBlocks_Tests() {
        List<byte[]> casesList = new ArrayList<>();

        for(byte i = 0; i < 127; i++) {
            byte[] testCase = new byte[i + 1];
            for (int j = 0; j < i + 1; j++) {
                testCase[j] = 1;
            }

            casesList.add(testCase);
        }

        int failures = 0;
        for (byte[] caseItem : casesList) {
            int reminder = caseItem.length % 8;
            int totalBlocks = (caseItem.length + (reminder == 0 ? 8 : 8 - reminder)) / 8;
            byte[][] blocks = DataEncryptionStandard.createBlocks(caseItem, true);

            if (totalBlocks != blocks.length) {
                failures++;
                System.out.printf("createBlocks_Tests failed (result: %d, expected: %d)\n", blocks.length, totalBlocks);
            }
        }

        if(failures == 0)
            System.out.println("Tests passed for 'createBlocks_Tests'");
    }

    public static void applyKeyPermutationChoice1_Tests() {
        testPermutation("applyKeyPermutationChoice1_Tests", generalPermutationCases, DataEncryptionStandard.PERMUTED_CHOICE_1, DataEncryptionStandard::applyKeyPermutationChoice1);
    }

    public static void  initialPermutation_Tests() {
        testPermutation("initialPermutation_Tests", generalPermutationCases, DataEncryptionStandard.INITIAL_PERMUTATION, DataEncryptionStandard::initialPermutation);
    }

    public static void  keyTransformation_Tests() {
        List<Map.Entry<byte[], byte[]>> casesList = new ArrayList<>();

        for(byte i = -128; i < 127; i++) {
            byte[] testCase = new byte[7];
            for (int j = 0; j < 7; j++) {
                testCase[j] = (byte) (i + j);
            }

            for (int roundNumber = 1; roundNumber <= 16; roundNumber++) {
                casesList.add(_keyTransformation(roundNumber, testCase));
            }
        }

        int caseNumber = 0;
        int totalFailed = 0;
        int roundNumber = 1;
        for(Map.Entry<byte[], byte[]> caseItem: casesList) {
            byte[] result = DataEncryptionStandard.keyTransformation(roundNumber++, caseItem.getKey());

            if(! Arrays.equals(caseItem.getValue(), result)) {
                totalFailed++;
                System.out.printf("keyTransformation_Tests failed for case %d (result: %s, expected: %s)\n", caseNumber,
                        Arrays.toString(result), Arrays.toString(caseItem.getValue()));
            }

            caseNumber++;
            if(roundNumber > 16) roundNumber = 1;
        }

        if(totalFailed == 0)
            System.out.println("Tests passed for 'keyTransformation_Tests'");
    }

    private static Map.Entry<byte[], byte[]> _keyTransformation(int roundNumber, byte[] key) {
        byte[] splittedKey = _splitKey(key).getValue();

        byte[] leftKeyPart = new byte[] {splittedKey[0], splittedKey[1], splittedKey[2], splittedKey[3]};
        byte[] rightKeyPart = new byte[] {splittedKey[4], splittedKey[5], splittedKey[6], splittedKey[7]};

        int bitsToRotate = 2;
        if(roundNumber == 1 || roundNumber == 2 | roundNumber == 9 || roundNumber == 16) {
            bitsToRotate = 1;
        }

        leftKeyPart = _applyLeftRotation(leftKeyPart, bitsToRotate).getValue();
        rightKeyPart = _applyLeftRotation(rightKeyPart, bitsToRotate).getValue();

        byte[] _expectedKey = _joinKeyHalves(new byte[][] {leftKeyPart, rightKeyPart}).getValue();

        return Map.entry(key, _expectedKey);
    }

    public static void processRound_Tests() {
        List<Map.Entry<byte[], byte[]>> casesList = new ArrayList<>();
        for(int i = -128; i <= 127; i++) {
            byte[] testCase = new byte[8];
            for (int j = 0; j < 8; j++) {
                testCase[j] = (byte) (i + j);
            }
            byte[] key = new byte[6];
            for (int j = 0; j < 6; j++) {
                key[j] = (byte) (i + j);
            }

            casesList.add(Map.entry(testCase, key));
        }

        byte[] result;
        byte[] expectedResult;
        int totalFailed = 0, idx = 0;
        for (Map.Entry<byte[], byte[]> caseItem: casesList) {
            result = DataEncryptionStandard.processRound(caseItem.getKey(), caseItem.getValue());
            expectedResult = _processRound(caseItem.getKey(), caseItem.getValue());

            if(! Arrays.equals(result, expectedResult)) {
                totalFailed++;
                System.out.printf("'processRound_Tests' failed for case (%s - %s) - result: %s, expected: %s%n", idx, Arrays.toString(caseItem.getKey()),
                        Arrays.toString(result), Arrays.toString(expectedResult));
            }
            idx++;
        }

        if(totalFailed == 0)
            System.out.println("Tests passed for 'processRound_Tests'");
    }

    public static void  finalPermutation_Tests() {
        testPermutation("finalPermutation_Tests", generalPermutationCases, DataEncryptionStandard.FINAL_PERMUTATION, DataEncryptionStandard::finalPermutation);
    }
    public static void  splitKey_Tests() {
        List<Map.Entry<byte[], byte[]>> casesList = new ArrayList<>();

        casesList.add(_splitKey(new byte[] {0, 0, 0, 0, 0, 0, 0}));
        casesList.add(_splitKey(new byte[] {-128, -128, -128, -128, -128, -128, -128}));
        casesList.add(_splitKey(new byte[] {-1, -2, -3, -4, -5, -6, -7}));
        casesList.add(_splitKey(new byte[] {0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7f}));
        casesList.add(_splitKey(new byte[] {1, 2, 3, 4, 5, 6, 7}));
        casesList.add(_splitKey(new byte[] {7, 6, 5, 4, 3, 2, 1}));
        casesList.add(_splitKey(new byte[] {0x7f, 0x7f, 0x7f, 0x7f, 0, 0, 0}));

        generateSplitKeysCases(casesList);

        int caseNumber = 0;
        int failures = 0;
        for(Map.Entry<byte[], byte[]> caseItem: casesList) {
            byte[][] result = DataEncryptionStandard.splitKey(caseItem.getKey());
            byte[] byteResult = new byte[] {result[0][0], result[0][1], result[0][2], result[0][3],
                    result[1][0], result[1][1], result[1][2], result[1][3]};

            if(! Arrays.equals(caseItem.getValue(), byteResult)) {
                failures++;
                System.out.printf("splitKey_Tests failed for case %d (result: %s, expected: %s)\n", caseNumber, Arrays.toString(byteResult), Arrays.toString(caseItem.getValue()));
            }
            caseNumber++;
        }

        if(failures == 0)
            System.out.println("Tests passed for 'splitKey_Tests'");
    }

    private static void generateSplitKeysCases(List<Map.Entry<byte[],byte[]>> casesList) {
        for(byte i = -128; i < 127; i++) {
            byte[] testCase = new byte[7];
            for(int j = 0; j < 7; j++) {
                testCase[j] = (byte) (i + j);
            }
            casesList.add(_splitKey(testCase));
        }
    }

    private static Map.Entry<byte[], byte[]> _splitKey(byte[] key) {
        if(key == null || key.length != 7) throw new IllegalArgumentException();

        String stringfiedKeyBits = stringifyBits(key);

        return Map.entry(key,
                new byte[] {
                        (byte) Integer.parseInt(stringfiedKeyBits.substring(0, 4), 2),
                        (byte) Integer.parseInt(stringfiedKeyBits.substring(4, 12), 2),
                        (byte) Integer.parseInt(stringfiedKeyBits.substring(12, 20), 2),
                        (byte) Integer.parseInt(stringfiedKeyBits.substring(20, 28), 2),

                        (byte) Integer.parseInt(stringfiedKeyBits.substring(28, 32), 2),
                        (byte) Integer.parseInt(stringfiedKeyBits.substring(32, 40), 2),
                        (byte) Integer.parseInt(stringfiedKeyBits.substring(40, 48), 2),
                        (byte) Integer.parseInt(stringfiedKeyBits.substring(48), 2),
                }
        );
    }

    private static List<Map.Entry<byte[], byte[]>> _applyLeftRotation_Tests(int bitsToRotate) {
        List<Map.Entry<byte[], byte[]>> casesList = new ArrayList<>();

        for(byte i = -128; i < 127; i++) {
            byte[] testCase = new byte[4];
            for(int j = 0; j < 4; j++) {
                testCase[j] = (byte) ((i + j) & (j == 0 ? 0x0f : 0xff));
            }
            casesList.add(_applyLeftRotation(testCase, bitsToRotate));
        }

        return casesList;
    }

    public static void  applyLeftRotation_Tests() {
        List<Map.Entry<byte[], byte[]>> casesList_1 = _applyLeftRotation_Tests(1);
        int failures = assertApplyLeftRotationCases(casesList_1, 1);

        List<Map.Entry<byte[], byte[]>> casesList_2 = _applyLeftRotation_Tests(2);
        failures += assertApplyLeftRotationCases(casesList_2, 2);

        if(failures == 0)
            System.out.println("Tests passed for 'applyLeftRotation_Tests'");
    }

    private static int assertApplyLeftRotationCases(List<Map.Entry<byte[],byte[]>> casesList, int bitsToRotate) {
        int caseNumber = 0;
        int failures = 0;
        for(Map.Entry<byte[], byte[]> caseItem: casesList) {
            byte[] result = DataEncryptionStandard.applyLeftRotation(caseItem.getKey(), bitsToRotate);

            if(! Arrays.equals(caseItem.getValue(), result)) {
                failures++;
                System.out.printf("applyLeftRotation_Tests failed for case %d [%d] (result: %s, expected: %s)\n", caseNumber, bitsToRotate,
                        Arrays.toString(result), Arrays.toString(caseItem.getValue()));
            }

            caseNumber++;
        }
        return failures;
    }

    private static Map.Entry<byte[], byte[]> _applyLeftRotation(byte[] splittedKey, int bitsToRotate) {
        StringBuilder stringfiedBits = new StringBuilder(stringifyBits(splittedKey)).delete(0, 4); // deletes the four MSB
        String bitsBackup = stringfiedBits.substring(0, bitsToRotate); // picks the first 'bitsToRotate' from the MSB

        stringfiedBits = stringfiedBits.delete(0, bitsToRotate); // removes the bitsBackup
        stringfiedBits = stringfiedBits.append(bitsBackup); // appends bitBackup to the end

        byte[] expectedResult = new byte[4];

        expectedResult[0] = (byte) Integer.parseInt(stringfiedBits.substring(0, 4), 2);
        expectedResult[1] = (byte) Integer.parseInt(stringfiedBits.substring(4, 12), 2);
        expectedResult[2] = (byte) Integer.parseInt(stringfiedBits.substring(12, 20), 2);
        expectedResult[3] = (byte) Integer.parseInt(stringfiedBits.substring(20), 2);

        return Map.entry(splittedKey, expectedResult);
    }

    public static void  joinKeyHalves_Tests() {
        List<Map.Entry<byte[][], byte[]>> casesList = new ArrayList<>();

        for(byte i = -128; i < 127; i++) {
            byte[] key = new byte[7];
            for(int j = 0; j < 7; j++) {
                key[j] = (byte) (i + j);
            }
            byte[][] splittedKey = DataEncryptionStandard.splitKey(key);
            casesList.add(_joinKeyHalves(splittedKey));
        }

        int caseNumber = 0;
        int totalFailed = 0;
        for(Map.Entry<byte[][], byte[]> caseItem: casesList) {
            byte[] result = DataEncryptionStandard.joinKeyHalves(caseItem.getKey()[0], caseItem.getKey()[1]);

            if(! Arrays.equals(caseItem.getValue(), result)) {
                totalFailed++;
                System.out.printf("joinKeyHalves_Tests failed for case %d (result: %s, expected: %s)\n", caseNumber,
                        Arrays.toString(result), Arrays.toString(caseItem.getValue()));
            }

            caseNumber++;
        }

        if(totalFailed == 0)
            System.out.println("Tests passed for 'joinKeyHalves_Tests'");
    }

    private static Map.Entry<byte[][], byte[]> _joinKeyHalves(byte[][] splittedKey) {
        byte[] expectedResult = new byte[7];

        String leftBits = stringifyBits(splittedKey[0]).substring(4);
        String rightBits = stringifyBits(splittedKey[1]).substring(4);

        expectedResult[0] = (byte) (Integer.parseInt(leftBits.substring(0, 8), 2));
        expectedResult[1] = (byte) (Integer.parseInt(leftBits.substring(8, 16), 2));
        expectedResult[2] = (byte) (Integer.parseInt(leftBits.substring(16, 24), 2));
        expectedResult[3] = (byte) (Integer.parseInt(leftBits.substring(24, 28) + rightBits.substring(0, 4), 2));
        expectedResult[4] = (byte) (Integer.parseInt(rightBits.substring(4, 12), 2));
        expectedResult[5] = (byte) (Integer.parseInt(rightBits.substring(12, 20), 2));
        expectedResult[6] = (byte) (Integer.parseInt(rightBits.substring(20, 28), 2));

        return Map.entry(splittedKey, expectedResult);
    }

    public static void  applyFunctionF_Tests() {
        List<Map.Entry<byte[], byte[]>> casesList = new ArrayList<>();
        for(int i = -128; i <= 127; i++) {
            byte[] testCase = new byte[4];
            for (int j = 0; j < 4; j++) {
                testCase[j] = (byte) (i + j);
            }
            byte[] key = new byte[7];
            for (int j = 0; j < 7; j++) {
                key[j] =(byte) (i + j);
            }

            casesList.add(Map.entry(testCase, key));
        }

        byte[] result;
        byte[] expectedResult;
        int totalFailed = 0, idx = 0;
        for (Map.Entry<byte[], byte[]> caseItem: casesList) {
            result = DataEncryptionStandard.applyFunctionF(caseItem.getKey(), DataEncryptionStandard.applyKeyPermutationChoice2(caseItem.getValue()));
            expectedResult = _applyFunctionF(caseItem.getKey(), testUtilsPermutation(caseItem.getValue(), DataEncryptionStandard.PERMUTED_CHOICE_2));

            if(! Arrays.equals(result, expectedResult)) {
                totalFailed++;
                System.out.printf("'applyFunctionF_Tests' failed for case (%s - %s) - result: %s, expected: %s%n", idx, Arrays.toString(caseItem.getKey()),
                        Arrays.toString(result), Arrays.toString(expectedResult));
            }
            idx++;
        }

        if(totalFailed == 0)
            System.out.println("Tests passed for 'applyFunctionF_Tests'");
    }

    public static void  expansionPermutation_Tests() {
        testPermutation("expansionPermutation_Tests", expansionPermutationCases, DataEncryptionStandard.EXPANSION_PERMUTATION, DataEncryptionStandard::expansionPermutation);
    }

    public static void  applyKeyPermutationChoice2_Tests() {
        testPermutation("applyKeyPermutationChoice2_Tests", generalPermutationCases, DataEncryptionStandard.PERMUTED_CHOICE_2, DataEncryptionStandard::applyKeyPermutationChoice2);
    }

    public static void  xorWithKey_Tests() {
        _xorWithKey(new byte[] {126, 127, -128, -127, -126, -125, -124, -123}, new byte[] {126, 127, -128, -127, -126, -125});

        List<Map.Entry<byte[][], byte[]>> casesList = new ArrayList<>();

        for(byte i = -128; i < 127; i++) {
            byte[] plainText = new byte[8];
            for(int j = 0; j < 8; j++) {
                plainText[j] = (byte) (i + j);
            }

            byte[] key = new byte[6];
            for(int j = 0; j < 6; j++) {
                key[j] = (byte) (i + j);
            }

            casesList.add(_xorWithKey(plainText, key));
        }

        int caseNumber = 0;
        int totalFailed = 0;
        for(Map.Entry<byte[][], byte[]> caseItem: casesList) {
            byte[] result = DataEncryptionStandard.xorWithKey(caseItem.getKey()[0], caseItem.getKey()[1]);

            if(! Arrays.equals(caseItem.getValue(), result)) {
                totalFailed++;
                System.out.printf("xorWithKey_Tests failed for case %d (%s, %s) (result: %s, expected: %s)\n", caseNumber, Arrays.toString(caseItem.getKey()[0]),
                        Arrays.toString(caseItem.getKey()[1]), Arrays.toString(result), Arrays.toString(caseItem.getValue()));
            }

            caseNumber++;
        }

        if(totalFailed == 0)
            System.out.println("Tests passed for 'xorWithKey_Tests'");
    }

    private static Map.Entry<byte[][],byte[]> _xorWithKey(byte[] plainText, byte[] key) {
        String[] keyStringfied = new String[6];
        int i = 0;
        for(byte keyItem: key) {
            keyStringfied[i++] = stringifyBits(new byte[] {keyItem});
        }

        byte[] expectedResult = new byte[8];
        expectedResult[0] = (byte) (plainText[0] ^ ((byte) Integer.parseInt(keyStringfied[0].substring(0, 6), 2)));
        expectedResult[1] = (byte) (plainText[1] ^ ((byte) Integer.parseInt(keyStringfied[0].substring(6) + keyStringfied[1].substring(0, 4), 2)));
        expectedResult[2] = (byte) (plainText[2] ^ ((byte) Integer.parseInt(keyStringfied[1].substring(4) + keyStringfied[2].substring(0, 2), 2)));
        expectedResult[3] = (byte) (plainText[3] ^ ((byte) Integer.parseInt(keyStringfied[2].substring(2), 2)));
        expectedResult[4] = (byte) (plainText[4] ^ ((byte) Integer.parseInt(keyStringfied[3].substring(0, 6), 2)));
        expectedResult[5] = (byte) (plainText[5] ^ ((byte) Integer.parseInt(keyStringfied[3].substring(6) + keyStringfied[4].substring(0, 4), 2)));
        expectedResult[6] = (byte) (plainText[6] ^ ((byte) Integer.parseInt(keyStringfied[4].substring(4) + keyStringfied[5].substring(0, 2), 2)));
        expectedResult[7] = (byte) (plainText[7] ^ ((byte) Integer.parseInt(keyStringfied[5].substring(2), 2)));

        return Map.entry(new byte[][] {plainText, key}, expectedResult);
    }

    private static byte[] _applyFunctionF(byte[] plainTextBlock, byte[] key) {
        plainTextBlock = testUtilsPermutation(plainTextBlock, DataEncryptionStandard.EXPANSION_PERMUTATION);

        plainTextBlock = _xorWithKey(plainTextBlock, key).getValue();

        plainTextBlock = _substitutionBoxPermutation(plainTextBlock);
        plainTextBlock = testUtilsPermutation(plainTextBlock, DataEncryptionStandard.PERMUTATION_P);

        return plainTextBlock;
    }

    private static byte _substitutionBoxPermutation(byte plainTextBlock, byte[][] substitutionBox) {
        String stringfiedBits = stringifyBits(new byte[]{plainTextBlock});

        return substitutionBox[Byte.parseByte(stringfiedBits.charAt(2) + "" + stringfiedBits.charAt(7), 2)][Byte.parseByte(stringfiedBits.substring(3, 7), 2)];
    }

    private static byte[] _substitutionBoxPermutation(byte[] plainTextBlock) {
        byte[] result = new byte[8];

        result[0] = _substitutionBoxPermutation(plainTextBlock[0], DataEncryptionStandard.SUBSTITUTION_BOX_1);
        result[1] = _substitutionBoxPermutation(plainTextBlock[1], DataEncryptionStandard.SUBSTITUTION_BOX_2);
        result[2] = _substitutionBoxPermutation(plainTextBlock[2], DataEncryptionStandard.SUBSTITUTION_BOX_3);
        result[3] = _substitutionBoxPermutation(plainTextBlock[3], DataEncryptionStandard.SUBSTITUTION_BOX_4);
        result[4] = _substitutionBoxPermutation(plainTextBlock[4], DataEncryptionStandard.SUBSTITUTION_BOX_5);
        result[5] = _substitutionBoxPermutation(plainTextBlock[5], DataEncryptionStandard.SUBSTITUTION_BOX_6);
        result[6] = _substitutionBoxPermutation(plainTextBlock[6], DataEncryptionStandard.SUBSTITUTION_BOX_7);
        result[7] = _substitutionBoxPermutation(plainTextBlock[7], DataEncryptionStandard.SUBSTITUTION_BOX_8);

        return result;
    }

    public static void  substitutionBoxPermutation_Tests() {
        List<byte[]> casesList = new ArrayList<>();
        for(int i = -128; i <= 127; i++) {
            byte[] testCase = new byte[8];
            for(int j = 0; j < 8; j++) {
                testCase[j] = (byte) (i + j);
            }
            casesList.add(testCase);
        }

        byte[] result;
        byte[] expectedResult;
        int totalFailed = 0, idx = 0;
        for (byte[] caseItem: casesList) {
            result = DataEncryptionStandard.substitutionBoxPermutation(caseItem);
            expectedResult = _substitutionBoxPermutation(caseItem);

            if(! Arrays.equals(result, expectedResult)) {
                totalFailed++;
                System.out.printf("'substitutionBoxPermutation_Tests' failed for case (%s - %s) - result: %s, expected: %s%n", idx, Arrays.toString(caseItem),
                        Arrays.toString(result), Arrays.toString(expectedResult));
            }
            idx++;
        }

        if(totalFailed == 0)
            System.out.println("Tests passed for 'substitutionBoxPermutation_Tests'");
    }

    public static void  pBoxPermutation_Tests() {
        testPermutation("pBoxPermutation_Tests", generalPermutationCases, DataEncryptionStandard.PERMUTATION_P, DataEncryptionStandard::pBoxPermutation);
    }

    public static byte[] _processRound(byte[] plainTextBlock, byte[] key) {
        byte[] leftIthBlocks = {plainTextBlock[0], plainTextBlock[1], plainTextBlock[2], plainTextBlock[3]};
        byte[] rightIthBlocks = {plainTextBlock[4], plainTextBlock[5], plainTextBlock[6], plainTextBlock[7]};

        byte[] resultingBlocksFromF = _applyFunctionF(rightIthBlocks, key);
        leftIthBlocks = DataEncryptionStandard.xor(leftIthBlocks, resultingBlocksFromF);

        return new byte[] {rightIthBlocks[0], rightIthBlocks[1], rightIthBlocks[2], rightIthBlocks[3],
                leftIthBlocks[0], leftIthBlocks[1], leftIthBlocks[2], leftIthBlocks[3]};
    }
}
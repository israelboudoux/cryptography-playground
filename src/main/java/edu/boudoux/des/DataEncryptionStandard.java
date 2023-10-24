package edu.boudoux.des;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class DataEncryptionStandard {

    //// Plaintext permutation
    public static final byte[][] INITIAL_PERMUTATION = {
            {58, 50, 42, 34, 26, 18, 10, 2},
            {60, 52, 44, 36, 28, 20, 12, 4},
            {62, 54, 46, 38, 30, 22, 14, 6},
            {64, 56, 48, 40, 32, 24, 16, 8},
            {57, 49, 41, 33, 25, 17, 9,  1},
            {59, 51, 43, 35, 27, 19, 11, 3},
            {61, 53, 45, 37, 29, 21, 13, 5},
            {63, 55, 47, 39, 31, 23, 15, 7}
    };

    public static final byte[][] FINAL_PERMUTATION = {
            {40, 8, 48, 16, 56, 24, 64, 32},
            {39, 7, 47, 15, 55, 23, 63, 31},
            {38, 6, 46, 14, 54, 22, 62, 30},
            {37, 5, 45, 13, 53, 21, 61, 29},
            {36, 4, 44, 12, 52, 20, 60, 28},
            {35, 3, 43, 11, 51, 19, 59, 27},
            {34, 2, 42, 10, 50, 18, 58, 26},
            {33, 1, 41,  9, 49, 17, 57, 25}
    };

    public static final byte[][] EXPANSION_PERMUTATION = {
            {32,  1,  2,  3,  4,  5},
            { 4,  5,  6,  7,  8,  9},
            { 8,  9, 10, 11, 12, 13},
            {12, 13, 14, 15, 16, 17},
            {16, 17, 18, 19, 20, 21},
            {20, 21, 22, 23, 24, 25},
            {24, 25, 26, 27, 28, 29},
            {28, 29, 30, 31, 32,  1}
    };

    public static final byte[][] SUBSTITUTION_BOX_1 = {
            {14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7},
            { 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8},
            { 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0},
            {15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13},
    };

    public static final byte[][] SUBSTITUTION_BOX_2 = {
            {15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10},
            { 3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5},
            { 0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15},
            {13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9}
    };

    public static final byte[][] SUBSTITUTION_BOX_3 = {
            {10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8},
            {13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1},
            {13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7},
            { 1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12}
    };

    public static final byte[][] SUBSTITUTION_BOX_4 = {
            { 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15},
            {13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9},
            {10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4},
            { 3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14}
    };

    public static final byte[][] SUBSTITUTION_BOX_5 = {
            { 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9},
            {14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6},
            { 4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14},
            {11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3}
    };

    public static final byte[][] SUBSTITUTION_BOX_6 = {
            {12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11},
            {10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8},
            { 9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6},
            { 4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13}
    };

    public static final byte[][] SUBSTITUTION_BOX_7 = {
            { 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1},
            {13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6},
            { 1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2},
            { 6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12}
    };

    public static final byte[][] SUBSTITUTION_BOX_8 = {
            {13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7},
            { 1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2},
            { 7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8},
            { 2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11}
    };

    public static final byte[][] PERMUTATION_P = {
            {16,  7, 20, 21, 29, 12, 28, 17},
            { 1, 15, 23, 26,  5, 18, 31, 10},
            { 2,  8, 24, 14, 32, 27,  3,  9},
            {19, 13, 30,  6, 22, 11,  4, 25}
    };

    //// Key Permutation
    public static final byte[][] PERMUTED_CHOICE_1 = {
            {57, 49, 41, 33, 25, 17,  9,  1},
            {58, 50, 42, 34, 26, 18, 10,  2},
            {59, 51, 43, 35, 27, 19, 11,  3},
            {60, 52, 44, 36, 63, 55, 47, 39},
            {31, 23, 15,  7, 62, 54, 46, 38},
            {30, 22, 14,  6, 61, 53, 45, 37},
            {29, 21, 13,  5, 28, 20, 12,  4}
    };

    public static final byte[][] PERMUTED_CHOICE_2 = {
            {14, 17, 11, 24,  1,  5,  3, 28},
            {15,  6, 21, 10, 23, 19, 12,  4},
            {26,  8, 16,  7, 27, 20, 13,  2},
            {41, 52, 31, 37, 47, 55, 30, 40},
            {51, 45, 33, 48, 44, 49, 39, 56},
            {34, 53, 46, 42, 50, 36, 29, 32}
    };

    public enum Operation {
        ENCRYPT,
        DECRYPT;
    }

    static byte[] _des(byte[] value, byte[] key, Operation operation, boolean usePadding) {
        if(value == null || value.length == 0)
            throw new IllegalArgumentException("Please, enter the value");

        if(key == null || key.length != 8)
            throw new IllegalArgumentException("The key should have 8 bytes");

        if(operation == null)
            throw new IllegalArgumentException("The mode is required!");

        byte[][] plainTextBlocks = createBlocks(value, usePadding && operation == Operation.ENCRYPT); // TODO implement a solution that pulls the blocks on demand
        byte[][] subKeys = createSubKeys(key);

        List<byte[]> resultingTextList = new ArrayList<>();
        byte[] roundCipherText;
        int tmpRound;
        for (byte[] plainTextBlock: plainTextBlocks) {
            roundCipherText = initialPermutation(plainTextBlock);

            for (int round = 1; round <= 16; round++) {
                // Inverts when decrypting
                tmpRound = (operation == Operation.DECRYPT ? 17 - round : round) - 1;

                byte[] roundSubKey = subKeys[tmpRound];

                roundCipherText = processRound(roundCipherText, roundSubKey);
            }

            roundCipherText = swapLeftRightBlocks(roundCipherText);
            roundCipherText = finalPermutation(roundCipherText);

            resultingTextList.add(roundCipherText);
        }

        if(operation == Operation.DECRYPT && usePadding) {
            return stripPadding(toArray(resultingTextList));
        }

        return toArray(resultingTextList);
    }

    public static byte[] _des(byte[] value, byte[] key, Operation operation) { // TODO Implement different Paddings
        return _des(value, key, operation, true);
    }

    private static byte[][] createSubKeys(byte[] key) {
        byte[] transformedKey = applyKeyPermutationChoice1(key);

        byte[][] resultingSubKeys = new byte[16][];
        for (int round = 1; round <= 16; round++) {
            transformedKey = keyTransformation(round, transformedKey);

            resultingSubKeys[round - 1] = applyKeyPermutationChoice2(transformedKey);
        }

        return resultingSubKeys;
    }

    private static byte[] swapLeftRightBlocks(byte[] roundCipherText) {
        return new byte[] {roundCipherText[4], roundCipherText[5], roundCipherText[6], roundCipherText[7],
                roundCipherText[0], roundCipherText[1], roundCipherText[2], roundCipherText[3]};
    }

    private static byte[] toArray(List<byte[]> cypherTextList) {
        byte[] cypherText = new byte[cypherTextList.size() * 8];
        int idx = 0;
        for(byte[] blocks: cypherTextList) {
            for(byte block: blocks) {
                cypherText[idx++] = block;
            }
        }

        return cypherText;
    }

    private static byte[] stripPadding(byte[] toArray) {
        int index = toArray.length - toArray[toArray.length - 1];
        if(index <= 0)
            throw new IllegalStateException("Decryption failed!");

        return Arrays.copyOfRange(toArray, 0, index);
    }

    public static byte[] processRound(byte[] plainTextBlock, byte[] key) {
        byte[] leftIthBlocks = {plainTextBlock[0], plainTextBlock[1], plainTextBlock[2], plainTextBlock[3]};
        byte[] rightIthBlocks = {plainTextBlock[4], plainTextBlock[5], plainTextBlock[6], plainTextBlock[7]};

        byte[] resultingBlocksFromF = applyFunctionF(rightIthBlocks, key);
        leftIthBlocks = xor(leftIthBlocks, resultingBlocksFromF);

        return new byte[] {rightIthBlocks[0], rightIthBlocks[1], rightIthBlocks[2], rightIthBlocks[3],
                leftIthBlocks[0], leftIthBlocks[1], leftIthBlocks[2], leftIthBlocks[3]};
    }

    public static byte[] applyFunctionF(byte[] plainTextBlock, byte[] key) {
        plainTextBlock = expansionPermutation(plainTextBlock);

        plainTextBlock = xorWithKey(plainTextBlock, key);

        plainTextBlock = substitutionBoxPermutation(plainTextBlock);
        plainTextBlock = pBoxPermutation(plainTextBlock);

        return plainTextBlock;
    }

    /**
     * Receives an array with 8 bytes and returns a 7 bytes one.
     *
     * @param key
     * @return
     */
    public static byte[] applyKeyPermutationChoice1(byte[] key) {
        return applyPermutation(PERMUTED_CHOICE_1, key);
    }

    /**
     * Permutes the 56 input bits coming from the key into 48 bits
     *
     * @param key
     * @return
     */
    public static byte[] applyKeyPermutationChoice2(byte[] key) {
        return applyPermutation(PERMUTED_CHOICE_2, key);
    }

    /**
     *
     * @param roundNumber
     * @param key
     *
     * @return
     */
    public static byte[] keyTransformation(int roundNumber, byte[] key) {
        // Divides the key into 2 parts
        byte[][] splittedKey = splitKey(key);

        byte[] leftKeyPart = splittedKey[0];
        byte[] rightKeyPart = splittedKey[1];

        // ... and rotate the bits of each part and join both part again
        //  1 bit shift is applied for rounds: 1, 2, 9, 16, otherwise a 2 bits shift is applied
        int bitsToRotate = 2;
        if(roundNumber == 1 || roundNumber == 2 | roundNumber == 9 || roundNumber == 16) {
            bitsToRotate = 1;
        }

        leftKeyPart = applyLeftRotation(leftKeyPart, bitsToRotate);
        rightKeyPart = applyLeftRotation(rightKeyPart, bitsToRotate);

        key = joinKeyHalves(leftKeyPart, rightKeyPart);

        return key;
    }

    /**
     * Apply bit left rotation. We should remember that the four Most Significant shouldn't be considered, then
     * the rotation for this slot shouldn't advance to that area.
     *
     * @param keyPart a byte array with length 4 - for the byte at index 0 only the four LSB should be considered
     * @param bitsToRotate total of bits to left rotate, possible values: 1 or 2
     *
     * @return
     */
    public static byte[] applyLeftRotation(byte[] keyPart, int bitsToRotate) {
        if(bitsToRotate != 1 && bitsToRotate != 2) {
            throw new IllegalArgumentException("Valid bitsToRotate are: 1, 2");
        }

        int bitsDifference = 8 - bitsToRotate;
        int bitsNullifier = 0x0f >> (4 - bitsToRotate);

        // picks the MSB of each array
        int bitsContentFromIdx0 = (keyPart[0] & 0x0f) >> (4 - bitsToRotate); // for the first byte only the four LSB are considered!
        int bitsContentFromIdx1 = (keyPart[1] >> bitsDifference) & bitsNullifier;
        int bitsContentFromIdx2 = (keyPart[2] >> bitsDifference) & bitsNullifier;
        int bitsContentFromIdx3 = (keyPart[3] >> bitsDifference) & bitsNullifier;

        byte[] result = new byte[4];

        // applies the rotation & append the bits picked previously
        result[0] = (byte) ((keyPart[0] << bitsToRotate) & 0x0f | bitsContentFromIdx1);
        result[1] = (byte) (keyPart[1] << bitsToRotate | bitsContentFromIdx2);
        result[2] = (byte) (keyPart[2] << bitsToRotate | bitsContentFromIdx3);
        result[3] = (byte) (keyPart[3] << bitsToRotate | bitsContentFromIdx0);

        return result;
    }

    public static byte[] joinKeyHalves(byte[] leftKeyPart, byte[] rightKeyPart) {
        return new byte[] {
                (byte) (leftKeyPart[0] << 4 | leftKeyPart[1] >> 4 & 0x0f),
                (byte) (leftKeyPart[1] << 4 | leftKeyPart[2] >> 4 & 0x0f),
                (byte) (leftKeyPart[2] << 4 | leftKeyPart[3] >> 4 & 0x0f),
                (byte) (leftKeyPart[3] << 4 | rightKeyPart[0]),
                rightKeyPart[1],
                rightKeyPart[2],
                rightKeyPart[3]
        };
    }

    /**
     * Split the key (7 bytes - 56 bits) into two halves (28 bits). It will return two arrays each having
     * 4 bytes. The four Most Significant Bits of the most significant byte are ignored and should be equal to 0x0.
     *
     * @param key
     * @return
     */
    public static byte[][] splitKey(byte[] key) {
        if(key == null || key.length != 7) throw new IllegalArgumentException("Key should have length equals seven");

        byte[] leftKeyPart = {
                (byte) (key[0] >> 4 & 0x0f),
                (byte) (key[0] << 4 | (key[1] >> 4 & 0x0f)),
                (byte) (key[1] << 4 | (key[2] >> 4 & 0x0f)),
                (byte) (key[2] << 4 | (key[3] >> 4 & 0x0f))
        };
        byte[] rightKeyPart = {
                (byte) (0x0f & key[3]),
                key[4],
                key[5],
                key[6]
        };

        return new byte[][] {leftKeyPart, rightKeyPart};
    }

    /**
     *
     * @param plainTextBlock a 8 bytes array where only the 6 LSB should be considered
     * @param key a 6 bytes array
     *
     * @return a byte array having length 8 with each byte containing a 6 bit value
     */
    public static byte[] xorWithKey(byte[] plainTextBlock, byte[] key) {
        return new byte[] {
                (byte) (plainTextBlock[0] ^ ((byte) (key[0] >> 2 & 0x3f))), // picks the 6 MSB from key[0]
                (byte) (plainTextBlock[1] ^ ((byte) (key[0] << 4 & 0x30 | key[1] >> 4 & 0x0f))), // picks the 2 LSB from key[0] + 4 MSB from key[1]
                (byte) (plainTextBlock[2] ^ ((byte) (key[1] << 2 & 0x3c | key[2] >> 6 & 0x03))), // picks the 4 LSB from key[1] + 2 MSB from key[2]
                (byte) (plainTextBlock[3] ^ ((byte) (key[2] & 0x3f))), // picks the 6 LSB from key[2]
                (byte) (plainTextBlock[4] ^ ((byte) (key[3] >> 2 & 0x3f))), // picks the 6 MSB from key[3]
                (byte) (plainTextBlock[5] ^ ((byte) (key[3] << 4 & 0x30 | key[4] >> 4 & 0x0f))), // picks the 2 LSB from key[3] + 4 MSB from key[4]
                (byte) (plainTextBlock[6] ^ ((byte) (key[4] << 2 & 0x3c | key[5] >> 6 & 0x03))), // picks the 4 LSB from key[4] + 2 MSB from key[5]
                (byte) (plainTextBlock[7] ^ ((byte) (key[5] & 0x3f))) // uses 6 bits from key[7] => 0x3f = 00111111
        };
    }

    /**
     * Perform a XOR between the two parameters.
     *
     * @return
     */
    public static byte[] xor(byte[] leftIthBlocks, byte[] rightIthBlocks) {
        return new byte[] {(byte) (rightIthBlocks[0] ^ leftIthBlocks[0]),
                (byte) (rightIthBlocks[1] ^ leftIthBlocks[1]),
                (byte) (rightIthBlocks[2] ^ leftIthBlocks[2]),
                (byte) (rightIthBlocks[3] ^ leftIthBlocks[3])};
    }

    public static byte[] pBoxPermutation(byte[] plainTextBlock) {
        return applyPermutation(PERMUTATION_P, plainTextBlock);
    }

    public static byte[] substitutionBoxPermutation(byte[] plainTextBlock) {
        byte[] result = new byte[8];

        result[0] = applySubstitutionBox(SUBSTITUTION_BOX_1, plainTextBlock[0]);
        result[1] = applySubstitutionBox(SUBSTITUTION_BOX_2, plainTextBlock[1]);
        result[2] = applySubstitutionBox(SUBSTITUTION_BOX_3, plainTextBlock[2]);
        result[3] = applySubstitutionBox(SUBSTITUTION_BOX_4, plainTextBlock[3]);
        result[4] = applySubstitutionBox(SUBSTITUTION_BOX_5, plainTextBlock[4]);
        result[5] = applySubstitutionBox(SUBSTITUTION_BOX_6, plainTextBlock[5]);
        result[6] = applySubstitutionBox(SUBSTITUTION_BOX_7, plainTextBlock[6]);
        result[7] = applySubstitutionBox(SUBSTITUTION_BOX_8, plainTextBlock[7]);

        return result;
    }

    /**
     * The most significant bit (MSB) and the least significant bit (LSB) of each 6-bit input select the row of
     * the table, while the four inner bits select the column. The integers 0,1,. . . ,15 of each
     * entry in the table represent the decimal notation of a 4-bit value.
     *
     * @param substitutionBox
     * @param _6BitValue
     * @return
     */
    public static byte applySubstitutionBox(byte[][] substitutionBox, byte _6BitValue) {
        return substitutionBox[(_6BitValue & 0x20) >> 4 | _6BitValue & 0x1][(_6BitValue & 0x1e) >> 1];
    }

    /**
     * The expansion permutation receives 4 bytes (32 bits) from the R(i-1), the right half of the full block (8 bytes) of the
     * previous round, and expands to 8 blocks of 6 bits each (48 bits). In Java there isn't a type that could hold only 6 bits,
     * then 8 bytes will be returned and only the 6 Least Significant Bits should be considered.
     *
     * @param rightIthFourBlocks
     * @return
     */
    public static byte[] expansionPermutation(byte[] rightIthFourBlocks) {
        return applyPermutation(EXPANSION_PERMUTATION, rightIthFourBlocks);
    }

    public static byte[][] createBlocks(byte[] value, boolean padding) {
        if(padding) {
            value = padding(value);
        }

        byte[][] resulting = new byte[value.length / 8][8];
        for(int i = 0, initialIndex = 0; i < resulting.length; i++, initialIndex += 8)
            resulting[i] = Arrays.copyOfRange(value, initialIndex, initialIndex + 8);

        return resulting;
    }

    public static byte[] padding(byte[] value) {
        byte remainder = (byte) (value.length % 8);

        byte paddingLength = 8;
        if(remainder != 0) {
            paddingLength -= remainder;
        }

        byte[] result = new byte[value.length + paddingLength];

        System.arraycopy(value, 0, result, 0, value.length);

        // fills the padding positions (except the last one), with the zero value
        for(int i = value.length; i < result.length - 1; i++) {
            result[i] = 0;
        }
        result[result.length - 1] = paddingLength;

        return result;
    }

    /**
     *
     * @param block an array having 8 positions
     *
     * @return
     */
    public static byte[] initialPermutation(byte[] block) {
        return applyPermutation(INITIAL_PERMUTATION, block);
    }

    /**
     *
     * @param block an array having 8 positions
     *
     * @return
     */
    public static byte[] finalPermutation(byte[] block) {
        return applyPermutation(FINAL_PERMUTATION, block);
    }

    public static int applyShift(int value, int positionPermutationBit, int positionToReplace) {;
        int result;
        if(positionPermutationBit > positionToReplace) {
            result = value << (positionPermutationBit - positionToReplace);
        } else {
            result = value >> (positionToReplace - positionPermutationBit);
        }

        return result;
    }

    /**
     * The default permutation applies an N x N, resulting block will have all bits permuted. A permutation can
     * permute just some bits instead of all of them.
     *
     * @param permutationArray
     * @param blockToPermutate
     * @return
     */
    public static byte[] applyPermutation(byte[][] permutationArray, byte[] blockToPermutate) {
        int[] bitsNullifier = { 0x80, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x01 }; // the bitNullifier zeroes all the other non-involved bits for the current iteration
        int bitsDifference = permutationArray[0].length < 8 ? 8 - permutationArray[0].length: 0; // if the permutation doesn't apply to the full 8 bits
        int blocksBitLength = blockToPermutate.length * 8;

        byte[] resultingBlock = new byte[permutationArray.length];

        for(int row = 0; row < permutationArray.length; row++) {
            byte[] permutationRow = permutationArray[row];
            int tmpBlock = 0;
            for(int bitPositionToBeReplaced = 0; bitPositionToBeReplaced < permutationRow.length; bitPositionToBeReplaced++) {
                int positionToPermutate = permutationRow[bitPositionToBeReplaced];
                int bitPosition = (blocksBitLength - positionToPermutate); // 0..63
                int bitPositionFromPermutationSource = bitPosition % 8; // 0..7
                int idxSourceByte = bitPosition / 8; // 0..[blockToPermutate.length - 1]

                byte permutationSource = blockToPermutate[idxSourceByte]; // picks the byte from which the bit will be permuted from (the source)

                int calculatedByte = applyShift(permutationSource & bitsNullifier[bitPositionFromPermutationSource], bitPositionFromPermutationSource, bitPositionToBeReplaced + bitsDifference);

                tmpBlock = (tmpBlock | calculatedByte);
            }
            resultingBlock[row] = (byte) tmpBlock;
        }

        return resultingBlock;
    }
}
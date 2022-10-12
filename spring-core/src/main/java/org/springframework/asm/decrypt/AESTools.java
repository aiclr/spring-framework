/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.asm.decrypt;

public final class AESTools implements DecryptClassTool {

	private static byte[] password = new byte[16];

	// 获取每轮密钥 共11轮 每轮的密钥长度都是 16 byte
	public static byte[][] pwdArrays = new byte[11][16];

	public static int[] GaloisFieldBase8 = AESTools.GaloisFieldBase(0x1B, 8);

	/**
	 * Rijndael S-box Substitution table used for encryption in the subBytes step, as well
	 * as the key expansion.
	 */
	private static final int[] SBOX = {0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE,
			0xD7, 0xAB, 0x76, 0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72,
			0xC0, 0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15, 0x04,
			0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75, 0x09, 0x83, 0x2C,
			0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84, 0x53, 0xD1, 0x00, 0xED, 0x20,
			0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF, 0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33,
			0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC,
			0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E,
			0x3D, 0x64, 0x5D, 0x19, 0x73, 0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE,
			0x5E, 0x0B, 0xDB, 0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4,
			0x79, 0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08, 0xBA,
			0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A, 0x70, 0x3E, 0xB5,
			0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, 0xE1, 0xF8, 0x98, 0x11, 0x69,
			0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF, 0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42,
			0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16};

	/**
	 * Inverse Rijndael S-box Substitution table used for decryption in the subBytesDec
	 * step.
	 */
	private static final int[] INVERSE_SBOX = {0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E,
			0x81, 0xF3, 0xD7, 0xFB, 0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE,
			0xE9, 0xCB, 0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
			0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25, 0x72, 0xF8,
			0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92, 0x6C, 0x70, 0x48, 0x50,
			0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84, 0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC,
			0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06, 0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02,
			0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B, 0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2,
			0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73, 0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8,
			0x1C, 0x75, 0xDF, 0x6E, 0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18,
			0xBE, 0x1B, 0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
			0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F, 0x60, 0x51,
			0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF, 0xA0, 0xE0, 0x3B, 0x4D,
			0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61, 0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77,
			0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D};

	/**
	 * 获取 11 轮密钥 1 2 4 8 16 32 64 128 27 54
	 */
	private static final byte[][] RCON = new byte[][]{{0x01, 0x00, 0x00, 0x00}, {0x02, 0x00, 0x00, 0x00},
			{0x04, 0x00, 0x00, 0x00}, {0x08, 0x00, 0x00, 0x00}, {0x10, 0x00, 0x00, 0x00},
			{0x20, 0x00, 0x00, 0x00}, {0x40, 0x00, 0x00, 0x00}, {(byte) 0x80, 0x00, 0x00, 0x00},
			{0x1b, 0x00, 0x00, 0x00}, {0x36, 0x00, 0x00, 0x00}};

	/**
	 * 加密列混淆矩阵
	 */
	private static final byte[] encodeMatrix = new byte[]{0x02, 0x01, 0x01, 0x03, 0x03, 0x02, 0x01, 0x01, 0x01, 0x03,
			0x02, 0x01, 0x01, 0x01, 0x03, 0x02};

	/**
	 * 解密列混淆矩阵
	 */
	private static final byte[] decodeMatrix = new byte[]{0x0E, 0x09, 0x0D, 0x0B, 0x0B, 0x0E, 0x09, 0x0D, 0x0D, 0x0B,
			0x0E, 0x09, 0x09, 0x0D, 0x0B, 0x0E};

	/**
	 * 根据原始数据 bytes 创建一个 128bit/16byte 字节数组 为后续运算准备 不足 16 byte 需要往前补零 TODO 补充内容可扩展
	 */
	public static byte[] splitBlockIntoCells(byte[] bytes) {
		byte[] cells = new byte[16];
		for (int i = 15, j = bytes.length - 1; i >= 0 && j >= 0; i--, j--) {
			cells[i] = bytes[j];
		}
		return cells;
	}

	/**
	 * 轮密钥加
	 *
	 * @param text 待加 byte 数组
	 * @param pwd  轮密钥
	 * @return 结果
	 */
	public static byte[] addRoundKey(byte[] text, byte[] pwd) {
		byte[] result = new byte[16];
		for (int i = 0; i < 16; i++) {
			result[i] = (byte) (text[i] ^ pwd[i]);
		}
		return result;
	}

	/**
	 * 循环左移
	 */
	public static byte[] cycleLeft(byte[] bytes) {
		byte tmp = bytes[0];
		bytes[0] = bytes[1];
		bytes[1] = bytes[2];
		bytes[2] = bytes[3];
		bytes[3] = tmp;
		return bytes;
	}

	/**
	 * 按 SBOX 映射 字节
	 */
	public static byte[] subBytes(byte[] ciphertext) {
		byte[] result = new byte[ciphertext.length];
		for (int i = 0; i < ciphertext.length; i++) {
			result[i] = (byte) SBOX[(int) ciphertext[i] & 0xff];
		}
		return result;
	}

	/**
	 * 按 INVERSE_SBOX 映射 字节
	 */
	public static byte[] subBytesDec(byte[] ciphertext) {
		byte[] result = new byte[ciphertext.length];
		for (int i = 0; i < ciphertext.length; i++) {
			result[i] = (byte) INVERSE_SBOX[(int) ciphertext[i] & 0xff];
		}
		return result;
	}

	/**
	 * 根据密钥 获取每轮加密的密钥
	 */
	public static byte[] getPWD(byte[] bytes, byte[] RC) {
		byte[] result = new byte[16];
		byte[] w4 = new byte[4];
		for (int i = bytes.length - 1, j = 3; j >= 0; j--, i--) {
			w4[j] = bytes[i];
		}
		// 循环左移一位
		cycleLeft(w4);
		// 映射字节
		byte[] subBytes = subBytes(w4);
		// 异或运算
		for (int i = 0; i < 4; i++) {
			w4[i] = (byte) (subBytes[i] ^ bytes[i] ^ RC[i]);
			result[i] = w4[i];
		}
		byte[] w5 = new byte[4];
		for (int i = 4; i < 8; i++) {
			w5[i - 4] = (byte) (bytes[i] ^ w4[i - 4]);
			result[i] = w5[i - 4];
		}
		byte[] w6 = new byte[4];
		for (int i = 8; i < 12; i++) {
			w6[i - 8] = (byte) (bytes[i] ^ w5[i - 8]);
			result[i] = w6[i - 8];
		}
		byte[] w7 = new byte[4];
		for (int i = 12; i < 16; i++) {
			w7[i - 12] = (byte) (bytes[i] ^ w6[i - 12]);
			result[i] = w7[i - 12];
		}
		return result;
	}

	/**
	 * 行偏移
	 */
	public static byte[] shiftRows(byte[] bytes) {
		for (int i = 5; i < bytes.length; i++) {
			// 偏移量 移动次数
			int offset = i % 4;
			// 是否需要偏移
			int tmpIdx = i / 4;
			// 第二轮开始
			if (offset > 0 && tmpIdx >= offset) {
				for (int j = offset; j > 0; j--) {
					int k = i - 4 * j;
					byte temp = bytes[i];
					bytes[i] = bytes[k];
					bytes[k] = temp;
				}
			}
		}
		return bytes;
	}

	/**
	 * 逆 行偏移
	 */
	public static byte[] inverseShiftRows(byte[] bytes) {
		for (int i = bytes.length; i > 4; i--) {
			int offset = i % 4;// 偏移量 移动次数
			int tmpIdx = i / 4;// 是否需要便宜
			if (offset > 0 && tmpIdx >= offset) {
				for (int j = 1; j <= offset; j++) {
					int k = i - 4 * j;
					byte temp = bytes[k];
					bytes[k] = bytes[i];
					bytes[i] = temp;
				}
			}
		}
		return bytes;
	}

	/**
	 * GF(256) 域 本原多项式 大于 0xFF 的 都需要使用 本原多项式 转化 后续一切转化都基于此 本原多项式 2^8 = 0x1B = 0001 1011 =
	 * x^4+x^3+x^1+x^0
	 *
	 * @param baseValue 本原多项式
	 * @param length    域范围 2^length
	 */
	public static int[] GaloisFieldBase(int baseValue, int length) {
		// length=8 域范围是[0,255] 最高位指数是7 会出现的最大指数是 2*7=14 即需要得到 2^14 的替换值。所以数组最大索引是14
		// 数组大小为14+1=15
		int size = 2 * (length - 1) + 1;
		// length=8-->0xff length=4-->0x0f length=16-->0xffff
		int max = (int) (Math.pow(2, length) - 1);
		int[] result = new int[size];
		int temp = 0x01;
		for (int i = 0; i < size; i++) {
			if (0 < i && i < length) {
				temp <<= 1;
			}
			if (length == i) {
				temp = baseValue;
			}
			if (length < i) {
				temp = temp << 1;
				if (temp > max) {
					int low = temp & max;
					temp = low ^ baseValue;
				}
			}
			result[i] = temp;
		}
		return result;
	}

	/**
	 * 伽罗华域 算法(有限域算法)
	 */
	public static byte GaloisField(byte b1, byte b2) {
		int result = 0;
		// 计算过程会超出 byte 范围 所以 使用 int 代换一次
		int I1 = Byte.toUnsignedInt(b1);
		int I2 = Byte.toUnsignedInt(b2);
		// 用于 保存 分配律 结果
		int[] array = new int[8];
		for (int i = 0; i < array.length; i++) {
			int tmp1 = 1 << i;
			// 当 第i个位置 为 1 时 该项分配律结果需要计算
			if ((tmp1 & I1) == tmp1) {
				// 分配律后的结果 二进制乘法 实质是移位运算
				int shiftVal = I2 << i;
				// 大于 255 数据超出 byte长度 8 bit,需要 GF域本原多项式进行转换
				if (shiftVal > 0xff) {
					// 获取 最右 八位 作为基础
					int lowVal = shiftVal & 0xff;
					// 从第9位 2^8 开始 逐位 判断是否进行伽罗华域 替换
					for (int j = 8; j < GaloisFieldBase8.length; j++) {
						// 1 0000 0000
						int tmp2 = 1 << j;
						// 需要替换 且 本原多项式 替换值的 索引 为 j
						if ((shiftVal & tmp2) == tmp2) {
							// 获取伽罗华域值 与最右8位 进行异或
							lowVal ^= GaloisFieldBase8[j];
						}
					}
					// 经过伽罗华域 转换后的 只有 8位的结果
					array[i] = lowVal;
				} else {
					// 数据不超过 byte 范围 不需要 GF域替换
					array[i] = shiftVal;
				}
				result ^= array[i];
			}
		}
		return (byte) result;
	}

	/**
	 * 列混淆 矩阵 左乘 === 在矩阵左边乘以 一个矩阵
	 */
	public static byte[] mixCols(byte[] bytes) {
		byte[] result = new byte[16];
		for (int i = 0; i <= bytes.length - 4; i += 4) {
			int j = 0;
			byte a00 = (byte) (GaloisField(AESTools.encodeMatrix[j], bytes[i])
					^ GaloisField(AESTools.encodeMatrix[j + 4], bytes[i + 1])
					^ GaloisField(AESTools.encodeMatrix[j + 2 * 4], bytes[i + 2])
					^ GaloisField(AESTools.encodeMatrix[j + 3 * 4], bytes[i + 3]));
			byte a01 = (byte) (GaloisField(AESTools.encodeMatrix[j + 1], bytes[i])
					^ GaloisField(AESTools.encodeMatrix[j + 4 + 1], bytes[i + 1])
					^ GaloisField(AESTools.encodeMatrix[j + 2 * 4 + 1], bytes[i + 2])
					^ GaloisField(AESTools.encodeMatrix[j + 3 * 4 + 1], bytes[i + 3]));
			byte a02 = (byte) (GaloisField(AESTools.encodeMatrix[j + 2], bytes[i])
					^ GaloisField(AESTools.encodeMatrix[j + 4 + 2], bytes[i + 1])
					^ GaloisField(AESTools.encodeMatrix[j + 2 * 4 + 2], bytes[i + 2])
					^ GaloisField(AESTools.encodeMatrix[j + 3 * 4 + 2], bytes[i + 3]));
			byte a03 = (byte) (GaloisField(AESTools.encodeMatrix[j + 3], bytes[i])
					^ GaloisField(AESTools.encodeMatrix[j + 4 + 3], bytes[i + 1])
					^ GaloisField(AESTools.encodeMatrix[j + 2 * 4 + 3], bytes[i + 2])
					^ GaloisField(AESTools.encodeMatrix[j + 3 * 4 + 3], bytes[i + 3]));
			result[i] = a00;
			result[i + 1] = a01;
			result[i + 2] = a02;
			result[i + 3] = a03;
		}
		return result;
	}

	/**
	 * 列混淆 矩阵 左乘 === 在矩阵左边乘以 一个矩阵
	 */
	public static byte[] inverseMixCols(byte[] bytes) {
		byte[] result = new byte[16];
		for (int i = 0; i <= bytes.length - 4; i += 4) {
			int j = 0;
			byte a00 = (byte) (GaloisField(AESTools.decodeMatrix[j], bytes[i])
					^ GaloisField(AESTools.decodeMatrix[j + 4], bytes[i + 1])
					^ GaloisField(AESTools.decodeMatrix[j + 2 * 4], bytes[i + 2])
					^ GaloisField(AESTools.decodeMatrix[j + 3 * 4], bytes[i + 3]));
			byte a01 = (byte) (GaloisField(AESTools.decodeMatrix[j + 1], bytes[i])
					^ GaloisField(AESTools.decodeMatrix[j + 4 + 1], bytes[i + 1])
					^ GaloisField(AESTools.decodeMatrix[j + 2 * 4 + 1], bytes[i + 2])
					^ GaloisField(AESTools.decodeMatrix[j + 3 * 4 + 1], bytes[i + 3]));
			byte a02 = (byte) (GaloisField(AESTools.decodeMatrix[j + 2], bytes[i])
					^ GaloisField(AESTools.decodeMatrix[j + 4 + 2], bytes[i + 1])
					^ GaloisField(AESTools.decodeMatrix[j + 2 * 4 + 2], bytes[i + 2])
					^ GaloisField(AESTools.decodeMatrix[j + 3 * 4 + 2], bytes[i + 3]));
			byte a03 = (byte) (GaloisField(AESTools.decodeMatrix[j + 3], bytes[i])
					^ GaloisField(AESTools.decodeMatrix[j + 4 + 3], bytes[i + 1])
					^ GaloisField(AESTools.decodeMatrix[j + 2 * 4 + 3], bytes[i + 2])
					^ GaloisField(AESTools.decodeMatrix[j + 3 * 4 + 3], bytes[i + 3]));
			result[i] = a00;
			result[i + 1] = a01;
			result[i + 2] = a02;
			result[i + 3] = a03;
		}
		return result;
	}

	private static volatile AESTools instance;

	public static AESTools getInstance() {
		if (instance == null) {
			throw new IllegalStateException("未创建 AESTools");
		}
		return instance;
	}

	public static AESTools getInstance(String password) {
		if (instance == null) {
			synchronized (AESTools.class) {
				if (instance == null) {
					instance = new AESTools(VerifyPermissions.stringToBytes(password));
				}
			}
		}
		return instance;
	}

	private AESTools(byte[] password) {
		AESTools.password = password;
		init();
	}

	public void init() {
		for (int i = 1; i < AESTools.pwdArrays.length; i++) {
			AESTools.pwdArrays[i] = AESTools.getPWD(AESTools.password, RCON[i - 1]);
		}
	}

	public static void showBytesHex(byte[] bytes) {
		for (byte b : bytes) {
			System.err.print(Integer.toString(Byte.toUnsignedInt(b), 16) + " ");
		}
		System.err.println();
	}

	public static void showBytes(byte[] bytes) {
		for (byte b : bytes) {
			System.err.print((((int) b) & 0xff) + "\t");
		}
		System.err.println();
	}

	@Override
	public byte[] decode(byte[] ciphertext, int bytesRead) {
		byte[] temp = AESTools.addRoundKey(ciphertext, AESTools.pwdArrays[10]);
		for (int i = 9; i > 0; i--) {
			// 逆行偏移
			byte[] isr = AESTools.inverseShiftRows(temp);
			// SBOX 反向值替换
			byte[] sbd = AESTools.subBytesDec(isr);
			// 轮密钥加
			byte[] ark = AESTools.addRoundKey(sbd, AESTools.pwdArrays[i]);
			temp = AESTools.inverseMixCols(ark);
		}
		// 第10 波 无逆向列混淆
		byte[] isr1 = AESTools.inverseShiftRows(temp);
		byte[] isb = AESTools.subBytesDec(isr1);
		return AESTools.addRoundKey(isb, AESTools.pwdArrays[0]);
	}

	@Override
	public byte[] encode(byte[] plaintext, int bytesRead) {
		// 共10轮 第一轮 轮密钥加
		byte[] temp = AESTools.addRoundKey(plaintext, AESTools.pwdArrays[0]);
		for (int i = 1; i < 10; i++) {
			// 值替换
			byte[] sub1 = AESTools.subBytes(temp);
			// 行偏移
			byte[] row1 = AESTools.shiftRows(sub1);
			// 列混淆
			byte[] col1 = AESTools.mixCols(row1);
			// 轮密钥加
			temp = AESTools.addRoundKey(col1, AESTools.pwdArrays[i]);
		}
		// 第10轮 值替换
		byte[] sub10 = AESTools.subBytes(temp);
		// 行偏移
		byte[] row10 = AESTools.shiftRows(sub10);
		// 轮密钥加
		return AESTools.addRoundKey(row10, AESTools.pwdArrays[10]);
	}
}
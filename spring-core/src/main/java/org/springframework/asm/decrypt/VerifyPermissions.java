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

import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;
import java.util.Optional;

public class VerifyPermissions {

	public static boolean needCheck=true;

	/**
	 * mac 地址白名单
	 */
	private static final List<String> whiteList = Arrays.asList("7470fd706e67", // developer
			"b8aeed9fa837"// 192.168.1.131
	);

	/**
	 * 根据mac地址 和 有效期 生产密码
	 * @param mac 宿主机 mac 地址
	 * @param lifespan 有效期 时间戳 1665557353659L 按二进制 每 8bit 一组 （低位在前高位在后） 0a47e4c68301
	 */
	public static void printPassword(String mac, long lifespan) {
		StringBuilder sb = new StringBuilder();
		System.err.println(mac);
		System.err.println(lifespan);
		long ff = Byte.toUnsignedLong((byte) 0xFF);
		for (int i = 0; i < 8; i++) {
			sb.append(String.format("%02x", (((ff << (i * 8)) & lifespan) >>> (i * 8))));
		}
		sb.append(mac);
		sb.append("0000");
		System.err.println(sb);
	}

	/**
	 * 从密码中分离出 有效期 和 mac 之后 校验 password = 8bytes lifespan + 6bytes mac + 保留位置 0000
	 * 0a47e4c683010000 d8c49792a3b0 0000
	 * @param password 密码
	 */
	public static boolean checkPassword(String password) throws IllegalArgumentException {
		StringBuilder sb = new StringBuilder();
		for (int i = 14; i >= 0; i -= 2) {
			sb.append(password, i, i + 2);
		}
		if (Long.parseUnsignedLong(sb.toString(), 16) - System.currentTimeMillis() > 0) {
			return checkMAC(password.substring(16, 28));
		}
		throw new IllegalArgumentException("===========================\n" + "======== 无法启动 ===========\n"
				+ "====== 请联系运维人员 ========\n" + "===========================");
	}

	/**
	 * string 密码转 byte[]
	 * @param str string
	 * @return byte[]
	 */
	public static byte[] stringToBytes(String str) {
		byte[] result = new byte[16];
		for (int i = 0; i < 32; i += 2) {
			result[i / 2] = (byte) Integer.parseUnsignedInt(str.substring(i, i + 2), 16);
		}
		return result;
	}

	/**
	 * 检查传入的mac 与 宿主机 mac 是否一致
	 * @param mac 切割成 16进制 byte 后拼接成的字符串 d8 c4 97 92 a3 b0
	 * @return 一致则返回true 否则返回 false
	 */
	public static boolean checkMAC(String mac) throws IllegalArgumentException {
		boolean result = true;
		// 校验 mac
		for (String white : whiteList) {
			// 白名单
			if (white.equalsIgnoreCase(mac))
				return result;
		}

		// 获取宿主机 所有 mac 地址
		List<String> macs = new ArrayList<>();
		try {
			StringBuilder sb = new StringBuilder();
			Enumeration<NetworkInterface> networkInterfaces = NetworkInterface.getNetworkInterfaces();
			while (networkInterfaces.hasMoreElements()) {
				NetworkInterface nif = networkInterfaces.nextElement();
				if (!nif.isLoopback() && !nif.isVirtual() && !nif.isPointToPoint() && nif.isUp()) {
					Optional.ofNullable(nif.getHardwareAddress()).ifPresent(bytes -> {
						for (byte byteTmp : bytes)
							sb.append(Integer.toString(Byte.toUnsignedInt(byteTmp), 16));
						macs.add(sb.toString());
						sb.setLength(0);
					});
				}
			}
			for (String mStr : macs) {
				// mac 一致
				if (mStr.equalsIgnoreCase(mac))
					return result;
			}
		}
		catch (SocketException ex) {
			throw new IllegalArgumentException(ex.getMessage());
		}
		return false;
	}

}

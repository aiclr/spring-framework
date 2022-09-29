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

public class AESTools implements DecryptClassTool {

	private static String password = "";

	private static volatile AESTools instance;

	public static AESTools getInstance(String[] args) {
		if (instance == null) {
			synchronized (AESTools.class) {
				if (instance == null) {
					instance = new AESTools(args);
				}
			}
		}
		return instance;
	}

	public static AESTools getInstance(String password) {
		if (instance == null) {
			synchronized (AESTools.class) {
				if (instance == null) {
					instance = new AESTools(password);
				}
			}
		}
		return instance;
	}

	private AESTools(String[] args) {
		for (String str : args) {
			if (str.contains("DES_PWD") && str.contains("=")) {
				password = str.substring(str.indexOf("=") + 1);
				break;
			}
		}
		password = (password == null || password.equals("")) ? "0123456789abcdef" : password;
	}

	private AESTools(String password) {
		AESTools.password = (password == null || password.equals("")) ? "0123456789abcdef" : password;
	}

	@Override
	public byte[] decode(byte[] ciphertext, byte[] plaintext, int bytesRead) {
		for (int i = 0; i < bytesRead; i++) {
			plaintext[i] = (byte) (ciphertext[i] ^ 1);
		}
		return plaintext;
	}

}

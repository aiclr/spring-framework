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

package org.springframework.core.type.classreading;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.List;

import org.springframework.asm.ClassReader;
import org.springframework.asm.decrypt.DecryptClassTool;
import org.springframework.core.NestedIOException;
import org.springframework.core.io.Resource;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.core.type.ClassMetadata;
import org.springframework.lang.Nullable;

/**
 * {@link MetadataReader} implementation based on an ASM
 * {@link org.springframework.asm.ClassReader}.
 *
 * @author Juergen Hoeller
 * @author Costin Leau
 * @since 2.5
 */
final class SimpleMetadataReader implements MetadataReader {

	private static final int PARSING_OPTIONS = ClassReader.SKIP_DEBUG
			| ClassReader.SKIP_CODE | ClassReader.SKIP_FRAMES;

	private final Resource resource;

	private final AnnotationMetadata annotationMetadata;


	SimpleMetadataReader(Resource resource, @Nullable ClassLoader classLoader) throws IOException {
		SimpleAnnotationMetadataReadingVisitor visitor = new SimpleAnnotationMetadataReadingVisitor(classLoader);
		getClassReader(resource).accept(visitor, PARSING_OPTIONS);
		this.resource = resource;
		this.annotationMetadata = visitor.getMetadata();
	}

	SimpleMetadataReader(Resource resource, @Nullable ClassLoader classLoader, DecryptClassTool decryptClassTool) throws IOException {
		SimpleAnnotationMetadataReadingVisitor visitor = new SimpleAnnotationMetadataReadingVisitor(classLoader);
		getClassReader(resource,decryptClassTool).accept(visitor, PARSING_OPTIONS);
		this.resource = resource;
		this.annotationMetadata = visitor.getMetadata();
	}

	private static ClassReader getClassReader(Resource resource) throws IOException {
		try (InputStream is = resource.getInputStream()) {
			try {
				return new ClassReader(is);
			}
			catch (IllegalArgumentException ex) {
				throw new NestedIOException("ASM ClassReader failed to parse class file - " +
						"probably due to a new Java class file version that isn't supported yet: " + resource, ex);
			}
		}
	}

	private static final String GroupPath = "cn/tnar/flyos";

	// private static final List<String> skip = Arrays.asList("AccessPaymentAspect.class",
	// "CashOutAspect.class");
	private static final List<String> skip = Arrays.asList("AccessPaymentAspect.class", "CashOutAspect.class",
			"CloudCouponsAssetsInfo.class", "LedText.class", "ParkDictVO.class", "ParkParamMessage.class",
			"PdaMessageVO.class", "MQParkMemberGroup.class", "EtcOrder.class", "FangKongVoice.class",
			"CarnoCallBack.class", "InEventParam.class", "STCloudBoxConfigVO.class", "TransactionResponseVO.class",
			"RevokeResponseVO.class", "DeductionResponseVO.class", "PrepaidResponseVO.class", "BillingRuleParam.class",
			"RuleInOutMessageVO.class", "ModelsUploadOutRecordRequest.class");

	private static ClassReader getClassReader(Resource resource, DecryptClassTool decryptClassTool) throws IOException {
		try (InputStream is = resource.getInputStream()) {
			try {
				if(resource.getURL().getPath().contains(GroupPath) && !skip.contains(resource.getFilename()) ) {
					return new ClassReader(is,decryptClassTool);
				}
				return new ClassReader(is);
			}
			catch (IllegalArgumentException ex) {
				throw new NestedIOException("ASM ClassReader failed to parse class file - " +
						"probably due to a new Java class file version that isn't supported yet: " + resource, ex);
			}
		}
	}

	@Override
	public Resource getResource() {
		return this.resource;
	}

	@Override
	public ClassMetadata getClassMetadata() {
		return this.annotationMetadata;
	}

	@Override
	public AnnotationMetadata getAnnotationMetadata() {
		return this.annotationMetadata;
	}

}

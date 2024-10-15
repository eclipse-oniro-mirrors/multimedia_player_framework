/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef AVMETADATASTUB_FUZZER_H
#define AVMETADATASTUB_FUZZER_H

#define FUZZ_PROJECT_NAME "avmetadatastub_local_fuzzer"
#include "avmetadata_service_proxy_local_fuzzer.h"

namespace OHOS {
namespace Media {
bool FuzzAvmetadataStub(uint8_t *data, size_t size);
}
}

#endif // AVMETADATASTUB_FUZZER_H
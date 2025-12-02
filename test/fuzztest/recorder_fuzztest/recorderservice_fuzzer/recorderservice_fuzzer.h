/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef RECORDERSERVICE_FUZZER
#define RECORDERSERVICE_FUZZER

#include <fcntl.h>
#include <securec.h>
#include <unistd.h>
#include <cstdint>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include "test_recorder.h"
#include "recorder_server.h"

#define FUZZ_PROJECT_NAME "recorderservice_fuzzer"

namespace OHOS {
namespace Media {
class RecorderServiceFuzzer : public TestRecorder {
public:
    RecorderServiceFuzzer();
    ~RecorderServiceFuzzer();
    bool FuzzRecorderService(uint8_t *data, size_t size);
    std::shared_ptr<TestRecorder> recorder = nullptr;
};
} // namespace Media
bool FuzzTestRecorderService(uint8_t *data, size_t size);
} // namespace OHOS
#endif
/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef RECORDERSETAUDIOENCODINGBITRATE_FUZZER
#define RECORDERSETAUDIOENCODINGBITRATE_FUZZER

#include <cstdint>
#include <unistd.h>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include "test_recorder.h"

#define FUZZ_PROJECT_NAME "recordersetaudioencodingbitrate_fuzzer"

namespace OHOS {
namespace Media {
class RecorderSetAudioEncodingBitRateFuzzer : public TestRecorder {
public:
    RecorderSetAudioEncodingBitRateFuzzer();
    ~RecorderSetAudioEncodingBitRateFuzzer();
    bool FuzzRecorderSetAudioEncodingBitRate(uint8_t *data, size_t size);
};
}
bool FuzzTestRecorderSetAudioEncodingBitRate(uint8_t *data, size_t size);
}
#endif
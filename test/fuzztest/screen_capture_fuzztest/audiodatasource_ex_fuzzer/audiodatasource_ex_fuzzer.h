/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef AUDIODATASOURCE_EX_FUZZER
#define AUDIODATASOURCE_EX_FUZZER

#include "audio_capturer_wrapper.h"
#include "audio_data_source_generic.h"
#include "audio_info.h"
#include "avbuffer.h"
#include "avsharedmemory.h"
#include "media_data_source.h"
#include "screen_capture_server.h"
#include "screen_capture_service_providers.h"
#include <atomic>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#include <memory>
#include <mutex>
#include <string>
#include <vector>
#define FUZZ_PROJECT_NAME "audiodatasource_ex_fuzzer"

namespace OHOS {
namespace Media {

class AudioDataSourceExFuzzer {
public:
    bool FuzzSetCapture(FuzzedDataProvider &fdp);
    bool FuzzReadAudioBuffer(FuzzedDataProvider &fdp);
    bool FuzzLostFrameNum(FuzzedDataProvider &fdp);
    bool FuzzAlignOrCombine(FuzzedDataProvider &fdp);
    bool FuzzCombine(FuzzedDataProvider &fdp);
    bool FuzzMixAudio(FuzzedDataProvider &fdp);

private:
    std::shared_ptr<CacheBuffer> CreateAudioBuffer(int64_t timestamp);
    std::shared_ptr<CacheBuffer> CreateAudioBuffer(int64_t timestamp, int32_t size);
    void Init(FuzzedDataProvider &fdp);
    void Release();

    std::shared_ptr<AudioDataSourceGeneric> audioSource_;
    int32_t datasize = 2048;
};
bool FuzzAudioDataSourceExCase(uint8_t *data, size_t size);
} // namespace Media
} // namespace OHOS
#endif // AUDIODATASOURCE_EX_FUZZER

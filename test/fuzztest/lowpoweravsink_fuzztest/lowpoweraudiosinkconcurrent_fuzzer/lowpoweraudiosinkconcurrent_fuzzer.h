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
 
#ifndef LOWPOWERAUDIOSINK_FUZZER_H
#define LOWPOWERAUDIOSINK_FUZZER_H
 
#include <iostream>
#define FUZZ_PROJECT_NAME "lowpoweraudiosinkconcurrent_fuzzer"
#include "i_standard_lpp_audio_streamer_service.h"
#include "i_standard_lpp_audio_streamer_listener.h"
#include "lpp_audio_streamer_listener_stub.h"
#include <unistd.h>
#include "media_server.h"
#include "media_parcel.h"
#include "stub_common.h"
#include <fcntl.h>
#include <unistd.h>
#include "fuzzer/FuzzedDataProvider.h"
#include <cstddef>
#include <cstdint>
#include <fstream>
 
namespace OHOS {
namespace Media {
class LowPowerAudioSinkconcurrentFuzz {
public:
    LowPowerAudioSinkconcurrentFuzz();
    ~LowPowerAudioSinkconcurrentFuzz();
    bool RunFuzz(uint8_t *data, size_t size);
private:
    sptr<IRemoteStub<IStandardLppAudioStreamerService>> GetAudioSinkStub();
    std::shared_ptr<AVBuffer> ReadAVBufferFromLocalFile(int32_t start, int32_t size);
};
} // namespace MEDIA
} // namespace OHOS
#endif
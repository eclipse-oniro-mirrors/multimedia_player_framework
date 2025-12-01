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
 
#ifndef LOWPOWERVIDEOSINK_FUZZER_H
#define LOWPOWERVIDEOSINK_FUZZER_H
 
#include <iostream>
#define FUZZ_PROJECT_NAME "lowpowervideosinkconcurrent_fuzzer"
#include "i_standard_lpp_video_streamer_service.h"
#include "i_standard_lpp_video_streamer_listener.h"
#include <unistd.h>
#include "media_server.h"
#include "media_parcel.h"
#include "stub_common.h"
#include <fcntl.h>
 
namespace OHOS {
namespace Media {
class LowPowerVideoSinkconcurrentFuzz {
public:
    LowPowerVideoSinkconcurrentFuzz();
    ~LowPowerVideoSinkconcurrentFuzz();
    
    bool RunFuzz(uint8_t *data, size_t size);
private:
    sptr<IRemoteStub<IStandardLppVideoStreamerService>> GetVideoSinkStub();
    std::shared_ptr<AVBuffer> ReadAVBufferFromLocalFile(int32_t start, int32_t size);
};
} // namespace MEDIA
} // namespace OHOS
#endif
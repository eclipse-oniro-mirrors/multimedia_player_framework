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
 
#include "lowpowervideosinkconcurrent_fuzzer.h"
#include <unistd.h>
#include <fcntl.h>
#include "fuzzer/FuzzedDataProvider.h"
#include <cstddef>
#include <cstdint>
#include <fcntl.h>
#include <fstream>
#include <avcodec_mime_type.h>
 
using namespace std;
using namespace OHOS;
using namespace OHOS::Media;

namespace {
const char *DATA_PATH = "/data/test/input.mp4";
const int32_t SYSTEM_ABILITY_ID = 3002;
const bool RUN_ON_CREATE = false;
constexpr int32_t VIDEO_MIME_TYPES_SIZE = 6;
constexpr uint32_t SLEEP_TIME = 1;

constexpr std::array<std::string_view, VIDEO_MIME_TYPES_SIZE> VIDEO_MIME_TYPES = {
    MediaAVCodec::AVCodecMimeType::MEDIA_MIMETYPE_VIDEO_AVC,
    MediaAVCodec::AVCodecMimeType::MEDIA_MIMETYPE_VIDEO_MPEG4,
    MediaAVCodec::AVCodecMimeType::MEDIA_MIMETYPE_VIDEO_HEVC,
    MediaAVCodec::AVCodecMimeType::MEDIA_MIMETYPE_VIDEO_RV30,
    MediaAVCodec::AVCodecMimeType::MEDIA_MIMETYPE_VIDEO_RV40,
    MediaAVCodec::AVCodecMimeType::MEDIA_MIMETYPE_VIDEO_VVC
};
}

namespace OHOS {
namespace Media {
 
LowPowerVideoSinkconcurrentFuzz::LowPowerVideoSinkconcurrentFuzz()
{
}
 
LowPowerVideoSinkconcurrentFuzz::~LowPowerVideoSinkconcurrentFuzz()
{
}

sptr<IRemoteStub<IStandardLppVideoStreamerService>> LowPowerVideoSinkconcurrentFuzz::GetVideoSinkStub()
{
    std::shared_ptr<MediaServer> mediaServer =
        std::make_shared<MediaServer>(SYSTEM_ABILITY_ID, RUN_ON_CREATE);
    sptr<IRemoteObject> listener = new(std::nothrow) MediaListenerStubFuzzer();
    sptr<IRemoteObject> lowPowerVideoSink = mediaServer->GetSubSystemAbility(
        IStandardMediaService::MediaSystemAbility::MEDIA_LPP_VIDEO_PLAYER, listener);
    if (lowPowerVideoSink == nullptr) {
        return nullptr;
    }
    sptr<IRemoteStub<IStandardLppVideoStreamerService>> lowPowerVideoSinkStub = iface_cast<IRemoteStub<IStandardLppVideoStreamerService>>(lowPowerVideoSink);
    return lowPowerVideoSinkStub;
}

bool LowPowerVideoSinkconcurrentFuzz::RunFuzz(uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    sptr<IRemoteStub<IStandardLppVideoStreamerService>> lowPowerVideoSinkStub = GetVideoSinkStub();
    if (lowPowerVideoSinkStub == nullptr) {
        return false;
    }
    std::string mime = VIDEO_MIME_TYPES[abs(fdp.ConsumeIntegral<int32_t>())%VIDEO_MIME_TYPES_SIZE].data();
    lowPowerVideoSinkStub->Init(mime);
    Format format;
    lowPowerVideoSinkStub->SetParameter(format);
    lowPowerVideoSinkStub->Configure(format);
    lowPowerVideoSinkStub->Prepare();
    lowPowerVideoSinkStub->Start();
    lowPowerVideoSinkStub->Pause();
    lowPowerVideoSinkStub->Resume();
    lowPowerVideoSinkStub->Flush();
    lowPowerVideoSinkStub->StartDecode();
    lowPowerVideoSinkStub->StartRender();
    static const int threadCode[] = {
        0, 1, 2, 3, 4
    };
    int code = fdp.PickValueInArray(threadCode);
    switch (code) {
        case 0 :{
            lowPowerVideoSinkStub->SetOutputSurface(nullptr);
            break;
        }
        case 1 :{
            lowPowerVideoSinkStub->SetSyncAudioStreamer(nullptr);
            break;
        }
        case 2 :{
            lowPowerVideoSinkStub->SetTargetStartFrame(fdp.ConsumeIntegral<int64_t>(), fdp.ConsumeIntegral<int32_t>());
            break;
        }
        case 3 :{
            lowPowerVideoSinkStub->SetVolume(fdp.ConsumeFloatingPoint<float>());
            break;
        }
        case 4 :{
            lowPowerVideoSinkStub->SetPlaybackSpeed(fdp.ConsumeFloatingPoint<float>());
            break;
        }
        default:
            break;
    }
    lowPowerVideoSinkStub->ReturnFrames(nullptr);
    lowPowerVideoSinkStub->RegisterCallback();
    lowPowerVideoSinkStub->SetLppVideoStreamerCallback();
    lowPowerVideoSinkStub->SetLppAudioStreamerId(fdp.ConsumeRandomLengthString());
    lowPowerVideoSinkStub->GetStreamerId();
    lowPowerVideoSinkStub->RenderFirstFrame();
    lowPowerVideoSinkStub->Stop();
    sleep(SLEEP_TIME);
    lowPowerVideoSinkStub->Reset();
    sleep(SLEEP_TIME);
    lowPowerVideoSinkStub->Release();
    sleep(SLEEP_TIME);
    return true;
}
}
}
 
/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    if (size < sizeof(int64_t)) {
        return false;
    }
    int32_t fd = open(DATA_PATH, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        return false;
    }
    int len = write(fd, data, size);
    if (len <= 0) {
        close(fd);
        return false;
    }
    close(fd);
    LowPowerVideoSinkconcurrentFuzz videoSink;
    videoSink.RunFuzz(data, size);
    unlink(DATA_PATH);
    return 0;
}
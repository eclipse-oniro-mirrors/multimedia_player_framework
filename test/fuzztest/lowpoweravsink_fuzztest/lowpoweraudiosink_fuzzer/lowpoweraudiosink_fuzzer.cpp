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
 
#include "lowpoweraudiosink_fuzzer.h"
#include <unistd.h>
#include <fcntl.h>
#include "fuzzer/FuzzedDataProvider.h"
#include <cstddef>
#include <cstdint>
#include <fcntl.h>
#include <fstream>
#include <avcodec_mime_type.h>
#include "buffer/avbuffer.h"
 
using namespace std;
using namespace OHOS;
using namespace OHOS::Media;

namespace {
const char *DATA_PATH = "/data/test/input.mp4";
const int32_t SYSTEM_ABILITY_ID = 3002;
const bool RUN_ON_CREATE = false;
constexpr int32_t AUDIO_MIME_TYPES_SIZE = 13;
constexpr int32_t STREAM_LENGTH = 13;
constexpr uint32_t SLEEP_TIME = 1;

constexpr std::array<std::string_view, AUDIO_MIME_TYPES_SIZE> AUDIO_MIME_TYPES = {
    MediaAVCodec::AVCodecMimeType::MEDIA_MIMETYPE_AUDIO_AAC,
    MediaAVCodec::AVCodecMimeType::MEDIA_MIMETYPE_AUDIO_FLAC,
    MediaAVCodec::AVCodecMimeType::MEDIA_MIMETYPE_AUDIO_VORBIS,
    MediaAVCodec::AVCodecMimeType::MEDIA_MIMETYPE_AUDIO_AMRNB,
    MediaAVCodec::AVCodecMimeType::MEDIA_MIMETYPE_AUDIO_OPUS,
    MediaAVCodec::AVCodecMimeType::MEDIA_MIMETYPE_AUDIO_MPEG,
    MediaAVCodec::AVCodecMimeType::MEDIA_MIMETYPE_AUDIO_AMRWB,
    MediaAVCodec::AVCodecMimeType::MEDIA_MIMETYPE_AUDIO_VIVID,
    MediaAVCodec::AVCodecMimeType::MEDIA_MIMETYPE_AUDIO_G711MU,
    MediaAVCodec::AVCodecMimeType::MEDIA_MIMETYPE_AUDIO_APE,
    MediaAVCodec::AVCodecMimeType::MEDIA_MIMETYPE_AUDIO_LBVC,
    MediaAVCodec::AVCodecMimeType::MEDIA_MIMETYPE_AUDIO_COOK,
    MediaAVCodec::AVCodecMimeType::MEDIA_MIMETYPE_AUDIO_AC3
};
}

namespace OHOS {
namespace Media {
 
LowPowerAudioSinkFuzz::LowPowerAudioSinkFuzz()
{
}
 
LowPowerAudioSinkFuzz::~LowPowerAudioSinkFuzz()
{
}

sptr<IRemoteStub<IStandardLppAudioStreamerService>> LowPowerAudioSinkFuzz::GetAudioSinkStub()
{
    std::shared_ptr<MediaServer> mediaServer =
        std::make_shared<MediaServer>(SYSTEM_ABILITY_ID, RUN_ON_CREATE);
    sptr<IRemoteObject> listener = new(std::nothrow) MediaListenerStubFuzzer();
    sptr<IRemoteObject> lowPowerAudioSink = mediaServer->GetSubSystemAbility(
        IStandardMediaService::MediaSystemAbility::MEDIA_LPP_AUDIO_PLAYER, listener);
    if (lowPowerAudioSink == nullptr) {
        return nullptr;
    }
    sptr<IRemoteStub<IStandardLppAudioStreamerService>> lowPowerAudioSinkStub = iface_cast<IRemoteStub<IStandardLppAudioStreamerService>>(lowPowerAudioSink);
    return lowPowerAudioSinkStub;
}

std::shared_ptr<AVBuffer> LowPowerAudioSinkFuzz::ReadAVBufferFromLocalFile(int32_t start, int32_t size)
{
    std::ifstream inputFile(DATA_PATH, std::ios::binary);
    if (!inputFile.is_open()) {
        return nullptr;
    }
    inputFile.seekg(0, std::ios::end);

    inputFile.seekg(start, std::ios::beg);

    auto allocator = AVAllocatorFactory::CreateSharedAllocator(MemoryFlag::MEMORY_READ_WRITE);
    std::shared_ptr<AVBuffer> avBuffer = AVBuffer::CreateAVBuffer(allocator, size);
    if (avBuffer == nullptr || avBuffer->memory_ == nullptr || avBuffer->memory_->GetAddr() == nullptr) {
        return nullptr;
    }
    inputFile.read(reinterpret_cast<char *>(avBuffer->memory_->GetAddr()), size);
    avBuffer->memory_->SetSize(size);
    return avBuffer;
}

bool LowPowerAudioSinkFuzz::RunFuzz(uint8_t *data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    sptr<IRemoteStub<IStandardLppAudioStreamerService>> lowPowerAudioSinkStub = GetAudioSinkStub();
    if (lowPowerAudioSinkStub == nullptr) {
        return false;
    }
    std::string mime = AUDIO_MIME_TYPES[abs(fdp.ConsumeIntegral<int32_t>())%AUDIO_MIME_TYPES_SIZE].data();
    lowPowerAudioSinkStub->Init(mime);
    Format format;
    lowPowerAudioSinkStub->SetParameter(format);
    lowPowerAudioSinkStub->Configure(format);
    lowPowerAudioSinkStub->RegisterCallback();
    lowPowerAudioSinkStub->SetLppAudioStreamerCallback();
    lowPowerAudioSinkStub->GetStreamerId();
    lowPowerAudioSinkStub->Prepare();
    lowPowerAudioSinkStub->Start();
    lowPowerAudioSinkStub->Pause();
    lowPowerAudioSinkStub->Resume();
    lowPowerAudioSinkStub->Flush();
    lowPowerAudioSinkStub->SetVolume(fdp.ConsumeFloatingPoint<float>());
    lowPowerAudioSinkStub->SetPlaybackSpeed(fdp.ConsumeFloatingPoint<float>());
    lowPowerAudioSinkStub->ReturnFrames(nullptr);
    lowPowerAudioSinkStub->SetLppVideoStreamerId(fdp.ConsumeRandomLengthString(STREAM_LENGTH));
    lowPowerAudioSinkStub->Stop();
    lowPowerAudioSinkStub->Reset();
    lowPowerAudioSinkStub->Release();
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
    LowPowerAudioSinkFuzz audioSink;
    audioSink.RunFuzz(data, size);
    unlink(DATA_PATH);
    return 0;
}


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

#include "cj_avplayer_ffi.h"
#include "media_log.h"
#include "media_source_ffi.h"

using namespace OHOS::FFI;

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "CJAVPlayer"};
int32_t g_serverIpAddressCode = 0;
int32_t g_avgDownloadRateCode = 1;
int32_t g_downloadRateCode = 2;
int32_t g_isDownloadingCode = 3;
int32_t g_bufferDurationCode = 4;
} // namespace

namespace OHOS {
namespace Media {
template <class RetData, class NativeT> int32_t VectorToRetData(RetData &ret, std::vector<NativeT> &data)
{
    auto len = data.size();
    if (len <= 0) {
        return MSERR_EXT_API9_OK;
    }
    NativeT *outValue = static_cast<NativeT *>(malloc(sizeof(NativeT) * len));
    if (outValue == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    for (size_t i = 0; i < len; ++i) {
        outValue[i] = data[i];
    }
    ret.size = static_cast<int64_t>(len);
    ret.head = outValue;
    return MSERR_EXT_API9_OK;
}

template <class NativeT> void *MallocObject(NativeT value)
{
    NativeT *data = static_cast<NativeT *>(malloc(sizeof(NativeT)));
    if (data == nullptr) {
        return nullptr;
    }
    *data = value;
    return static_cast<void *>(data);
}

AVPlayStrategy ConvertCPlaystrategy(CPlayStrategy &strategy)
{
    AVPlayStrategy avPlayStrategy;
    avPlayStrategy.preferredWidth = strategy.preferredWidth;
    avPlayStrategy.preferredHeight = strategy.preferredHeight;
    avPlayStrategy.preferredBufferDuration = strategy.preferredBufferDuration;
    avPlayStrategy.preferredHdr = strategy.preferredHdr;
    avPlayStrategy.mutedMediaType = static_cast<OHOS::Media::MediaType>(strategy.mutedMediaType);
    if (strategy.preferredAudioLanguage != nullptr) {
        avPlayStrategy.preferredAudioLanguage = std::string(strategy.preferredAudioLanguage);
    }
    if (strategy.preferredSubtitleLanguage != nullptr) {
        avPlayStrategy.preferredSubtitleLanguage = std::string(strategy.preferredSubtitleLanguage);
    }
    return avPlayStrategy;
}

extern "C" {
int64_t FfiMediaCreateAVPlayer(int32_t *errCode)
{
    auto avPlayerImpl = FFIData::Create<CJAVPlayer>();
    if (avPlayerImpl == nullptr) {
        *errCode = MSERR_EXT_API9_NO_MEMORY;
        return INVALID_ID;
    }
    if (!avPlayerImpl->Constructor()) {
        *errCode = MSERR_EXT_API9_NO_MEMORY;
        FFI::FFIData::Release(avPlayerImpl->GetID());
        return INVALID_ID;
    }
    return avPlayerImpl->GetID();
}

char *FfiMediaAVPlayerGetUrl(int64_t id, int32_t *errCode)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        *errCode = MSERR_EXT_API9_NO_MEMORY;
        return nullptr;
    }
    return avPlayerImpl->GetUrl();
}

void FfiMediaAVPlayerSetUrl(int64_t id, char *url, int32_t *errCode)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        *errCode = MSERR_EXT_API9_NO_MEMORY;
        return;
    }
    avPlayerImpl->SetUrl(url);
}

CAVFileDescriptor FfiMediaAVPlayerGetAVFileDescriptor(int64_t id, int32_t *errCode)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        *errCode = MSERR_EXT_API9_NO_MEMORY;
        return CAVFileDescriptor{0};
    }
    return avPlayerImpl->GetAVFileDescriptor();
}

void FfiMediaAVPlayerSetAVFileDescriptor(int64_t id, CAVFileDescriptor fileDescriptor, int32_t *errCode)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        *errCode = MSERR_EXT_API9_NO_MEMORY;
        return;
    }
    avPlayerImpl->SetAVFileDescriptor(fileDescriptor);
}

CAVDataSrcDescriptor FfiMediaAVPlayerGetDataSrc(int64_t id, int32_t *errCode)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        *errCode = MSERR_EXT_API9_NO_MEMORY;
        return CAVDataSrcDescriptor{0};
    }
    return avPlayerImpl->GetDataSrc();
}

void FfiMediaAVPlayerSetDataSrc(int64_t id, CAVDataSrcDescriptor dataSrcDescriptor, int32_t *errCode)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        *errCode = MSERR_EXT_API9_NO_MEMORY;
        return;
    }
    avPlayerImpl->SetDataSrc(dataSrcDescriptor);
}

char *FfiMediaAVPlayerGetSurfaceID(int64_t id, int32_t *errCode)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        *errCode = MSERR_EXT_API9_NO_MEMORY;
        return nullptr;
    }
    return avPlayerImpl->GetSurfaceID();
}

void FfiMediaAVPlayerSetSurfaceID(int64_t id, char *surfaceId, int32_t *errCode)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        *errCode = MSERR_EXT_API9_NO_MEMORY;
        return;
    }
    avPlayerImpl->SetSurfaceID(surfaceId);
}

bool FfiMediaAVPlayerGetLoop(int64_t id, int32_t *errCode)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        *errCode = MSERR_EXT_API9_NO_MEMORY;
        return false;
    }
    return avPlayerImpl->GetLoop();
}

void FfiMediaAVPlayerSetLoop(int64_t id, bool loop, int32_t *errCode)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        *errCode = MSERR_EXT_API9_NO_MEMORY;
        return;
    }
    avPlayerImpl->SetLoop(loop);
}

int32_t FfiMediaAVPlayerGetVideoScaleType(int64_t id, int32_t *errCode)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        *errCode = MSERR_EXT_API9_NO_MEMORY;
        return 0;
    }
    return avPlayerImpl->GetVideoScaleType();
}

void FfiMediaAVPlayerSetVideoScaleType(int64_t id, int32_t videoScaleType, int32_t *errCode)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        *errCode = MSERR_EXT_API9_NO_MEMORY;
        return;
    }
    avPlayerImpl->SetVideoScaleType(videoScaleType);
}

int32_t FfiMediaAVPlayerGetAudioInterruptMode(int64_t id, int32_t *errCode)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        *errCode = MSERR_EXT_API9_NO_MEMORY;
        return 0;
    }
    return avPlayerImpl->GetAudioInterruptMode();
}

void FfiMediaAVPlayerSetAudioInterruptMode(int64_t id, int32_t interruptMode, int32_t *errCode)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        *errCode = MSERR_EXT_API9_NO_MEMORY;
        return;
    }
    avPlayerImpl->SetAudioInterruptMode(interruptMode);
}

OHOS::AudioStandard::CAudioRendererInfo FfiMediaAVPlayerGetAudioRendererInfo(int64_t id, int32_t *errCode)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        *errCode = MSERR_EXT_API9_NO_MEMORY;
        return OHOS::AudioStandard::CAudioRendererInfo{0};
    }
    return avPlayerImpl->GetAudioRendererInfo();
}

void FfiMediaAVPlayerSetAudioRendererInfo(int64_t id, OHOS::AudioStandard::CAudioRendererInfo info, int32_t *errCode)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        *errCode = MSERR_EXT_API9_NO_MEMORY;
        return;
    }
    avPlayerImpl->SetAudioRendererInfo(info);
}

int32_t FfiMediaAVPlayerGetAudioEffectMode(int64_t id, int32_t *errCode)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        *errCode = MSERR_EXT_API9_NO_MEMORY;
        return 0;
    }
    return avPlayerImpl->GetAudioEffectMode();
}

void FfiMediaAVPlayerSetAudioEffectMode(int64_t id, int32_t effectMode, int32_t *errCode)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        *errCode = MSERR_EXT_API9_NO_MEMORY;
        return;
    }
    avPlayerImpl->SetAudioEffectMode(effectMode);
}

char *FfiMediaAVPlayerGetState(int64_t id, int32_t *errCode)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        *errCode = MSERR_EXT_API9_NO_MEMORY;
        return nullptr;
    }
    return avPlayerImpl->GetState();
}

int32_t FfiMediaAVPlayerGetCurrentTime(int64_t id, int32_t *errCode)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        *errCode = MSERR_EXT_API9_NO_MEMORY;
        return 0;
    }
    return avPlayerImpl->GetCurrentTime();
}

int32_t FfiMediaAVPlayerGetDuration(int64_t id, int32_t *errCode)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        *errCode = MSERR_EXT_API9_NO_MEMORY;
        return 0;
    }
    return avPlayerImpl->GetDuration();
}

int32_t FfiMediaAVPlayerGetWidth(int64_t id, int32_t *errCode)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        *errCode = MSERR_EXT_API9_NO_MEMORY;
        return 0;
    }
    return avPlayerImpl->GetWidth();
}

int32_t FfiMediaAVPlayerGetHeight(int64_t id, int32_t *errCode)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        *errCode = MSERR_EXT_API9_NO_MEMORY;
        return 0;
    }
    return avPlayerImpl->GetHeight();
}

int32_t FfiMediaAVPlayerPrepare(int64_t id)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return avPlayerImpl->Prepare();
}

int32_t FfiMediaAVPlayerPlay(int64_t id)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return avPlayerImpl->Play();
}

int32_t FfiMediaAVPlayerPause(int64_t id)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return avPlayerImpl->Pause();
}

int32_t FfiMediaAVPlayerStop(int64_t id)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return avPlayerImpl->Stop();
}

int32_t FfiMediaAVPlayerReset(int64_t id)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return avPlayerImpl->Reset();
}

int32_t FfiMediaAVPlayerRelease(int64_t id)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return avPlayerImpl->Release();
}

int32_t FfiMediaAVPlayerSeek(int64_t id, int32_t time, int32_t mode)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    avPlayerImpl->Seek(time, mode);
    return MSERR_EXT_API9_OK;
}

int32_t FfiMediaAVPlayerOnStateChange(int64_t id, int64_t callbackId)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return avPlayerImpl->OnStateChange(callbackId);
}

int32_t FfiMediaAVPlayerOffStateChange(int64_t id, int64_t callbackId)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return avPlayerImpl->OffStateChange(callbackId);
}

int32_t FfiMediaAVPlayerOffStateChangeAll(int64_t id)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return avPlayerImpl->OffStateChangeAll();
}

int32_t FfiMediaAVPlayerOnError(int64_t id, int64_t callbackId)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return avPlayerImpl->OnError(callbackId);
}

int32_t FfiMediaAVPlayerOffError(int64_t id, int64_t callbackId)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return avPlayerImpl->OffError(callbackId);
}

int32_t FfiMediaAVPlayerOffErrorAll(int64_t id)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return avPlayerImpl->OffErrorAll();
}

int32_t FfiMediaAVPlayerOnSeekDone(int64_t id, int64_t callbackId)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return avPlayerImpl->OnSeekDone(callbackId);
}

int32_t FfiMediaAVPlayerOffSeekDone(int64_t id, int64_t callbackId)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return avPlayerImpl->OffSeekDone(callbackId);
}

int32_t FfiMediaAVPlayerOffSeekDoneAll(int64_t id)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return avPlayerImpl->OffSeekDoneAll();
}

int32_t FfiMediaAVPlayerOnSpeedDone(int64_t id, int64_t callbackId)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return avPlayerImpl->OnSpeedDone(callbackId);
}

int32_t FfiMediaAVPlayerOffSpeedDone(int64_t id, int64_t callbackId)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return avPlayerImpl->OffSpeedDone(callbackId);
}

int32_t FfiMediaAVPlayerOffSpeedDoneAll(int64_t id)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return avPlayerImpl->OffSpeedDoneAll();
}

int32_t FfiMediaAVPlayerOnBitRateDone(int64_t id, int64_t callbackId)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return avPlayerImpl->OnBitRateDone(callbackId);
}

int32_t FfiMediaAVPlayerOffBitRateDone(int64_t id, int64_t callbackId)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return avPlayerImpl->OffBitRateDone(callbackId);
}

int32_t FfiMediaAVPlayerOffBitRateDoneAll(int64_t id)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return avPlayerImpl->OffBitRateDoneAll();
}

int32_t FfiMediaAVPlayerOnAvailableBitrates(int64_t id, int64_t callbackId)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return avPlayerImpl->OnAvailableBitrates(callbackId);
}

int32_t FfiMediaAVPlayerOffAvailableBitrates(int64_t id, int64_t callbackId)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return avPlayerImpl->OffAvailableBitrates(callbackId);
}

int32_t FfiMediaAVPlayerOffAvailableBitratesAll(int64_t id)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return avPlayerImpl->OffAvailableBitratesAll();
}

int32_t FfiMediaAVPlayerOnMediaKeySystemInfoUpdate(int64_t id, int64_t callbackId)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return avPlayerImpl->OnMediaKeySystemInfoUpdate(callbackId);
}

int32_t FfiMediaAVPlayerOffMediaKeySystemInfoUpdate(int64_t id, int64_t callbackId)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return avPlayerImpl->OffMediaKeySystemInfoUpdate(callbackId);
}

int32_t FfiMediaAVPlayerOffMediaKeySystemInfoUpdateAll(int64_t id)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return avPlayerImpl->OffMediaKeySystemInfoUpdateAll();
}

int32_t FfiMediaAVPlayerOnVolumeChange(int64_t id, int64_t callbackId)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return avPlayerImpl->OnVolumeChange(callbackId);
}

int32_t FfiMediaAVPlayerOffVolumeChange(int64_t id, int64_t callbackId)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return avPlayerImpl->OffVolumeChange(callbackId);
}

int32_t FfiMediaAVPlayerOffVolumeChangeAll(int64_t id)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return avPlayerImpl->OffVolumeChangeAll();
}

int32_t FfiMediaAVPlayerOnEndOfStream(int64_t id, int64_t callbackId)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return avPlayerImpl->OnEndOfStream(callbackId);
}

int32_t FfiMediaAVPlayerOffEndOfStream(int64_t id, int64_t callbackId)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return avPlayerImpl->OffEndOfStream(callbackId);
}

int32_t FfiMediaAVPlayerOffEndOfStreamAll(int64_t id)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return avPlayerImpl->OffEndOfStreamAll();
}

int32_t FfiMediaAVPlayerOnTimeUpdate(int64_t id, int64_t callbackId)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return avPlayerImpl->OnTimeUpdate(callbackId);
}

int32_t FfiMediaAVPlayerOffTimeUpdate(int64_t id, int64_t callbackId)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return avPlayerImpl->OffTimeUpdate(callbackId);
}

int32_t FfiMediaAVPlayerOffTimeUpdateAll(int64_t id)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return avPlayerImpl->OffTimeUpdateAll();
}

int32_t FfiMediaAVPlayerOnDurationUpdate(int64_t id, int64_t callbackId)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return avPlayerImpl->OnDurationUpdate(callbackId);
}

int32_t FfiMediaAVPlayerOffDurationUpdate(int64_t id, int64_t callbackId)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return avPlayerImpl->OffDurationUpdate(callbackId);
}

int32_t FfiMediaAVPlayerOffDurationUpdateAll(int64_t id)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return avPlayerImpl->OffDurationUpdateAll();
}

int32_t FfiMediaAVPlayerOnBufferingUpdate(int64_t id, int64_t callbackId)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return avPlayerImpl->OnBufferingUpdate(callbackId);
}

int32_t FfiMediaAVPlayerOffBufferingUpdate(int64_t id, int64_t callbackId)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return avPlayerImpl->OffBufferingUpdate(callbackId);
}

int32_t FfiMediaAVPlayerOffBufferingUpdateAll(int64_t id)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return avPlayerImpl->OffBufferingUpdateAll();
}

int32_t FfiMediaAVPlayerOnStartRenderFrame(int64_t id, int64_t callbackId)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return avPlayerImpl->OnStartRenderFrame(callbackId);
}

int32_t FfiMediaAVPlayerOffStartRenderFrame(int64_t id, int64_t callbackId)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return avPlayerImpl->OffStartRenderFrame(callbackId);
}

int32_t FfiMediaAVPlayerOffStartRenderFrameAll(int64_t id)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return avPlayerImpl->OffStartRenderFrameAll();
}

int32_t FfiMediaAVPlayerOnVideoSizeChange(int64_t id, int64_t callbackId)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return avPlayerImpl->OnVideoSizeChange(callbackId);
}

int32_t FfiMediaAVPlayerOffVideoSizeChange(int64_t id, int64_t callbackId)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return avPlayerImpl->OffVideoSizeChange(callbackId);
}

int32_t FfiMediaAVPlayerOffVideoSizeChangeAll(int64_t id)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return avPlayerImpl->OffVideoSizeChangeAll();
}

int32_t FfiMediaAVPlayerOnAudioInterrupt(int64_t id, int64_t callbackId)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return avPlayerImpl->OnAudioInterrupt(callbackId);
}

int32_t FfiMediaAVPlayerOffAudioInterrupt(int64_t id, int64_t callbackId)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return avPlayerImpl->OffAudioInterrupt(callbackId);
}

int32_t FfiMediaAVPlayerOffAudioInterruptAll(int64_t id)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return avPlayerImpl->OffAudioInterruptAll();
}

int32_t FfiMediaAVPlayerOnAudioDeviceChange(int64_t id, int64_t callbackId)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return avPlayerImpl->OnAudioDeviceChange(callbackId);
}

int32_t FfiMediaAVPlayerOffAudioDeviceChange(int64_t id, int64_t callbackId)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return avPlayerImpl->OffAudioDeviceChange(callbackId);
}

int32_t FfiMediaAVPlayerOffAudioDeviceChangeAll(int64_t id)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return avPlayerImpl->OffAudioDeviceChangeAll();
}

int32_t FfiMediaAVPlayerOnSubtitleUpdate(int64_t id, int64_t callbackId)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return avPlayerImpl->OnSubtitleUpdate(callbackId);
}

int32_t FfiMediaAVPlayerOffSubtitleUpdate(int64_t id, int64_t callbackId)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return avPlayerImpl->OffSubtitleUpdate(callbackId);
}

int32_t FfiMediaAVPlayerOffSubtitleUpdateAll(int64_t id)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return avPlayerImpl->OffSubtitleUpdateAll();
}

int32_t FfiMediaAVPlayerOnTrackChange(int64_t id, int64_t callbackId)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return avPlayerImpl->OnTrackChange(callbackId);
}

int32_t FfiMediaAVPlayerOffTrackChange(int64_t id, int64_t callbackId)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return avPlayerImpl->OffTrackChange(callbackId);
}

int32_t FfiMediaAVPlayerOffTrackChangeAll(int64_t id)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return avPlayerImpl->OffTrackChangeAll();
}

int32_t FfiMediaAVPlayerOnTrackInfoUpdate(int64_t id, int64_t callbackId)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return avPlayerImpl->OnTrackInfoUpdate(callbackId);
}

int32_t FfiMediaAVPlayerOffTrackInfoUpdate(int64_t id, int64_t callbackId)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return avPlayerImpl->OffTrackInfoUpdate(callbackId);
}

int32_t FfiMediaAVPlayerOffTrackInfoUpdateAll(int64_t id)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return avPlayerImpl->OffTrackInfoUpdateAll();
}

int32_t FfiMediaAVPlayerOnAmplitudeUpdate(int64_t id, int64_t callbackId)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return avPlayerImpl->OnAmplitudeUpdate(callbackId);
}

int32_t FfiMediaAVPlayerOffAmplitudeUpdate(int64_t id, int64_t callbackId)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return avPlayerImpl->OffAmplitudeUpdate(callbackId);
}

int32_t FfiMediaAVPlayerOffAmplitudeUpdateAll(int64_t id)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return avPlayerImpl->OffAmplitudeUpdateAll();
}

int32_t FfiMediaAVPlayerSetMediaSource(int64_t id, int64_t srcId, CPlayStrategy strategy)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    auto mediaSrcImpl = FFIData::GetData<CJMediaSource>(srcId);
    if (mediaSrcImpl == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return avPlayerImpl->SetMediaSource(mediaSrcImpl->mediaSource, ConvertCPlaystrategy(strategy));
}

int32_t FfiMediaAVPlayerSetPlaybackStrategy(int64_t id, CPlayStrategy strategy)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return avPlayerImpl->SetPlaybackStrategy(ConvertCPlaystrategy(strategy));
}

int32_t FfiMediaAVPlayerSetMediaMuted(int64_t id, int32_t mediaType, bool muted)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return avPlayerImpl->SetMediaMuted(mediaType, muted);
}

CArrI32 FfiMediaAVPlayerGetSelectedTracks(int64_t id, int32_t *errCode)
{
    CArrI32 ret = {.head = nullptr, .size = 0};
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        *errCode = MSERR_EXT_API9_NO_MEMORY;
        return ret;
    }
    std::vector<int32_t> tracks;
    *errCode = avPlayerImpl->GetSelectedTracks(tracks);
    if (*errCode != MSERR_EXT_API9_OK) {
        return ret;
    }
    *errCode = VectorToRetData<CArrI32, int32_t>(ret, tracks);
    return ret;
}

int32_t FfiMediaAVPlayerSelectTrack(int64_t id, int32_t index, int32_t mode)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return avPlayerImpl->SelectTrack(index, mode);
}

int32_t FfiMediaAVPlayerDeselectTrack(int64_t id, int32_t index)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return avPlayerImpl->DeselectTrack(index);
}

void FreeCArrCMediaKeySystemInfo(CArrCMediaKeySystemInfo &info, int64_t index, bool isUuidNeed)
{
    for (int64_t i = 0; i < index; i++) {
        free(info.head[i].uuid);
        free(info.head[i].pssh.head);
        info.head[i].uuid = nullptr;
        info.head[i].pssh.head = nullptr;
    }
    if (isUuidNeed) {
        free(info.head[index].uuid);
        info.head[index].uuid = nullptr;
    }
}

void FfiMediaAVPlayerSetSpeed(int64_t id, int32_t speed)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        MEDIA_LOGE("failed to get CJAVPlayer");
        return;
    }
    avPlayerImpl->SetSpeed(speed);
}

void FfiMediaAVPlayerSetBitrate(int64_t id, int32_t bitrate)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        MEDIA_LOGE("failed to get CJAVPlayer");
        return;
    }
    avPlayerImpl->SetBitrate(bitrate);
}

void FfiMediaAVPlayerSetVolume(int64_t id, float volume)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        MEDIA_LOGE("failed to get CJAVPlayer");
        return;
    }
    avPlayerImpl->SetVolume(volume);
}

int32_t FfiMediaAVPlayerAddSubtitleFromFd(int64_t id, int32_t fd, int64_t offset, int64_t length)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        MEDIA_LOGE("failed to get CJAVPlayer");
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return avPlayerImpl->AddSubtitleFromFd(fd, offset, length);
}

int32_t FfiMediaAVPlayerAddSubtitleFromUrl(int64_t id, char *url)
{
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        MEDIA_LOGE("failed to get CJAVPlayer");
        return MSERR_EXT_API9_NO_MEMORY;
    }
    return avPlayerImpl->AddSubtitleFromUrl(std::string(url));
}

void FreeCPlaybackInfos(CPlaybackInfo *infos, int64_t index)
{
    for (int64_t i = 0; i < index; i++) {
        free(infos[i].value);
        infos[i].value = nullptr;
    }
    free(infos);
}

bool GetServerIpAddress(Format &format, CPlaybackInfo *infos, int64_t &index)
{
    std::string ip;
    if (format.GetStringValue(PlaybackInfoKey::SERVER_IP_ADDRESS, ip)) {
        char *data = MallocCString(ip);
        if (data == nullptr) {
            free(infos);
            return false;
        }
        infos[index].value = static_cast<void *>(data);
        infos[index].key = g_serverIpAddressCode;
        index++;
    }
    return true;
}

bool GetAvgDnowloadRate(Format &format, CPlaybackInfo *infos, int64_t &index)
{
    int64_t avgDnowloadRate;
    if (format.GetLongValue(PlaybackInfoKey::AVG_DOWNLOAD_RATE, avgDnowloadRate)) {
        infos[index].value = MallocObject<int64_t>(avgDnowloadRate);
        if (infos[index].value == nullptr) {
            FreeCPlaybackInfos(infos, index);
            return false;
        }
        infos[index].key = g_avgDownloadRateCode;
        index++;
    }
    return true;
}

bool GetDnowloadRate(Format &format, CPlaybackInfo *infos, int64_t &index)
{
    int64_t dnowloadRate;
    if (format.GetLongValue(PlaybackInfoKey::DOWNLOAD_RATE, dnowloadRate)) {
        infos[index].value = MallocObject<int64_t>(dnowloadRate);
        if (infos[index].value == nullptr) {
            FreeCPlaybackInfos(infos, index);
            return false;
        }
        infos[index].key = g_downloadRateCode;
        index++;
    }
    return true;
}

CArrCPlaybackInfo ConvertPlaybackInfo(Format &format, int32_t *errCode)
{
    CArrCPlaybackInfo ret = {.infos = nullptr, .size = 0};
    auto formatMap = format.GetFormatMap();
    auto size = static_cast<int64_t>(formatMap.size());
    if (size <= 0) {
        return ret;
    }
    *errCode = MSERR_EXT_API9_NO_MEMORY;
    CPlaybackInfo *infos = static_cast<CPlaybackInfo *>(malloc(sizeof(CPlaybackInfo) * size));
    if (infos == nullptr) {
        return ret;
    }
    int64_t index = 0;
    if (!GetServerIpAddress(format, infos, index)) {
        return ret;
    }
    if (!GetAvgDnowloadRate(format, infos, index)) {
        return ret;
    }
    if (!GetDnowloadRate(format, infos, index)) {
        return ret;
    }
    int32_t isDnowloading;
    if (format.GetIntValue(PlaybackInfoKey::IS_DOWNLOADING, isDnowloading)) {
        infos[index].value = MallocObject<int32_t>(isDnowloading);
        if (infos[index].value == nullptr) {
            FreeCPlaybackInfos(infos, index);
            return ret;
        }
        infos[index].key = g_isDownloadingCode;
        index++;
    }
    int64_t bufferDuration;
    if (format.GetLongValue(PlaybackInfoKey::BUFFER_DURATION, bufferDuration)) {
        infos[index].value = MallocObject<int64_t>(bufferDuration);
        if (infos[index].value == nullptr) {
            FreeCPlaybackInfos(infos, index);
            return ret;
        }
        infos[index].key = g_bufferDurationCode;
    }
    ret.infos = infos;
    ret.size = size;
    *errCode = MSERR_EXT_API9_OK;
    return ret;
}

CArrCPlaybackInfo FfiMediaAVPlayerGetPlaybackInfo(int64_t id, int32_t *errCode)
{
    CArrCPlaybackInfo info = {.infos = nullptr, .size = 0};
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        MEDIA_LOGE("failed to get CJAVPlayer");
        *errCode = MSERR_EXT_API9_NO_MEMORY;
        return info;
    }
    Format format;
    *errCode = avPlayerImpl->GetPlaybackInfo(format);
    if (*errCode != MSERR_EXT_API9_OK) {
        return info;
    }
    return ConvertPlaybackInfo(format, errCode);
}

CArrCMediaDescription FfiMediaAVPlayerGetTrackDescription(int64_t id, int32_t *errCode)
{
    CArrCMediaDescription info = {.head = nullptr, .size = 0};
    auto avPlayerImpl = FFIData::GetData<CJAVPlayer>(id);
    if (avPlayerImpl == nullptr) {
        MEDIA_LOGE("failed to get CJAVPlayer");
        *errCode = MSERR_EXT_API9_NO_MEMORY;
        return info;
    }
    std::vector<Format> trackInfos;
    *errCode = avPlayerImpl->GetTrackDescription(trackInfos);
    if (*errCode != MSERR_EXT_API9_OK) {
        return info;
    }
    return Convert2CArrCMediaDescription(trackInfos);
}
} // extern "C"
} // namespace Media
} // namespace OHOS
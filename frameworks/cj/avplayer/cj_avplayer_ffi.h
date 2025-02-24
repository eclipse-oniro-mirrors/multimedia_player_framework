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

#ifndef CJ_AVPLAYER_FFI_H
#define CJ_AVPLAYER_FFI_H

#include "cj_avplayer.h"
#include "cj_avplayer_utils.h"
#include "cj_common_ffi.h"
#include "ffi_remote_data.h"

namespace OHOS {
namespace Media {

extern "C" {
// AVPlayer
FFI_EXPORT int64_t FfiMediaCreateAVPlayer(int32_t *errCode);

FFI_EXPORT char *FfiMediaAVPlayerGetUrl(int64_t id, int32_t *errCode);
FFI_EXPORT void FfiMediaAVPlayerSetUrl(int64_t id, char *url, int32_t *errCode);
FFI_EXPORT CAVFileDescriptor FfiMediaAVPlayerGetAVFileDescriptor(int64_t id, int32_t *errCode);
FFI_EXPORT void FfiMediaAVPlayerSetAVFileDescriptor(int64_t id, CAVFileDescriptor fileDescriptor, int32_t *errCode);
FFI_EXPORT CAVDataSrcDescriptor FfiMediaAVPlayerGetDataSrc(int64_t id, int32_t *errCode);
FFI_EXPORT void FfiMediaAVPlayerSetDataSrc(int64_t id, CAVDataSrcDescriptor dataSrcDescriptor, int32_t *errCode);
FFI_EXPORT char *FfiMediaAVPlayerGetSurfaceID(int64_t id, int32_t *errCode);
FFI_EXPORT void FfiMediaAVPlayerSetSurfaceID(int64_t id, char *surfaceId, int32_t *errCode);
FFI_EXPORT bool FfiMediaAVPlayerGetLoop(int64_t id, int32_t *errCode);
FFI_EXPORT void FfiMediaAVPlayerSetLoop(int64_t id, bool loop, int32_t *errCode);
FFI_EXPORT int32_t FfiMediaAVPlayerGetVideoScaleType(int64_t id, int32_t *errCode);
FFI_EXPORT void FfiMediaAVPlayerSetVideoScaleType(int64_t id, int32_t videoScaleType, int32_t *errCode);
FFI_EXPORT int32_t FfiMediaAVPlayerGetAudioInterruptMode(int64_t id, int32_t *errCode);
FFI_EXPORT void FfiMediaAVPlayerSetAudioInterruptMode(int64_t id, int32_t interruptMode, int32_t *errCode);
FFI_EXPORT OHOS::AudioStandard::CAudioRendererInfo FfiMediaAVPlayerGetAudioRendererInfo(int64_t id, int32_t *errCode);
FFI_EXPORT void FfiMediaAVPlayerSetAudioRendererInfo(int64_t id, OHOS::AudioStandard::CAudioRendererInfo info,
                                                     int32_t *errCode);
FFI_EXPORT int32_t FfiMediaAVPlayerGetAudioEffectMode(int64_t id, int32_t *errCode);
FFI_EXPORT void FfiMediaAVPlayerSetAudioEffectMode(int64_t id, int32_t effectMode, int32_t *errCode);
FFI_EXPORT char *FfiMediaAVPlayerGetState(int64_t id, int32_t *errCode);
FFI_EXPORT int32_t FfiMediaAVPlayerGetCurrentTime(int64_t id, int32_t *errCode);
FFI_EXPORT int32_t FfiMediaAVPlayerGetDuration(int64_t id, int32_t *errCode);
FFI_EXPORT int32_t FfiMediaAVPlayerGetWidth(int64_t id, int32_t *errCode);
FFI_EXPORT int32_t FfiMediaAVPlayerGetHeight(int64_t id, int32_t *errCode);

FFI_EXPORT int32_t FfiMediaAVPlayerPrepare(int64_t id);
FFI_EXPORT int32_t FfiMediaAVPlayerPlay(int64_t id);
FFI_EXPORT int32_t FfiMediaAVPlayerPause(int64_t id);
FFI_EXPORT int32_t FfiMediaAVPlayerStop(int64_t id);
FFI_EXPORT int32_t FfiMediaAVPlayerReset(int64_t id);
FFI_EXPORT int32_t FfiMediaAVPlayerRelease(int64_t id);
FFI_EXPORT int32_t FfiMediaAVPlayerSeek(int64_t id, int32_t time, int32_t mode);

FFI_EXPORT int32_t FfiMediaAVPlayerOnStateChange(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiMediaAVPlayerOffStateChange(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiMediaAVPlayerOffStateChangeAll(int64_t id);
FFI_EXPORT int32_t FfiMediaAVPlayerOnError(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiMediaAVPlayerOffError(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiMediaAVPlayerOffErrorAll(int64_t id);
FFI_EXPORT int32_t FfiMediaAVPlayerOnSeekDone(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiMediaAVPlayerOffSeekDone(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiMediaAVPlayerOffSeekDoneAll(int64_t id);
FFI_EXPORT int32_t FfiMediaAVPlayerOnSpeedDone(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiMediaAVPlayerOffSpeedDone(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiMediaAVPlayerOffSpeedDoneAll(int64_t id);
FFI_EXPORT int32_t FfiMediaAVPlayerOnBitRateDone(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiMediaAVPlayerOffBitRateDone(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiMediaAVPlayerOffBitRateDoneAll(int64_t id);
FFI_EXPORT int32_t FfiMediaAVPlayerOnAvailableBitrates(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiMediaAVPlayerOffAvailableBitrates(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiMediaAVPlayerOffAvailableBitratesAll(int64_t id);
FFI_EXPORT int32_t FfiMediaAVPlayerOnMediaKeySystemInfoUpdate(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiMediaAVPlayerOffMediaKeySystemInfoUpdate(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiMediaAVPlayerOffMediaKeySystemInfoUpdateAll(int64_t id);
FFI_EXPORT int32_t FfiMediaAVPlayerOnVolumeChange(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiMediaAVPlayerOffVolumeChange(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiMediaAVPlayerOffVolumeChangeAll(int64_t id);
FFI_EXPORT int32_t FfiMediaAVPlayerOnEndOfStream(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiMediaAVPlayerOffEndOfStream(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiMediaAVPlayerOffEndOfStreamAll(int64_t id);
FFI_EXPORT int32_t FfiMediaAVPlayerOnTimeUpdate(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiMediaAVPlayerOffTimeUpdate(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiMediaAVPlayerOffTimeUpdateAll(int64_t id);
FFI_EXPORT int32_t FfiMediaAVPlayerOnDurationUpdate(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiMediaAVPlayerOffDurationUpdate(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiMediaAVPlayerOffDurationUpdateAll(int64_t id);
FFI_EXPORT int32_t FfiMediaAVPlayerOnBufferingUpdate(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiMediaAVPlayerOffBufferingUpdate(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiMediaAVPlayerOffBufferingUpdateAll(int64_t id);
FFI_EXPORT int32_t FfiMediaAVPlayerOnStartRenderFrame(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiMediaAVPlayerOffStartRenderFrame(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiMediaAVPlayerOffStartRenderFrameAll(int64_t id);
FFI_EXPORT int32_t FfiMediaAVPlayerOnVideoSizeChange(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiMediaAVPlayerOffVideoSizeChange(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiMediaAVPlayerOffVideoSizeChangeAll(int64_t id);
FFI_EXPORT int32_t FfiMediaAVPlayerOnAudioInterrupt(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiMediaAVPlayerOffAudioInterrupt(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiMediaAVPlayerOffAudioInterruptAll(int64_t id);
FFI_EXPORT int32_t FfiMediaAVPlayerOnAudioDeviceChange(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiMediaAVPlayerOffAudioDeviceChange(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiMediaAVPlayerOffAudioDeviceChangeAll(int64_t id);
FFI_EXPORT int32_t FfiMediaAVPlayerOnSubtitleUpdate(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiMediaAVPlayerOffSubtitleUpdate(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiMediaAVPlayerOffSubtitleUpdateAll(int64_t id);
FFI_EXPORT int32_t FfiMediaAVPlayerOnTrackChange(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiMediaAVPlayerOffTrackChange(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiMediaAVPlayerOffTrackChangeAll(int64_t id);
FFI_EXPORT int32_t FfiMediaAVPlayerOnTrackInfoUpdate(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiMediaAVPlayerOffTrackInfoUpdate(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiMediaAVPlayerOffTrackInfoUpdateAll(int64_t id);
FFI_EXPORT int32_t FfiMediaAVPlayerOnAmplitudeUpdate(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiMediaAVPlayerOffAmplitudeUpdate(int64_t id, int64_t callbackId);
FFI_EXPORT int32_t FfiMediaAVPlayerOffAmplitudeUpdateAll(int64_t id);

FFI_EXPORT int32_t FfiMediaAVPlayerSetMediaSource(int64_t id, int64_t srcId, CPlayStrategy strategy);
FFI_EXPORT int32_t FfiMediaAVPlayerSetPlaybackStrategy(int64_t id, CPlayStrategy strategy);
FFI_EXPORT int32_t FfiMediaAVPlayerSetMediaMuted(int64_t id, int32_t mediaType, bool muted);
FFI_EXPORT CArrI32 FfiMediaAVPlayerGetSelectedTracks(int64_t id, int32_t *errCode);
FFI_EXPORT int32_t FfiMediaAVPlayerSelectTrack(int64_t id, int32_t index, int32_t mode);
FFI_EXPORT int32_t FfiMediaAVPlayerDeselectTrack(int64_t id, int32_t index);
FFI_EXPORT CArrCMediaKeySystemInfo FfiMediaAVPlayerGetMediaKeySystemInfos(int64_t id, int32_t *errCode);
FFI_EXPORT void FfiMediaAVPlayerSetSpeed(int64_t id, int32_t speed);
FFI_EXPORT void FfiMediaAVPlayerSetBitrate(int64_t id, int32_t bitrate);
FFI_EXPORT void FfiMediaAVPlayerSetVolume(int64_t id, float volume);
FFI_EXPORT int32_t FfiMediaAVPlayerAddSubtitleFromFd(int64_t id, int32_t fd, int64_t offset, int64_t length);
FFI_EXPORT int32_t FfiMediaAVPlayerAddSubtitleFromUrl(int64_t id, char *url);
FFI_EXPORT CArrCPlaybackInfo FfiMediaAVPlayerGetPlaybackInfo(int64_t id, int32_t *errCode);
FFI_EXPORT CArrCMediaDescription FfiMediaAVPlayerGetTrackDescription(int64_t id, int32_t *errCode);
} // extern "C"
} // namespace Media
} // namespace OHOS
#endif
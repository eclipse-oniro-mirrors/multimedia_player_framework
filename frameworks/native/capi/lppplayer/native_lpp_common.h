/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef NATIVE_LPP_COMMON_H
#define NATIVE_LPP_COMMON_H

#include <memory>
#include <mutex>
#include <refbase.h>
#include <securec.h>

#include "media_log.h"
#include "media_errors.h"
#include "native_averrors.h"
#include "native_mfmagic.h"
#include "native_player_magic.h"
#include "lpp_audio_streamer.h"
#include "native_averrors.h"
#include "lowpower_audio_sink.h"
#include "lowpower_video_sink.h"
#include "lowpower_avsink_base.h"
#include "native_avbuffer.h"
#include "lpp_video_streamer.h"
#include "lpp_common.h"
#include "native_window.h"

namespace OHOS {
namespace Media {

const std::map<MediaServiceExtErrCodeAPI9, OH_AVErrCode> MSERREXT_TO_OHAVERR_MAP = {
    {MSERR_EXT_API9_OK, AV_ERR_OK},
    {MSERR_EXT_API9_NO_PERMISSION, AV_ERR_OPERATE_NOT_PERMIT},
    {MSERR_EXT_API9_PERMISSION_DENIED, AV_ERR_OPERATE_NOT_PERMIT},
    {MSERR_EXT_API9_INVALID_PARAMETER, AV_ERR_INVALID_VAL},
    {MSERR_EXT_API9_UNSUPPORT_CAPABILITY, AV_ERR_OPERATE_NOT_PERMIT},
    {MSERR_EXT_API9_NO_MEMORY, AV_ERR_NO_MEMORY},
    {MSERR_EXT_API9_OPERATE_NOT_PERMIT, AV_ERR_OPERATE_NOT_PERMIT},
    {MSERR_EXT_API9_IO, AV_ERR_IO},
    {MSERR_EXT_API9_TIMEOUT, AV_ERR_TIMEOUT},
    {MSERR_EXT_API9_SERVICE_DIED, AV_ERR_SERVICE_DIED},
    {MSERR_EXT_API9_UNSUPPORT_FORMAT, AV_ERR_UNSUPPORT},
    {MSERR_EXT_API9_AUDIO_INTERRUPTED, AV_ERR_OPERATE_NOT_PERMIT},
    {MSERR_EXT_API20_HARDWARE_FAILED, AV_ERR_HARDWARE_FAILED},
};

inline __attribute__((visibility("default"))) OH_AVErrCode LppMsErrToOHAvErr(int32_t code)
{
    MediaServiceExtErrCodeAPI9 errCode = MSErrorToExtErrorAPI9(static_cast<MediaServiceErrCode>(code));
    if (MSERREXT_TO_OHAVERR_MAP.find(errCode) != MSERREXT_TO_OHAVERR_MAP.end()) {
        return MSERREXT_TO_OHAVERR_MAP.at(errCode);
    }
    return AV_ERR_IO;
}

struct AVSamplesBufferObject : public OH_AVSamplesBuffer {
    explicit AVSamplesBufferObject(OHOS::sptr<LppDataPacket> &lppDataPacket) : lppDataPacket_(lppDataPacket)
    {}
    ~AVSamplesBufferObject() = default;

    OHOS::sptr<LppDataPacket> lppDataPacket_ = nullptr;
};

struct LowPowerAudioSinkObject : public OH_LowPowerAudioSink {
    explicit LowPowerAudioSinkObject(
        const std::shared_ptr<AudioStreamer> &audioStreamer, AVSamplesBufferObject *framePacket)
        : audioStreamer_(audioStreamer), framePacket_(framePacket)
    {}
    ~LowPowerAudioSinkObject() = default;

    const std::shared_ptr<AudioStreamer> audioStreamer_ = nullptr;
    AVSamplesBufferObject *framePacket_ = nullptr;
};

struct LowPowerVideoSinkObject : public OH_LowPowerVideoSink {
    explicit LowPowerVideoSinkObject(
        const std::shared_ptr<VideoStreamer> &videoStreamer, AVSamplesBufferObject *framePacket)
        : videoStreamer_(videoStreamer), framePacket_(framePacket)
    {}
    ~LowPowerVideoSinkObject() = default;

    const std::shared_ptr<VideoStreamer> videoStreamer_ = nullptr;
    AVSamplesBufferObject *framePacket_ = nullptr;
};
}  // namespace Media
}  // namespace OHOS
#endif  // NATIVE_LPP_COMMON_H
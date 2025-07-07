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

#include "media_lpp_errors.h"
#include "avcodec_errors.h"
#include "audio_errors.h"
#include "audio_info.h"
#ifdef SUPPORT_LPP
#include "hdf_base.h"
#endif


namespace OHOS {
namespace Media {
const std::map<MediaAVCodec::AVCodecServiceErrCode, MediaServiceErrCode> AVCSERROR_TO_MSERROR = {
    {MediaAVCodec::AVCS_ERR_OK,                                   MSERR_OK},
    {MediaAVCodec::AVCS_ERR_NO_MEMORY,                            MSERR_NO_MEMORY},
    {MediaAVCodec::AVCS_ERR_INVALID_OPERATION,                    MSERR_INVALID_OPERATION},
    {MediaAVCodec::AVCS_ERR_INVALID_VAL,                          MSERR_INVALID_VAL},
    {MediaAVCodec::AVCS_ERR_UNKNOWN,                              MSERR_UNKNOWN},
    {MediaAVCodec::AVCS_ERR_SERVICE_DIED,                         MSERR_SERVICE_DIED},
    {MediaAVCodec::AVCS_ERR_INVALID_STATE,                        MSERR_INVALID_STATE},
    {MediaAVCodec::AVCS_ERR_UNSUPPORT,                            MSERR_UNSUPPORT},
    {MediaAVCodec::AVCS_ERR_UNSUPPORT_AUD_SRC_TYPE,               MSERR_UNSUPPORT_AUD_SRC_TYPE},
    {MediaAVCodec::AVCS_ERR_UNSUPPORT_AUD_SAMPLE_RATE,            MSERR_UNSUPPORT_AUD_SAMPLE_RATE},
    {MediaAVCodec::AVCS_ERR_UNSUPPORT_AUD_CHANNEL_NUM,            MSERR_UNSUPPORT_AUD_CHANNEL_NUM},
    {MediaAVCodec::AVCS_ERR_UNSUPPORT_AUD_ENC_TYPE,               MSERR_UNSUPPORT_AUD_ENC_TYPE},
    {MediaAVCodec::AVCS_ERR_UNSUPPORT_AUD_PARAMS,                 MSERR_UNSUPPORT_AUD_PARAMS},
    {MediaAVCodec::AVCS_ERR_UNSUPPORT_VID_SRC_TYPE,               MSERR_UNSUPPORT_VID_SRC_TYPE},
    {MediaAVCodec::AVCS_ERR_UNSUPPORT_VID_ENC_TYPE,               MSERR_UNSUPPORT_VID_ENC_TYPE},
    {MediaAVCodec::AVCS_ERR_UNSUPPORT_VID_PARAMS,                 MSERR_UNSUPPORT_VID_PARAMS},
    {MediaAVCodec::AVCS_ERR_UNSUPPORT_FILE_TYPE,                  MSERR_UNSUPPORT_FILE},
    {MediaAVCodec::AVCS_ERR_UNSUPPORT_PROTOCOL_TYPE,              MSERR_UNSUPPORT_PROTOCOL_TYPE},
    {MediaAVCodec::AVCS_ERR_UNSUPPORT_VID_DEC_TYPE,               MSERR_UNSUPPORT_VID_DEC_TYPE},
    {MediaAVCodec::AVCS_ERR_UNSUPPORT_AUD_DEC_TYPE,               MSERR_UNSUPPORT_AUD_DEC_TYPE},
    {MediaAVCodec::AVCS_ERR_UNSUPPORT_STREAM,                     MSERR_UNSUPPORT_STREAM},
    {MediaAVCodec::AVCS_ERR_UNSUPPORT_SOURCE,                     MSERR_UNSUPPORT_SOURCE},
    {MediaAVCodec::AVCS_ERR_AUD_RENDER_FAILED,                    MSERR_AUD_RENDER_FAILED},
    {MediaAVCodec::AVCS_ERR_AUD_ENC_FAILED,                       MSERR_AUD_ENC_FAILED},
    {MediaAVCodec::AVCS_ERR_VID_ENC_FAILED,                       MSERR_VID_ENC_FAILED},
    {MediaAVCodec::AVCS_ERR_AUD_DEC_FAILED,                       MSERR_AUD_DEC_FAILED},
    {MediaAVCodec::AVCS_ERR_VID_DEC_FAILED,                       MSERR_VID_DEC_FAILED},
    {MediaAVCodec::AVCS_ERR_MUXER_FAILED,                         MSERR_MUXER_FAILED},
    {MediaAVCodec::AVCS_ERR_DEMUXER_FAILED,                       MSERR_DEMUXER_FAILED},
    {MediaAVCodec::AVCS_ERR_OPEN_FILE_FAILED,                     MSERR_OPEN_FILE_FAILED},
    {MediaAVCodec::AVCS_ERR_FILE_ACCESS_FAILED,                   MSERR_FILE_ACCESS_FAILED},
    {MediaAVCodec::AVCS_ERR_START_FAILED,                         MSERR_START_FAILED},
    {MediaAVCodec::AVCS_ERR_PAUSE_FAILED,                         MSERR_PAUSE_FAILED},
    {MediaAVCodec::AVCS_ERR_STOP_FAILED,                          MSERR_STOP_FAILED},
    {MediaAVCodec::AVCS_ERR_SEEK_FAILED,                          MSERR_SEEK_FAILED},
    {MediaAVCodec::AVCS_ERR_NETWORK_TIMEOUT,                      MSERR_NETWORK_TIMEOUT},
    {MediaAVCodec::AVCS_ERR_NOT_FIND_FILE,                        MSERR_NOT_FIND_CONTAINER},
    {MediaAVCodec::AVCS_ERR_DATA_SOURCE_IO_ERROR,                 MSERR_DATA_SOURCE_IO_ERROR},
    {MediaAVCodec::AVCS_ERR_DATA_SOURCE_OBTAIN_MEM_ERROR,         MSERR_DATA_SOURCE_ERROR_UNKNOWN},
    {MediaAVCodec::AVCS_ERR_DATA_SOURCE_ERROR_UNKNOWN,            MSERR_DATA_SOURCE_ERROR_UNKNOWN},
    {MediaAVCodec::AVCS_ERR_CODEC_PARAM_INCORRECT,                MSERR_PARAMETER_VERIFICATION_FAILED},
    {MediaAVCodec::AVCS_ERR_NOT_ENOUGH_DATA,                      MSERR_INVALID_VAL},
    {MediaAVCodec::AVCS_ERR_CONFIGURE_MISMATCH_CHANNEL_COUNT,     MSERR_INCORRECT_PARAMETER_TYPE},
    {MediaAVCodec::AVCS_ERR_MISMATCH_SAMPLE_RATE,                 MSERR_INCORRECT_PARAMETER_TYPE},
    {MediaAVCodec::AVCS_ERR_MISMATCH_BIT_RATE,                    MSERR_INCORRECT_PARAMETER_TYPE},
    {MediaAVCodec::AVCS_ERR_CONFIGURE_ERROR,                      MSERR_UNSUPPORT},
    {MediaAVCodec::AVCS_ERR_INVALID_DATA,                         MSERR_INVALID_VAL},
    {MediaAVCodec::AVCS_ERR_INPUT_DATA_ERROR,                     MSERR_INVALID_VAL},
};

const std::map<int32_t, MediaServiceErrCode> AUDIOSTANDARDERROR_TO_MSERROR = {
    {AudioStandard::SUCCESS,                                MSERR_OK},
    {AudioStandard::ERROR,                                  MSERR_AUD_RENDER_FAILED},
    {AudioStandard::ERR_ILLEGAL_STATE,                      MSERR_INVALID_STATE},
    {AudioStandard::ERR_EARLY_PREPARE,                      MSERR_INVALID_OPERATION},
    {AudioStandard::ERR_INVALID_OPERATION,                  MSERR_INVALID_OPERATION},
    {AudioStandard::ERR_OPERATION_FAILED,                   MSERR_INVALID_OPERATION},
    {AudioStandard::ERR_READ_BUFFER,                        MSERR_AUD_RENDER_FAILED},
    {AudioStandard::ERR_WRITE_BUFFER,                       MSERR_AUD_RENDER_FAILED},
    {AudioStandard::ERR_NOT_STARTED,                        MSERR_AUD_RENDER_FAILED},
    {AudioStandard::ERR_INVALID_HANDLE,                     MSERR_INVALID_OPERATION},
    {AudioStandard::ERR_NOT_SUPPORTED,                      MSERR_UNSUPPORT},
    {AudioStandard::ERR_DEVICE_NOT_SUPPORTED,               MSERR_UNSUPPORT},
    {AudioStandard::ERR_WRITE_FAILED,                       MSERR_AUD_RENDER_FAILED},
    {AudioStandard::ERR_READ_FAILED,                        MSERR_AUD_RENDER_FAILED},
    {AudioStandard::ERR_DEVICE_INIT,                        MSERR_AUD_RENDER_FAILED},
    {AudioStandard::ERR_INVALID_READ,                       MSERR_INVALID_VAL},
    {AudioStandard::ERR_INVALID_WRITE,                      MSERR_INVALID_VAL},
    {AudioStandard::ERR_INVALID_INDEX,                      MSERR_INVALID_VAL},
    {AudioStandard::ERR_FOCUS_DENIED,                       MSERR_AUD_RENDER_FAILED},
    {AudioStandard::ERR_PERMISSION_DENIED,                  MSERR_UNSUPPORT},
    {AudioStandard::ERR_MICROPHONE_DISABLED_BY_EDM,         MSERR_UNSUPPORT},
    {AudioStandard::ERR_SYSTEM_PERMISSION_DENIED,           MSERR_UNSUPPORT},
    {AudioStandard::ERR_CALLBACK_NOT_REGISTERED,            MSERR_INVALID_VAL},
    {AudioStandard::ERR_NEED_NOT_SWITCH_DEVICE,             MSERR_INVALID_OPERATION},
    {AudioStandard::ERR_CONCEDE_INCOMING_STREAM,            MSERR_INVALID_VAL},
    {AudioStandard::ERR_RENDERER_IN_SERVER_UNDERRUN,        MSERR_INVALID_VAL},
    {AudioStandard::ERR_EXCEED_MAX_STREAM_CNT,              MSERR_UNSUPPORT},
    {AudioStandard::ERR_EXCEED_MAX_STREAM_CNT_PER_UID,      MSERR_UNSUPPORT},
    {AudioStandard::ERR_NULL_POINTER,                       MSERR_INVALID_VAL},
    {AudioStandard::ERR_MMI_SUBSCRIBE,                      MSERR_INVALID_VAL},
    {AudioStandard::ERR_SET_VOL_FAILED_BY_SAFE_VOL,         MSERR_INVALID_VAL},
    {AudioStandard::ERR_CONFIG_NAME_ERROR,                  MSERR_INVALID_VAL},
    {AudioStandard::ERR_RETRY_IN_CLIENT,                    MSERR_AUD_RENDER_FAILED},
    {AudioStandard::ERR_AUDIO_STREAM_REGISTER_EXCEED_MAX,   MSERR_INVALID_VAL},
    {AudioStandard::ERR_AUDIO_STREAM_REGISTER_REPEAT,       MSERR_INVALID_VAL},
};

const std::map<AudioStandard::AudioErrors, MediaServiceErrCode> AUDIOINFOERROR_TO_MSERROR = {
    {AudioStandard::ERROR_INVALID_PARAM,        MSERR_INVALID_VAL},
    {AudioStandard::ERROR_NO_MEMORY,            MSERR_NO_MEMORY},
    {AudioStandard::ERROR_ILLEGAL_STATE,        MSERR_INVALID_STATE},
    {AudioStandard::ERROR_UNSUPPORTED,          MSERR_UNSUPPORT},
    {AudioStandard::ERROR_TIMEOUT,              MSERR_AUD_RENDER_FAILED},
    {AudioStandard::ERROR_UNSUPPORTED_FORMAT,   MSERR_UNSUPPORT_AUD_SRC_TYPE},
    {AudioStandard::ERROR_STREAM_LIMIT,         MSERR_UNSUPPORT_STREAM},
    {AudioStandard::ERROR_SYSTEM,               MSERR_AUD_RENDER_FAILED},
};


#ifdef SUPPORT_LPP
const std::map<HDF_STATUS, MediaServiceErrCode> HDF_STATUS_TO_MSERROR = {
    {HDF_SUCCESS,   MSERR_OK},
    {HDF_FAILURE,   MSERR_HARDWARE_ERROR},
};
#endif

#ifdef SUPPORT_LPP
const std::map<HDFErrCode, MediaServiceErrCode> HDF_ERROR_TO_MSERROR = {
    {HDF_ERR_OK,                            MSERR_OK},
    {HDF_ERR_SHB_TIME_ANCHOR_GIANT_GAP,     MSERR_OK},
    {HDF_ERR_SHB_SET_SPEED_ERR,             MSERR_OK},
    {HDF_ERR_SHB_THREAD_CREATE_FAIL,        MSERR_SHB_THREAD_CREATION_FAILED},
    {HDF_ERR_SHB_MUTEX_INIT_FAIL,           MSERR_SHB_INIT_FAILED},
    {HDF_ERR_SHB_TIMER_INIT_FAIL,           MSERR_SHB_INIT_FAILED},
    {HDF_ERR_SHB_MSG_QUEUE_CREATE_FAIL,     MSERR_SHB_MSG_QUE_CREATION_FAILED},
    {HDF_ERR_SHB_MEM_ALLOC_FAIL,            MSERR_SHB_NO_MEMORY},
    {HDF_ERR_SHB_DACC_INIT_FAIL,            MSERR_SHB_INIT_FAILED},
    {HDF_ERR_SHB_RS_RINGBUFF_INIT_FAIL,     MSERR_RS_INIT_FAILED},
    {HDF_ERR_SHB_RS_UPLOAD_DATA_FAIL,       MSERR_RS_DATA_FALLBACK_FAILED},
    {HDF_ERR_SHB_VDEC_RINGBUFF_INIT_FAIL,   MSERR_RS_INIT_FAILED},
    {HDF_ERR_SHB_OUTPUT_BUFF_FOUND_ERR,     MSERR_INVALID_OPERATION},
    {HDF_ERR_SHB_SID_INVALID_ERR,           MSERR_INVALID_VAL},
    {HDF_ERR_SHB_INVALID_BUFF_CNT,          MSERR_INVALID_VAL},
    {HDF_ERR_LPPDRV_INSTANCE_EXCEED_LIMIT,  MSERR_LPP_INSTANCE_EXCEED_LIMIT},
    {HDF_ERR_LPPDRV_STATE_MACH_ERR,         MSERR_INVALID_OPERATION},
    {HDF_ERR_LPPDRV_MMAP_FAIL,              MSERR_NO_MEMORY},
    {HDF_ERR_LPPDRV_SHB_CRASH,              MSERR_SHB_CRASH_ERROR},
    {HDF_ERR_DSS_CREATE_FAIL,               MSERR_DSS_THREAD_CREATION_FAILED},
    {HDF_ERR_DSS_MUTEX_TIMEOUT_FAIL,        MSERR_DSS_STRAT_FAILED},
    {HDF_ERR_DSS_POWER_STATE_CHECK_FAIL,    MSERR_DSS_STRAT_FAILED},
    {HDF_ERR_DSS_VSYNC_REGIST_FAIL,         MSERR_DSS_STRAT_FAILED},
};
#endif

MediaServiceErrCode AVCSErrorToMSError(int32_t code)
{
    MediaAVCodec::AVCodecServiceErrCode errCode = static_cast<MediaAVCodec::AVCodecServiceErrCode>(code);
    if (AVCSERROR_TO_MSERROR.find(errCode) != AVCSERROR_TO_MSERROR.end()) {
        return AVCSERROR_TO_MSERROR.at(errCode);
    }
    return MSERR_UNSUPPORT;
}

MediaServiceErrCode AudioStandardStatusToMSError(int32_t code)
{
    if (AUDIOSTANDARDERROR_TO_MSERROR.find(code) != AUDIOSTANDARDERROR_TO_MSERROR.end()) {
        return AUDIOSTANDARDERROR_TO_MSERROR.at(code);
    }
    return MSERR_AUD_RENDER_FAILED;
}

MediaServiceErrCode AudioStandardErrorToMSError(int32_t code)
{
    AudioStandard::AudioErrors errCode = static_cast<AudioStandard::AudioErrors>(code);
    if (AUDIOINFOERROR_TO_MSERROR.find(errCode) != AUDIOINFOERROR_TO_MSERROR.end()) {
        return AUDIOINFOERROR_TO_MSERROR.at(errCode);
    }
    return MSERR_AUD_RENDER_FAILED;
}

MediaServiceErrCode HDIStatusToMSError(int32_t code)
{
#ifdef SUPPORT_LPP
    HDF_STATUS errCode = static_cast<HDF_STATUS>(code);
    if (HDF_STATUS_TO_MSERROR.find(errCode) != HDF_STATUS_TO_MSERROR.end()) {
        return HDF_STATUS_TO_MSERROR.at(errCode);
    }
#endif
    return MSERR_HARDWARE_ERROR;
}

MediaServiceErrCode HDIErrorToMSError(int32_t code)
{
#ifdef SUPPORT_LPP
    HDFErrCode errCode = static_cast<HDFErrCode>(code);
    if (HDF_ERROR_TO_MSERROR.find(errCode) != HDF_ERROR_TO_MSERROR.end()) {
        return HDF_ERROR_TO_MSERROR.at(errCode);
    }
#endif
    return MSERR_HARDWARE_ERROR;
}
} // namespace Media
} // namespace OHOS
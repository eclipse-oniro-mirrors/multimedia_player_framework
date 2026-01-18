/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "player_server_unit_test.h"
#include <unistd.h>
#include <securec.h>
#include "media_errors.h"
#include "audio_effect.h"
#include "av_common.h"
#include "meta/video_types.h"

using namespace std;
using namespace testing::ext;
using namespace OHOS::Media::PlayerTestParam;

namespace OHOS {
namespace Media {
namespace {
using ErrorMessageFunc = std::function<std::string(const std::string& param1, const std::string& param2)>;
const std::map<MediaServiceErrCode, std::string> MSERRCODE_INFOS = {
    {MSERR_OK, "success"},
    {MSERR_NO_MEMORY, "no memory"},
    {MSERR_INVALID_OPERATION, "operation not be permitted"},
    {MSERR_INVALID_VAL, "invalid argument"},
    {MSERR_UNKNOWN, "unkown error"},
    {MSERR_MANDATORY_PARAMETER_UNSPECIFIED, "mandatory parameters are left unspecified"},
    {MSERR_INCORRECT_PARAMETER_TYPE, "Incorrect parameter types"},
    {MSERR_PARAMETER_VERIFICATION_FAILED, "Parameter verification failed"},
    {MSERR_SERVICE_DIED, "media service died"},
    {MSERR_CREATE_REC_ENGINE_FAILED, "create recorder engine failed"},
    {MSERR_CREATE_PLAYER_ENGINE_FAILED, "create player engine failed"},
    {MSERR_CREATE_AVMETADATAHELPER_ENGINE_FAILED, "create avmetadatahelper engine failed"},
    {MSERR_INVALID_STATE, "the state is not support this operation"},
    {MSERR_UNSUPPORT, "unsupport interface"},
    {MSERR_UNSUPPORT_AUD_SRC_TYPE, "unsupport audio source type"},
    {MSERR_UNSUPPORT_AUD_SAMPLE_RATE, "unsupport audio sample rate"},
    {MSERR_UNSUPPORT_AUD_CHANNEL_NUM, "unsupport audio channel"},
    {MSERR_UNSUPPORT_AUD_ENC_TYPE, "unsupport audio encoder type"},
    {MSERR_UNSUPPORT_AUD_PARAMS, "unsupport audio params(other params)"},
    {MSERR_UNSUPPORT_VID_SRC_TYPE, "unsupport video source type"},
    {MSERR_UNSUPPORT_VID_ENC_TYPE, "unsupport video encoder type"},
    {MSERR_UNSUPPORT_VID_PARAMS, "unsupport video params(other params)"},
    {MSERR_UNSUPPORT_CONTAINER_TYPE, "unsupport container format type"},
    {MSERR_UNSUPPORT_PROTOCOL_TYPE, "unsupport protocol type"},
    {MSERR_UNSUPPORT_VID_DEC_TYPE, "unsupport video decoder type"},
    {MSERR_UNSUPPORT_AUD_DEC_TYPE, "unsupport audio decoder type"},
    {MSERR_UNSUPPORT_STREAM, "internal data stream error"},
    {MSERR_UNSUPPORT_FILE, "this appears to be a text file"},
    {MSERR_UNSUPPORT_SOURCE, "unsupport source type"},
    {MSERR_VID_RESIZE_FAILED, "video resize failed"},
    {MSERR_AUD_ENC_FAILED, "audio encode failed"},
    {MSERR_AUD_RENDER_FAILED, "audio render failed"},
    {MSERR_VID_ENC_FAILED, "video encode failed"},
    {MSERR_AUD_DEC_FAILED, "audio decode failed"},
    {MSERR_VID_DEC_FAILED, "video decode failed"},
    {MSERR_MUXER_FAILED, "stream avmuxer failed"},
    {MSERR_DEMUXER_FAILED, "stream demuxer or parser failed"},
    {MSERR_OPEN_FILE_FAILED, "open file failed"},
    {MSERR_FILE_ACCESS_FAILED, "read or write file failed"},
    {MSERR_START_FAILED, "audio or video start failed"},
    {MSERR_PAUSE_FAILED, "audio or video pause failed"},
    {MSERR_STOP_FAILED, "audio or video stop failed"},
    {MSERR_SEEK_FAILED, "audio or video seek failed"},
    {MSERR_NETWORK_TIMEOUT, "network timeout"},
    {MSERR_NOT_FIND_CONTAINER, "not find a demuxer"},
    {MSERR_EXTEND_START, "extend start error code"},
    {MSERR_AUD_INTERRUPT, "audio interrupted"},
    {MSERR_USER_NO_PERMISSION, "user no permission"},
    {MSERR_DATA_SOURCE_ERROR_UNKNOWN, "media data source error unknow"},
    {MSERR_DATA_SOURCE_IO_ERROR, "media data source IO failed"},
    {MSERR_DRM_VERIFICATION_FAILED, "DRM verification failed"},
    {MSERR_UNSUPPORT_WATER_MARK, "unsupported water mark"},
    {MSERR_DEMUXER_BUFFER_NO_MEMORY, "demuxer cache data reached its limit"},
    {MSERR_IO_CANNOT_FIND_HOST, "IO can not find host"},
    {MSERR_IO_CONNECTION_TIMEOUT, "IO connection timeout"},
    {MSERR_IO_NETWORK_ABNORMAL, "IO network abnormal"},
    {MSERR_IO_NETWORK_UNAVAILABLE, "IO network unavailable"},
    {MSERR_IO_NO_PERMISSION, "IO no permission"},
    {MSERR_IO_NETWORK_ACCESS_DENIED, "IO request denied"},
    {MSERR_IO_RESOURE_NOT_FOUND, "IO resource not found"},
    {MSERR_IO_SSL_CLIENT_CERT_NEEDED, "IO SSL client cert needed"},
    {MSERR_IO_SSL_CONNECT_FAIL, "IO SSL connect fail"},
    {MSERR_IO_SSL_SERVER_CERT_UNTRUSTED, "IO SSL server cert untrusted"},
    {MSERR_IO_UNSUPPORTTED_REQUEST, "IO unsupported request"},
    {MSERR_SEEK_CONTINUOUS_UNSUPPORTED, "seek continonous is unsupported for this source"},
    {MSERR_SUPER_RESOLUTION_UNSUPPORTED, "super resolution not supported"},
    {MSERR_SUPER_RESOLUTION_NOT_ENABLED, "super resolution not enabled"},
    {MSERR_GET_INPUT_SURFACE_FAILED, "video encoder or resize get input surface failed"},
    {MSERR_SET_OUTPUT_SURFACE_FAILED, "video decoder or resize set output surface failed"},
    {MSERR_DSS_THREAD_CREATION_FAILED, "DSS of the LPP thread creation failed"},
    {MSERR_DSS_TASK_CREATION_FAILED, "DSS of the LPP task creation failed"},
    {MSERR_DSS_STRAT_FAILED, "DSS of the LPP start failed"},
    {MSERR_SHB_THREAD_CREATION_FAILED, "SHB of the LPP thread creation failed"},
    {MSERR_SHB_INIT_FAILED, "SHB of the LPP init failed"},
    {MSERR_SHB_MSG_QUE_CREATION_FAILED, "SHB of the LPP message queue creation failed"},
    {MSERR_SHB_NO_MEMORY, "SHB of the LPP failed to allocate memory."},
    {MSERR_SHB_CRASH_ERROR, "SHB of the LPP crash happend."},
    {MSERR_RS_INIT_FAILED, "RS of the LPP init failed"},
    {MSERR_RS_DATA_FALLBACK_FAILED, "RS of the LPP data fallback failed"},
    {MSERR_LPP_INSTANCE_EXCEED_LIMIT, "LPP instance limit exceeded"},
    {MSERR_HARDWARE_ERROR, "underlying hardware error happened"},
};

const std::map<MediaServiceErrCode, MediaServiceExtErrCode> MSERRCODE_TO_EXTERRORCODE = {
    {MSERR_OK,                                  MSERR_EXT_OK},
    {MSERR_NO_MEMORY,                           MSERR_EXT_NO_MEMORY},
    {MSERR_DEMUXER_BUFFER_NO_MEMORY,            MSERR_EXT_IO},
    {MSERR_INVALID_OPERATION,                   MSERR_EXT_OPERATE_NOT_PERMIT},
    {MSERR_INVALID_VAL,                         MSERR_EXT_INVALID_VAL},
    {MSERR_UNKNOWN,                             MSERR_EXT_UNKNOWN},
    {MSERR_SERVICE_DIED,                        MSERR_EXT_SERVICE_DIED},
    {MSERR_CREATE_REC_ENGINE_FAILED,            MSERR_EXT_UNKNOWN},
    {MSERR_CREATE_PLAYER_ENGINE_FAILED,         MSERR_EXT_UNKNOWN},
    {MSERR_INVALID_STATE,                       MSERR_EXT_INVALID_STATE},
    {MSERR_UNSUPPORT,                           MSERR_EXT_UNSUPPORT},
    {MSERR_UNSUPPORT_AUD_SRC_TYPE,              MSERR_EXT_UNSUPPORT},
    {MSERR_UNSUPPORT_AUD_SAMPLE_RATE,           MSERR_EXT_UNSUPPORT},
    {MSERR_UNSUPPORT_AUD_CHANNEL_NUM,           MSERR_EXT_UNSUPPORT},
    {MSERR_UNSUPPORT_AUD_ENC_TYPE,              MSERR_EXT_UNSUPPORT},
    {MSERR_UNSUPPORT_AUD_PARAMS,                MSERR_EXT_UNSUPPORT},
    {MSERR_UNSUPPORT_VID_SRC_TYPE,              MSERR_EXT_UNSUPPORT},
    {MSERR_UNSUPPORT_VID_ENC_TYPE,              MSERR_EXT_UNSUPPORT},
    {MSERR_UNSUPPORT_VID_PARAMS,                MSERR_EXT_UNSUPPORT},
    {MSERR_UNSUPPORT_CONTAINER_TYPE,            MSERR_EXT_UNSUPPORT},
    {MSERR_UNSUPPORT_PROTOCOL_TYPE,             MSERR_EXT_UNSUPPORT},
    {MSERR_UNSUPPORT_VID_DEC_TYPE,              MSERR_EXT_UNSUPPORT},
    {MSERR_UNSUPPORT_AUD_DEC_TYPE,              MSERR_EXT_UNSUPPORT},
    {MSERR_UNSUPPORT_STREAM,                    MSERR_EXT_UNSUPPORT},
    {MSERR_UNSUPPORT_FILE,                      MSERR_EXT_UNSUPPORT},
    {MSERR_UNSUPPORT_SOURCE,                    MSERR_EXT_UNSUPPORT},
    {MSERR_AUD_RENDER_FAILED,                   MSERR_EXT_UNSUPPORT},
    {MSERR_VID_RESIZE_FAILED,                   MSERR_EXT_UNKNOWN},
    {MSERR_AUD_ENC_FAILED,                      MSERR_EXT_UNKNOWN},
    {MSERR_VID_ENC_FAILED,                      MSERR_EXT_UNKNOWN},
    {MSERR_AUD_DEC_FAILED,                      MSERR_EXT_UNKNOWN},
    {MSERR_VID_DEC_FAILED,                      MSERR_EXT_UNKNOWN},
    {MSERR_MUXER_FAILED,                        MSERR_EXT_UNKNOWN},
    {MSERR_DEMUXER_FAILED,                      MSERR_EXT_UNKNOWN},
    {MSERR_OPEN_FILE_FAILED,                    MSERR_EXT_UNKNOWN},
    {MSERR_FILE_ACCESS_FAILED,                  MSERR_EXT_UNKNOWN},
    {MSERR_START_FAILED,                        MSERR_EXT_UNKNOWN},
    {MSERR_PAUSE_FAILED,                        MSERR_EXT_UNKNOWN},
    {MSERR_STOP_FAILED,                         MSERR_EXT_UNKNOWN},
    {MSERR_SEEK_FAILED,                         MSERR_EXT_UNKNOWN},
    {MSERR_NETWORK_TIMEOUT,                     MSERR_EXT_TIMEOUT},
    {MSERR_NOT_FIND_CONTAINER,                  MSERR_EXT_UNSUPPORT},
    {MSERR_EXTEND_START,                        MSERR_EXT_EXTEND_START},
    {MSERR_IO_CANNOT_FIND_HOST,                 MSERR_EXT_IO},
    {MSERR_IO_CONNECTION_TIMEOUT,               MSERR_EXT_IO},
    {MSERR_IO_NETWORK_ABNORMAL,                 MSERR_EXT_IO},
    {MSERR_IO_NETWORK_UNAVAILABLE,              MSERR_EXT_IO},
    {MSERR_IO_NO_PERMISSION,                    MSERR_EXT_IO},
    {MSERR_IO_NETWORK_ACCESS_DENIED,            MSERR_EXT_IO},
    {MSERR_IO_RESOURE_NOT_FOUND,                MSERR_EXT_IO},
    {MSERR_IO_SSL_CLIENT_CERT_NEEDED,           MSERR_EXT_IO},
    {MSERR_IO_SSL_CONNECT_FAIL,                 MSERR_EXT_IO},
    {MSERR_IO_SSL_SERVER_CERT_UNTRUSTED,        MSERR_EXT_IO},
    {MSERR_IO_UNSUPPORTTED_REQUEST,             MSERR_EXT_IO},
    {MSERR_SUPER_RESOLUTION_UNSUPPORTED,        MSERR_EXT_UNSUPPORT},
    {MSERR_SUPER_RESOLUTION_NOT_ENABLED,        MSERR_EXT_UNKNOWN},
    {MSERR_GET_INPUT_SURFACE_FAILED,            MSERR_EXT_UNKNOWN},
    {MSERR_SET_OUTPUT_SURFACE_FAILED,           MSERR_EXT_UNKNOWN},
    {MSERR_DSS_THREAD_CREATION_FAILED,          MSERR_EXT_UNKNOWN},
    {MSERR_DSS_TASK_CREATION_FAILED,            MSERR_EXT_UNKNOWN},
    {MSERR_DSS_STRAT_FAILED,                    MSERR_EXT_EXTEND_START},
    {MSERR_SHB_THREAD_CREATION_FAILED,          MSERR_EXT_UNKNOWN},
    {MSERR_SHB_INIT_FAILED,                     MSERR_EXT_UNKNOWN},
    {MSERR_SHB_MSG_QUE_CREATION_FAILED,         MSERR_EXT_UNKNOWN},
    {MSERR_SHB_NO_MEMORY,                       MSERR_EXT_NO_MEMORY},
    {MSERR_SHB_CRASH_ERROR,                     MSERR_EXT_SERVICE_DIED},
    {MSERR_RS_INIT_FAILED,                      MSERR_EXT_UNKNOWN},
    {MSERR_RS_DATA_FALLBACK_FAILED,             MSERR_EXT_UNKNOWN},
    {MSERR_LPP_INSTANCE_EXCEED_LIMIT,           MSERR_EXT_UNKNOWN},
    {MSERR_HARDWARE_ERROR,                      MSERR_EXT_UNKNOWN},
};

const std::map<MediaServiceExtErrCode, std::string> MSEXTERRCODE_INFOS = {
    {MSERR_EXT_OK, "success"},
    {MSERR_EXT_NO_MEMORY, "no memory"},
    {MSERR_EXT_OPERATE_NOT_PERMIT, "operation not be permitted"},
    {MSERR_EXT_INVALID_VAL, "invalid argument"},
    {MSERR_EXT_IO, "IO error"},
    {MSERR_EXT_TIMEOUT, "network timeout"},
    {MSERR_EXT_UNKNOWN, "unkown error"},
    {MSERR_EXT_SERVICE_DIED, "media service died"},
    {MSERR_EXT_INVALID_STATE, "the state is not support this operation"},
    {MSERR_EXT_UNSUPPORT, "unsupport interface"},
    {MSERR_EXT_EXTEND_START, "extend err start"},
};

const std::map<MediaServiceErrCode, MediaServiceExtErrCodeAPI9> MSERRCODE_TO_EXTERRORCODEAPI9 = {
    {MSERR_OK,                                  MSERR_EXT_API9_OK},
    {MSERR_NO_MEMORY,                           MSERR_EXT_API9_NO_MEMORY},
    {MSERR_INVALID_OPERATION,                   MSERR_EXT_API9_OPERATE_NOT_PERMIT},
    {MSERR_INVALID_VAL,                         MSERR_EXT_API9_INVALID_PARAMETER},
    {MSERR_MANDATORY_PARAMETER_UNSPECIFIED,     MSERR_EXT_API9_INVALID_PARAMETER},
    {MSERR_INCORRECT_PARAMETER_TYPE,            MSERR_EXT_API9_INVALID_PARAMETER},
    {MSERR_PARAMETER_VERIFICATION_FAILED,       MSERR_EXT_API9_INVALID_PARAMETER},
    {MSERR_SERVICE_DIED,                        MSERR_EXT_API9_SERVICE_DIED},
    {MSERR_CREATE_REC_ENGINE_FAILED,            MSERR_EXT_API9_NO_MEMORY},
    {MSERR_CREATE_PLAYER_ENGINE_FAILED,         MSERR_EXT_API9_NO_MEMORY},
    {MSERR_INVALID_STATE,                       MSERR_EXT_API9_OPERATE_NOT_PERMIT},
    {MSERR_UNSUPPORT,                           MSERR_EXT_API9_UNSUPPORT_FORMAT},
    {MSERR_UNSUPPORT_AUD_SRC_TYPE,              MSERR_EXT_API9_UNSUPPORT_FORMAT},
    {MSERR_UNSUPPORT_AUD_SAMPLE_RATE,           MSERR_EXT_API9_UNSUPPORT_FORMAT},
    {MSERR_UNSUPPORT_AUD_CHANNEL_NUM,           MSERR_EXT_API9_UNSUPPORT_FORMAT},
    {MSERR_UNSUPPORT_AUD_ENC_TYPE,              MSERR_EXT_API9_UNSUPPORT_FORMAT},
    {MSERR_UNSUPPORT_AUD_PARAMS,                MSERR_EXT_API9_UNSUPPORT_FORMAT},
    {MSERR_UNSUPPORT_VID_SRC_TYPE,              MSERR_EXT_API9_UNSUPPORT_FORMAT},
    {MSERR_UNSUPPORT_VID_ENC_TYPE,              MSERR_EXT_API9_UNSUPPORT_FORMAT},
    {MSERR_UNSUPPORT_VID_PARAMS,                MSERR_EXT_API9_UNSUPPORT_FORMAT},
    {MSERR_UNSUPPORT_CONTAINER_TYPE,            MSERR_EXT_API9_UNSUPPORT_FORMAT},
    {MSERR_UNSUPPORT_PROTOCOL_TYPE,             MSERR_EXT_API9_UNSUPPORT_FORMAT},
    {MSERR_UNSUPPORT_VID_DEC_TYPE,              MSERR_EXT_API9_UNSUPPORT_FORMAT},
    {MSERR_UNSUPPORT_AUD_DEC_TYPE,              MSERR_EXT_API9_UNSUPPORT_FORMAT},
    {MSERR_UNSUPPORT_STREAM,                    MSERR_EXT_API9_UNSUPPORT_FORMAT},
    {MSERR_UNSUPPORT_FILE,                      MSERR_EXT_API9_UNSUPPORT_FORMAT},
    {MSERR_UNSUPPORT_SOURCE,                    MSERR_EXT_API9_UNSUPPORT_FORMAT},
    {MSERR_VID_RESIZE_FAILED,                   MSERR_EXT_API9_IO},
    {MSERR_AUD_RENDER_FAILED,                   MSERR_EXT_API9_IO},
    {MSERR_AUD_ENC_FAILED,                      MSERR_EXT_API9_IO},
    {MSERR_VID_ENC_FAILED,                      MSERR_EXT_API9_IO},
    {MSERR_AUD_DEC_FAILED,                      MSERR_EXT_API9_IO},
    {MSERR_VID_DEC_FAILED,                      MSERR_EXT_API9_IO},
    {MSERR_MUXER_FAILED,                        MSERR_EXT_API9_UNSUPPORT_FORMAT},
    {MSERR_DEMUXER_FAILED,                      MSERR_EXT_API9_UNSUPPORT_FORMAT},
    {MSERR_OPEN_FILE_FAILED,                    MSERR_EXT_API9_IO},
    {MSERR_FILE_ACCESS_FAILED,                  MSERR_EXT_API9_IO},
    {MSERR_START_FAILED,                        MSERR_EXT_API9_OPERATE_NOT_PERMIT},
    {MSERR_PAUSE_FAILED,                        MSERR_EXT_API9_OPERATE_NOT_PERMIT},
    {MSERR_STOP_FAILED,                         MSERR_EXT_API9_OPERATE_NOT_PERMIT},
    {MSERR_SEEK_FAILED,                         MSERR_EXT_API9_OPERATE_NOT_PERMIT},
    {MSERR_DRM_VERIFICATION_FAILED,             MSERR_EXT_API9_OPERATE_NOT_PERMIT},
    {MSERR_NETWORK_TIMEOUT,                     MSERR_EXT_API9_TIMEOUT},
    {MSERR_NOT_FIND_CONTAINER,                  MSERR_EXT_API9_UNSUPPORT_FORMAT},
    {MSERR_UNKNOWN,                             MSERR_EXT_API9_IO},
    {MSERR_DATA_SOURCE_IO_ERROR,                MSERR_EXT_API9_IO},
    {MSERR_DATA_SOURCE_ERROR_UNKNOWN,           MSERR_EXT_API9_IO},
    {MSERR_AUD_INTERRUPT,                       MSERR_EXT_API9_AUDIO_INTERRUPTED},
    {MSERR_USER_NO_PERMISSION,                  MSERR_EXT_API9_NO_PERMISSION},
    {MSERR_UNSUPPORT_WATER_MARK,                MSERR_EXT_API9_UNSUPPORT_CAPABILITY},
    {MSERR_DEMUXER_BUFFER_NO_MEMORY,            MSERR_EXT_API9_IO},
    {MSERR_IO_CANNOT_FIND_HOST,                 MSERR_EXT_API14_IO_CANNOT_FIND_HOST},
    {MSERR_IO_CONNECTION_TIMEOUT,               MSERR_EXT_API14_IO_CONNECTION_TIMEOUT},
    {MSERR_IO_NETWORK_ABNORMAL,                 MSERR_EXT_API14_IO_NETWORK_ABNORMAL},
    {MSERR_IO_NETWORK_UNAVAILABLE,              MSERR_EXT_API14_IO_NETWORK_UNAVAILABLE},
    {MSERR_IO_NO_PERMISSION,                    MSERR_EXT_API14_IO_NO_PERMISSION},
    {MSERR_IO_NETWORK_ACCESS_DENIED,            MSERR_EXT_API14_IO_NETWORK_ACCESS_DENIED},
    {MSERR_IO_RESOURE_NOT_FOUND,                MSERR_EXT_API14_IO_RESOURE_NOT_FOUND},
    {MSERR_IO_SSL_CLIENT_CERT_NEEDED,           MSERR_EXT_API14_IO_SSL_CLIENT_CERT_NEEDED},
    {MSERR_IO_SSL_CONNECT_FAIL,                 MSERR_EXT_API14_IO_SSL_CONNECT_FAIL},
    {MSERR_IO_SSL_SERVER_CERT_UNTRUSTED,        MSERR_EXT_API14_IO_SSL_SERVER_CERT_UNTRUSTED},
    {MSERR_IO_UNSUPPORTTED_REQUEST,             MSERR_EXT_API14_IO_UNSUPPORTTED_REQUEST},
    {MSERR_SEEK_CONTINUOUS_UNSUPPORTED,         MSERR_EXT_API16_SEEK_CONTINUOUS_UNSUPPORTED},
    {MSERR_SUPER_RESOLUTION_UNSUPPORTED,        MSERR_EXT_API16_SUPER_RESOLUTION_UNSUPPORTED},
    {MSERR_SUPER_RESOLUTION_NOT_ENABLED,        MSERR_EXT_API16_SUPER_RESOLUTION_NOT_ENABLED},
    {MSERR_GET_INPUT_SURFACE_FAILED,            MSERR_EXT_API9_IO},
    {MSERR_SET_OUTPUT_SURFACE_FAILED,           MSERR_EXT_API9_IO},
    {MSERR_DSS_THREAD_CREATION_FAILED,          MSERR_EXT_API20_HARDWARE_FAILED},
    {MSERR_DSS_TASK_CREATION_FAILED,            MSERR_EXT_API20_HARDWARE_FAILED},
    {MSERR_DSS_STRAT_FAILED,                    MSERR_EXT_API20_HARDWARE_FAILED},
    {MSERR_SHB_THREAD_CREATION_FAILED,          MSERR_EXT_API20_HARDWARE_FAILED},
    {MSERR_SHB_INIT_FAILED,                     MSERR_EXT_API20_HARDWARE_FAILED},
    {MSERR_SHB_MSG_QUE_CREATION_FAILED,         MSERR_EXT_API20_HARDWARE_FAILED},
    {MSERR_SHB_NO_MEMORY,                       MSERR_EXT_API9_NO_MEMORY},
    {MSERR_SHB_CRASH_ERROR,                     MSERR_EXT_API20_HARDWARE_FAILED},
    {MSERR_RS_INIT_FAILED,                      MSERR_EXT_API20_HARDWARE_FAILED},
    {MSERR_RS_DATA_FALLBACK_FAILED,             MSERR_EXT_API20_HARDWARE_FAILED},
    {MSERR_LPP_INSTANCE_EXCEED_LIMIT,           MSERR_EXT_API20_HARDWARE_FAILED},
    {MSERR_HARDWARE_ERROR,                      MSERR_EXT_API20_HARDWARE_FAILED},
};

const std::map<MediaServiceExtErrCodeAPI9, std::string> MSEXTERRCODE_API9_INFOS = {
    {MSERR_EXT_API9_OK, "Success: "},
    {MSERR_EXT_API9_NO_PERMISSION, "No Permission: "},
    {MSERR_EXT_API9_PERMISSION_DENIED, "Permission Denied"},
    {MSERR_EXT_API9_INVALID_PARAMETER, "Invalid Parameter: "},
    {MSERR_EXT_API9_UNSUPPORT_CAPABILITY, "Unsupport Capability: "},
    {MSERR_EXT_API9_NO_MEMORY, "No Memory: "},
    {MSERR_EXT_API9_OPERATE_NOT_PERMIT, "Operate Not Permit: "},
    {MSERR_EXT_API9_IO, "IO Error: "},
    {MSERR_EXT_API9_TIMEOUT, "Network Timeout: "},
    {MSERR_EXT_API9_SERVICE_DIED, "Service Died: "},
    {MSERR_EXT_API9_UNSUPPORT_FORMAT, "Unsupported Format: "},
    {MSERR_EXT_API9_AUDIO_INTERRUPTED, "Audio Interruped: "},
    {MSERR_EXT_API14_IO_CANNOT_FIND_HOST, "IO Cannot Find Host: "},
    {MSERR_EXT_API14_IO_CONNECTION_TIMEOUT, "IO Connection Timeout: "},
    {MSERR_EXT_API14_IO_NETWORK_ABNORMAL, "IO Network Abnormal: "},
    {MSERR_EXT_API14_IO_NETWORK_UNAVAILABLE, "IO Network Unavailable: "},
    {MSERR_EXT_API14_IO_NO_PERMISSION, "IO No Permission: "},
    {MSERR_EXT_API14_IO_NETWORK_ACCESS_DENIED, "IO Request Denied: "},
    {MSERR_EXT_API14_IO_RESOURE_NOT_FOUND, "IO Resource Not Found: "},
    {MSERR_EXT_API14_IO_SSL_CLIENT_CERT_NEEDED, "IO SSL Client Cert Needed: "},
    {MSERR_EXT_API14_IO_SSL_CONNECT_FAIL, "IO SSL Connect Fail: "},
    {MSERR_EXT_API14_IO_SSL_SERVER_CERT_UNTRUSTED, "IO SSL Server Cert Untrusted: "},
    {MSERR_EXT_API14_IO_UNSUPPORTTED_REQUEST, "IO Unsupported Request: "},
    {MSERR_EXT_API20_HARDWARE_FAILED, "Hardware failed: "}
};

std::string ErrorMessageOk(const std::string& param1, const std::string& param2)
{
    (void)param1;
    (void)param2;
    return "success";
}

std::string ErrorMessageNoPermission(const std::string& param1, const std::string& param2)
{
    std::string message = "Try to do " + param1 + " failed. User should request permission " + param2 +" first.";
    return message;
}

std::string ErrorMessageInvalidParameter(const std::string& param1, const std::string& param2)
{
    (void)param2;
    std::string message = "The Parameter " + param1 + " is invalid. Please check the type and range.";
    return message;
}

std::string ErrorMessageUnsupportCapability(const std::string& param1, const std::string& param2)
{
    (void)param2;
    std::string message = "Function " + param1 + " can not work correctly due to limited device capability.";
    return message;
}

std::string ErrorMessageNoMemory(const std::string& param1, const std::string& param2)
{
    (void)param2;
    std::string message = "Create " + param1 + " failed due to system memory.";
    return message;
}

std::string ErrorMessageOperateNotPermit(const std::string& param1, const std::string& param2)
{
    (void)param2;
    std::string message = "The operate " + param1 + " failed due to not permit in current state.";
    return message;
}

std::string ErrorMessageIO(const std::string& param1, const std::string& param2)
{
    (void)param2;
    std::string message = "IO error happened due to " + param1 + ".";
    return message;
}

std::string ErrorMessageTimeout(const std::string& param1, const std::string& param2)
{
    std::string message = "Timeout happend when " + param1 + " due to " + param2 + ".";
    return message;
}

std::string ErrorMessageServiceDied(const std::string& param1, const std::string& param2)
{
    (void)param1;
    (void)param2;
    std::string message = "Media Serviced Died.";
    return message;
}

std::string ErrorMessageUnsupportFormat(const std::string& param1, const std::string& param2)
{
    (void)param2;
    std::string message = "The format " + param1 + " is not support.";
    return message;
}

std::string ErrorMessageAudioInterruped(const std::string & param1, const std::string& param2)
{
    (void)param1;
    (void)param2;
    std::string message = "Audio Interrupted by other process.";
    return message;
}

const std::map<MediaServiceExtErrCodeAPI9, ErrorMessageFunc> MSEXTERRAPI9CODE_FUNCS = {
    {MSERR_EXT_API9_OK, &ErrorMessageOk},
    {MSERR_EXT_API9_NO_PERMISSION, &ErrorMessageNoPermission},
    {MSERR_EXT_API9_INVALID_PARAMETER, &ErrorMessageInvalidParameter},
    {MSERR_EXT_API9_UNSUPPORT_CAPABILITY, &ErrorMessageUnsupportCapability},
    {MSERR_EXT_API9_NO_MEMORY, &ErrorMessageNoMemory},
    {MSERR_EXT_API9_OPERATE_NOT_PERMIT, &ErrorMessageOperateNotPermit},
    {MSERR_EXT_API9_IO, &ErrorMessageIO},
    {MSERR_EXT_API9_TIMEOUT, &ErrorMessageTimeout},
    {MSERR_EXT_API9_SERVICE_DIED, &ErrorMessageServiceDied},
    {MSERR_EXT_API9_UNSUPPORT_FORMAT, &ErrorMessageUnsupportFormat},
    {MSERR_EXT_API9_AUDIO_INTERRUPTED, &ErrorMessageAudioInterruped},
};
}

void PlayerServerUnitTest::SetUpTestCase(void)
{
}

void PlayerServerUnitTest::TearDownTestCase(void)
{
    std::cout << "sleep one second to protect PlayerEngine safely exit." << endl;
    sleep(1); //let PlayEngine safe exit.
}

void PlayerServerUnitTest::SetUp(void)
{
    callback_ = std::make_shared<PlayerCallbackTest>();
    ASSERT_NE(nullptr, callback_);
    player_ = std::make_shared<PlayerServerMock>(callback_);
    ASSERT_NE(nullptr, player_);
    EXPECT_TRUE(player_->CreatePlayer());
    EXPECT_EQ(MSERR_OK, player_->SetPlayerCallback(callback_));
}

void PlayerServerUnitTest::TearDown(void)
{
    if (player_ != nullptr) {
        player_->Release();
    }
}

void PlayerServerUnitTest::PlayFunTest(const std::string &protocol)
{
    int32_t duration = 0;
    float playbackRate = 2.5f;
    if (player_ != nullptr) {
        EXPECT_EQ(MSERR_OK, player_->GetDuration(duration));
        EXPECT_EQ(MSERR_OK, player_->Play());
        EXPECT_TRUE(player_->IsPlaying());
        EXPECT_EQ(MSERR_OK, player_->GetDuration(duration));
        EXPECT_EQ(MSERR_OK, player_->Pause());
        int32_t time;
        EXPECT_EQ(MSERR_OK, player_->GetCurrentTime(time));
        std::vector<Format> videoTrack;
        std::vector<Format> audioTrack;
        EXPECT_EQ(MSERR_OK, player_->GetVideoTrackInfo(videoTrack));
        EXPECT_EQ(MSERR_OK, player_->GetAudioTrackInfo(audioTrack));
        PlaybackRateMode mode;
        player_->SetPlaybackRate(playbackRate);
        player_->SetPlaybackSpeed(SPEED_FORWARD_2_00_X);
        player_->GetPlaybackSpeed(mode);
        EXPECT_EQ(MSERR_OK, player_->SetLooping(true));
        EXPECT_EQ(true, player_->IsLooping());
        EXPECT_EQ(MSERR_OK, player_->Seek(duration, SEEK_NEXT_SYNC));
        EXPECT_EQ(MSERR_OK, player_->Play());
        sleep(PLAYING_TIME_2_SEC);
        if (protocol == PlayerTestParam::HLS_PLAY) {
            EXPECT_EQ(MSERR_OK, player_->SelectBitRate(200000));  // 200000:bitrate
            sleep(PLAYING_TIME_2_SEC);
        }
        EXPECT_EQ(MSERR_OK, player_->SetLooping(false));
        EXPECT_EQ(false, player_->IsLooping());
        EXPECT_EQ(MSERR_OK, player_->SetVolume(1, 1));
        EXPECT_EQ(MSERR_OK, player_->Seek(SEEK_TIME_2_SEC, SEEK_NEXT_SYNC));
        EXPECT_EQ(MSERR_OK, player_->Stop());
        EXPECT_EQ(MSERR_OK, player_->Reset());
    }
}

void PlayerServerUnitTest::GetSetParaFunTest()
{
    if (player_ != nullptr) {
        int32_t duration = 0;
        int32_t time = 0;
        float playbackRate = 2.0f;
        PlaybackRateMode mode;
        std::vector<Format> videoTrack;
        std::vector<Format> audioTrack;
        player_->GetVideoTrackInfo(videoTrack);
        player_->GetAudioTrackInfo(audioTrack);
        player_->GetCurrentTime(time);
        player_->GetDuration(duration);
        player_->SetPlaybackRate(playbackRate);
        player_->SetPlaybackSpeed(SPEED_FORWARD_2_00_X);
        player_->GetPlaybackSpeed(mode);
        player_->SetLooping(true);
        player_->IsLooping();
        player_->SetVolume(1, 1);
    }
}

void PlayerServerUnitTest::MediaServiceErrCodeTest(MediaServiceErrCode code)
{
    if (MSERRCODE_INFOS.count(code) != 0) {
        EXPECT_EQ(MSERRCODE_INFOS.at(code), MSErrorToString(code));
    } else if (code > MSERR_EXTEND_START) {
        EXPECT_EQ("extend error:" + std::to_string(static_cast<int32_t>(code - MSERR_EXTEND_START)),
            MSErrorToString(code));
    } else {
        EXPECT_EQ("invalid error code:" + std::to_string(static_cast<int32_t>(code)), MSErrorToString(code));
    }

    if (MSERRCODE_INFOS.count(code) != 0 && MSERRCODE_TO_EXTERRORCODE.count(code) != 0 &&
        MSEXTERRCODE_INFOS.count(MSERRCODE_TO_EXTERRORCODE.at(code)) != 0) {
        EXPECT_EQ(MSEXTERRCODE_INFOS.at(MSERRCODE_TO_EXTERRORCODE.at(code)), MSErrorToExtErrorString(code));
    } else {
        EXPECT_EQ("unkown error", MSErrorToExtErrorString(code));
    }

    if (MSERRCODE_INFOS.count(code) != 0 && MSERRCODE_TO_EXTERRORCODE.count(code) != 0) {
        EXPECT_EQ(MSERRCODE_TO_EXTERRORCODE.at(code), MSErrorToExtError(code));
    } else {
        EXPECT_EQ(MSERR_EXT_UNKNOWN, MSErrorToExtError(code));
    }

    if (MSERRCODE_INFOS.count(code) != 0 && MSERRCODE_TO_EXTERRORCODEAPI9.count(code) != 0 &&
        MSEXTERRAPI9CODE_FUNCS.count(MSERRCODE_TO_EXTERRORCODEAPI9.at(code)) != 0) {
        EXPECT_EQ(MSEXTERRAPI9CODE_FUNCS.at(MSERRCODE_TO_EXTERRORCODEAPI9.at(code))("test1", "test2"),
            MSErrorToExtErrorAPI9String(code, "test1", "test2"));
    } else {
        EXPECT_EQ("unkown error", MSErrorToExtErrorAPI9String(code, "test1", "test2"));
    }

    if (MSERRCODE_INFOS.count(code) != 0 && MSERRCODE_TO_EXTERRORCODEAPI9.count(code) != 0) {
        EXPECT_EQ(MSERRCODE_TO_EXTERRORCODEAPI9.at(code), MSErrorToExtErrorAPI9(code));
    } else {
        EXPECT_EQ(MSERR_EXT_API9_IO, MSErrorToExtErrorAPI9(code));
    }
}

void PlayerServerUnitTest::MediaServiceExtErrCodeAPI9Test(MediaServiceExtErrCodeAPI9 code)
{
    if (MSEXTERRAPI9CODE_FUNCS.count(code) != 0) {
        EXPECT_EQ(MSEXTERRAPI9CODE_FUNCS.at(code)("test1", "test2"),
            MSExtErrorAPI9ToString(code, "test1", "test2"));
    } else {
        EXPECT_EQ("invalid error code:" + std::to_string(code), MSExtErrorAPI9ToString(code, "test1", "test2"));
    }

    if (MSEXTERRCODE_API9_INFOS.count(code) != 0) {
        EXPECT_EQ(MSEXTERRCODE_API9_INFOS.at(code), MSExtAVErrorToString(code));
    } else {
        EXPECT_EQ("invalid error code:", MSExtAVErrorToString(code));
    }
}

/**
 * @tc.name  : Test Player SetMediaSource API
 * @tc.number: Player_SetMediaSource_001
 * @tc.desc  : Test Player SetMediaSource interface
 */
HWTEST_F(PlayerServerUnitTest, Player_SetMediaSource_001, TestSize.Level1)
{
    std::map<std::string, std::string> header = {
        {"key1", "value1"},
        {"key2", "value2"},
    };
    struct AVPlayStrategy strategy = {1080, 920, 10000, false};
    std::shared_ptr<AVMediaSource> mediaSource = std::make_shared<AVMediaSource>(VIDEO_FILE1, header);
    int32_t ret = player_->SetMediaSource(mediaSource, strategy);
    EXPECT_EQ(MSERR_OK, ret);
}

/**
 * @tc.name  : Test Player SetMediaSource API
 * @tc.number: Player_SetMediaSource_002
 * @tc.desc  : Test Player SetMediaSource interface
 */
HWTEST_F(PlayerServerUnitTest, Player_SetMediaSource_002, TestSize.Level1)
{
    struct AVPlayStrategy strategy = {1080, 920, 10000, false};
    int32_t ret = player_->SetMediaSource(nullptr, strategy);
    EXPECT_NE(MSERR_OK, ret);
}

/**
 * @tc.name  : Test Player SetMediaSource API
 * @tc.number: Player_SetMediaSource_003
 * @tc.desc  : Test Player SetMediaSource interface
 */
HWTEST_F(PlayerServerUnitTest, Player_SetMediaSource_003, TestSize.Level1)
{
    std::map<std::string, std::string> header = {
        {"key1", "value1"},
        {"key2", "value2"},
    };
    struct AVPlayStrategy strategy = {1080, 920, 10000, false};
    std::shared_ptr<AVMediaSource> mediaSource = std::make_shared<AVMediaSource>(MEDIA_ROOT + "error.mp4", header);
    int32_t ret = player_->SetMediaSource(mediaSource, strategy);
    EXPECT_EQ(MSERR_OK, ret);
    EXPECT_NE(MSERR_OK, player_->PrepareAsync());
}

/**
 * @tc.name  : Test Player SetMediaSource API
 * @tc.number: Player_SetMediaSource_004
 * @tc.desc  : Test Player SetMediaSource interface
 */
HWTEST_F(PlayerServerUnitTest, Player_SetMediaSource_004, TestSize.Level1)
{
    std::map<std::string, std::string> header = {
        {"key1", "value1"},
        {"key2", "value2"},
    };
    struct AVPlayStrategy strategy = {1080, 920, 10000, false};
    std::shared_ptr<AVMediaSource> mediaSource = std::make_shared<AVMediaSource>(MEDIA_ROOT + "error.mp4", header);
    int32_t ret = player_->SetMediaSource(mediaSource, strategy);
    EXPECT_EQ(MSERR_OK, ret);
    EXPECT_NE(MSERR_OK, player_->PrepareAsync());
    EXPECT_NE(MSERR_OK, player_->Prepare());
}

/**
 * @tc.name  : Test Player SetMediaSource API
 * @tc.number: Player_SetMediaSource_005
 * @tc.desc  : Test Player SetMediaSource interface
 */
HWTEST_F(PlayerServerUnitTest, Player_SetMediaSource_005, TestSize.Level1)
{
    std::map<std::string, std::string> header = {
        {"key1", "value1"},
        {"key2", "value2"},
    };
    struct AVPlayStrategy strategy = {1080, 920, 10000, false};
    std::shared_ptr<AVMediaSource> mediaSource = std::make_shared<AVMediaSource>(MEDIA_ROOT + "error.mp4", header);
    int32_t ret = player_->SetMediaSource(mediaSource, strategy);
    EXPECT_EQ(MSERR_OK, ret);
    EXPECT_NE(MSERR_OK, player_->Play());
    EXPECT_EQ(false, player_->IsPlaying());
}

/**
 * @tc.name  : Test Player SetMediaSource API
 * @tc.number: Player_SetMediaSource_006
 * @tc.desc  : Test Player SetMediaSource interface
 */
HWTEST_F(PlayerServerUnitTest, Player_SetMediaSource_006, TestSize.Level1)
{
    std::map<std::string, std::string> header = {
    };
    struct AVPlayStrategy strategy = {1080, 920, 10000, false};
    std::shared_ptr<AVMediaSource> mediaSource = std::make_shared<AVMediaSource>(MEDIA_ROOT + "error.mp4", header);
    int32_t ret = player_->SetMediaSource(mediaSource, strategy);
    EXPECT_EQ(MSERR_OK, ret);
    EXPECT_NE(MSERR_OK, player_->Play());
    EXPECT_EQ(false, player_->IsPlaying());
}

/**
 * @tc.name  : Test Player StrToInt API
 * @tc.number: Player_StrToInt_001
 * @tc.desc  : Test Player StrToInt interface
 */
HWTEST_F(PlayerServerUnitTest, Player_StrToInt_001, TestSize.Level1)
{
    std::string str = "123";
    int32_t fd = -1;
    int32_t num = 123;
    auto res = StrToInt(str, fd);
    EXPECT_EQ(res, true);
    EXPECT_EQ(fd, num);
}

/**
 * @tc.name  : Test Player StrToInt API
 * @tc.number: Player_StrToInt_002
 * @tc.desc  : Test Player StrToInt interface
 */
HWTEST_F(PlayerServerUnitTest, Player_StrToInt_002, TestSize.Level1)
{
    std::string str = "12a3";
    int32_t fd = -1;
    auto res = StrToInt(str, fd);
    EXPECT_EQ(res, false);
}

/**
 * @tc.name  : Test Player StrToInt API
 * @tc.number: Player_StrToInt_003
 * @tc.desc  : Test Player StrToInt interface
 */
HWTEST_F(PlayerServerUnitTest, Player_StrToInt_003, TestSize.Level1)
{
    std::string str = "9223372036854775809";
    int32_t fd = -1;
    auto res = StrToInt(str, fd);
    EXPECT_EQ(res, false);
}

/**
 * @tc.name  : Test Player SetSource API
 * @tc.number: Player_SetSource_001
 * @tc.desc  : Test Player SetSource interface
 */
HWTEST_F(PlayerServerUnitTest, Player_SetSource_001, TestSize.Level1)
{
    int32_t ret = player_->SetSource(VIDEO_FILE1);
    EXPECT_EQ(MSERR_OK, ret);
}

/**
 * @tc.name  : Test Player SetSource API
 * @tc.number: Player_SetSource_002
 * @tc.desc  : Test Player SetSource interface with invalid path
 */
HWTEST_F(PlayerServerUnitTest, Player_SetSource_002, TestSize.Level1)
{
    int32_t ret = player_->SetSource(MEDIA_ROOT + "kong.mp4");
    EXPECT_NE(MSERR_OK, ret);
}

/**
 * @tc.name  : Test Player SetSource API
 * @tc.number: Player_SetSource_003
 * @tc.desc  : Test Player SetSource interface with wrong mp3
 */
HWTEST_F(PlayerServerUnitTest, Player_SetSource_003, TestSize.Level2)
{
    system("param set sys.media.player.buffering.enable TRUE");
    PlaybackRateMode mode;
    int32_t time = 0;
    int32_t duration = 0;
    float playbackRate = 1.5f;
    std::vector<Format> videoTrack;
    std::vector<Format> audioTrack;
    int32_t ret = player_->SetSource(MEDIA_ROOT + "1kb.mp3");
    EXPECT_EQ(MSERR_OK, ret);
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_NE(MSERR_OK, player_->PrepareAsync());
    EXPECT_NE(MSERR_OK, player_->Prepare());
    Format format;
    format.PutIntValue(PlayerKeys::VIDEO_SCALE_TYPE,
        static_cast<int32_t>(Plugins::VideoScaleType::VIDEO_SCALE_TYPE_FIT));
    EXPECT_NE(MSERR_OK, player_->SetParameter(format));
    EXPECT_NE(MSERR_OK, player_->SetVolume(1, 1));
    EXPECT_NE(MSERR_OK, player_->Play());
    EXPECT_EQ(false, player_->IsPlaying());
    EXPECT_NE(MSERR_OK, player_->Pause());
    EXPECT_NE(MSERR_OK, player_->Seek(0, SEEK_CLOSEST));
    EXPECT_NE(MSERR_OK, player_->SetLooping(true));
    EXPECT_EQ(false, player_->IsLooping());
    EXPECT_NE(MSERR_OK, player_->SetVolume(1, 1));
    EXPECT_NE(MSERR_OK, player_->SetPlaybackRate(playbackRate));
    EXPECT_NE(MSERR_OK, player_->SetPlaybackSpeed(SPEED_FORWARD_2_00_X));
    EXPECT_NE(MSERR_OK, player_->GetPlaybackSpeed(mode));
    EXPECT_NE(MSERR_OK, player_->GetCurrentTime(time));
    EXPECT_NE(MSERR_OK, player_->GetDuration(duration));
    EXPECT_NE(MSERR_OK, player_->GetVideoTrackInfo(videoTrack));
    EXPECT_NE(MSERR_OK, player_->GetAudioTrackInfo(audioTrack));
    EXPECT_NE(480, player_->GetVideoHeight());
    EXPECT_NE(720, player_->GetVideoWidth());
    EXPECT_NE(MSERR_OK, player_->Stop());
    EXPECT_EQ(MSERR_OK, player_->Reset());
    system("param set sys.media.player.buffering.enable FALSE");
}

/**
 * @tc.name  : Test Player SetSource API
 * @tc.number: Player_SetSource_004
 * @tc.desc  : Test Player SetSource interface with txt
 */
HWTEST_F(PlayerServerUnitTest, Player_SetSource_004, TestSize.Level2)
{
    int32_t ret = player_->SetSource(MEDIA_ROOT + "error.mp4");
    EXPECT_EQ(MSERR_OK, ret);
    EXPECT_NE(MSERR_OK, player_->PrepareAsync());
}
} // namespace Media
} // namespace OHOS

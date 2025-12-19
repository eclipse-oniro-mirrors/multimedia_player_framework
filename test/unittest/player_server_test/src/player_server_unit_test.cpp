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

/**
 * @tc.name  : Test Player SetSource
 * @tc.number: Player_SetSource_005
 * @tc.desc  : Test Player SetSource interface
 */
HWTEST_F(PlayerServerUnitTest, Player_SetSource_005, TestSize.Level3)
{
    PlaybackRateMode mode;
    int32_t duration = 0;
    float playbackRate = 1.5f;
    std::vector<Format> videoTrack;
    std::vector<Format> audioTrack;
    Format format;
    format.PutIntValue(PlayerKeys::VIDEO_SCALE_TYPE,
        static_cast<int32_t>(Plugins::VideoScaleType::VIDEO_SCALE_TYPE_FIT));
    EXPECT_NE(MSERR_OK, player_->SetParameter(format));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_NE(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_NE(MSERR_OK, player_->PrepareAsync());
    EXPECT_NE(MSERR_OK, player_->Prepare());
    EXPECT_NE(MSERR_OK, player_->SetParameter(format));
    EXPECT_EQ(MSERR_OK, player_->SetVolume(1, 1));
    EXPECT_NE(MSERR_OK, player_->Play());
    EXPECT_NE(MSERR_OK, player_->Pause());
    EXPECT_NE(MSERR_OK, player_->Seek(0, SEEK_CLOSEST));
    EXPECT_EQ(MSERR_OK, player_->SetLooping(true));
    EXPECT_EQ(true, player_->IsLooping());
    EXPECT_EQ(MSERR_OK, player_->SetVolume(1, 1));
    EXPECT_NE(MSERR_OK, player_->SetPlaybackRate(playbackRate));
    EXPECT_NE(MSERR_OK, player_->SetPlaybackSpeed(SPEED_FORWARD_2_00_X));
    EXPECT_EQ(MSERR_OK, player_->GetPlaybackSpeed(mode));
    EXPECT_EQ(SPEED_FORWARD_1_00_X, mode);
    EXPECT_NE(MSERR_OK, player_->GetDuration(duration));
    EXPECT_NE(MSERR_OK, player_->GetVideoTrackInfo(videoTrack));
    EXPECT_NE(MSERR_OK, player_->GetAudioTrackInfo(audioTrack));
    EXPECT_NE(480, player_->GetVideoHeight());
    EXPECT_NE(720, player_->GetVideoWidth());
    EXPECT_NE(MSERR_OK, player_->Stop());
    EXPECT_NE(MSERR_OK, player_->Reset());
}

/**
 * @tc.name  : Test Player SetSource API
 * @tc.number: Player_SetSource_006
 * @tc.desc  : Test Player SetSource interface
 */
HWTEST_F(PlayerServerUnitTest, Player_SetSource_006, TestSize.Level2)
{
    int32_t ret = player_->SetSource(VIDEO_FILE1);
    EXPECT_EQ(MSERR_OK, ret);
    EXPECT_EQ(MSERR_OK, player_->Reset());
    EXPECT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
}

/**
 * @tc.name  : Test Player SetSource API
 * @tc.number: Player_SetSource_007
 * @tc.desc  : Test Player SetSource interface
 */
HWTEST_F(PlayerServerUnitTest, Player_SetSource_007, TestSize.Level2)
{
    EXPECT_NE(MSERR_OK, player_->SetSource(INVALID_FILE));
}

/**
 * @tc.name  : Test Player SetSource API
 * @tc.number: Player_SetSource_009
 * @tc.desc  : Test Player SetSource interface
 */
HWTEST_F(PlayerServerUnitTest, Player_SetSource_009, TestSize.Level2)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    int32_t ret = player_->PrepareAsync();
    ASSERT_NE(MSERR_OK, player_->SetSource(MEDIA_ROOT + "AVC_Baseline@L1.2_81.0Kbps_320x240.mp4"));
    if (ret == MSERR_OK) {
        PlayFunTest(LOCAL_PLAY);
    }
}

/**
 * @tc.name  : Test Player SetSource API
 * @tc.number: Player_SetSource_012
 * @tc.desc  : Test Player SetSource interface
 */
HWTEST_F(PlayerServerUnitTest, Player_SetSource_012, TestSize.Level2)
{
    int32_t ret = player_->SetSource(VIDEO_FILE1, 0, 0);
    ASSERT_EQ(MSERR_OK, ret);
}

/**
 * @tc.name  : Test Player Local
 * @tc.number: Player_Local_001
 * @tc.desc  : Test Player Local source
 */
HWTEST_F(PlayerServerUnitTest, Player_Local_001, TestSize.Level2)
{
    int32_t ret = player_->SetSource(MEDIA_ROOT + "AVC_Baseline@L1.2_81.0Kbps_320x240.mp4");
    EXPECT_EQ(MSERR_OK, ret);
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    ret = player_->PrepareAsync();
    if (ret == MSERR_OK) {
        PlayFunTest(LOCAL_PLAY);
    }
}

/**
 * @tc.name  : Test Player Local
 * @tc.number: Player_Local_003
 * @tc.desc  : Test Player Local source
 */
HWTEST_F(PlayerServerUnitTest, Player_Local_003, TestSize.Level2)
{
    int32_t ret = player_->SetSource(MEDIA_ROOT + "H264_MP3.mp4");
    EXPECT_EQ(MSERR_OK, ret);
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    ret = player_->PrepareAsync();
    if (ret == MSERR_OK) {
        PlayFunTest(LOCAL_PLAY);
    }
}

/**
 * @tc.name  : Test Player Local
 * @tc.number: Player_Local_008
 * @tc.desc  : Test Player Local source
 */
HWTEST_F(PlayerServerUnitTest, Player_Local_008, TestSize.Level2)
{
    int32_t ret = player_->SetSource(MEDIA_ROOT + "out_170_170.mp4");
    EXPECT_EQ(MSERR_OK, ret);
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    ret = player_->PrepareAsync();
    if (ret == MSERR_OK) {
        PlayFunTest(LOCAL_PLAY);
    }
}

/**
 * @tc.name  : Test Player Local
 * @tc.number: Player_Local_009
 * @tc.desc  : Test Player Local source
 */
HWTEST_F(PlayerServerUnitTest, Player_Local_009, TestSize.Level2)
{
    int32_t ret = player_->SetSource(MEDIA_ROOT + "H264_AAC_320x240.mp4");
    EXPECT_EQ(MSERR_OK, ret);
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    ret = player_->PrepareAsync();
    if (ret == MSERR_OK) {
        PlayFunTest(LOCAL_PLAY);
    }
}

/**
 * @tc.name  : Test Player Local
 * @tc.number: Player_Local_010
 * @tc.desc  : Test Player Local source
 */
HWTEST_F(PlayerServerUnitTest, Player_Local_010, TestSize.Level2)
{
    int32_t ret = player_->SetSource(MEDIA_ROOT + "aac_44100Hz_143kbs_stereo.aac");
    EXPECT_EQ(MSERR_OK, ret);
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    ret = player_->PrepareAsync();
    if (ret == MSERR_OK) {
        PlayFunTest(LOCAL_PLAY);
    }
}

/**
 * @tc.name  : Test Player Local
 * @tc.number: Player_Local_011
 * @tc.desc  : Test Player Local source
 */
HWTEST_F(PlayerServerUnitTest, Player_Local_011, TestSize.Level2)
{
    int32_t ret = player_->SetSource(MEDIA_ROOT + "mp3_48000Hz_64kbs_mono.mp3");
    EXPECT_EQ(MSERR_OK, ret);
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    ret = player_->PrepareAsync();
    if (ret == MSERR_OK) {
        PlayFunTest(LOCAL_PLAY);
    }
}

/**
 * @tc.name  : Test Player Local
 * @tc.number: Player_Local_013
 * @tc.desc  : Test Player Local source
 */
HWTEST_F(PlayerServerUnitTest, Player_Local_013, TestSize.Level2)
{
    int32_t ret = player_->SetSource(MEDIA_ROOT + "pcm_s16le_48000Hz_768kbs_mono.wav");
    EXPECT_EQ(MSERR_OK, ret);
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    ret = player_->PrepareAsync();
    if (ret == MSERR_OK) {
        PlayFunTest(LOCAL_PLAY);
    }
}

/**
 * @tc.name  : Test Player Local
 * @tc.number: Player_Local_014
 * @tc.desc  : Test Player Local source
 */
HWTEST_F(PlayerServerUnitTest, Player_Local_014, TestSize.Level2)
{
    int32_t ret = player_->SetSource(MEDIA_ROOT + "vorbis_48000Hz_80kbs_mono.ogg");
    EXPECT_EQ(MSERR_OK, ret);
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    ret = player_->PrepareAsync();
    if (ret == MSERR_OK) {
        PlayFunTest(LOCAL_PLAY);
    }
}

/**
 * @tc.name  : Test Player Local
 * @tc.number: Player_Local_015
 * @tc.desc  : Test Player Local source
 */
HWTEST_F(PlayerServerUnitTest, Player_Local_015, TestSize.Level2)
{
    int32_t ret = player_->SetSource(MEDIA_ROOT + "aac_48000Hz_70kbs_mono.m4a");
    EXPECT_EQ(MSERR_OK, ret);
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    ret = player_->PrepareAsync();
    if (ret == MSERR_OK) {
        PlayFunTest(LOCAL_PLAY);
    }
}

#ifdef SUBSCRIBE_HISTREAMER_EXT
/**
 * @tc.name  : Test Player Local
 * @tc.number: Player_Local_016
 * @tc.desc  : Test Player Local source
 */
HWTEST_F(PlayerServerUnitTest, Player_Local_016, TestSize.Level2)
{
    int32_t ret = player_->SetSource(MEDIA_ROOT + "H265_AAC.mp4");
    EXPECT_EQ(MSERR_OK, ret);
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    ret = player_->PrepareAsync();
    if (ret == MSERR_OK) {
        PlayFunTest(LOCAL_PLAY);
    }
}
#endif

/**
 * @tc.name  : Test Player Local
 * @tc.number: Player_Local_017
 * @tc.desc  : Test Player Local source
 */
HWTEST_F(PlayerServerUnitTest, Player_Local_017, TestSize.Level2)
{
    int32_t ret = player_->SetSource(MEDIA_ROOT + "amr_nb_8ksr_7400kbr_1ch.amr");
    EXPECT_EQ(MSERR_OK, ret);
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    ret = player_->PrepareAsync();
    if (ret == MSERR_OK) {
        PlayFunTest(LOCAL_PLAY);
    }
}

/**
 * @tc.name  : Test Player SetPlayerCallback API
 * @tc.number: Player_SetPlayerCallback_001
 * @tc.desc  : Test Player SetPlayerCallback interface
 */
HWTEST_F(PlayerServerUnitTest, Player_SetPlayerCallback_001, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    std::shared_ptr<PlayerCallbackTest> callback = std::make_shared<PlayerCallbackTest>();
    ASSERT_NE(nullptr, callback);
    EXPECT_NE(MSERR_OK, player_->SetPlayerCallback(callback));
    player_->Reset();
    player_->SetPlayerCallback(callback);
}

/**
 * @tc.name  : Test Player Prepare API
 * @tc.number: Player_Prepare_001
 * @tc.desc  : Test Player Prepare interface
 */
HWTEST_F(PlayerServerUnitTest, Player_Prepare_001, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
}

/**
 * @tc.name  : Test Player Prepare API
 * @tc.number: Player_Prepare_002
 * @tc.desc  : Test Player Prepare->Prepare
 */
HWTEST_F(PlayerServerUnitTest, Player_Prepare_002, TestSize.Level2)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    EXPECT_NE(MSERR_OK, player_->Prepare());
}

/**
 * @tc.name  : Test Player Prepare API
 * @tc.number: Player_Prepare_003
 * @tc.desc  : Test Player SetVolume/SetLooping/SetPlaybackSpeed->Prepare
 */
HWTEST_F(PlayerServerUnitTest, Player_Prepare_003, TestSize.Level2)
{
    float playbackRate = 1.5f;
    PlaybackRateMode rateMode;
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> renderSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, renderSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(renderSurface));
    EXPECT_EQ(MSERR_OK, player_->SetLooping(true));
    bool ret = player_->IsLooping();
    EXPECT_EQ(true, ret);
    EXPECT_EQ(MSERR_OK, player_->SetVolume(1, 1));
    EXPECT_NE(MSERR_OK, player_->SetPlaybackRate(playbackRate));
    EXPECT_NE(MSERR_OK, player_->SetPlaybackSpeed(SPEED_FORWARD_2_00_X));
    EXPECT_EQ(MSERR_OK, player_->GetPlaybackSpeed(rateMode));
    EXPECT_NE(SPEED_FORWARD_2_00_X, rateMode);
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    EXPECT_EQ(true, player_->IsLooping());
    EXPECT_EQ(MSERR_OK, player_->GetPlaybackSpeed(rateMode));
    EXPECT_NE(SPEED_FORWARD_2_00_X, rateMode);
}

/**
 * @tc.name  : Test Player Prepare API
 * @tc.number: Player_Prepare_004
 * @tc.desc  : Test Player Stop->Prepare
 */
HWTEST_F(PlayerServerUnitTest, Player_Prepare_004, TestSize.Level2)
{
    float playbackRate = 1.5f;
    PlaybackRateMode mode;
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    EXPECT_EQ(MSERR_OK, player_->SetLooping(true));
    EXPECT_EQ(MSERR_OK, player_->SetVolume(1, 1));
    EXPECT_EQ(MSERR_OK, player_->SetPlaybackRate(playbackRate));
    EXPECT_EQ(MSERR_OK, player_->SetPlaybackSpeed(SPEED_FORWARD_2_00_X));
    EXPECT_EQ(MSERR_OK, player_->GetPlaybackSpeed(mode));
    EXPECT_EQ(mode, SPEED_FORWARD_2_00_X);
    EXPECT_EQ(MSERR_OK, player_->Stop());
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    EXPECT_EQ(true, player_->IsLooping());
    EXPECT_EQ(MSERR_OK, player_->GetPlaybackSpeed(mode));
    EXPECT_EQ(mode, SPEED_FORWARD_2_00_X);
}

/**
 * @tc.name  : Test Player Prepare API
 * @tc.number: Player_Prepare_005
 * @tc.desc  : Test Player Play->Prepare
 */
HWTEST_F(PlayerServerUnitTest, Player_Prepare_005, TestSize.Level2)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_NE(MSERR_OK, player_->Prepare());
}

/**
 * @tc.name  : Test Player PrepareAsync API
 * @tc.number: Player_PrepareAsync_001
 * @tc.desc  : Test Player PrepareAsync interface
 */
HWTEST_F(PlayerServerUnitTest, Player_PrepareAsync_001, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->PrepareAsync());
}

/**
 * @tc.name  : Test Player PrepareAsync API
 * @tc.number: Player_PrepareAsync_002
 * @tc.desc  : Test Player PrepareAsync->PrepareAsync
 */
HWTEST_F(PlayerServerUnitTest, Player_PrepareAsync_002, TestSize.Level2)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->PrepareAsync());
    EXPECT_NE(MSERR_OK, player_->PrepareAsync());
}

/**
 * @tc.name  : Test Player PrepareAsync API
 * @tc.number: Player_PrepareAsync_003
 * @tc.desc  : Test Player SetVolume/SetLooping/SetPlaybackSpeed->PrepareAsync
 */
HWTEST_F(PlayerServerUnitTest, Player_PrepareAsync_003, TestSize.Level2)
{
    PlaybackRateMode mode;
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->SetLooping(true));
    EXPECT_EQ(true, player_->IsLooping());
    EXPECT_EQ(MSERR_OK, player_->SetVolume(1, 1));
    EXPECT_NE(MSERR_OK, player_->SetPlaybackSpeed(SPEED_FORWARD_2_00_X));
    EXPECT_EQ(MSERR_OK, player_->GetPlaybackSpeed(mode));
    EXPECT_NE(SPEED_FORWARD_2_00_X, mode);
    EXPECT_EQ(MSERR_OK, player_->PrepareAsync());
    EXPECT_EQ(true, player_->IsLooping());
    EXPECT_EQ(MSERR_OK, player_->GetPlaybackSpeed(mode));
    EXPECT_NE(SPEED_FORWARD_2_00_X, mode);
}

/**
 * @tc.name  : Test Player PrepareAsync API
 * @tc.number: Player_PrepareAsync1_003
 * @tc.desc  : Test Player SetVolume/SetLooping/SetPlaybackRate->PrepareAsync
 */
HWTEST_F(PlayerServerUnitTest, Player_PrepareAsync1_003, TestSize.Level2)
{
    float playbackRate = 2.0f;
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->SetLooping(true));
    EXPECT_EQ(true, player_->IsLooping());
    EXPECT_EQ(MSERR_OK, player_->SetVolume(1, 1));
    EXPECT_NE(MSERR_OK, player_->SetPlaybackRate(playbackRate));
    EXPECT_EQ(MSERR_OK, player_->PrepareAsync());
    EXPECT_EQ(true, player_->IsLooping());
}

/**
 * @tc.name  : Test Player PrepareAsync API
 * @tc.number: Player_PrepareAsync_004
 * @tc.desc  : Test Player Stop->PrepareAsync
 */
HWTEST_F(PlayerServerUnitTest, Player_PrepareAsync_004, TestSize.Level2)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->PrepareAsync());
    EXPECT_EQ(MSERR_OK, player_->Stop());
    EXPECT_EQ(MSERR_OK, player_->PrepareAsync());
}

/**
 * @tc.name  : Test Player PrepareAsync API
 * @tc.number: Player_PrepareAsync_005
 * @tc.desc  : Test Player Play->PrepareAsync
 */
HWTEST_F(PlayerServerUnitTest, Player_PrepareAsync_005, TestSize.Level2)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->PrepareAsync());
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_NE(MSERR_OK, player_->PrepareAsync());
}

/**
 * @tc.name  : Test Player PrepareAsync API
 * @tc.number: Player_PrepareAsync_006
 * @tc.desc  : Test Player Play->PrepareAsync
 */
HWTEST_F(PlayerServerUnitTest, Player_PrepareAsync_006, TestSize.Level2)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(MEDIA_ROOT + "H264_AAC_DRM.ts"));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_NE(MSERR_OK, player_->PrepareAsync());
}

/**
 * @tc.name  : Test Player SetVideoSurface API
 * @tc.number: Player_SetVideoSurface_001
 * @tc.desc  : Test Player SetVideoSurface interface
 */
HWTEST_F(PlayerServerUnitTest, Player_SetVideoSurface_001, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(player_->GetVideoSurface()));
}

/**
 * @tc.name  : Test Player SetVideoSurface API
 * @tc.number: Player_SetVideoSurface_002
 * @tc.desc  : Test Player PrepareAsync->SetVideoSurface
 */
HWTEST_F(PlayerServerUnitTest, Player_SetVideoSurface_002, TestSize.Level2)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    EXPECT_EQ(MSERR_OK, player_->PrepareAsync());
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_NE(MSERR_OK, player_->SetVideoSurface(videoSurface));
}

/**
 * @tc.name  : Test Player SetVideoSurface API
 * @tc.number: Player_SetVideoSurface_003
 * @tc.desc  : Test Player SetVideoSurface interface
 */
HWTEST_F(PlayerServerUnitTest, Player_SetVideoSurface_003, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_NE(MSERR_OK, player_->SetVideoSurface(videoSurface));
}

/**
 * @tc.name  : Test Player Play API
 * @tc.number: Player_Play_001
 * @tc.desc  : Test Player Play interface
 */
HWTEST_F(PlayerServerUnitTest, Player_Play_001, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->PrepareAsync());
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_TRUE(player_->IsPlaying());
    EXPECT_EQ(MSERR_OK, player_->Pause());
    EXPECT_EQ(MSERR_OK, player_->Play());
}

/**
 * @tc.name  : Test Player Play API
 * @tc.number: Player_Play_002
 * @tc.desc  : Test Player Reset->Play
 */
HWTEST_F(PlayerServerUnitTest, Player_Play_002, TestSize.Level2)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->PrepareAsync());
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_TRUE(player_->IsPlaying());
    EXPECT_EQ(MSERR_OK, player_->Reset());
    EXPECT_NE(MSERR_OK, player_->Play());
}

/**
 * @tc.name  : Test Player Play API
 * @tc.number: Player_Play_003
 * @tc.desc  : Test Player complete->Play
 */
HWTEST_F(PlayerServerUnitTest, Player_Play_003, TestSize.Level2)
{
    int32_t duration = 0;
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->PrepareAsync());
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_TRUE(player_->IsPlaying());
    EXPECT_EQ(MSERR_OK, player_->GetDuration(duration));
    EXPECT_EQ(MSERR_OK, player_->Seek(duration, SEEK_CLOSEST));
    sleep(PLAYING_TIME_2_SEC);
    EXPECT_EQ(MSERR_OK, player_->Play());
}

/**
 * @tc.name  : Test Player Play API
 * @tc.number: Player_Play_004
 * @tc.desc  : Test Player Play->Play
 */
HWTEST_F(PlayerServerUnitTest, Player_Play_004, TestSize.Level2)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->PrepareAsync());
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_TRUE(player_->IsPlaying());
    EXPECT_NE(MSERR_OK, player_->Play());
}

/**
 * @tc.name  : Test Player Stop API
 * @tc.number: Player_Stop_001
 * @tc.desc  : Test Player Stop Play->Stop
 */
HWTEST_F(PlayerServerUnitTest, Player_Stop_001, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1, 0, 0));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_TRUE(player_->IsPlaying());
    EXPECT_EQ(MSERR_OK, player_->Stop());
}

/**
 * @tc.name  : Test Player Stop API
 * @tc.number: Player_Stop_002
 * @tc.desc  : Test Player Stop Prepare->Stop
 */
HWTEST_F(PlayerServerUnitTest, Player_Stop_002, TestSize.Level2)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1, 0, 0));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    EXPECT_EQ(MSERR_OK, player_->Stop());
}

/**
 * @tc.name  : Test Player Stop API
 * @tc.number: Player_Stop_003
 * @tc.desc  : Test Player Stop complete/stop->Stop
 */
HWTEST_F(PlayerServerUnitTest, Player_Stop_003, TestSize.Level2)
{
    int32_t duration = 0;
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1, 0, 0));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    EXPECT_EQ(MSERR_OK, player_->GetDuration(duration));
    EXPECT_EQ(MSERR_OK, player_->Seek(duration, SEEK_CLOSEST));
    sleep(PLAYING_TIME_2_SEC);
    EXPECT_EQ(MSERR_OK, player_->Stop());
    EXPECT_NE(MSERR_OK, player_->Stop());
}

/**
 * @tc.name  : Test Player Stop API
 * @tc.number: Player_Stop_004
 * @tc.desc  : Test Player Stop Reset->Stop
 */
HWTEST_F(PlayerServerUnitTest, Player_Stop_004, TestSize.Level2)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1, 0, 0));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_EQ(MSERR_OK, player_->Reset());
    EXPECT_NE(MSERR_OK, player_->Stop());
}

/**
 * @tc.name  : Test Player Stop API
 * @tc.number: Player_Stop_005
 * @tc.desc  : Test Player Reset->Stop
 */
HWTEST_F(PlayerServerUnitTest, Player_Stop_005, TestSize.Level2)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1, 0, 0));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_TRUE(player_->IsPlaying());
    EXPECT_EQ(MSERR_OK, player_->Reset());
    EXPECT_NE(MSERR_OK, player_->Stop());
}

/**
 * @tc.name  : Test Player Pause API
 * @tc.number: Player_Pause_001
 * @tc.desc  : Test Player Pause interface
 */
HWTEST_F(PlayerServerUnitTest, Player_Pause_001, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_TRUE(player_->IsPlaying());
    EXPECT_EQ(MSERR_OK, player_->Pause());
    EXPECT_FALSE(player_->IsPlaying());
    EXPECT_EQ(MSERR_OK, player_->Pause());
}

/**
 * @tc.name  : Test Player Pause API
 * @tc.number: Player_Pause_002
 * @tc.desc  : Test Player Pause interface
 */
HWTEST_F(PlayerServerUnitTest, Player_Pause_002, TestSize.Level2)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    EXPECT_NE(MSERR_OK, player_->Pause());
}

/**
 * @tc.name  : Test Player Pause API
 * @tc.number: Player_Pause_003
 * @tc.desc  : Test Player Pause interface, Stop -> Pause
 */
HWTEST_F(PlayerServerUnitTest, Player_Pause_003, TestSize.Level2)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    EXPECT_EQ(MSERR_OK, player_->Stop());
    EXPECT_NE(MSERR_OK, player_->Pause());
}

/**
 * @tc.name  : Test Player Reset API
 * @tc.number: Player_Reset_001
 * @tc.desc  : Test Player Reset interface
 */
HWTEST_F(PlayerServerUnitTest, Player_Reset_001, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    EXPECT_EQ(MSERR_OK, player_->Reset());
    EXPECT_NE(MSERR_OK, player_->Reset());
}

/**
 * @tc.name  : Test Player Seek API
 * @tc.number: Player_Seek_001
 * @tc.desc  : Test Player Seek interface with valid parameters
 */
HWTEST_F(PlayerServerUnitTest, Player_Seek_001, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    EXPECT_EQ(MSERR_OK, player_->Seek(SEEK_TIME_4_SEC, SEEK_NEXT_SYNC));
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_TRUE(player_->IsPlaying());
    EXPECT_EQ(MSERR_OK, player_->Seek(SEEK_TIME_4_SEC, SEEK_CLOSEST));
    int32_t time = 0;
    EXPECT_EQ(MSERR_OK, player_->GetCurrentTime(time));
    EXPECT_NEAR(SEEK_TIME_4_SEC, time, DELTA_TIME);
    EXPECT_EQ(MSERR_OK, player_->Pause());
    EXPECT_EQ(MSERR_OK, player_->Seek(SEEK_TIME_4_SEC, SEEK_NEXT_SYNC));
}

/**
 * @tc.name  : Test Player Seek API
 * @tc.number: Player_Seek_002
 * @tc.desc  : Test Player Seek interface with seek mode
 */
HWTEST_F(PlayerServerUnitTest, Player_Seek_002, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    EXPECT_EQ(MSERR_OK, player_->Seek(0, SEEK_NEXT_SYNC));
    EXPECT_EQ(MSERR_OK, player_->Seek(0, SEEK_PREVIOUS_SYNC));
    EXPECT_EQ(MSERR_OK, player_->Seek(0, SEEK_CLOSEST_SYNC));
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_TRUE(player_->IsPlaying());
    EXPECT_EQ(MSERR_OK, player_->Seek(SEEK_TIME_2_SEC, SEEK_NEXT_SYNC));
    EXPECT_EQ(MSERR_OK, player_->Seek(SEEK_TIME_2_SEC, SEEK_PREVIOUS_SYNC));
    EXPECT_EQ(MSERR_OK, player_->Seek(SEEK_TIME_2_SEC, SEEK_CLOSEST_SYNC));
    EXPECT_NE(MSERR_OK, player_->Seek(SEEK_TIME_2_SEC, (PlayerSeekMode)5));
}

/**
 * @tc.name  : Test Player Seek API
 * @tc.number: Player_Seek_002
 * @tc.desc  : Test Player Seek out of duration
 */
HWTEST_F(PlayerServerUnitTest, Player_Seek_003, TestSize.Level2)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_TRUE(player_->IsPlaying());
    EXPECT_EQ(MSERR_OK, player_->Seek(1000000, SEEK_NEXT_SYNC));
}

/**
 * @tc.name  : Test Seek API
 * @tc.number: Player_Seek_004
 * @tc.desc  : Test Player Seek
 */
HWTEST_F(PlayerServerUnitTest, Player_Seek_004, TestSize.Level2)
{
    int32_t duration = 0;
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    EXPECT_NE(MSERR_OK, player_->Seek(SEEK_TIME_2_SEC, SEEK_NEXT_SYNC));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_NE(MSERR_OK, player_->Seek(SEEK_TIME_2_SEC, SEEK_NEXT_SYNC));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    EXPECT_EQ(MSERR_OK, player_->Seek(SEEK_TIME_2_SEC, SEEK_NEXT_SYNC));
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_EQ(MSERR_OK, player_->Seek(SEEK_TIME_2_SEC, SEEK_NEXT_SYNC));
    EXPECT_EQ(MSERR_OK, player_->Pause());
    EXPECT_EQ(MSERR_OK, player_->Seek(SEEK_TIME_2_SEC, SEEK_NEXT_SYNC));
    EXPECT_EQ(MSERR_OK, player_->GetDuration(duration));
    EXPECT_EQ(MSERR_OK, player_->Seek(duration, SEEK_CLOSEST));
    EXPECT_EQ(MSERR_OK, player_->Play());
    sleep(PLAYING_TIME_2_SEC);
    EXPECT_EQ(MSERR_OK, player_->Seek(SEEK_TIME_2_SEC, SEEK_NEXT_SYNC));
    EXPECT_EQ(MSERR_OK, player_->Stop());
    EXPECT_NE(MSERR_OK, player_->Seek(SEEK_TIME_2_SEC, SEEK_NEXT_SYNC));
    EXPECT_EQ(MSERR_OK, player_->Reset());
    EXPECT_NE(MSERR_OK, player_->Seek(SEEK_TIME_2_SEC, SEEK_NEXT_SYNC));
}

/**
 * @tc.name  : Test Player Seek API
 * @tc.number: Player_Seek_005
 * @tc.desc  : Test Player Seek interface
 */
HWTEST_F(PlayerServerUnitTest, Player_Seek_005, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    EXPECT_NE(MSERR_OK, player_->Seek(SEEK_TIME_2_SEC, SEEK_PREVIOUS_SYNC));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_NE(MSERR_OK, player_->Seek(SEEK_TIME_2_SEC, SEEK_PREVIOUS_SYNC));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    EXPECT_EQ(MSERR_OK, player_->Seek(SEEK_TIME_2_SEC, SEEK_PREVIOUS_SYNC));
}

/**
 * @tc.name  : Test Player Seek API
 * @tc.number: Player_Seek_006
 * @tc.desc  : Test Player Seek interface
 */
HWTEST_F(PlayerServerUnitTest, Player_Seek_006, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    EXPECT_NE(MSERR_OK, player_->Seek(SEEK_TIME_2_SEC, SEEK_CLOSEST));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_NE(MSERR_OK, player_->Seek(SEEK_TIME_2_SEC, SEEK_CLOSEST));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    EXPECT_EQ(MSERR_OK, player_->Seek(SEEK_TIME_2_SEC, SEEK_CLOSEST));
}

/**
 * @tc.name  : Test Player Seek API
 * @tc.number: Player_Seek_007
 * @tc.desc  : Test Player Seek interface
 */
HWTEST_F(PlayerServerUnitTest, Player_Seek_007, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    EXPECT_NE(MSERR_OK, player_->Seek(SEEK_TIME_2_SEC, SEEK_NEXT_SYNC));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_NE(MSERR_OK, player_->Seek(SEEK_TIME_2_SEC, SEEK_NEXT_SYNC));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    EXPECT_EQ(MSERR_OK, player_->Seek(SEEK_TIME_2_SEC, SEEK_NEXT_SYNC));
}

/**
 * @tc.name  : Test Player Seek API
 * @tc.number: Player_Seek_008
 * @tc.desc  : Test Player Seek interface
 */
HWTEST_F(PlayerServerUnitTest, Player_Seek_008, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_EQ(MSERR_OK, player_->Seek(0, SEEK_CLOSEST));
    EXPECT_EQ(MSERR_OK, player_->Seek(SEEK_TIME_2_SEC, SEEK_CLOSEST));
    int32_t duration = 0;
    EXPECT_EQ(MSERR_OK, player_->GetDuration(duration));
    EXPECT_EQ(MSERR_OK, player_->Seek(duration, SEEK_CLOSEST));
    EXPECT_EQ(MSERR_OK, player_->Seek(SEEK_TIME_2_SEC, SEEK_CLOSEST));
    EXPECT_EQ(MSERR_OK, player_->Seek(0, SEEK_CLOSEST));
}

/**
 * @tc.name  : Test Player Seek API
 * @tc.number: Player_Seek_009
 * @tc.desc  : Test Player Seek interface
 */
HWTEST_F(PlayerServerUnitTest, Player_Seek_009, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_EQ(MSERR_OK, player_->Seek(0, SEEK_PREVIOUS_SYNC));
    EXPECT_EQ(MSERR_OK, player_->Seek(SEEK_TIME_2_SEC, SEEK_PREVIOUS_SYNC));
    int32_t duration = 0;
    EXPECT_EQ(MSERR_OK, player_->GetDuration(duration));
    EXPECT_EQ(MSERR_OK, player_->Seek(duration, SEEK_PREVIOUS_SYNC));
    EXPECT_EQ(MSERR_OK, player_->Seek(SEEK_TIME_2_SEC, SEEK_PREVIOUS_SYNC));
    EXPECT_EQ(MSERR_OK, player_->Seek(0, SEEK_PREVIOUS_SYNC));
}

/**
 * @tc.name  : Test Player Seek API
 * @tc.number: Player_Seek_010
 * @tc.desc  : Test Player Seek interface
 */
HWTEST_F(PlayerServerUnitTest, Player_Seek_010, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_EQ(MSERR_OK, player_->Seek(0, SEEK_NEXT_SYNC));
    EXPECT_EQ(MSERR_OK, player_->Seek(SEEK_TIME_2_SEC, SEEK_NEXT_SYNC));
    int32_t duration = 0;
    EXPECT_EQ(MSERR_OK, player_->GetDuration(duration));
    EXPECT_EQ(MSERR_OK, player_->Seek(duration, SEEK_NEXT_SYNC));
    EXPECT_EQ(MSERR_OK, player_->Seek(SEEK_TIME_2_SEC, SEEK_NEXT_SYNC));
    EXPECT_EQ(MSERR_OK, player_->Seek(0, SEEK_NEXT_SYNC));
}

/**
 * @tc.name  : Test GetVideoTrackInfo API
 * @tc.number: Player_GetVideoTrackInfo_001
 * @tc.desc  : Test Player GetVideoTrackInfo
 */
HWTEST_F(PlayerServerUnitTest, Player_GetVideoTrackInfo_001, TestSize.Level1)
{
    std::vector<Format> videoTrack;
    std::vector<Format> audioTrack;
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_EQ(MSERR_OK, player_->GetVideoTrackInfo(videoTrack));
    EXPECT_EQ(MSERR_OK, player_->GetAudioTrackInfo(audioTrack));
}

/**
 * @tc.name  : Test GetVideoTrackInfo API
 * @tc.number: Player_GetVideoTrackInfo_002
 * @tc.desc  : Test Player GetVideoTrackInfo
 */
HWTEST_F(PlayerServerUnitTest, Player_GetVideoTrackInfo_002, TestSize.Level2)
{
    std::vector<Format> videoTrack;
    std::vector<Format> audioTrack;
    int32_t duration = 0;
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    EXPECT_NE(MSERR_OK, player_->GetVideoTrackInfo(videoTrack));
    EXPECT_NE(MSERR_OK, player_->GetAudioTrackInfo(audioTrack));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_NE(MSERR_OK, player_->GetVideoTrackInfo(videoTrack));
    EXPECT_NE(MSERR_OK, player_->GetAudioTrackInfo(audioTrack));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    EXPECT_EQ(MSERR_OK, player_->GetVideoTrackInfo(videoTrack));
    EXPECT_EQ(MSERR_OK, player_->GetAudioTrackInfo(audioTrack));
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_EQ(MSERR_OK, player_->GetVideoTrackInfo(videoTrack));
    EXPECT_EQ(MSERR_OK, player_->GetAudioTrackInfo(audioTrack));
    EXPECT_EQ(MSERR_OK, player_->Pause());
    EXPECT_EQ(MSERR_OK, player_->GetVideoTrackInfo(videoTrack));
    EXPECT_EQ(MSERR_OK, player_->GetAudioTrackInfo(audioTrack));
    EXPECT_EQ(MSERR_OK, player_->GetDuration(duration));
    EXPECT_EQ(MSERR_OK, player_->Seek(duration, SEEK_CLOSEST));
    EXPECT_EQ(MSERR_OK, player_->Play());
    sleep(PLAYING_TIME_2_SEC);
    EXPECT_EQ(MSERR_OK, player_->GetVideoTrackInfo(videoTrack));
    EXPECT_EQ(MSERR_OK, player_->GetAudioTrackInfo(audioTrack));
    EXPECT_EQ(MSERR_OK, player_->Stop());
    EXPECT_NE(MSERR_OK, player_->GetVideoTrackInfo(videoTrack));
    EXPECT_NE(MSERR_OK, player_->GetAudioTrackInfo(audioTrack));
    EXPECT_EQ(MSERR_OK, player_->Reset());
    EXPECT_NE(MSERR_OK, player_->GetVideoTrackInfo(videoTrack));
    EXPECT_NE(MSERR_OK, player_->GetAudioTrackInfo(audioTrack));
}

/**
 * @tc.name  : Test GetAudioTrackInfo API
 * @tc.number: Player_GetAudioTrackInfo_001
 * @tc.desc  : Test Player GetAudioTrackInfo
 */
HWTEST_F(PlayerServerUnitTest, Player_GetAudioTrackInfo_001, TestSize.Level2)
{
    std::vector<Format> audioTrack;
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    EXPECT_EQ(MSERR_OK, player_->Play());
    sleep(PLAYING_TIME_2_SEC);
    EXPECT_EQ(MSERR_OK, player_->GetAudioTrackInfo(audioTrack));
    EXPECT_EQ(1, audioTrack.size());
    Format audioTrackFormat = audioTrack.front();
    int32_t sampleDepth;
    audioTrackFormat.GetIntValue("sample_depth", sampleDepth);
    EXPECT_EQ(16, sampleDepth);
}

/**
 * @tc.name  : Test SelectTrack and DeselectTrack API
 * @tc.number: Player_SelectTrack_001
 * @tc.desc  : Test Player SelectTrack and DeselectTrack
 */
HWTEST_F(PlayerServerUnitTest, Player_SelectTrack_001, TestSize.Level1)
{
    bool trackChange = false;
    std::vector<Format> audioTrack;
    std::vector<int32_t> audioTrackIds;
    int32_t currentAudioTrackIndex = -1;
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE2));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_EQ(MSERR_OK, player_->SetVolume(1, 1));
    sleep(PLAYING_TIME_2_SEC);
    EXPECT_EQ(MSERR_OK, player_->GetCurrentTrack(MediaType::MEDIA_TYPE_AUD, currentAudioTrackIndex));
    EXPECT_EQ(MSERR_OK, player_->GetAudioTrackInfo(audioTrack));
    for (Format audioTrackFormat: audioTrack) {
        int32_t trackIndex = -1;
        audioTrackFormat.GetIntValue("track_index", trackIndex);
        audioTrackIds.push_back(trackIndex);
    }
    for (int32_t trackIndex: audioTrackIds) {
        if (trackIndex != currentAudioTrackIndex) {
            trackChange = false;
            EXPECT_EQ(MSERR_OK, player_->SelectTrack(trackIndex, trackChange));
            EXPECT_EQ(trackChange, true);
            EXPECT_EQ(MSERR_OK, player_->GetCurrentTrack(MediaType::MEDIA_TYPE_AUD, currentAudioTrackIndex));
            sleep(PLAYING_TIME_2_SEC);
            trackChange = false;
            EXPECT_EQ(MSERR_OK, player_->DeselectTrack(currentAudioTrackIndex, trackChange));
            EXPECT_EQ(trackChange, true);
            EXPECT_EQ(MSERR_OK, player_->GetCurrentTrack(MediaType::MEDIA_TYPE_AUD, currentAudioTrackIndex));
            sleep(PLAYING_TIME_2_SEC);
        }
    }
    EXPECT_EQ(MSERR_OK, player_->Stop());
}

/**
 * @tc.name  : Test SelectTrack API
 * @tc.number: Player_SelectTrack_002
 * @tc.desc  : Test Player SelectTrack invalid trackId
 */
HWTEST_F(PlayerServerUnitTest, Player_SelectTrack_002, TestSize.Level1)
{
    bool trackChange = false;
    int32_t currentAudioTrackIndex = -1;
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE2));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_EQ(MSERR_OK, player_->SetVolume(1, 1));
    sleep(PLAYING_TIME_2_SEC);
    EXPECT_EQ(MSERR_OK, player_->GetCurrentTrack(MediaType::MEDIA_TYPE_AUD, currentAudioTrackIndex));
    EXPECT_NE(MSERR_OK, player_->SelectTrack(currentAudioTrackIndex, trackChange));
    sleep(PLAYING_TIME_2_SEC);
    EXPECT_EQ(MSERR_OK, player_->Stop());
}

/**
 * @tc.name  : Test DeselectTrack API
 * @tc.number: Player_DeselectTrack_001
 * @tc.desc  : Test Player DeselectTrack invalid trackId
 */
HWTEST_F(PlayerServerUnitTest, Player_DeselectTrack_001, TestSize.Level1)
{
    std::vector<Format> audioTrack;
    std::vector<int32_t> audioTrackIds;
    int32_t defaultAudioTrackIndex = -1;
    bool trackChange = false;
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE2));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_EQ(MSERR_OK, player_->SetVolume(1, 1));
    sleep(PLAYING_TIME_2_SEC);
    EXPECT_EQ(MSERR_OK, player_->GetAudioTrackInfo(audioTrack));
    EXPECT_GT(audioTrack.size(), 0);
    audioTrack[0].GetIntValue("track_index", defaultAudioTrackIndex);
    EXPECT_GT(defaultAudioTrackIndex, -1);
    EXPECT_NE(MSERR_OK, player_->DeselectTrack(defaultAudioTrackIndex, trackChange));
    sleep(PLAYING_TIME_2_SEC);
    EXPECT_EQ(MSERR_OK, player_->Stop());
}

/**
 * @tc.name  : Test GetVideoHeight API
 * @tc.number: Player_GetVideoHeight_001
 * @tc.desc  : Test Player GetVideoHeight
 */
HWTEST_F(PlayerServerUnitTest, Player_GetVideoHeight_001, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_EQ(480, player_->GetVideoHeight());
    EXPECT_EQ(720, player_->GetVideoWidth());
}

/**
 * @tc.name  : Test GetVideoHeight API
 * @tc.number: Player_GetVideoHeight_002
 * @tc.desc  : Test Player GetVideoHeight
 */
HWTEST_F(PlayerServerUnitTest, Player_GetVideoHeight_002, TestSize.Level2)
{
    int32_t duration = 0;
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    EXPECT_NE(480, player_->GetVideoHeight());
    EXPECT_NE(720, player_->GetVideoWidth());
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_NE(480, player_->GetVideoHeight());
    EXPECT_NE(720, player_->GetVideoWidth());
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    EXPECT_EQ(480, player_->GetVideoHeight());
    EXPECT_EQ(720, player_->GetVideoWidth());
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_EQ(480, player_->GetVideoHeight());
    EXPECT_EQ(720, player_->GetVideoWidth());
    EXPECT_EQ(MSERR_OK, player_->Pause());
    EXPECT_EQ(480, player_->GetVideoHeight());
    EXPECT_EQ(720, player_->GetVideoWidth());
    EXPECT_EQ(MSERR_OK, player_->GetDuration(duration));
    EXPECT_EQ(MSERR_OK, player_->Seek(duration, SEEK_CLOSEST));
    EXPECT_EQ(MSERR_OK, player_->Play());
    sleep(PLAYING_TIME_2_SEC);
    EXPECT_EQ(480, player_->GetVideoHeight());
    EXPECT_EQ(720, player_->GetVideoWidth());
    EXPECT_EQ(MSERR_OK, player_->Stop());
    EXPECT_EQ(480, player_->GetVideoHeight());
    EXPECT_EQ(720, player_->GetVideoWidth());
    EXPECT_EQ(MSERR_OK, player_->Reset());
    EXPECT_NE(480, player_->GetVideoHeight());
    EXPECT_NE(720, player_->GetVideoWidth());
}

/**
 * @tc.name  : Test GetDuration API
 * @tc.number: Player_GetDuration_001
 * @tc.desc  : Test Player GetDuration
 */
HWTEST_F(PlayerServerUnitTest, Player_GetDuration_001, TestSize.Level1)
{
    int32_t duration = 0;
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_EQ(MSERR_OK, player_->GetDuration(duration));
    EXPECT_NEAR(10000, duration, DELTA_TIME); // duration 10000ms
}

/**
 * @tc.name  : Test GetDuration API
 * @tc.number: Player_GetDuration_002
 * @tc.desc  : Test Player GetDuration
 */
HWTEST_F(PlayerServerUnitTest, Player_GetDuration_002, TestSize.Level2)
{
    int32_t duration = 0;
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    EXPECT_NE(MSERR_OK, player_->GetDuration(duration));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_NE(MSERR_OK, player_->GetDuration(duration));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    EXPECT_EQ(MSERR_OK, player_->GetDuration(duration));
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_EQ(MSERR_OK, player_->GetDuration(duration));
    EXPECT_EQ(MSERR_OK, player_->Pause());
    EXPECT_EQ(MSERR_OK, player_->GetDuration(duration));
    EXPECT_EQ(MSERR_OK, player_->Seek(duration, SEEK_CLOSEST));
    EXPECT_EQ(MSERR_OK, player_->Play());
    sleep(PLAYING_TIME_2_SEC);
    EXPECT_EQ(MSERR_OK, player_->GetDuration(duration));
    EXPECT_EQ(MSERR_OK, player_->Stop());
    EXPECT_EQ(MSERR_OK, player_->GetDuration(duration));
    EXPECT_EQ(MSERR_OK, player_->Reset());
    EXPECT_NE(MSERR_OK, player_->GetDuration(duration));
}

/**
 * @tc.name  : Test SetPlaybackSpeed API
 * @tc.number: Player_SetPlaybackSpeed_001
 * @tc.desc  : Test Player SetPlaybackSpeed
 */
HWTEST_F(PlayerServerUnitTest, Player_SetPlaybackSpeed_001, TestSize.Level1)
{
    PlaybackRateMode mode;
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_EQ(MSERR_OK, player_->SetPlaybackSpeed(SPEED_FORWARD_2_00_X));
    EXPECT_EQ(MSERR_OK, player_->GetPlaybackSpeed(mode));
    EXPECT_EQ(SPEED_FORWARD_2_00_X, mode);
}
/**
 * @tc.name  : Test SetPlaybackRate API
 * @tc.number: Player_SetPlaybackRate_001
 * @tc.desc  : Test Player SetPlaybackRate
 */
HWTEST_F(PlayerServerUnitTest, Player_SetPlaybackRate_001, TestSize.Level1)
{
    float playbackRate = 2.0f;
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_EQ(MSERR_OK, player_->SetPlaybackRate(playbackRate));
}

/**
 * @tc.name  : Test SetPlaybackSpeed API
 * @tc.number: Player_SetPlaybackSpeed_002
 * @tc.desc  : Test Player SetPlaybackSpeed
 */
HWTEST_F(PlayerServerUnitTest, Player_SetPlaybackSpeed_002, TestSize.Level2)
{
    int32_t duration = 0;
    PlaybackRateMode mode;
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    EXPECT_NE(MSERR_OK, player_->SetPlaybackSpeed(SPEED_FORWARD_2_00_X));
    EXPECT_EQ(MSERR_OK, player_->GetPlaybackSpeed(mode));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_NE(MSERR_OK, player_->SetPlaybackSpeed(SPEED_FORWARD_2_00_X));
    EXPECT_EQ(MSERR_OK, player_->GetPlaybackSpeed(mode));
    EXPECT_EQ(MSERR_OK, player_->PrepareAsync());
    EXPECT_EQ(MSERR_OK, player_->SetPlaybackSpeed(SPEED_FORWARD_2_00_X));
    EXPECT_EQ(MSERR_OK, player_->GetPlaybackSpeed(mode));
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_EQ(MSERR_OK, player_->SetPlaybackSpeed(SPEED_FORWARD_2_00_X));
    EXPECT_EQ(MSERR_OK, player_->GetPlaybackSpeed(mode));
    EXPECT_EQ(MSERR_OK, player_->Pause());
    EXPECT_EQ(MSERR_OK, player_->SetPlaybackSpeed(SPEED_FORWARD_1_75_X));
    EXPECT_EQ(MSERR_OK, player_->GetPlaybackSpeed(mode));
    EXPECT_EQ(MSERR_OK, player_->GetDuration(duration));
    EXPECT_EQ(MSERR_OK, player_->Seek(duration, SEEK_CLOSEST));
    EXPECT_EQ(MSERR_OK, player_->Play());
    sleep(PLAYING_TIME_2_SEC);
    EXPECT_EQ(MSERR_OK, player_->SetPlaybackSpeed(SPEED_FORWARD_0_75_X));
    EXPECT_EQ(MSERR_OK, player_->GetPlaybackSpeed(mode));
    EXPECT_EQ(MSERR_OK, player_->Stop());
    EXPECT_NE(MSERR_OK, player_->SetPlaybackSpeed(SPEED_FORWARD_1_25_X));
    EXPECT_EQ(MSERR_OK, player_->GetPlaybackSpeed(mode));
    EXPECT_EQ(MSERR_OK, player_->Reset());
    EXPECT_NE(MSERR_OK, player_->SetPlaybackSpeed(SPEED_FORWARD_2_00_X));
    EXPECT_EQ(MSERR_OK, player_->GetPlaybackSpeed(mode));
}

/**
 * @tc.name  : Test SetPlaybackRate API
 * @tc.number: Player_SetPlaybackRate_002
 * @tc.desc  : Test Player SetPlaybackRate
 */
HWTEST_F(PlayerServerUnitTest, Player_SetPlaybackRate_002, TestSize.Level2)
{
    int32_t duration = 0;
    float playbackRate1 = 2.0f;
    float playbackRate2 = 1.75f;
    float playbackRate3 = 1.25f;
    float playbackRate4 = 0.75f;
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    EXPECT_NE(MSERR_OK, player_->SetPlaybackRate(playbackRate1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_NE(MSERR_OK, player_->SetPlaybackRate(playbackRate1));
    EXPECT_EQ(MSERR_OK, player_->PrepareAsync());
    EXPECT_EQ(MSERR_OK, player_->SetPlaybackRate(playbackRate1));
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_EQ(MSERR_OK, player_->SetPlaybackRate(playbackRate1));
    EXPECT_EQ(MSERR_OK, player_->Pause());
    EXPECT_EQ(MSERR_OK, player_->SetPlaybackRate(playbackRate2));
    EXPECT_EQ(MSERR_OK, player_->GetDuration(duration));
    EXPECT_EQ(MSERR_OK, player_->Seek(duration, SEEK_CLOSEST));
    EXPECT_EQ(MSERR_OK, player_->Play());
    sleep(PLAYING_TIME_2_SEC);
    EXPECT_EQ(MSERR_OK, player_->SetPlaybackRate(playbackRate4));
    EXPECT_EQ(MSERR_OK, player_->Stop());
    EXPECT_NE(MSERR_OK, player_->SetPlaybackRate(playbackRate3));
    EXPECT_EQ(MSERR_OK, player_->Reset());
    EXPECT_NE(MSERR_OK, player_->SetPlaybackRate(playbackRate1));
}

/**
 * @tc.name  : Test SetLooping API
 * @tc.number: Player_SetLooping_001
 * @tc.desc  : Test Player SetLooping
 */
HWTEST_F(PlayerServerUnitTest, Player_SetLooping_001, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_EQ(MSERR_OK, player_->SetLooping(true));
    EXPECT_EQ(true, player_->IsLooping());
    EXPECT_EQ(MSERR_OK, player_->SetLooping(false));
    EXPECT_EQ(false, player_->IsLooping());
}

/**
 * @tc.name  : Test SetLooping API
 * @tc.number: Player_SetLooping_002
 * @tc.desc  : Test Player SetLooping liveStream
 */
HWTEST_F(PlayerServerUnitTest, Player_SetLooping_002, TestSize.Level0)
{
    std::shared_ptr<PlayerServer> server = std::make_shared<PlayerServer>();
    server->isLiveStream_ = true;
    EXPECT_EQ(MSERR_INVALID_OPERATION, server->SetLooping(true));
}

/**
 * @tc.name  : Test SetLooping API
 * @tc.number: Player_SetLooping_003
 * @tc.desc  : Test Player SetLooping invalid playerEngine
 */
HWTEST_F(PlayerServerUnitTest, Player_SetLooping_003, TestSize.Level0)
{
    std::shared_ptr<PlayerServer> server = std::make_shared<PlayerServer>();
    server->lastOpStatus_ = PLAYER_STARTED;
    EXPECT_EQ(MSERR_OK, server->SetLooping(true));
}

/**
 * @tc.name  : Test SetVolume API
 * @tc.number: Player_SetVolume_001
 * @tc.desc  : Test Player SetVolume
 */
HWTEST_F(PlayerServerUnitTest, Player_SetVolume_001, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_EQ(MSERR_OK, player_->SetVolume(1, 1));
}

/**
 * @tc.name  : Test SetVolume API
 * @tc.number: Player_SetVolume_002
 * @tc.desc  : Test Player SetVolume
 */
HWTEST_F(PlayerServerUnitTest, Player_SetVolume_002, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_NE(MSERR_OK, player_->SetVolume(1.1, 0.1));
    EXPECT_NE(MSERR_OK, player_->SetVolume(0.1, 1.1));
    EXPECT_NE(MSERR_OK, player_->SetVolume(1.1, 1.1));
    EXPECT_NE(MSERR_OK, player_->SetVolume(-0.1, 0.1));
    EXPECT_NE(MSERR_OK, player_->SetVolume(0.1, -0.1));
    EXPECT_NE(MSERR_OK, player_->SetVolume(-0.1, -0.1));
}

/**
 * @tc.name  : Test SetVolume API
 * @tc.number: Player_SetVolume_003
 * @tc.desc  : Test Player SetVolume
 */
HWTEST_F(PlayerServerUnitTest, Player_SetVolume_003, TestSize.Level2)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    EXPECT_EQ(MSERR_OK, player_->SetVolume(1, 1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->SetVolume(1, 1));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    EXPECT_EQ(MSERR_OK, player_->SetVolume(1, 1));
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_EQ(MSERR_OK, player_->SetVolume(1, 1));
    EXPECT_EQ(MSERR_OK, player_->Pause());
    EXPECT_EQ(MSERR_OK, player_->SetVolume(1, 1));
    EXPECT_EQ(MSERR_OK, player_->Stop());
    EXPECT_EQ(MSERR_OK, player_->SetVolume(1, 1));
    EXPECT_EQ(MSERR_OK, player_->Reset());
    EXPECT_EQ(MSERR_OK, player_->SetVolume(1, 1));
}

/**
 * @tc.name  : Test SetVolume API
 * @tc.number: Player_SetVolume_004
 * @tc.desc  : Test Player SetVolume
 */
HWTEST_F(PlayerServerUnitTest, Player_SetVolume_004, TestSize.Level2)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    EXPECT_EQ(MSERR_OK, player_->SetVolume(1, 1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->PrepareAsync());
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_EQ(MSERR_OK, player_->SetVolume(1e-7, 1));
    EXPECT_EQ(MSERR_OK, player_->SetVolume(1, 1e-7));
    EXPECT_EQ(MSERR_OK, player_->SetVolume(1e-7, 1e-7));
}

/**
 * @tc.name  : Test SetVideoScaleType API
 * @tc.number: Player_SetVideoScaleType_001
 * @tc.desc  : Test Player SetVideoScaleType
 */
HWTEST_F(PlayerServerUnitTest, Player_SetVideoScaleType_001, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    EXPECT_EQ(MSERR_OK, player_->Play());
    Format format;
    format.PutIntValue(PlayerKeys::VIDEO_SCALE_TYPE,
        static_cast<int32_t>(Plugins::VideoScaleType::VIDEO_SCALE_TYPE_FIT));
    EXPECT_EQ(MSERR_OK, player_->SetParameter(format));
    format.PutIntValue(PlayerKeys::VIDEO_SCALE_TYPE,
        static_cast<int32_t>(Plugins::VideoScaleType::VIDEO_SCALE_TYPE_FIT_CROP));
    EXPECT_EQ(MSERR_OK, player_->SetParameter(format));
}

/**
 * @tc.name  : Test SetRendererInfo API
 * @tc.number: Player_SetRendererInfo_001
 * @tc.desc  : Test Player SetRendererInfo
 */
HWTEST_F(PlayerServerUnitTest, Player_SetRendererInfo_001, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    Format format;
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    int32_t contentType = 1;
    int32_t streamUsage = 1;
    int32_t rendererFlags = 0;
    (void)format.PutIntValue(PlayerKeys::CONTENT_TYPE, contentType);
    (void)format.PutIntValue(PlayerKeys::STREAM_USAGE, streamUsage);
    (void)format.PutIntValue(PlayerKeys::RENDERER_FLAG, rendererFlags);
    EXPECT_EQ(MSERR_OK, player_->SetParameter(format));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    EXPECT_EQ(MSERR_OK, player_->Play());
}

/**
 * @tc.name  : Test SetVolumeMode API
 * @tc.number: Player_SetVolumeMode_001
 * @tc.desc  : Test Player SetVolumeMode
 */
HWTEST_F(PlayerServerUnitTest, Player_SetVolumeMode_001, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    Format format;
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    int32_t contentType = 1;
    int32_t streamUsage = 1;
    int32_t rendererFlags = 0;
    int32_t mode = 1;
    (void)format.PutIntValue(PlayerKeys::CONTENT_TYPE, contentType);
    (void)format.PutIntValue(PlayerKeys::STREAM_USAGE, streamUsage);
    (void)format.PutIntValue(PlayerKeys::RENDERER_FLAG, rendererFlags);
    EXPECT_EQ(MSERR_OK, player_->SetParameter(format));
    EXPECT_EQ(MSERR_OK, player_->SetVolumeMode(mode));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    EXPECT_EQ(MSERR_OK, player_->Play());
}

/**
 * @tc.name  : Test SetInterrupt API
 * @tc.number: Player_SetInterrupt_001
 * @tc.desc  : Test Player SetInterrupt
 */
HWTEST_F(PlayerServerUnitTest, Player_SetInterrupt_001, TestSize.Level1)
{
    Format format;
    int32_t mode = 1;
    int32_t type = 1;
    std::shared_ptr<PlayerServerMock> player = nullptr;
    std::shared_ptr<PlayerCallbackTest> callback = nullptr;
    callback = std::make_shared<PlayerCallbackTest>();
    ASSERT_NE(nullptr, callback);
    player = std::make_shared<PlayerServerMock>(callback);
    ASSERT_NE(nullptr, player);
    EXPECT_TRUE(player->CreatePlayer());
    EXPECT_EQ(MSERR_OK, player->SetPlayerCallback(callback));
    ASSERT_EQ(MSERR_OK, player->SetSource(MEDIA_ROOT + "01.mp3"));
    EXPECT_EQ(MSERR_OK, player->Prepare());

    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    (void)format.PutIntValue(PlayerKeys::AUDIO_INTERRUPT_MODE, mode);
    (void)format.PutIntValue(PlayerKeys::AUDIO_INTERRUPT_TYPE, type);
    EXPECT_EQ(MSERR_OK, player->SetParameter(format));
    EXPECT_EQ(MSERR_OK, player->Play());
    sleep(PLAYING_TIME_2_SEC);
    EXPECT_EQ(MSERR_OK, player_->Play());
    sleep(PLAYING_TIME_2_SEC);
    EXPECT_EQ(MSERR_OK, player->ReleaseSync());
}

/**
 * @tc.name  : Test Player SelectBitRate API
 * @tc.number: Player_SelectBitRate_001
 * @tc.desc  : Test Player SelectBitRate interface
 */
HWTEST_F(PlayerServerUnitTest, Player_SelectBitRate_001, TestSize.Level1)
{
    EXPECT_EQ(MSERR_OK, player_->SelectBitRate(0));
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->PrepareAsync());
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_EQ(MSERR_OK, player_->SelectBitRate(0));
}

/**
 * @tc.name: Player_Performance_Prepared_001
 * @tc.desc: test player start
 * @tc.type: PERFORMANCE
 * @tc.require: issueI5NYBJ
 */
HWTEST_F(PlayerServerUnitTest, Player_Performance_Prepared_001, TestSize.Level1)
{
    struct timeval startTime = {};
    struct timeval finishTime = {};
    int32_t runTimes = 10;
    float timeConv = 1000;
    float deltaTime = 0;
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    for (int32_t i = 0; i < runTimes; i++) {
        EXPECT_EQ(MSERR_OK, gettimeofday(&startTime, nullptr));
        ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
        EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
        EXPECT_EQ(MSERR_OK, player_->PrepareAsync());
        EXPECT_EQ(MSERR_OK, gettimeofday(&finishTime, nullptr));
        EXPECT_EQ(MSERR_OK, player_->Play());
        deltaTime += (finishTime.tv_sec - startTime.tv_sec) * timeConv +
            (finishTime.tv_usec - startTime.tv_usec) / timeConv;
        EXPECT_EQ(MSERR_OK, player_->Reset());
    }
    EXPECT_LE(deltaTime / runTimes, 1000); // less than 1000 ms
}

/**
 * @tc.name  : Test Player Play mp4 with rotation
 * @tc.number: Player_Rotate_001
 * @tc.desc  : Test Player Play interface
 */
HWTEST_F(PlayerServerUnitTest, Player_Rotate_001, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(MEDIA_ROOT + "MP4_ROTATE_90.mp4"));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->PrepareAsync());
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_TRUE(player_->IsPlaying());
}

/**
 * @tc.name  : Test Player Dump Dot
 * @tc.number: Player_Dump_Dot_001
 * @tc.desc  : Test Player Dump Dot
 */
HWTEST_F(PlayerServerUnitTest, Player_Dump_Dot_001, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(MEDIA_ROOT + "MP4_ROTATE_90.mp4"));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->PrepareAsync());
    EXPECT_EQ(MSERR_OK, player_->Play());
    system("param set sys.media.dump.dot.path /data/test/media");
    EXPECT_TRUE(player_->IsPlaying());
    EXPECT_EQ(MSERR_OK, player_->Pause());
    EXPECT_EQ(MSERR_OK, player_->Play());
}

/**
 * @tc.name  : Test Player Dump Dot
 * @tc.number: Player_Dump_Dot_002
 * @tc.desc  : Test Player Dump Dot
 */
HWTEST_F(PlayerServerUnitTest, Player_Dump_Dot_002, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(MEDIA_ROOT + "MP4_ROTATE_90.mp4"));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->PrepareAsync());
    EXPECT_EQ(MSERR_OK, player_->Play());
    system("param set sys.media.dump.dot.path /xx");
    EXPECT_TRUE(player_->IsPlaying());
    EXPECT_EQ(MSERR_OK, player_->Pause());
    EXPECT_EQ(MSERR_OK, player_->Play());
}

/**
 * @tc.name  : Test Player Dump GlibMem
 * @tc.number: Player_Dump_GlibMem_001
 * @tc.desc  : Test Player Dump GlibMem
 */
HWTEST_F(PlayerServerUnitTest, Player_Dump_GlibMem_001, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(MEDIA_ROOT + "MP4_ROTATE_90.mp4"));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->PrepareAsync());
    EXPECT_EQ(MSERR_OK, player_->Play());
    system("hidumper -s 3002 -a glibmem");
    system("param set sys.media.dump.codec.vdec ALL");
    EXPECT_TRUE(player_->IsPlaying());
    EXPECT_EQ(MSERR_OK, player_->Pause());
}

/**
 * @tc.name  : Test Player Dump GlibPool
 * @tc.number: Player_Dump_GlibPool_001
 * @tc.desc  : Test Player Dump GlibPool
 */
HWTEST_F(PlayerServerUnitTest, Player_Dump_GlibPool_001, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(MEDIA_ROOT + "MP4_ROTATE_90.mp4"));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->PrepareAsync());
    system("param set sys.media.dump.frame.enable true");
    system("param set sys.media.set.mute TRUE");
    system("param set sys.media.kpi.avsync.log.enable true");
    system("param set sys.media.kpi.opt.renderdelay.enable true");
    EXPECT_EQ(MSERR_OK, player_->Play());
    system("hidumper -s 3002 -a glibpool");
    system("param set sys.media.dump.codec.vdec ALL");
    EXPECT_TRUE(player_->IsPlaying());
    EXPECT_EQ(MSERR_OK, player_->Pause());
}

/**
 * @tc.name  : Test Player Dump Log
 * @tc.number: Player_Dump_Log_001
 * @tc.desc  : Test Player Dump Log
 */
HWTEST_F(PlayerServerUnitTest, Player_Dump_Log_001, TestSize.Level1)
{
    system("mkdir /data/media/log");
    system("chmod 777 -R /data/media");
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->PrepareAsync());
    system("param set sys.media.log.level *:l,multiqueue,decodecbin:,tsdemux:D,multiqueue:D,hlsdemux:D,souphttpsrc:W");
    system("param set sys.media.log.level *:l,basesrcmmmbasesrcmmmbasesrcmmmbasesrcmmmbasesrcmmmbasesrcmmmbasesrcmmm" \
        "basesrcmmmbasesrcmmmbasesrcmmmbasesrcmmmbasesrcmmmbasesrcmmm:D");
    system("param set sys.media.dump.frame.enable false");
    system("param set sys.media.set.mute FALSE");
    system("param set sys.media.kpi.avsync.log.enable false");
    system("param set sys.media.kpi.opt.renderdelay.enable false");
    EXPECT_EQ(MSERR_OK, player_->Play());
    system("param set sys.media.dump.codec.vdec NULL");
    EXPECT_TRUE(player_->IsPlaying());
    EXPECT_EQ(MSERR_OK, player_->Pause());
    system("rm -rf /data/media/log");
}

/**
 * @tc.name  : Test Player Dump gstbuffer
 * @tc.number: Player_Dump_GstBuffer_001
 * @tc.desc  : Test Player Dump gstbuffer
 */
HWTEST_F(PlayerServerUnitTest, Player_Dump_GstBuffer_001, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->PrepareAsync());
    system("param set sys.media.dump.gstbuffer 1");
    system("param set sys.media.set.mute null");
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_TRUE(player_->IsPlaying());
    EXPECT_EQ(MSERR_OK, player_->Pause());
    system("param set sys.media.dump.gstbuffer 0");
}

/**
 * @tc.name  : Test Player With Not Performance
 * @tc.number: Player_Not_Performance_001
 * @tc.desc  : Test Player Not Performance
 */
HWTEST_F(PlayerServerUnitTest, Player_Not_Performance_001, TestSize.Level2)
{
    system("param set sys.media.player.performance.enable FALSE");
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->PrepareAsync());
    system("param set sys.media.player.performance.enable TRUE");
}

/**
 * @tc.name  : Test Player Mem Recycle
 * @tc.number: Player_Mem_Recycle_001
 * @tc.desc  : Test Player Mem Recycle
 */
HWTEST_F(PlayerServerUnitTest, Player_Mem_Recycle_001, TestSize.Level1)
{
    sptr<Surface> renderSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, renderSurface);
    std::vector<std::string> srcVector = {MEDIA_ROOT + "H264_MP3.mp4"};
    for (int32_t i = 0; i < static_cast<int32_t>(srcVector.size()); i++) {
        if (srcVector[i] == MEDIA_ROOT + "H264_MP3.mp4") {
            system("param set sys.media.player.resource.type NetWork");
        }
        ASSERT_EQ(MSERR_OK, player_->SetSource(srcVector[i]));
        EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(renderSurface));
        char text[100]; // 100: text len
        sprintf_s(text, 100, "hidumper -s 1909 -a \"-d %d %d %d\"", 0, 0, 4);
        system(text);
        sprintf_s(text, 100, "hidumper -s 1909 -a \"-d %d %d %d\"", getpid(), 0, 4);
        system(text);
        system("hidumper -s 1909 -a \"-t 6\"");
        system("hidumper -s 1909 -a \"-t 3\"");
        int32_t ret = player_->Prepare();
        EXPECT_EQ(MSERR_OK, ret);
        EXPECT_EQ(MSERR_OK, player_->Reset());
        system("param set sys.media.player.resource.type Local");
    }
}

/**
 * @tc.name  : Test Player Mem Recycle
 * @tc.number: Player_Mem_Recycle_002
 * @tc.desc  : Test Player Mem Recycle
 */
HWTEST_F(PlayerServerUnitTest, Player_Mem_Recycle_002, TestSize.Level1)
{
    sptr<Surface> vSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, vSurface);
    std::vector<std::string> srcVec = {MEDIA_ROOT + "H264_MP3.mp4"};
    for (uint32_t i = 0; i < srcVec.size(); i++) {
        if (srcVec[i] == MEDIA_ROOT + "H264_MP3.mp4") {
            system("param set sys.media.player.resource.type NetWork");
        }
        ASSERT_EQ(MSERR_OK, player_->SetSource(srcVec[i]));
        EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(vSurface));
        EXPECT_EQ(MSERR_OK, player_->Prepare());
        char str[100]; // 100: str len
        sprintf_s(str, 100, "hidumper -s 1909 -a \"-d %d %d %d\"", getpid(), getuid(), 4);
        system(str);
        system("hidumper -s 1909 -a \"-t 3\"");
        EXPECT_EQ(MSERR_OK, player_->Play());
        EXPECT_EQ(MSERR_OK, player_->Reset());
        system("param set sys.media.player.resource.type Local");
    }
}

/**
 * @tc.name  : Test Player Mem Recycle
 * @tc.number: Player_Mem_Recycle_003
 * @tc.desc  : Test Player Mem Recycle
 */
HWTEST_F(PlayerServerUnitTest, Player_Mem_Recycle_003, TestSize.Level1)
{
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    std::vector<std::string> srcVec = {MEDIA_ROOT + "H264_MP3.mp4"};
    for (uint32_t i = 0; i < srcVec.size(); i++) {
        if (srcVec[i] == MEDIA_ROOT + "H264_MP3.mp4") {
            system("param set sys.media.player.resource.type NetWork");
        }
        ASSERT_EQ(MSERR_OK, player_->SetSource(srcVec[i]));
        EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
        EXPECT_EQ(MSERR_OK, player_->Prepare());
        EXPECT_EQ(MSERR_OK, player_->Play());
        sleep(15);
        char str[100]; // 100: str len
        sprintf_s(str, 100, "hidumper -s 1909 -a \"-d %d %d %d\"", getpid(), getuid(), 4);
        system(str);
        system("hidumper -s 1909 -a \"-t 3\"");
        EXPECT_EQ(MSERR_OK, player_->Play());
        EXPECT_EQ(MSERR_OK, player_->Reset());
        system("param set sys.media.player.resource.type Local");
    }
}

/**
 * @tc.name  : Test Player Mem Recycle
 * @tc.number: Player_Mem_Recycle_004
 * @tc.desc  : Test Player Mem Recycle
 */
HWTEST_F(PlayerServerUnitTest, Player_Mem_Recycle_004, TestSize.Level1)
{
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    std::vector<std::string> vec = {MEDIA_ROOT + "H264_MP3.mp4"};
    for (uint32_t i = 0; i < vec.size(); i++) {
        if (vec[i] == MEDIA_ROOT + "H264_MP3.mp4") {
            system("param set sys.media.player.resource.type NetWork");
        }
        const auto ret = MSERR_OK;
        ASSERT_EQ(ret, player_->SetSource(vec[i]));
        EXPECT_EQ(ret, player_->SetVideoSurface(videoSurface));
        EXPECT_EQ(ret, player_->Prepare());
        EXPECT_EQ(ret, player_->Play());
        EXPECT_EQ(ret, player_->Pause());
        char str[100]; // 100: str len
        sprintf_s(str, 100, "hidumper -s 1909 -a \"-d %d %d %d\"", getpid(), getuid(), 4);
        system(str);
        system("hidumper -s 1909 -a \"-t 3\"");
        int32_t currentTime = 0;
        std::vector<Format> videoTrack;
        std::vector<Format> audioTrack;
        int32_t duration = 0;
        PlaybackRateMode mode;
        EXPECT_EQ(MSERR_OK, player_->GetVideoTrackInfo(videoTrack));
        EXPECT_EQ(MSERR_OK, player_->GetAudioTrackInfo(audioTrack));
        EXPECT_EQ(MSERR_OK, player_->GetCurrentTime(currentTime));
        EXPECT_NE(0, player_->GetVideoWidth());
        EXPECT_NE(0, player_->GetVideoHeight());
        EXPECT_EQ(MSERR_OK, player_->GetDuration(duration));
        EXPECT_EQ(MSERR_OK, player_->GetPlaybackSpeed(mode));
        int32_t index;
        EXPECT_EQ(MSERR_OK, player_->GetCurrentTrack(MediaType::MEDIA_TYPE_AUD, index));
        EXPECT_EQ(MSERR_OK, player_->GetCurrentTrack(MediaType::MEDIA_TYPE_VID, index));
        EXPECT_EQ(MSERR_OK, player_->GetCurrentTrack(MediaType::MEDIA_TYPE_SUBTITLE, index));
        EXPECT_NE(MSERR_OK, player_->GetCurrentTrack(100, index));
        EXPECT_EQ(false, player_->IsPlaying());
        EXPECT_EQ(false, player_->IsLooping());
        EXPECT_EQ(MSERR_OK, player_->Seek(1000, SEEK_NEXT_SYNC));
        EXPECT_EQ(MSERR_OK, player_->Reset());
        system("param set sys.media.player.resource.type Local");
    }
}

/**
 * @tc.name  : Test Player Mem Recycle
 * @tc.number: Player_Mem_Recycle_005
 * @tc.desc  : Test Player Mem Recycle
 */
HWTEST_F(PlayerServerUnitTest, Player_Mem_Recycle_005, TestSize.Level1)
{
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    std::vector<std::string> srcVec = {MEDIA_ROOT + "H264_MP3.mp4"};
    for (uint32_t i = 0; i < srcVec.size(); i++) {
        if (srcVec[i] == MEDIA_ROOT + "H264_MP3.mp4") {
            system("param set sys.media.player.resource.type NetWork");
        }
        const auto result = MSERR_OK;
        ASSERT_EQ(result, player_->SetSource(srcVec[i]));
        EXPECT_EQ(result, player_->SetVideoSurface(videoSurface));
        EXPECT_EQ(result, player_->Prepare());
        EXPECT_EQ(result, player_->Play());
        EXPECT_EQ(result, player_->Pause());
        char str[100]; // 100: str len
        sprintf_s(str, 100, "hidumper -s 1909 -a \"-d %d %d %d\"", getpid(), getuid(), 4);
        system(str);
        system("hidumper -s 1909 -a \"-t 3\"");
        EXPECT_EQ(result, player_->Reset());
        system("param set sys.media.player.resource.type Local");
    }
}

/**
 * @tc.name  : Test Player Mem Recycle
 * @tc.number: Player_Mem_Recycle_006
 * @tc.desc  : Test Player Mem Recycle
 */
HWTEST_F(PlayerServerUnitTest, Player_Mem_Recycle_006, TestSize.Level1)
{
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    std::vector<std::string> srcVec = {MEDIA_ROOT + "H264_MP3.mp4"};
    for (uint32_t i = 0; i < srcVec.size(); i++) {
        if (srcVec[i] == MEDIA_ROOT + "H264_MP3.mp4") {
            system("param set sys.media.player.resource.type NetWork");
        }
        ASSERT_EQ(MSERR_OK, player_->SetSource(srcVec[i]));
        EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
        EXPECT_EQ(MSERR_OK, player_->Prepare());
        EXPECT_EQ(MSERR_OK, player_->Play());
        EXPECT_EQ(MSERR_OK, player_->Pause());
        char str[100]; // 100: str len
        sprintf_s(str, 100, "hidumper -s 1909 -a \"-d %d %d %d\"", getpid(), getuid(), 4);
        system(str);
        system("hidumper -s 1909 -a \"-t 3\"");
        EXPECT_EQ(MSERR_OK, player_->Reset());
        system("param set sys.media.player.resource.type Local");
    }
}

/**
 * @tc.name  : Test Player Mem Recycle
 * @tc.number: Player_Mem_Recycle_007
 * @tc.desc  : Test Player Mem Recycle
 */
HWTEST_F(PlayerServerUnitTest, Player_Mem_Recycle_007, TestSize.Level1)
{
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    std::vector<std::string> srcVec = {MEDIA_ROOT + "H264_MP3.mp4"};
    std::vector<PlaybackRateMode> speedMode = {SPEED_FORWARD_2_00_X, SPEED_FORWARD_1_25_X};
    for (uint32_t i = 0; i < srcVec.size(); i++) {
        if (srcVec[i] == MEDIA_ROOT + "H264_MP3.mp4") {
            system("param set sys.media.player.resource.type NetWork");
        }
        ASSERT_EQ(MSERR_OK, player_->SetSource(srcVec[i]));
        EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
        EXPECT_EQ(MSERR_OK, player_->Prepare());
        EXPECT_EQ(MSERR_OK, player_->Play());
        EXPECT_EQ(MSERR_OK, player_->Pause());
        char str[100]; // 100: str len
        sprintf_s(str, 100, "hidumper -s 1909 -a \"-d %d %d %d\"", getpid(), getuid(), 4);
        system(str);
        system("hidumper -s 1909 -a \"-t 3\"");
        EXPECT_EQ(MSERR_OK, player_->SetPlaybackSpeed(speedMode[i]));
        EXPECT_EQ(MSERR_OK, player_->Reset());
        system("param set sys.media.player.resource.type Local");
    }
}

/**
 * @tc.name  : Test Player Mem Recycle
 * @tc.number: Player_Mem_Recycle_008
 * @tc.desc  : Test Player Mem Recycle
 */
HWTEST_F(PlayerServerUnitTest, Player_Mem_Recycle_008, TestSize.Level1)
{
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    std::vector<std::string> srcVec = {MEDIA_ROOT + "H264_MP3.mp4"};
    for (uint32_t i = 0; i < srcVec.size(); i++) {
        if (srcVec[i] == MEDIA_ROOT + "H264_MP3.mp4") {
            system("param set sys.media.player.resource.type NetWork");
        }
        ASSERT_EQ(MSERR_OK, player_->SetSource(srcVec[i]));
        EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
        EXPECT_EQ(MSERR_OK, player_->Prepare());
        EXPECT_EQ(MSERR_OK, player_->Play());
        EXPECT_EQ(MSERR_OK, player_->Pause());
        EXPECT_EQ(MSERR_OK, player_->SetPlaybackSpeed(SPEED_FORWARD_2_00_X));
        EXPECT_EQ(MSERR_OK, player_->SetLooping(true));
        EXPECT_EQ(MSERR_OK, player_->SetVolume(0.5, 0.5));
        char str[100]; // 100: str len
        sprintf_s(str, 100, "hidumper -s 1909 -a \"-d %d %d %d\"", getpid(), getuid(), 4);
        system(str);
        system("hidumper -s 1909 -a \"-t 3\"");
        EXPECT_EQ(MSERR_OK, player_->SetLooping(false));
        EXPECT_EQ(MSERR_OK, player_->Reset());
        system("param set sys.media.player.resource.type Local");
    }
}

/**
 * @tc.name  : Test Player Mem Recycle
 * @tc.number: Player_Mem_Recycle_009
 * @tc.desc  : Test Player Mem Recycle
 */
HWTEST_F(PlayerServerUnitTest, Player_Mem_Recycle_009, TestSize.Level1)
{
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    std::vector<std::string> srcVec = {MEDIA_ROOT + "H264_MP3.mp4"};
    for (uint32_t i = 0; i < srcVec.size(); i++) {
        if (srcVec[i] == MEDIA_ROOT + "H264_MP3.mp4") {
            system("param set sys.media.player.resource.type NetWork");
        }
        ASSERT_EQ(MSERR_OK, player_->SetSource(srcVec[i]));
        EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
        EXPECT_EQ(MSERR_OK, player_->Prepare());
        EXPECT_EQ(MSERR_OK, player_->Play());
        EXPECT_EQ(MSERR_OK, player_->Pause());
        char str[100]; // 100: str len
        sprintf_s(str, 100, "hidumper -s 1909 -a \"-d %d %d %d\"", getpid(), getuid(), 4);
        system(str);
        system("hidumper -s 1909 -a \"-t 3\"");
        EXPECT_EQ(MSERR_OK, player_->SelectBitRate(0));
        EXPECT_EQ(MSERR_OK, player_->Reset());
        system("param set sys.media.player.resource.type Local");
    }
}

/**
 * @tc.name  : Test Player Mem Recycle
 * @tc.number: Player_Mem_Recycle_010
 * @tc.desc  : Test Player Mem Recycle
 */
HWTEST_F(PlayerServerUnitTest, Player_Mem_Recycle_010, TestSize.Level1)
{
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    std::vector<std::string> srcVec = {MEDIA_ROOT + "H264_MP3.mp4"};
    for (uint32_t i = 0; i < srcVec.size(); i++) {
        if (srcVec[i] == MEDIA_ROOT + "H264_MP3.mp4") {
            system("param set sys.media.player.resource.type NetWork");
        }
        ASSERT_EQ(MSERR_OK, player_->SetSource(srcVec[i]));
        EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
        EXPECT_EQ(MSERR_OK, player_->Prepare());
        EXPECT_EQ(MSERR_OK, player_->Play());
        EXPECT_EQ(MSERR_OK, player_->Stop());
        char str[100]; // 100: str len
        sprintf_s(str, 100, "hidumper -s 1909 -a \"-d %d %d %d\"", getpid(), getuid(), 4);
        system(str);
        system("hidumper -s 1909 -a \"-t 3\"");
        EXPECT_EQ(MSERR_OK, player_->Reset());
        system("param set sys.media.player.resource.type Local");
    }
}

/**
 * @tc.name  : Test Player Mem Recycle
 * @tc.number: Player_Mem_Recycle_011
 * @tc.desc  : Test Player Mem Recycle
 */
HWTEST_F(PlayerServerUnitTest, Player_Mem_Recycle_011, TestSize.Level1)
{
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    std::vector<std::string> srcVec = {MEDIA_ROOT + "H264_MP3.mp4"};
    for (uint32_t i = 0; i < srcVec.size(); i++) {
        if (srcVec[i] == MEDIA_ROOT + "H264_MP3.mp4") {
            system("param set sys.media.player.resource.type NetWork");
        }
        ASSERT_EQ(MSERR_OK, player_->SetSource(srcVec[i]));
        EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
        EXPECT_EQ(MSERR_OK, player_->Prepare());
        EXPECT_EQ(MSERR_OK, player_->Play());
        EXPECT_EQ(MSERR_OK, player_->Pause());
        char str[100]; // 100: str len
        sprintf_s(str, 100, "hidumper -s 1909 -a \"-d %d %d %d\"", getpid(), getuid(), 4);
        system(str);
        system("hidumper -s 1909 -a \"-t 2\"");
        EXPECT_EQ(MSERR_OK, player_->Reset());
        system("param set sys.media.player.resource.type Local");
    }
}

/**
 * @tc.name  : Test Player Mem Recycle
 * @tc.number: Player_Mem_Recycle_012
 * @tc.desc  : Test Player Mem Recycle
 */
HWTEST_F(PlayerServerUnitTest, Player_Mem_Recycle_012, TestSize.Level1)
{
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    std::vector<std::string> srcVec = {MEDIA_ROOT + "H264_MP3.mp4"};
    for (uint32_t i = 0; i < srcVec.size(); i++) {
        if (srcVec[i] == MEDIA_ROOT + "H264_MP3.mp4") {
            system("param set sys.media.player.resource.type NetWork");
        }
        ASSERT_EQ(MSERR_OK, player_->SetSource(srcVec[i]));
        EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
        EXPECT_EQ(MSERR_OK, player_->Prepare());
        EXPECT_EQ(MSERR_OK, player_->Play());
        EXPECT_EQ(MSERR_OK, player_->Pause());
        char str[100]; // 100: str len
        sprintf_s(str, 100, "hidumper -s 1909 -a \"-d %d %d %d\"", getpid(), getuid(), 4);
        system(str);
        system("hidumper -s 1909 -a \"-t 4\"");
        EXPECT_EQ(MSERR_OK, player_->Reset());
        system("param set sys.media.player.resource.type Local");
    }
}

/**
 * @tc.name  : Test Player Mem Recycle
 * @tc.number: Player_Mem_Recycle_013
 * @tc.desc  : Test Player Mem Recycle
 */
HWTEST_F(PlayerServerUnitTest, Player_Mem_Recycle_013, TestSize.Level1)
{
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    std::vector<std::string> srcVec = {MEDIA_ROOT + "H264_MP3.mp4"};
    for (uint32_t i = 0; i < srcVec.size(); i++) {
        if (srcVec[i] == MEDIA_ROOT + "H264_MP3.mp4") {
            system("param set sys.media.player.resource.type NetWork");
        }
        ASSERT_EQ(MSERR_OK, player_->SetSource(srcVec[i]));
        EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
        EXPECT_EQ(MSERR_OK, player_->Prepare());
        EXPECT_EQ(MSERR_OK, player_->Play());
        EXPECT_EQ(MSERR_OK, player_->Pause());
        char str[100]; // 100: str len
        sprintf_s(str, 100, "hidumper -s 1909 -a \"-d %d %d %d\"", getpid(), getuid(), 4);
        system(str);
        system("hidumper -s 1909 -a \"-f 3\"");
        EXPECT_EQ(MSERR_OK, player_->Reset());
        system("param set sys.media.player.resource.type Local");
        system("killall memmgrservice");
        sleep(1);
    }
}

/**
 * @tc.name  : Test Player Mem Recycle
 * @tc.number: Player_Mem_Recycle_014
 * @tc.desc  : Test Player Mem Recycle
 */
HWTEST_F(PlayerServerUnitTest, Player_Mem_Recycle_014, TestSize.Level1)
{
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    std::vector<std::string> srcVector = {MEDIA_ROOT + "H264_AAC.mp4"};
    for (uint32_t i = 0; i < srcVector.size(); i++) {
        if (srcVector[i] == MEDIA_ROOT + "H264_AAC.mp4") {
            system("param set sys.media.player.resource.type NetWork");
        }
        ASSERT_EQ(MSERR_OK, player_->SetSource(srcVector[i]));
        EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
        EXPECT_EQ(MSERR_OK, player_->Prepare());
        char str[100]; // 100: str len
        sprintf_s(str, 100, "hidumper -s 1909 -a \"-d %d %d %d\"", getpid(), getuid(), 4);
        system(str);
        sprintf_s(str, 100, "hidumper -s 1909 -a \"-d %d %d %d\"", getpid(), getuid(), 2);
        system(str);
        sleep(30);
        EXPECT_EQ(MSERR_OK, player_->Play());
        EXPECT_EQ(MSERR_OK, player_->Reset());
        system("param set sys.media.player.resource.type Local");
    }
}

/**
 * @tc.name  : Test Player Mem Recycle
 * @tc.number: Player_Mem_Recycle_015
 * @tc.desc  : Test Player Mem Recycle
 */
HWTEST_F(PlayerServerUnitTest, Player_Mem_Recycle_015, TestSize.Level1)
{
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    std::vector<std::string> srcVec = {MEDIA_ROOT + "H264_AAC.mp4"};
    for (uint32_t i = 0; i < srcVec.size(); i++) {
        if (srcVec[i] == MEDIA_ROOT + "H264_AAC.mp4") {
            system("param set sys.media.player.resource.type NetWork");
        }
        ASSERT_EQ(MSERR_OK, player_->SetSource(srcVec[i]));
        EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
        EXPECT_EQ(MSERR_OK, player_->Prepare());
        char str[100]; // 100: str len
        sprintf_s(str, 100, "hidumper -s 1909 -a \"-d %d %d %d\"", getpid(), getuid(), 4);
        system(str);
        system("hidumper -s 3002 -a \"player\"");
        sleep(30);
        system("hidumper -s 3002 -a \"player\"");
        EXPECT_EQ(MSERR_OK, player_->Play());
        EXPECT_EQ(MSERR_OK, player_->Stop());
        EXPECT_EQ(MSERR_OK, player_->Reset());
        system("param set sys.media.player.resource.type Local");
    }
}

/**
 * @tc.name  : Test Player Mem Recycle
 * @tc.number: Player_Mem_Recycle_016
 * @tc.desc  : Test Player Mem Recycle
 */
HWTEST_F(PlayerServerUnitTest, Player_Mem_Recycle_016, TestSize.Level1)
{
    int32_t duration = 0;
    std::vector<Format> videoTrack;
    std::vector<Format> audioTrack;
    PlaybackRateMode mode;
    int32_t index = 0;
    EXPECT_EQ(MSERR_OK, player_->SetVolume(0.9, 0.9));
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1, 0, 0));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->SetLooping(true));
    EXPECT_EQ(true, player_->IsLooping());
    EXPECT_EQ(MSERR_OK, player_->PrepareAsync());
    char str[100]; // 100: str len
    sprintf_s(str, 100, "hidumper -s 1909 -a \"-d %d %d %d\"", getpid(), getuid(), 4);
    system(str);
    system("hidumper -s 1909 -a \"-t 4\"");
    EXPECT_EQ(720, player_->GetVideoWidth());
    EXPECT_EQ(480, player_->GetVideoHeight());
    EXPECT_EQ(MSERR_OK, player_->GetVideoTrackInfo(videoTrack));
    EXPECT_EQ(MSERR_OK, player_->GetAudioTrackInfo(audioTrack));
    EXPECT_EQ(MSERR_OK, player_->GetDuration(duration));
    EXPECT_EQ(MSERR_OK, player_->GetPlaybackSpeed(mode));
    EXPECT_EQ(SPEED_FORWARD_1_00_X, mode);
    EXPECT_EQ(MSERR_OK, player_->SetPlaybackSpeed(SPEED_FORWARD_0_50_X));
    EXPECT_EQ(MSERR_OK, player_->GetPlaybackSpeed(mode));
    EXPECT_EQ(SPEED_FORWARD_0_50_X, mode);
    EXPECT_EQ(MSERR_OK, player_->SetPlaybackSpeed(SPEED_FORWARD_2_00_X));
    EXPECT_EQ(MSERR_OK, player_->GetPlaybackSpeed(mode));
    EXPECT_EQ(SPEED_FORWARD_2_00_X, mode);

    EXPECT_EQ(false, player_->IsPlaying());
    EXPECT_EQ(true, player_->IsLooping());

    EXPECT_EQ(MSERR_OK, player_->GetCurrentTrack(MediaType::MEDIA_TYPE_AUD, index));
    EXPECT_EQ(MSERR_OK, player_->GetCurrentTrack(MediaType::MEDIA_TYPE_VID, index));
    EXPECT_EQ(MSERR_OK, player_->GetCurrentTrack(MediaType::MEDIA_TYPE_SUBTITLE, index));
    EXPECT_NE(MSERR_OK, player_->GetCurrentTrack(100, index));

    EXPECT_EQ(MSERR_OK, player_->GetDuration(duration));
    EXPECT_EQ(MSERR_OK, player_->Seek(duration, PlayerSeekMode::SEEK_PREVIOUS_SYNC));
    EXPECT_EQ(MSERR_OK, player_->Reset());
    EXPECT_EQ(MSERR_OK, player_->Release());
}

/**
 * @tc.name  : Test SetEffect API
 * @tc.number: Player_SetEffect_001
 * @tc.desc  : Test Player SetEffect state machine
 */
HWTEST_F(PlayerServerUnitTest, Player_SetEffect_001, TestSize.Level1)
{
    Format format;
    const float FLOAT_VALUE = 1.0;
    const double DOUBLE_VALUE = 2.5;
    const std::string STRING_VALUE = "player_test";
    const int32_t INT_VALUE = 1;
    (void)format.PutIntValue(PlayerKeys::AUDIO_EFFECT_MODE, OHOS::AudioStandard::AudioEffectMode::EFFECT_NONE);
    EXPECT_NE(MSERR_OK, player_->SetParameter(format));
    (void)format.PutFloatValue(PlayerKeys::AUDIO_EFFECT_MODE, FLOAT_VALUE);
    EXPECT_NE(MSERR_OK, player_->SetParameter(format));
    (void)format.PutDoubleValue(PlayerKeys::AUDIO_EFFECT_MODE, DOUBLE_VALUE);
    EXPECT_NE(MSERR_OK, player_->SetParameter(format));
    (void)format.PutStringValue(PlayerKeys::AUDIO_EFFECT_MODE, STRING_VALUE);
    EXPECT_NE(MSERR_OK, player_->SetParameter(format));
    (void)format.PutIntValue(PlayerKeys::AUDIO_EFFECT_MODE, INT_VALUE);
    EXPECT_NE(MSERR_OK, player_->SetParameter(format));

    ASSERT_EQ(MSERR_OK, player_->SetSource(MEDIA_ROOT + "01.mp3"));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));

    EXPECT_NE(MSERR_OK, player_->SetParameter(format));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    EXPECT_EQ(MSERR_OK, player_->SetParameter(format));
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_EQ(MSERR_OK, player_->SetParameter(format));
    EXPECT_EQ(MSERR_OK, player_->Pause());
    EXPECT_EQ(MSERR_OK, player_->SetParameter(format));
    EXPECT_EQ(MSERR_OK, player_->Stop());
    EXPECT_NE(MSERR_OK, player_->SetParameter(format));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    EXPECT_EQ(MSERR_OK, player_->SetParameter(format));
    EXPECT_EQ(MSERR_OK, player_->Reset());
    EXPECT_NE(MSERR_OK, player_->SetParameter(format));
    EXPECT_EQ(MSERR_OK, player_->Release());
    EXPECT_NE(MSERR_OK, player_->SetParameter(format));
}

/**
 * @tc.name  : Test SetEffect API
 * @tc.number: Player_SetEffect_002
 * @tc.desc  : Test Player SetEffect param
 */
HWTEST_F(PlayerServerUnitTest, Player_SetEffect_002, TestSize.Level1)
{
    Format format;
    ASSERT_EQ(MSERR_OK, player_->SetSource(MEDIA_ROOT + "01.mp3"));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->Prepare());

    (void)format.PutIntValue(PlayerKeys::AUDIO_EFFECT_MODE, OHOS::AudioStandard::AudioEffectMode::EFFECT_DEFAULT);
    EXPECT_EQ(MSERR_OK, player_->SetParameter(format));
    (void)format.PutIntValue(PlayerKeys::AUDIO_EFFECT_MODE, OHOS::AudioStandard::AudioEffectMode::EFFECT_NONE);
    EXPECT_EQ(MSERR_OK, player_->SetParameter(format));
    (void)format.PutIntValue(PlayerKeys::AUDIO_EFFECT_MODE, 100); // 100 is an invalid parameter.
    EXPECT_NE(MSERR_OK, player_->SetParameter(format));
    (void)format.PutIntValue(PlayerKeys::AUDIO_EFFECT_MODE, -1); // -1 is an invalid parameter.
    EXPECT_NE(MSERR_OK, player_->SetParameter(format));

    EXPECT_EQ(MSERR_OK, player_->Release());
}

/**
 * @tc.name  : Test media error
 * @tc.number: Player_Media_Error
 * @tc.desc  : Test Player Media Error
 */
HWTEST_F(PlayerServerUnitTest, Player_Media_Error, TestSize.Level0)
{
    std::array<MediaServiceErrCode, 5> errCodes = {MSERR_OK, MSERR_NO_MEMORY, MSERR_INVALID_OPERATION,
        MSERR_INVALID_VAL, MSERR_UNKNOWN};
    for (const auto& code : errCodes) {
        MediaServiceErrCodeTest(code);
    }
    for (MediaServiceErrCode code = MSERR_SERVICE_DIED; code < MSERR_EXTEND_START;
        code = (MediaServiceErrCode)(code + 1)) {
        MediaServiceErrCodeTest(code);
    }
    MediaServiceErrCodeTest(MSERR_EXTEND_START);

    for (auto code = MSERR_EXT_OK; code <= MSERR_EXT_UNSUPPORT; code = (MediaServiceExtErrCode)(code + 1)) {
        EXPECT_EQ(MSEXTERRCODE_INFOS.at(code), MSExtErrorToString(code));
    }
    EXPECT_EQ(MSEXTERRCODE_INFOS.at(MSERR_EXT_EXTEND_START), MSExtErrorToString(MSERR_EXT_EXTEND_START));

    std::array<MediaServiceExtErrCodeAPI9, 5> errCodesAPI9 = {MSERR_EXT_API9_OK, MSERR_EXT_API9_NO_PERMISSION,
        MSERR_EXT_API9_PERMISSION_DENIED, MSERR_EXT_API9_INVALID_PARAMETER, MSERR_EXT_API9_UNSUPPORT_CAPABILITY};
    for (const auto& errCodeApi9 : errCodesAPI9) {
        MediaServiceExtErrCodeAPI9Test(errCodeApi9);
    }
    for (auto code = MSERR_EXT_API9_NO_MEMORY;
        code <= MSERR_EXT_API9_AUDIO_INTERRUPTED; code = (MediaServiceExtErrCodeAPI9)(code + 1)) {
        MediaServiceExtErrCodeAPI9Test(code);
    }
}

/**
 * @tc.name  : Test ChangeSurface
 * @tc.number: Player_ChangeSurface_001
 * @tc.desc  : Test video player change surface in idle state
 */
HWTEST_F(PlayerServerUnitTest, Player_ChangeSurface_001, TestSize.Level1)
{
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_NE(MSERR_OK, player_->SetVideoSurface(videoSurface));
}

/**
 * @tc.name  : Test ChangeSurface
 * @tc.number: Player_ChangeSurface_002
 * @tc.desc  : Test video player change surface in released state
 */
HWTEST_F(PlayerServerUnitTest, Player_ChangeSurface_002, TestSize.Level1)
{
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    player_->Release();
    EXPECT_NE(MSERR_OK, player_->SetVideoSurface(videoSurface));
}

/**
 * @tc.name  : Test ChangeSurface
 * @tc.number: Player_ChangeSurface_003
 * @tc.desc  : Test video player change surface in error state
 */
HWTEST_F(PlayerServerUnitTest, Player_ChangeSurface_003, TestSize.Level1)
{
    int32_t ret = player_->SetSource(MEDIA_ROOT + "error.mp4");
    EXPECT_EQ(MSERR_OK, ret);
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_NE(MSERR_OK, player_->PrepareAsync());
    sleep(PLAYING_TIME_2_SEC);
    sptr<Surface> nextVideoSurface = player_->GetVideoSurfaceNext();
    ASSERT_NE(nullptr, nextVideoSurface);
    EXPECT_NE(MSERR_OK, player_->SetVideoSurface(nextVideoSurface));
}

/**
 * @tc.name  : Test ChangeSurface
 * @tc.number: Player_ChangeSurface_004
 * @tc.desc  : Test video player change surface in initialized state
 */
HWTEST_F(PlayerServerUnitTest, Player_ChangeSurface_004, TestSize.Level1)
{
    int32_t ret = player_->SetSource(VIDEO_FILE1);
    EXPECT_EQ(MSERR_OK, ret);
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    sptr<Surface> nextVideoSurface = player_->GetVideoSurfaceNext();
    ASSERT_NE(nullptr, nextVideoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(nextVideoSurface));
}

/**
 * @tc.name  : Test ChangeSurface
 * @tc.number: Player_ChangeSurface_005
 * @tc.desc  : Test video player change surface in prepared state
 */
HWTEST_F(PlayerServerUnitTest, Player_ChangeSurface_005, TestSize.Level1)
{
    int32_t ret = player_->SetSource(VIDEO_FILE1);
    EXPECT_EQ(MSERR_OK, ret);
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->PrepareAsync());
    sleep(PLAYING_TIME_2_SEC);
    sptr<Surface> nextVideoSurface = player_->GetVideoSurfaceNext();
    ASSERT_NE(nullptr, nextVideoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(nextVideoSurface));
}

/**
 * @tc.name  : Test ChangeSurface
 * @tc.number: Player_ChangeSurface_006
 * @tc.desc  : Test video player change surface in playing state
 */
HWTEST_F(PlayerServerUnitTest, Player_ChangeSurface_006, TestSize.Level1)
{
    int32_t ret = player_->SetSource(VIDEO_FILE1);
    EXPECT_EQ(MSERR_OK, ret);
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->PrepareAsync());
    sleep(PLAYING_TIME_2_SEC);
    EXPECT_EQ(MSERR_OK, player_->Play());
    sleep(PLAYING_TIME_2_SEC);
    sptr<Surface> nextVideoSurface = player_->GetVideoSurfaceNext();
    ASSERT_NE(nullptr, nextVideoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(nextVideoSurface));
}

/**
 * @tc.name  : Test ChangeSurface
 * @tc.number: Player_ChangeSurface_007
 * @tc.desc  : Test video player change surface in paused state
 */
HWTEST_F(PlayerServerUnitTest, Player_ChangeSurface_007, TestSize.Level1)
{
    int32_t ret = player_->SetSource(VIDEO_FILE1);
    EXPECT_EQ(MSERR_OK, ret);
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->PrepareAsync());
    sleep(PLAYING_TIME_2_SEC);
    EXPECT_EQ(MSERR_OK, player_->Play());
    sleep(PLAYING_TIME_2_SEC);
    EXPECT_EQ(MSERR_OK, player_->Pause());
    sleep(PLAYING_TIME_2_SEC);
    sptr<Surface> nextVideoSurface = player_->GetVideoSurfaceNext();
    ASSERT_NE(nullptr, nextVideoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(nextVideoSurface));
}

/**
 * @tc.name  : Test ChangeSurface
 * @tc.number: Player_ChangeSurface_008
 * @tc.desc  : Test video player change surface in stopped state
 */
HWTEST_F(PlayerServerUnitTest, Player_ChangeSurface_008, TestSize.Level1)
{
    int32_t ret = player_->SetSource(VIDEO_FILE1);
    EXPECT_EQ(MSERR_OK, ret);
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->PrepareAsync());
    sleep(PLAYING_TIME_2_SEC);
    EXPECT_EQ(MSERR_OK, player_->Play());
    sleep(PLAYING_TIME_2_SEC);
    EXPECT_EQ(MSERR_OK, player_->Stop());
    sleep(PLAYING_TIME_2_SEC);
    sptr<Surface> nextVideoSurface = player_->GetVideoSurfaceNext();
    ASSERT_NE(nullptr, nextVideoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(nextVideoSurface));
}

/**
 * @tc.name  : Test ChangeSurface
 * @tc.number: Player_ChangeSurface_009
 * @tc.desc  : Test video player change surface in completed state
 */
HWTEST_F(PlayerServerUnitTest, Player_ChangeSurface_009, TestSize.Level1)
{
    int32_t ret = player_->SetSource(VIDEO_FILE1);
    EXPECT_EQ(MSERR_OK, ret);
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->PrepareAsync());
    sleep(PLAYING_TIME_2_SEC);
    EXPECT_EQ(MSERR_OK, player_->Play());
    int32_t duration = 0;
    EXPECT_EQ(MSERR_OK, player_->Seek(duration, SEEK_CLOSEST));
    sleep(PLAYING_TIME_10_SEC);
    sptr<Surface> nextVideoSurface = player_->GetVideoSurfaceNext();
    ASSERT_NE(nullptr, nextVideoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(nextVideoSurface));
}

/**
 * @tc.name  : Test SetPlaybackSpeed API
 * @tc.number: Player_SetPlaybackSpeed_003
 * @tc.desc  : Test Player SetPlaybackSpeed SPEED_FORWARD_0_50_X
 */
HWTEST_F(PlayerServerUnitTest, Player_SetPlaybackSpeed_003, TestSize.Level1)
{
    PlaybackRateMode mode;
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_EQ(MSERR_OK, player_->SetPlaybackSpeed(SPEED_FORWARD_0_50_X));
    EXPECT_EQ(MSERR_OK, player_->GetPlaybackSpeed(mode));
    EXPECT_EQ(SPEED_FORWARD_0_50_X, mode);
}

/**
 * @tc.name  : Test SetPlaybackRate API
 * @tc.number: Player_SetPlaybackRate_003
 * @tc.desc  : Test Player SetPlaybacRate SPEED_FORWARD_0_50_X
 */
HWTEST_F(PlayerServerUnitTest, Player_SetPlaybackRate_003, TestSize.Level1)
{
    float playbackRate = 0.5f;
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_EQ(MSERR_OK, player_->SetPlaybackRate(playbackRate));
}

/**
 * @tc.name  : Test SetPlaybackSpeed API
 * @tc.number: Player_SetPlaybackSpeed_004
 * @tc.desc  : Test Player SetPlaybackSpeed SPEED_FORWARD_1_50_X
 */
HWTEST_F(PlayerServerUnitTest, Player_SetPlaybackSpeed_004, TestSize.Level1)
{
    PlaybackRateMode mode;
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_EQ(MSERR_OK, player_->SetPlaybackSpeed(SPEED_FORWARD_1_50_X));
    EXPECT_EQ(MSERR_OK, player_->GetPlaybackSpeed(mode));
    EXPECT_EQ(SPEED_FORWARD_1_50_X, mode);
}

/**
 * @tc.name  : Test SetPlaybackRate API
 * @tc.number: Player_SetPlaybackRate_004
 * @tc.desc  : Test Player SetPlaybackRate SPEED_FORWARD_1_50_X
 */
HWTEST_F(PlayerServerUnitTest, Player_SetPlaybackRate_004, TestSize.Level1)
{
    float playbackRate = 1.5f;
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_EQ(MSERR_OK, player_->SetPlaybackRate(playbackRate));
}

/**
 * @tc.name  : Test SetPlaybackSpeed API
 * @tc.number: Player_SetPlaybackSpeed_005
 * @tc.desc  : Test Player SetPlaybackSpeed SPEED_FORWARD_1_50_X
 */
HWTEST_F(PlayerServerUnitTest, Player_SetPlaybackSpeed_005, TestSize.Level1)
{
    PlaybackRateMode mode;
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    EXPECT_EQ(MSERR_OK, player_->Play());
    int32_t speed = -1;
    EXPECT_EQ(MSERR_OK, player_->SetPlaybackSpeed(static_cast<OHOS::Media::PlaybackRateMode>(speed)));
    EXPECT_EQ(MSERR_OK, player_->GetPlaybackSpeed(mode));
    EXPECT_EQ(-1, mode);
}

/**
 * @tc.name  : Test SetPlaybackRate API
 * @tc.number: Player_SetPlaybackRate_005
 * @tc.desc  : Test Player SetPlaybackRate Unvalid Value
 */
HWTEST_F(PlayerServerUnitTest, Player_SetPlaybackRate_005, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    EXPECT_EQ(MSERR_OK, player_->Play());
    float playbackRate = -1;
    EXPECT_NE(MSERR_OK, player_->SetPlaybackRate(playbackRate));
}

/**
 * @tc.name  : Test SetSurface API
 * @tc.number: Player_SetSurface_001
 * @tc.desc  : Test Player SetSurface->SetSurface
 */
HWTEST_F(PlayerServerUnitTest, Player_SetSurface_001, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    int32_t ret = player_->PrepareAsync();
    if (ret == MSERR_OK) {
        PlayFunTest(LOCAL_PLAY);
    }
}

/**
 * @tc.name  : Test AddSubSource
 * @tc.number: Player_AddSubSource_001
 * @tc.desc  : Test Player AddSubSource state machine
 */
HWTEST_F(PlayerServerUnitTest, Player_AddSubSource_001, TestSize.Level1)
{
    ASSERT_NE(MSERR_OK, player_->AddSubSource(SUBTITLE_SRT_FIELE, 0, 0));
    ASSERT_EQ(MSERR_OK, player_->SetSource(MEDIA_ROOT + "AVC_Baseline@L1.2_81.0Kbps_320x240.mp4", 0, 0));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_NE(MSERR_OK, player_->AddSubSource(SUBTITLE_SRT_FIELE));    // Illegal state machine
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_NE(SUBTITLE_0_SEC, player_->GetSubtitleText(SUBTITLE_0_SEC));
    EXPECT_EQ(MSERR_OK, player_->Pause());
    EXPECT_EQ(MSERR_OK, player_->Stop());
    EXPECT_EQ(MSERR_OK, player_->Reset());
    EXPECT_EQ(MSERR_OK, player_->Release());
}

/**
 * @tc.name  : Test AddSubSource
 * @tc.number: Player_AddSubSource_002
 * @tc.desc  : Test Player AddSubSource behavior
 */
HWTEST_F(PlayerServerUnitTest, Player_AddSubSource_002, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(MEDIA_ROOT + "H264_AAC.mp4", 0, 0));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_NE(MSERR_OK, player_->AddSubSource(SUBTITLE_SRT_FIELE, 0, 0));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_EQ(MSERR_OK, player_->Seek(SEEK_TIME_5_SEC, SEEK_CLOSEST));
    EXPECT_EQ("", player_->GetSubtitleText(""));
    EXPECT_EQ(MSERR_OK, player_->Seek(SEEK_TIME_2_SEC, SEEK_CLOSEST));
    EXPECT_EQ("", player_->GetSubtitleText(""));
    EXPECT_EQ(MSERR_OK, player_->Seek(SEEK_TIME_5_SEC, SEEK_NEXT_SYNC));
    EXPECT_EQ("", player_->GetSubtitleText(""));
    EXPECT_EQ(MSERR_OK, player_->Seek(SEEK_TIME_5_SEC, SEEK_PREVIOUS_SYNC));
    EXPECT_EQ("", player_->GetSubtitleText(""));
    int duration = 0;
    EXPECT_EQ(MSERR_OK, player_->GetDuration(duration));
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_EQ(MSERR_OK, player_->Seek(duration, SEEK_CLOSEST));
    EXPECT_EQ("", player_->GetSubtitleText(""));
}

/**
 * @tc.name  : Test PlayerServer Stop
 * @tc.number: PlayerServer_Stop_001
 * @tc.desc  : Test PlayerServer Stop on different status
 */
HWTEST_F(PlayerServerUnitTest, PlayerServer_Stop_001, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(MEDIA_ROOT + "H264_AAC.mp4", 0, 0));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->PrepareAsync());
    EXPECT_EQ(MSERR_OK, player_->Stop());
}

/**
 * @tc.name  : Test PlayerServer Stop
 * @tc.number: PlayerServer_Stop_002
 * @tc.desc  : Test PlayerServer Stop on different status
 */
HWTEST_F(PlayerServerUnitTest, PlayerServer_Stop_002, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(MEDIA_ROOT + "H264_AAC.mp4", 0, 0));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->PrepareAsync());
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_TRUE(player_->IsPlaying());
    EXPECT_EQ(MSERR_OK, player_->Stop());
}

/**
 * @tc.name  : Test PlayerServer Stop
 * @tc.number: PlayerServer_Stop_003
 * @tc.desc  : Test PlayerServer Stop on different status
 */
HWTEST_F(PlayerServerUnitTest, PlayerServer_Stop_003, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(MEDIA_ROOT + "H264_AAC.mp4", 0, 0));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    int32_t duration = 0;
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->PrepareAsync());
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_EQ(MSERR_OK, player_->GetDuration(duration));
    EXPECT_EQ(MSERR_OK, player_->Seek(duration, SEEK_NEXT_SYNC));
    EXPECT_TRUE(player_->IsPlaying());
    sleep(PLAYING_TIME_2_SEC);
    EXPECT_EQ(MSERR_OK, player_->Stop());
}

/**
 * @tc.name  : Test PlayerServer Stop
 * @tc.number: PlayerServer_Stop_004
 * @tc.desc  : Test PlayerServer Stop on different status
 */
HWTEST_F(PlayerServerUnitTest, PlayerServer_Stop_004, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(MEDIA_ROOT + "H264_AAC.mp4", 0, 0));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->PrepareAsync());
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_TRUE(player_->IsPlaying());
    EXPECT_EQ(MSERR_OK, player_->Pause());
    EXPECT_EQ(MSERR_OK, player_->Stop());
}

/**
 * @tc.name  : Test PlayerServer Stop
 * @tc.number: PlayerServer_Stop_005
 * @tc.desc  : Test PlayerServer Stop on different status
 */
HWTEST_F(PlayerServerUnitTest, PlayerServer_Stop_005, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(MEDIA_ROOT + "H264_AAC.mp4", 0, 0));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_NE(MSERR_OK, player_->Stop());
}

/**
 * @tc.name  : Test SetParameter Stop
 * @tc.number: Player_SetParameter_001
 * @tc.desc  : Test Player SetParameter
 */
HWTEST_F(PlayerServerUnitTest, Player_SetParameter_001, TestSize.Level1)
{
    std::vector<Format> videoTrack;
    std::vector<Format> audioTrack;
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->PrepareAsync());
    EXPECT_EQ(MSERR_OK, player_->SetLooping(true));
    Format format;
    EXPECT_EQ(MSERR_OK, player_->SetParameter(format));
    EXPECT_EQ(MSERR_OK, player_->GetVideoTrackInfo(videoTrack));
    EXPECT_EQ(MSERR_OK, player_->GetAudioTrackInfo(audioTrack));
}

/**
 * @tc.name  : Test SetParameter Stop
 * @tc.number: Player_SetParameter_002
 * @tc.desc  : Test Player SetParameter
 */
HWTEST_F(PlayerServerUnitTest, Player_SetParameter_002, TestSize.Level1)
{
    std::vector<Format> videoTrack;
    std::vector<Format> audioTrack;
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->PrepareAsync());
    EXPECT_EQ(MSERR_OK, player_->SetLooping(true));
    Format format;
    int32_t contentType = 1;
    int32_t scaleType = 1;
    int32_t streamUsage = 1;
    int32_t rendererFlags = 1;
    int32_t audioInterruptMode = 1;
    format.PutIntValue(PlayerKeys::VIDEO_SCALE_TYPE, scaleType);
    format.PutIntValue(PlayerKeys::CONTENT_TYPE, contentType);
    format.PutIntValue(PlayerKeys::STREAM_USAGE, streamUsage);
    format.PutIntValue(PlayerKeys::RENDERER_FLAG, rendererFlags);
    format.PutIntValue(PlayerKeys::AUDIO_INTERRUPT_MODE, audioInterruptMode);
    EXPECT_EQ(MSERR_OK, player_->SetParameter(format));
    EXPECT_EQ(MSERR_OK, player_->GetVideoTrackInfo(videoTrack));
    EXPECT_EQ(MSERR_OK, player_->GetAudioTrackInfo(audioTrack));
}

/**
 * @tc.name  : Test SetParameter Stop
 * @tc.number: Player_SetParameter_003
 * @tc.desc  : Test Player SetParameter
 */
HWTEST_F(PlayerServerUnitTest, Player_SetParameter_003, TestSize.Level1)
{
    Format formatScaleType;
    Format formatContentType;
    Format formatStreamUsage;
    Format formatStreamUsageAndContentType;
    Format formatInterruptMode;
    std::vector<Format> videoTrack;
    std::vector<Format> audioTrack;
    int32_t contentType = 1;
    int32_t scaleType = 1;
    int32_t streamUsage = 1;
    int32_t audioInterruptMode = 1;
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->PrepareAsync());
    EXPECT_EQ(MSERR_OK, player_->SetLooping(true));

    formatScaleType.PutIntValue(PlayerKeys::VIDEO_SCALE_TYPE, scaleType);
    EXPECT_EQ(MSERR_OK, player_->SetParameter(formatScaleType));

    formatContentType.PutIntValue(PlayerKeys::CONTENT_TYPE, contentType);
    EXPECT_EQ(MSERR_OK, player_->SetParameter(formatContentType));

    formatStreamUsage.PutIntValue(PlayerKeys::STREAM_USAGE, streamUsage);
    EXPECT_EQ(MSERR_OK, player_->SetParameter(formatStreamUsage));

    formatStreamUsageAndContentType.PutIntValue(PlayerKeys::CONTENT_TYPE, contentType);
    formatStreamUsageAndContentType.PutIntValue(PlayerKeys::STREAM_USAGE, streamUsage);
    EXPECT_EQ(MSERR_OK, player_->SetParameter(formatStreamUsageAndContentType));

    formatInterruptMode.PutIntValue(PlayerKeys::AUDIO_INTERRUPT_MODE, audioInterruptMode);
    EXPECT_EQ(MSERR_OK, player_->SetParameter(formatInterruptMode));

    EXPECT_EQ(MSERR_OK, player_->GetVideoTrackInfo(videoTrack));
    EXPECT_EQ(MSERR_OK, player_->GetAudioTrackInfo(audioTrack));
}

/**
 * @tc.name  : Test Player state machine, invalid operation on stopped
 * @tc.number: Player_State_Machine_001
 * @tc.desc  : Test Player state machine, invalid operation on stopped
 */
HWTEST_F(PlayerServerUnitTest, Player_State_Machine_001, TestSize.Level1)
{
    ASSERT_EQ(PlayerStates::PLAYER_IDLE, player_->GetState());
    ASSERT_EQ(MSERR_OK, player_->SetSource(MEDIA_ROOT + "mp3_48000Hz_64kbs_mono.mp3"));
    ASSERT_EQ(MSERR_OK, player_->PrepareAsync());
    sleep(1);
    ASSERT_EQ(PlayerStates::PLAYER_PREPARED, player_->GetState());
    int32_t duration = 0;
    ASSERT_EQ(MSERR_OK, player_->GetDuration(duration));
    ASSERT_EQ(MSERR_OK, player_->Play());
    sleep(1);
    ASSERT_EQ(true, player_->IsPlaying());
    ASSERT_EQ(PlayerStates::PLAYER_STARTED, player_->GetState());
    ASSERT_EQ(MSERR_OK, player_->Stop());
    sleep(1);
    ASSERT_EQ(PlayerStates::PLAYER_STOPPED, player_->GetState());
    ASSERT_EQ(MSERR_INVALID_OPERATION, player_->Pause());
    ASSERT_EQ(MSERR_INVALID_OPERATION, player_->Play());
    ASSERT_EQ(MSERR_INVALID_OPERATION, player_->SetSource(MEDIA_ROOT + "mp3_48000Hz_64kbs_mono.mp3"));
}

/**
 * @tc.name  : Test Player state machine, invalid operation on error
 * @tc.number: Player_State_Machine_002
 * @tc.desc  : Test Player state machine, invalid operation on error
 */
HWTEST_F(PlayerServerUnitTest, Player_State_Machine_002, TestSize.Level1)
{
    ASSERT_EQ(PlayerStates::PLAYER_IDLE, player_->GetState());
    ASSERT_EQ(MSERR_OK, player_->SetSource(MEDIA_ROOT + "1kb.mp3"));
    ASSERT_NE(MSERR_OK, player_->PrepareAsync());
    sleep(1);
    ASSERT_EQ(PlayerStates::PLAYER_STATE_ERROR, player_->GetState());
    int32_t duration = 0;
    ASSERT_EQ(MSERR_INVALID_OPERATION, player_->GetDuration(duration));
    ASSERT_EQ(MSERR_INVALID_OPERATION, player_->Seek(0, PlayerSeekMode::SEEK_NEXT_SYNC));
    ASSERT_EQ(MSERR_INVALID_OPERATION, player_->Play());
    sleep(1);
    ASSERT_EQ(false, player_->IsPlaying());
    ASSERT_EQ(MSERR_INVALID_OPERATION, player_->Stop());
    sleep(1);
    ASSERT_EQ(MSERR_INVALID_OPERATION, player_->Pause());
    ASSERT_EQ(MSERR_INVALID_OPERATION, player_->Play());
    ASSERT_EQ(MSERR_INVALID_OPERATION, player_->SetSource(MEDIA_ROOT + "mp3_48000Hz_64kbs_mono.mp3"));
    ASSERT_EQ(MSERR_OK, player_->Reset());
    ASSERT_EQ(PlayerStates::PLAYER_IDLE, player_->GetState());
    ASSERT_EQ(MSERR_INVALID_OPERATION, player_->Reset());
}

/**
 * @tc.name  : Test Player state machine, invalid operation on idle
 * @tc.number: Player_State_Machine_003
 * @tc.desc  : Test Player state machine, invalid operation on idle
 */
HWTEST_F(PlayerServerUnitTest, Player_State_Machine_003, TestSize.Level1)
{
    ASSERT_EQ(PlayerStates::PLAYER_IDLE, player_->GetState());
    ASSERT_EQ(MSERR_INVALID_OPERATION, player_->PrepareAsync());
    sleep(1);
    int32_t duration = 0;
    ASSERT_EQ(MSERR_INVALID_OPERATION, player_->GetDuration(duration));
    ASSERT_EQ(MSERR_INVALID_OPERATION, player_->Play());
    sleep(1);
    ASSERT_EQ(false, player_->IsPlaying());
    ASSERT_EQ(PlayerStates::PLAYER_IDLE, player_->GetState());
    ASSERT_EQ(MSERR_NO_MEMORY, player_->Seek(0, PlayerSeekMode::SEEK_NEXT_SYNC));
    sleep(1);
    ASSERT_EQ(false, player_->IsPlaying());
    ASSERT_EQ(MSERR_INVALID_OPERATION, player_->Pause());
    ASSERT_EQ(MSERR_INVALID_OPERATION, player_->Stop());
}

/**
 * @tc.name  : Test Player state machine, invalid operation on initialized
 * @tc.number: Player_State_Machine_004
 * @tc.desc  : Test Player state machine, invalid operation on initialized
 */
HWTEST_F(PlayerServerUnitTest, Player_State_Machine_004, TestSize.Level1)
{
    ASSERT_EQ(PlayerStates::PLAYER_IDLE, player_->GetState());
    ASSERT_EQ(MSERR_OK, player_->SetSource(MEDIA_ROOT + "mp3_48000Hz_64kbs_mono.mp3"));
    sleep(1);
    int32_t duration = 0;
    ASSERT_EQ(MSERR_INVALID_OPERATION, player_->GetDuration(duration));
    ASSERT_EQ(MSERR_INVALID_OPERATION, player_->Seek(duration, PlayerSeekMode::SEEK_NEXT_SYNC));
    ASSERT_EQ(MSERR_INVALID_OPERATION, player_->Play());
    sleep(1);
    ASSERT_EQ(false, player_->IsPlaying());
    ASSERT_EQ(MSERR_INVALID_OPERATION, player_->Stop());
    sleep(1);
    ASSERT_EQ(MSERR_INVALID_OPERATION, player_->Pause());
    ASSERT_EQ(MSERR_INVALID_OPERATION, player_->Play());
}

/**
 * @tc.name  : Test Player state machine, invalid operation on prepared
 * @tc.number: Player_State_Machine_005
 * @tc.desc  : Test Player state machine, invalid operation on prepared
 */
HWTEST_F(PlayerServerUnitTest, Player_State_Machine_005, TestSize.Level1)
{
    ASSERT_EQ(PlayerStates::PLAYER_IDLE, player_->GetState());
    ASSERT_EQ(MSERR_OK, player_->SetSource(MEDIA_ROOT + "mp3_48000Hz_64kbs_mono.mp3"));
    ASSERT_EQ(MSERR_OK, player_->PrepareAsync());
    sleep(1);
    ASSERT_EQ(MSERR_INVALID_OPERATION, player_->SetSource(MEDIA_ROOT + "mp3_48000Hz_64kbs_mono.mp3"));
    int32_t duration = 0;
    ASSERT_EQ(MSERR_OK, player_->GetDuration(duration));
    ASSERT_EQ(MSERR_OK, player_->Seek(duration, PlayerSeekMode::SEEK_NEXT_SYNC));
    ASSERT_EQ(PlayerStates::PLAYER_PREPARED, player_->GetState());
    ASSERT_EQ(MSERR_INVALID_OPERATION, player_->Pause());
    sleep(1);
    ASSERT_EQ(false, player_->IsPlaying());
    ASSERT_EQ(MSERR_OK, player_->Stop());
}

/**
 * @tc.name  : Test Player state machine, invalid operation on playing
 * @tc.number: Player_State_Machine_006
 * @tc.desc  : Test Player state machine, invalid operation on playing
 */
HWTEST_F(PlayerServerUnitTest, Player_State_Machine_006, TestSize.Level1)
{
    ASSERT_EQ(PlayerStates::PLAYER_IDLE, player_->GetState());
    ASSERT_EQ(MSERR_OK, player_->SetSource(MEDIA_ROOT + "mp3_48000Hz_64kbs_mono.mp3"));
    ASSERT_EQ(MSERR_OK, player_->PrepareAsync());
    ASSERT_EQ(MSERR_OK, player_->SetLooping(true));
    sleep(1);
    int32_t duration = 0;
    ASSERT_EQ(MSERR_OK, player_->GetDuration(duration));
    ASSERT_EQ(MSERR_OK, player_->Play());
    ASSERT_EQ(MSERR_INVALID_OPERATION, player_->SetSource(MEDIA_ROOT + "mp3_48000Hz_64kbs_mono.mp3"));
    ASSERT_EQ(MSERR_OK, player_->Seek(duration, PlayerSeekMode::SEEK_NEXT_SYNC));
    sleep(1);
    ASSERT_EQ(true, player_->IsPlaying());
    ASSERT_EQ(MSERR_OK, player_->Stop());
}

/**
 * @tc.name  : Test Player state machine, invalid operation on completed
 * @tc.number: Player_State_Machine_007
 * @tc.desc  : Test Player state machine, invalid operation on completed
 */
HWTEST_F(PlayerServerUnitTest, Player_State_Machine_007, TestSize.Level1)
{
    ASSERT_EQ(PlayerStates::PLAYER_IDLE, player_->GetState());
    ASSERT_EQ(MSERR_OK, player_->SetSource(MEDIA_ROOT + "mp3_48000Hz_64kbs_mono.mp3"));
    ASSERT_EQ(MSERR_OK, player_->PrepareAsync());
    sleep(1);
    int32_t duration = 0;
    ASSERT_EQ(MSERR_OK, player_->GetDuration(duration));
    ASSERT_EQ(MSERR_OK, player_->Seek(duration, PlayerSeekMode::SEEK_NEXT_SYNC));
    ASSERT_EQ(MSERR_OK, player_->Play());
    sleep(1);
    ASSERT_EQ(false, player_->IsPlaying());
    ASSERT_EQ(PlayerStates::PLAYER_PLAYBACK_COMPLETE, player_->GetState());
    ASSERT_EQ(MSERR_INVALID_OPERATION, player_->Pause());
    ASSERT_EQ(MSERR_INVALID_OPERATION, player_->PrepareAsync());
    ASSERT_EQ(MSERR_INVALID_OPERATION, player_->SetSource(MEDIA_ROOT + "mp3_48000Hz_64kbs_mono.mp3"));
}

/**
 * @tc.name  : Test Player state machine, invalid operation on paused
 * @tc.number: Player_State_Machine_008
 * @tc.desc  : Test Player state machine, invalid operation on paused
 */
HWTEST_F(PlayerServerUnitTest, Player_State_Machine_008, TestSize.Level1)
{
    ASSERT_EQ(PlayerStates::PLAYER_IDLE, player_->GetState());
    ASSERT_EQ(MSERR_OK, player_->SetSource(MEDIA_ROOT + "mp3_48000Hz_64kbs_mono.mp3"));
    ASSERT_EQ(MSERR_OK, player_->PrepareAsync());
    sleep(1);
    int32_t duration = 0;
    ASSERT_EQ(MSERR_OK, player_->GetDuration(duration));
    ASSERT_EQ(MSERR_OK, player_->Play());
    ASSERT_EQ(MSERR_OK, player_->Pause());
    sleep(1);
    ASSERT_EQ(PlayerStates::PLAYER_PAUSED, player_->GetState());
    ASSERT_EQ(MSERR_INVALID_OPERATION, player_->SetSource(MEDIA_ROOT + "mp3_48000Hz_64kbs_mono.mp3"));
    ASSERT_EQ(MSERR_INVALID_OPERATION, player_->PrepareAsync());
}

/**
 * @tc.name  : Test SetPlayRange [0, 600]
 * @tc.number: Player_SetPlayRange_001
 * @tc.desc  : Test Player SetPlayRange interface
 */
HWTEST_F(PlayerServerUnitTest, Player_SetPlayRange_001, TestSize.Level1)
{
    int32_t duration = 0;
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->SetPlayRange(0, 600));
    EXPECT_EQ(MSERR_OK, player_->PrepareAsync());
    EXPECT_EQ(MSERR_OK, player_->GetDuration(duration));
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_TRUE(player_->IsPlaying());
    EXPECT_EQ(MSERR_OK, player_->Pause());
    EXPECT_EQ(MSERR_OK, player_->SetPlayRange(0, duration));
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_EQ(MSERR_OK, player_->Pause());
}

/**
 * @tc.name  : Test SetPlayRange [0, 600]
 * @tc.number: Player_SetPlayRange_002
 * @tc.desc  : Test Player SetPlayRange interface
 */
HWTEST_F(PlayerServerUnitTest, Player_SetPlayRange_002, TestSize.Level1)
{
    int32_t duration = 0;
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->PrepareAsync());
    EXPECT_EQ(MSERR_OK, player_->GetDuration(duration));
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_TRUE(player_->IsPlaying());
    EXPECT_EQ(MSERR_OK, player_->Pause());
    EXPECT_EQ(MSERR_OK, player_->SetPlayRange(0, 600));
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_EQ(MSERR_OK, player_->Pause());
}

/**
 * @tc.name  : Test SetPlayRange [-2, -1]
 * @tc.number: Player_SetPlayRange_003
 * @tc.desc  : Test Player SetPlayRange interface
 */
HWTEST_F(PlayerServerUnitTest, Player_SetPlayRange_003, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    ASSERT_NE(MSERR_OK, player_->SetPlayRange(-2, -1));
}

/**
 * @tc.name  : Test SetPlayRange [-1, -2]
 * @tc.number: Player_SetPlayRange_004
 * @tc.desc  : Test Player SetPlayRange interface
 */
HWTEST_F(PlayerServerUnitTest, Player_SetPlayRange_004, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    ASSERT_NE(MSERR_OK, player_->SetPlayRange(-1, -2));
}

/**
 * @tc.name  : Test SetPlayRange [-1, 0]
 * @tc.number: Player_SetPlayRange_005
 * @tc.desc  : Test Player SetPlayRange interface
 */
HWTEST_F(PlayerServerUnitTest, Player_SetPlayRange_005, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    ASSERT_NE(MSERR_OK, player_->SetPlayRange(-1, 0));
}

/**
 * @tc.name  : Test SetPlayRange [-1, -1]
 * @tc.number: Player_SetPlayRange_006
 * @tc.desc  : Test Player SetPlayRange interface
 */
HWTEST_F(PlayerServerUnitTest, Player_SetPlayRange_006, TestSize.Level1)
{
    int32_t duration = 0;
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->PrepareAsync());
    EXPECT_EQ(MSERR_OK, player_->GetDuration(duration));
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_TRUE(player_->IsPlaying());
    EXPECT_EQ(MSERR_OK, player_->Pause());
    EXPECT_EQ(MSERR_OK, player_->SetPlayRange(-1, 600));
    EXPECT_EQ(MSERR_OK, player_->SetPlayRange(-1, -1));
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_EQ(MSERR_OK, player_->Pause());
}

/**
 * @tc.name  : Test SetPlayRange [100, 2]
 * @tc.number: Player_SetPlayRange_007
 * @tc.desc  : Test Player SetPlayRange interface
 */
HWTEST_F(PlayerServerUnitTest, Player_SetPlayRange_007, TestSize.Level1)
{
    int32_t duration = 0;
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->PrepareAsync());
    EXPECT_EQ(MSERR_OK, player_->GetDuration(duration));
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_TRUE(player_->IsPlaying());
    EXPECT_EQ(MSERR_OK, player_->Pause());
    ASSERT_NE(MSERR_OK, player_->SetPlayRange(100, 2));
}

/**
 * @tc.name  : Test SetPlayRange [duration + 1, duration + 2]
 * @tc.number: Player_SetPlayRange_008
 * @tc.desc  : Test Player SetPlayRange interface
 */
HWTEST_F(PlayerServerUnitTest, Player_SetPlayRange_008, TestSize.Level1)
{
    int32_t duration = 0;
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->PrepareAsync());
    EXPECT_EQ(MSERR_OK, player_->GetDuration(duration));
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_TRUE(player_->IsPlaying());
    EXPECT_EQ(MSERR_OK, player_->Pause());
    int32_t start = duration + 1;
    int32_t end = duration + 2;
    ASSERT_NE(MSERR_OK, player_->SetPlayRange(start, end));
}

/**
 * @tc.name  : Test SetPlayRange [100, duration + 1]
 * @tc.number: Player_SetPlayRange_009
 * @tc.desc  : Test Player SetPlayRange interface
 */
HWTEST_F(PlayerServerUnitTest, Player_SetPlayRange_009, TestSize.Level1)
{
    int32_t duration = 0;
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->PrepareAsync());
    EXPECT_EQ(MSERR_OK, player_->GetDuration(duration));
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_TRUE(player_->IsPlaying());
    EXPECT_EQ(MSERR_OK, player_->Pause());
    int32_t end = duration + 1;
    ASSERT_NE(MSERR_OK, player_->SetPlayRange(100, end));
}

/**
 * @tc.name  : Test SetPlayRange [10035, 10037]
 * @tc.number: Player_SetPlayRange_010
 * @tc.desc  : Test Player SetPlayRange interface, duration 10034
 */
HWTEST_F(PlayerServerUnitTest, Player_SetPlayRange_010, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->SetPlayRange(10035, 10037));
    ASSERT_NE(MSERR_OK, player_->PrepareAsync());
}

/**
 * @tc.name  : Test SetPlayRange [100, 10037]
 * @tc.number: Player_SetPlayRange_011
 * @tc.desc  : Test Player SetPlayRange interface, duration 10034
 */
HWTEST_F(PlayerServerUnitTest, Player_SetPlayRange_011, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->SetPlayRange(100, 10037));
    ASSERT_NE(MSERR_OK, player_->PrepareAsync());
}

/**
 * @tc.name  : Test SetPlayRange
 * @tc.number: Player_SetPlayRange_012
 * @tc.desc  : Test Player SetPlayRange invalid state
 */
HWTEST_F(PlayerServerUnitTest, Player_SetPlayRange_012, TestSize.Level0)
{
    EXPECT_NE(MSERR_OK, player_->SetPlayRange(100, 10037));
}

/**
 * @tc.name  : Test SetPlayRange
 * @tc.number: Player_SetPlayRange_013
 * @tc.desc  : Test Player SetPlayRange invalid playerEngine
 */
HWTEST_F(PlayerServerUnitTest, Player_SetPlayRange_013, TestSize.Level0)
{
    std::shared_ptr<PlayerServer> server = std::make_shared<PlayerServer>();
    server->lastOpStatus_ = PLAYER_INITIALIZED;
    EXPECT_EQ(MSERR_OK, server->SetPlayRange(100, 10037));
}

/**
 * @tc.name  : Test SeekContinuous in prepared
 * @tc.number: Player_SeekContinuous_001
 * @tc.desc  : Test Player SeekContinuous
 */
HWTEST_F(PlayerServerUnitTest, Player_SeekContinuous_001, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->PrepareAsync());
    for (int i = 0; i < 10; i++) {
        EXPECT_EQ(MSERR_OK, player_->SeekContinuous(i * 100));
        usleep(SEEK_CONTINUOUS_WAIT_US);
    }
    EXPECT_EQ(MSERR_OK, player_->Play());
}

/**
 * @tc.name  : Test SeekContinuous in playing
 * @tc.number: Player_SeekContinuous_002
 * @tc.desc  : Test Player SeekContinuous
 */
HWTEST_F(PlayerServerUnitTest, Player_SeekContinuous_002, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->PrepareAsync());
    EXPECT_EQ(MSERR_OK, player_->Play());
    sleep(PLAYING_TIME_2_SEC);
    for (int i = 0; i < 30; i++) {
        EXPECT_EQ(MSERR_OK, player_->SeekContinuous(i * 100));
        usleep(SEEK_CONTINUOUS_WAIT_US);
    }
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_EQ(MSERR_OK, player_->Stop());
}

/**
 * @tc.name  : Test SeekContinuous in paused
 * @tc.number: Player_SeekContinuous_003
 * @tc.desc  : Test Player SeekContinuous
 */
HWTEST_F(PlayerServerUnitTest, Player_SeekContinuous_003, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->PrepareAsync());
    EXPECT_EQ(MSERR_OK, player_->Play());
    sleep(PLAYING_TIME_2_SEC);
    EXPECT_EQ(MSERR_OK, player_->Pause());
    for (int i = 0; i < 30; i++) {
        EXPECT_EQ(MSERR_OK, player_->SeekContinuous(i * 100));
        usleep(SEEK_CONTINUOUS_WAIT_US);
    }
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_EQ(MSERR_OK, player_->Stop());
}

/**
 * @tc.name  : Test SeekContinuous in completed
 * @tc.number: Player_SeekContinuous_004
 * @tc.desc  : Test Player SeekContinuous
 */
HWTEST_F(PlayerServerUnitTest, Player_SeekContinuous_004, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->PrepareAsync());
    EXPECT_EQ(MSERR_OK, player_->Play());
    sleep(PLAYING_TIME_2_SEC);
    EXPECT_EQ(MSERR_OK, player_->Seek(9, SEEK_PREVIOUS_SYNC));
    sleep(PLAYING_TIME_10_SEC);
    for (int i = 0; i < 30; i++) {
        EXPECT_EQ(MSERR_OK, player_->SeekContinuous(i * 100));
        usleep(SEEK_CONTINUOUS_WAIT_US);
    }
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_EQ(MSERR_OK, player_->Stop());
}

/**
 * @tc.name  : Test SeekContinuous backward
 * @tc.number: Player_SeekContinuous_005
 * @tc.desc  : Test Player SeekContinuous
 */
HWTEST_F(PlayerServerUnitTest, Player_SeekContinuous_005, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->PrepareAsync());
    EXPECT_EQ(MSERR_OK, player_->Play());
    sleep(PLAYING_TIME_2_SEC);
    for (int i = 0; i < 30; i++) {
        EXPECT_EQ(MSERR_OK, player_->SeekContinuous(9000 - i * 100));
        usleep(SEEK_CONTINUOUS_WAIT_US);
    }
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_EQ(MSERR_OK, player_->Stop());
}

/**
 * @tc.name  : Test SeekContinuous forward and backward
 * @tc.number: Player_SeekContinuous_006
 * @tc.desc  : Test Player SeekContinuous
 */
HWTEST_F(PlayerServerUnitTest, Player_SeekContinuous_006, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->PrepareAsync());
    EXPECT_EQ(MSERR_OK, player_->Play());
    sleep(PLAYING_TIME_2_SEC);
    for (int i = 0; i < 30; i++) {
        EXPECT_EQ(MSERR_OK, player_->SeekContinuous(9000 - i * 100));
        usleep(SEEK_CONTINUOUS_WAIT_US);
    }
    for (int i = 0; i < 30; i++) {
        EXPECT_EQ(MSERR_OK, player_->SeekContinuous(9000 - i * 100));
        usleep(SEEK_CONTINUOUS_WAIT_US);
    }
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_EQ(MSERR_OK, player_->Stop());
}

/**
 * @tc.name  : Test SetPlaybackSpeed API
 * @tc.number: Player_SetPlaybackSpeed_006
 * @tc.desc  : Test Player SetPlaybackSpeed SPEED_FORWARD_3_00_X
 */
HWTEST_F(PlayerServerUnitTest, Player_SetPlaybackSpeed_006, TestSize.Level1)
{
    float playbackSpeed = 3.0f;
    PlaybackRateMode mode;
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_EQ(MSERR_OK, player_->SetPlaybackRate(playbackSpeed));
    EXPECT_EQ(MSERR_OK, player_->SetPlaybackSpeed(SPEED_FORWARD_3_00_X));
    EXPECT_EQ(MSERR_OK, player_->GetPlaybackSpeed(mode));
    EXPECT_EQ(SPEED_FORWARD_3_00_X, mode);
}

/**
 * @tc.name  : Test SetMaxAmplitudeCbStatus API
 * @tc.number: Player_SetMaxAmplitudeCbStatus_001
 * @tc.desc  : Test Player SetMaxAmplitudeCbStatus status on before prepare
 */
HWTEST_F(PlayerServerUnitTest, Player_SetMaxAmplitudeCbStatus_001, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetMaxAmplitudeCbStatus(true));
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    EXPECT_EQ(MSERR_OK, player_->Play());
}

/**
 * @tc.name  : Test SetMaxAmplitudeCbStatus API
 * @tc.number: Player_SetMaxAmplitudeCbStatus_002
 * @tc.desc  : Test Player SetMaxAmplitudeCbStatus status on after prepare
 */
HWTEST_F(PlayerServerUnitTest, Player_SetMaxAmplitudeCbStatus_002, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    EXPECT_EQ(MSERR_OK, player_->SetMaxAmplitudeCbStatus(true));
    EXPECT_EQ(MSERR_OK, player_->Play());
}

/**
 * @tc.name  : Test SetMaxAmplitudeCbStatus API
 * @tc.number: Player_SetMaxAmplitudeCbStatus_003
 * @tc.desc  : Test Player SetMaxAmplitudeCbStatus status off before prepare
 */
HWTEST_F(PlayerServerUnitTest, Player_SetMaxAmplitudeCbStatus_003, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetMaxAmplitudeCbStatus(false));
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    EXPECT_EQ(MSERR_OK, player_->Play());
}

/**
 * @tc.name  : Test SetMaxAmplitudeCbStatus API
 * @tc.number: Player_SetMaxAmplitudeCbStatus_004
 * @tc.desc  : Test Player SetMaxAmplitudeCbStatus status off after prepare
 */
HWTEST_F(PlayerServerUnitTest, Player_SetMaxAmplitudeCbStatus_004, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    EXPECT_EQ(MSERR_OK, player_->SetMaxAmplitudeCbStatus(false));
    EXPECT_EQ(MSERR_OK, player_->Play());
}

/**
 * @tc.name  : Test SetDeviceChangeCbStatus API
 * @tc.number: Player_SetDeviceChangeCbStatus_001
 * @tc.desc  : Test Player SetDeviceChangeCbStatus status on before prepare
 */
HWTEST_F(PlayerServerUnitTest, Player_SetDeviceChangeCbStatus_001, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetDeviceChangeCbStatus(true));
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    EXPECT_EQ(MSERR_OK, player_->Play());
}

/**
 * @tc.name  : Test SetDeviceChangeCbStatus API
 * @tc.number: Player_SetDeviceChangeCbStatus_002
 * @tc.desc  : Test Player SetDeviceChangeCbStatus status on after prepare
 */
HWTEST_F(PlayerServerUnitTest, Player_SetDeviceChangeCbStatus_002, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    EXPECT_EQ(MSERR_OK, player_->SetDeviceChangeCbStatus(true));
    EXPECT_EQ(MSERR_OK, player_->Play());
}

/**
 * @tc.name  : Test SetDeviceChangeCbStatus API
 * @tc.number: Player_SetDeviceChangeCbStatus_003
 * @tc.desc  : Test Player SetDeviceChangeCbStatus status off before prepare
 */
HWTEST_F(PlayerServerUnitTest, Player_SetDeviceChangeCbStatus_003, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetDeviceChangeCbStatus(false));
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    EXPECT_EQ(MSERR_OK, player_->Play());
}

/**
 * @tc.name  : Test SetDeviceChangeCbStatus API
 * @tc.number: Player_SetDeviceChangeCbStatus_004
 * @tc.desc  : Test Player SetDeviceChangeCbStatus status off after prepare
 */
HWTEST_F(PlayerServerUnitTest, Player_SetDeviceChangeCbStatus_004, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    EXPECT_EQ(MSERR_OK, player_->SetDeviceChangeCbStatus(false));
    EXPECT_EQ(MSERR_OK, player_->Play());
}

/**
 * @tc.name  : Test SetPlaybackStrategy
 * @tc.number: Player_SetPlaybackStrategy_001
 * @tc.desc  : Test Player SetPlaybackStrategy
 */
HWTEST_F(PlayerServerUnitTest, Player_SetPlaybackStrategy_001, TestSize.Level1)
{
    AVPlayStrategy playbackStrategy = {
        .mutedMediaType = OHOS::Media::MediaType::MEDIA_TYPE_AUD
    };
    ASSERT_NE(MSERR_OK, player_->SetPlaybackStrategy(playbackStrategy));
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    ASSERT_EQ(MSERR_OK, player_->SetPlaybackStrategy(playbackStrategy));
}

HWTEST_F(PlayerServerUnitTest, Player_SetPlaybackStrategy_002, TestSize.Level1)
{
    AVPlayStrategy playbackStrategy = {
        .mutedMediaType = OHOS::Media::MediaType::MEDIA_TYPE_VID,
        .keepDecodingOnMute = false
    };
    ASSERT_NE(MSERR_OK, player_->SetPlaybackStrategy(playbackStrategy));
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    ASSERT_EQ(MSERR_OK, player_->SetPlaybackStrategy(playbackStrategy));
}

/**
 * @tc.name  : Test SetMediaMuted
 * @tc.number: Player_SetMediaMuted_001
 * @tc.desc  : Test Player SetMediaMuted
 */
HWTEST_F(PlayerServerUnitTest, Player_SetMediaMuted_001, TestSize.Level1)
{
    ASSERT_NE(MSERR_OK, player_->SetMediaMuted(OHOS::Media::MediaType::MEDIA_TYPE_AUD, true));
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    ASSERT_EQ(MSERR_OK, player_->SetMediaMuted(OHOS::Media::MediaType::MEDIA_TYPE_AUD, true));
    ASSERT_EQ(MSERR_OK, player_->PrepareAsync());
    ASSERT_EQ(MSERR_OK, player_->SetMediaMuted(OHOS::Media::MediaType::MEDIA_TYPE_AUD, true));
    ASSERT_EQ(MSERR_OK, player_->Play());
    ASSERT_EQ(MSERR_OK, player_->SetMediaMuted(OHOS::Media::MediaType::MEDIA_TYPE_AUD, true));
    ASSERT_EQ(MSERR_OK, player_->Pause());
    ASSERT_EQ(MSERR_OK, player_->SetMediaMuted(OHOS::Media::MediaType::MEDIA_TYPE_AUD, true));
    ASSERT_EQ(MSERR_OK, player_->Stop());
    ASSERT_EQ(MSERR_OK, player_->SetMediaMuted(OHOS::Media::MediaType::MEDIA_TYPE_AUD, true));
}

/**
 * @tc.name  : Test SetMediaMuted
 * @tc.number: Player_SetMediaMuted_002
 * @tc.desc  : Test Player SetMediaMuted
 */
HWTEST_F(PlayerServerUnitTest, Player_SetMediaMuted_002, TestSize.Level1)
{
    ASSERT_NE(MSERR_OK, player_->SetMediaMuted(OHOS::Media::MediaType::MEDIA_TYPE_VID, true));
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    ASSERT_EQ(MSERR_OK, player_->SetMediaMuted(OHOS::Media::MediaType::MEDIA_TYPE_VID, true));
    ASSERT_EQ(MSERR_OK, player_->PrepareAsync());
    ASSERT_EQ(MSERR_OK, player_->SetMediaMuted(OHOS::Media::MediaType::MEDIA_TYPE_VID, true));
    ASSERT_EQ(MSERR_OK, player_->Play());
    ASSERT_EQ(MSERR_OK, player_->SetMediaMuted(OHOS::Media::MediaType::MEDIA_TYPE_VID, true));
    ASSERT_EQ(MSERR_OK, player_->Stop());
    ASSERT_EQ(MSERR_OK, player_->SetMediaMuted(OHOS::Media::MediaType::MEDIA_TYPE_VID, true));
}

/**
 * @tc.name  : Test GetCurrentTime
 * @tc.number: Player_GetCurrentTime_001
 * @tc.desc  : Test GetCurrentTime interface with invalid parameters
 */
HWTEST_F(PlayerServerUnitTest, Player_GetCurrentTime_001, TestSize.Level0)
{
    int32_t time = 0;
    int32_t duration = 0;
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    EXPECT_EQ(MSERR_OK, player_->GetCurrentTime(time));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->GetCurrentTime(time));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    EXPECT_EQ(MSERR_OK, player_->GetCurrentTime(time));
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_EQ(MSERR_OK, player_->GetCurrentTime(time));
    EXPECT_EQ(MSERR_OK, player_->Pause());
    EXPECT_EQ(MSERR_OK, player_->GetCurrentTime(time));
    EXPECT_EQ(MSERR_OK, player_->GetDuration(duration));
    EXPECT_EQ(MSERR_OK, player_->Seek(duration, SEEK_CLOSEST));
    EXPECT_EQ(MSERR_OK, player_->Play());
    sleep(PLAYING_TIME_2_SEC);
    EXPECT_EQ(MSERR_OK, player_->GetCurrentTime(time));
    EXPECT_EQ(MSERR_OK, player_->Stop());
    EXPECT_EQ(MSERR_OK, player_->GetCurrentTime(time));
    EXPECT_EQ(MSERR_OK, player_->Reset());
    EXPECT_NE(MSERR_OK, player_->GetCurrentTime(time));
}

/**
 * @tc.name  : Test GetCurrentTime
 * @tc.number: Player_GetCurrentTime_002
 * @tc.desc  : Test GetCurrentTime interface with invalid parameters
 */
HWTEST_F(PlayerServerUnitTest, Player_GetCurrentTime_002, TestSize.Level0)
{
    std::shared_ptr<PlayerServer> server = std::make_shared<PlayerServer>();
    int32_t time = 0;
    server->lastOpStatus_ = PLAYER_INITIALIZED;
    server->isLiveStream_ = true;
    EXPECT_EQ(MSERR_OK, server->GetCurrentTime(time));
}

/**
 * @tc.name  : Test GetPlaybackInfo API
 * @tc.number: Player_GetPlaybackInfo_001
 * @tc.desc  : Test Player GetPlaybackInfo
 */
HWTEST_F(PlayerServerUnitTest, Player_GetPlaybackInfo_001, TestSize.Level0)
{
    Format playbackInfo;
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_EQ(MSERR_OK, player_->GetPlaybackInfo(playbackInfo));
}

/**
 * @tc.name  : Test GetPlaybackInfo API
 * @tc.number: Player_GetPlaybackInfo_002
 * @tc.desc  : Test Player GetPlaybackInfo
 */
HWTEST_F(PlayerServerUnitTest, Player_GetPlaybackInfo_002, TestSize.Level2)
{
    Format playbackInfo;
    int32_t duration = 0;
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    EXPECT_NE(MSERR_OK, player_->GetPlaybackInfo(playbackInfo));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_NE(MSERR_OK, player_->GetPlaybackInfo(playbackInfo));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    EXPECT_EQ(MSERR_OK, player_->GetPlaybackInfo(playbackInfo));
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_EQ(MSERR_OK, player_->GetPlaybackInfo(playbackInfo));
    EXPECT_EQ(MSERR_OK, player_->Pause());
    EXPECT_EQ(MSERR_OK, player_->GetPlaybackInfo(playbackInfo));
    EXPECT_EQ(MSERR_OK, player_->GetDuration(duration));
    EXPECT_EQ(MSERR_OK, player_->Seek(duration, SEEK_CLOSEST));
    EXPECT_EQ(MSERR_OK, player_->Play());
    sleep(PLAYING_TIME_2_SEC);
    EXPECT_EQ(MSERR_OK, player_->GetPlaybackInfo(playbackInfo));
    EXPECT_EQ(MSERR_OK, player_->Stop());
    EXPECT_NE(MSERR_OK, player_->GetPlaybackInfo(playbackInfo));
    EXPECT_EQ(MSERR_OK, player_->Reset());
    EXPECT_NE(MSERR_OK, player_->GetPlaybackInfo(playbackInfo));
}

/**
 * @tc.name  : Test GetPlaybackStatisticMetrics API
 * @tc.number: Player_GetPlaybackStatisticMetrics_001
 * @tc.desc  : Test Player GetPlaybackStatisticMetrics
 */
HWTEST_F(PlayerServerUnitTest, Player_GetPlaybackStatisticMetrics_001, TestSize.Level0)
{
    Format playbackStatisticMetrics;
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_EQ(MSERR_OK, player_->GetPlaybackStatisticMetrics(playbackStatisticMetrics));
}

/**
 * @tc.name  : Test GetPlaybackStatisticMetrics API
 * @tc.number: Player_GetPlaybackStatisticMetrics_002
 * @tc.desc  : Test Player GetPlaybackStatisticMetrics
 */
HWTEST_F(PlayerServerUnitTest, Player_GetPlaybackStatisticMetrics_002, TestSize.Level2)
{
    Format playbackStatisticMetrics;
    int32_t duration = 0;
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    EXPECT_NE(MSERR_OK, player_->GetPlaybackStatisticMetrics(playbackStatisticMetrics));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_NE(MSERR_OK, player_->GetPlaybackStatisticMetrics(playbackStatisticMetrics));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    EXPECT_EQ(MSERR_OK, player_->GetPlaybackStatisticMetrics(playbackStatisticMetrics));
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_EQ(MSERR_OK, player_->GetPlaybackStatisticMetrics(playbackStatisticMetrics));
    EXPECT_EQ(MSERR_OK, player_->Pause());
    EXPECT_EQ(MSERR_OK, player_->GetPlaybackStatisticMetrics(playbackStatisticMetrics));
    EXPECT_EQ(MSERR_OK, player_->GetDuration(duration));
    EXPECT_EQ(MSERR_OK, player_->Seek(duration, SEEK_CLOSEST));
    EXPECT_EQ(MSERR_OK, player_->Play());
    sleep(PLAYING_TIME_2_SEC);
    EXPECT_EQ(MSERR_OK, player_->GetPlaybackStatisticMetrics(playbackStatisticMetrics));
    EXPECT_EQ(MSERR_OK, player_->Stop());
    EXPECT_EQ(MSERR_OK, player_->GetPlaybackStatisticMetrics(playbackStatisticMetrics));
    EXPECT_EQ(MSERR_OK, player_->Reset());
    EXPECT_NE(MSERR_OK, player_->GetPlaybackStatisticMetrics(playbackStatisticMetrics));
}

/**
 * @tc.name  : Test GetSubtitleTrackInfo API
 * @tc.number: Player_GetSubtitleTrackInfo_001
 * @tc.desc  : Test Player GetSubtitleTrackInfo
 */
HWTEST_F(PlayerServerUnitTest, Player_GetSubtitleTrackInfo_001, TestSize.Level0)
{
    std::vector<Format> subtitleTrackInfo;
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_EQ(MSERR_OK, player_->GetSubtitleTrackInfo(subtitleTrackInfo));
}

/**
 * @tc.name  : Test GetSubtitleTrackInfo API
 * @tc.number: Player_GetSubtitleTrackInfo_002
 * @tc.desc  : Test Player GetSubtitleTrackInfo
 */
HWTEST_F(PlayerServerUnitTest, Player_GetSubtitleTrackInfo_002, TestSize.Level2)
{
    std::vector<Format> subtitleTrackInfo;
    int32_t duration = 0;
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    EXPECT_NE(MSERR_OK, player_->GetSubtitleTrackInfo(subtitleTrackInfo));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_NE(MSERR_OK, player_->GetSubtitleTrackInfo(subtitleTrackInfo));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    EXPECT_EQ(MSERR_OK, player_->GetSubtitleTrackInfo(subtitleTrackInfo));
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_EQ(MSERR_OK, player_->GetSubtitleTrackInfo(subtitleTrackInfo));
    EXPECT_EQ(MSERR_OK, player_->Pause());
    EXPECT_EQ(MSERR_OK, player_->GetSubtitleTrackInfo(subtitleTrackInfo));
    EXPECT_EQ(MSERR_OK, player_->GetDuration(duration));
    EXPECT_EQ(MSERR_OK, player_->Seek(duration, SEEK_CLOSEST));
    EXPECT_EQ(MSERR_OK, player_->Play());
    sleep(PLAYING_TIME_2_SEC);
    EXPECT_EQ(MSERR_OK, player_->GetSubtitleTrackInfo(subtitleTrackInfo));
    EXPECT_EQ(MSERR_OK, player_->Stop());
    EXPECT_NE(MSERR_OK, player_->GetSubtitleTrackInfo(subtitleTrackInfo));
    EXPECT_EQ(MSERR_OK, player_->Reset());
    EXPECT_NE(MSERR_OK, player_->GetSubtitleTrackInfo(subtitleTrackInfo));
}

/**
 * @tc.name  : Test SetRenderFirstFrame API
 * @tc.number: Player_SetRenderFirstFrame_001
 * @tc.desc  : Test Player SetRenderFirstFrame
 */
HWTEST_F(PlayerServerUnitTest, Player_SetRenderFirstFrame_001, TestSize.Level0)
{
    bool display = false;
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE2));
    EXPECT_EQ(MSERR_OK, player_->SetRenderFirstFrame(display));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    EXPECT_NE(MSERR_OK, player_->SetRenderFirstFrame(display));
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_NE(MSERR_OK, player_->SetRenderFirstFrame(display));
    EXPECT_EQ(MSERR_OK, player_->Reset());
    display = true;
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE2));
    EXPECT_EQ(MSERR_OK, player_->SetRenderFirstFrame(display));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    EXPECT_NE(MSERR_OK, player_->SetRenderFirstFrame(display));
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_NE(MSERR_OK, player_->SetRenderFirstFrame(display));
}

/**
 * @tc.name  : Test SetRenderFirstFrame API
 * @tc.number: Player_SetRenderFirstFrame_002
 * @tc.desc  : Test Player SetRenderFirstFrame invalid playerEngine
 */
HWTEST_F(PlayerServerUnitTest, Player_SetRenderFirstFrame_002, TestSize.Level0)
{
    bool display = false;
    std::shared_ptr<PlayerServer> server = std::make_shared<PlayerServer>();
    server->lastOpStatus_ = PLAYER_INITIALIZED;
    EXPECT_EQ(MSERR_OK, server->SetRenderFirstFrame(display));
}

/**
 * @tc.name  : Test PreparedHandleEos API
 * @tc.number: Player_PreparedHandleEos_001
 * @tc.desc  : Test Player PreparedHandleEos
 */
HWTEST_F(PlayerServerUnitTest, Player_PreparedHandleEos_001, TestSize.Level0)
{
    std::shared_ptr<PlayerServer> server = std::make_shared<PlayerServer>();
    (void)server->Init();
    ASSERT_EQ(MSERR_OK, server->SetSource(VIDEO_FILE1));
    EXPECT_EQ(MSERR_OK, server->Prepare());
    EXPECT_EQ(MSERR_OK, server->Play());
    EXPECT_EQ(MSERR_OK, server->SetLooping(true));
    EXPECT_EQ(true, server->IsLooping());
    server->PreparedHandleEos();
    EXPECT_NE(server->lastOpStatus_, PLAYER_PLAYBACK_COMPLETE);
    EXPECT_EQ(MSERR_OK, server->SetLooping(false));
    EXPECT_EQ(false, server->IsLooping());
    server->PreparedHandleEos();
    EXPECT_EQ(server->lastOpStatus_, PLAYER_PLAYBACK_COMPLETE);
    server->Release();
}

/**
 * @tc.name  : Test HandleEos API
 * @tc.number: Player_HandleEos_001
 * @tc.desc  : Test Player HandleEos
 */
HWTEST_F(PlayerServerUnitTest, Player_HandleEos_001, TestSize.Level0)
{
    std::shared_ptr<PlayerServer> server = std::make_shared<PlayerServer>();
    server->HandleEos();
    EXPECT_EQ(server->disableNextSeekDone_, false);
}

/**
 * @tc.name  : Test HandleInterruptEvent API
 * @tc.number: Player_HandleInterruptEvent_001
 * @tc.desc  : Test Player HandleInterruptEvent
 */
HWTEST_F(PlayerServerUnitTest, Player_HandleInterruptEvent_001, TestSize.Level0)
{
    std::shared_ptr<PlayerServer> server = std::make_shared<PlayerServer>();
    server->interruptEventState_ = PLAYER_PREPARING;
    Format infoBody;
    infoBody.PutIntValue(PlayerKeys::AUDIO_INTERRUPT_TYPE, -1);
    infoBody.PutIntValue(PlayerKeys::AUDIO_INTERRUPT_FORCE, -1);
    infoBody.PutIntValue(PlayerKeys::AUDIO_INTERRUPT_HINT, -1);
    server->HandleInterruptEvent(infoBody);
    EXPECT_EQ(server->interruptEventState_, PLAYER_PREPARING);

    infoBody.PutIntValue(PlayerKeys::AUDIO_INTERRUPT_FORCE, OHOS::AudioStandard::INTERRUPT_FORCE);
    server->HandleInterruptEvent(infoBody);
    EXPECT_EQ(server->interruptEventState_, PLAYER_PREPARING);
}

/**
 * @tc.name  : Test BackGroundChangeState API
 * @tc.number: Player_BackGroundChangeState_001
 * @tc.desc  : Test Player BackGroundChangeState
 */
HWTEST_F(PlayerServerUnitTest, Player_BackGroundChangeState_001, TestSize.Level0)
{
    std::shared_ptr<PlayerServer> server = std::make_shared<PlayerServer>();
    (void)server->Init();
    ASSERT_EQ(MSERR_OK, server->SetSource(VIDEO_FILE1));
    EXPECT_EQ(MSERR_OK, server->Prepare());
    EXPECT_EQ(MSERR_OK, server->Play());
    EXPECT_EQ(MSERR_OK, server->BackGroundChangeState(PLAYER_PAUSED, true));
    EXPECT_EQ(MSERR_OK, server->BackGroundChangeState(PLAYER_STARTED, true));
    EXPECT_EQ(MSERR_OK, server->Stop());
    EXPECT_NE(MSERR_OK, server->BackGroundChangeState(PLAYER_STOPPED, true));
}

/**
 * @tc.name  : Test PlayerState API
 * @tc.number: Player_PlayerState_001
 * @tc.desc  : Test Player PlayerState
 */
HWTEST_F(PlayerServerUnitTest, Player_PlayerState_001, TestSize.Level0)
{
    std::shared_ptr<PlayerServer> server_ = std::make_shared<PlayerServer>();
    (void)server_->Init();
    server_->lastOpStatus_ = PLAYER_STATE_ERROR;
    EXPECT_EQ(false, server_->IsCompleted());
    EXPECT_EQ(false, server_->IsPrepared());
    EXPECT_EQ(false, server_->IsPlaying());

    server_->lastOpStatus_ = PLAYER_PLAYBACK_COMPLETE;
    EXPECT_EQ(true, server_->IsCompleted());
    EXPECT_EQ(false, server_->IsPrepared());
    EXPECT_EQ(false, server_->IsPlaying());

    server_->lastOpStatus_ = PLAYER_STARTED;
    EXPECT_EQ(false, server_->IsCompleted());
    EXPECT_EQ(false, server_->IsPrepared());
    EXPECT_EQ(true, server_->IsPlaying());
}

/**
 * @tc.name  : Test AddSubSource API
 * @tc.number: Player_AddSubSource_003
 * @tc.desc  : Test Player AddSubSource
 */
HWTEST_F(PlayerServerUnitTest, Player_AddSubSource_003, TestSize.Level0)
{
    std::shared_ptr<PlayerServer> server_ = std::make_shared<PlayerServer>();
    (void)server_->Init();
    server_->subtitleTrackNum_ = 10;
    EXPECT_NE(MSERR_OK, server_->AddSubSource(SUBTITLE_SRT_FIELE));
    EXPECT_NE(MSERR_OK, server_->AddSubSource(0, 0, 0));
}

/**
 * @tc.name  : Test AddSubSource API
 * @tc.number: Player_AddSubSource_004
 * @tc.desc  : Test Player AddSubSource invalid subtitleTrackNum
 */
HWTEST_F(PlayerServerUnitTest, Player_AddSubSource_004, TestSize.Level0)
{
    std::shared_ptr<PlayerServer> server = std::make_shared<PlayerServer>();
    ASSERT_EQ(MSERR_OK, server->SetSource(VIDEO_FILE1));
    server->subtitleTrackNum_ = 10;
    EXPECT_NE(MSERR_OK, server->AddSubSource(SUBTITLE_SRT_FIELE));
    EXPECT_NE(MSERR_OK, server->AddSubSource(0, 0, 0));
}

/**
 * @tc.name  : Test PrepareInReleasing API
 * @tc.number: Player_PrepareInReleasing_001
 * @tc.desc  : Test Player PrepareInReleasing
 */
HWTEST_F(PlayerServerUnitTest, Player_PrepareInReleasing_001, TestSize.Level0)
{
    std::shared_ptr<PlayerServer> server_ = std::make_shared<PlayerServer>();
    (void)server_->Init();
    ASSERT_EQ(MSERR_OK, server_->SetSource(VIDEO_FILE1));
    EXPECT_EQ(MSERR_OK, server_->Prepare());
    EXPECT_EQ(MSERR_OK, server_->Play());
    EXPECT_EQ(MSERR_OK, server_->Stop());
    server_->inReleasing_ = true;
    EXPECT_NE(MSERR_OK, server_->Prepare());
    EXPECT_NE(MSERR_OK, server_->PrepareAsync());
}

/**
 * @tc.name  : Test media error
 * @tc.number: Player_Media_Error_002
 * @tc.desc  : Test Player Media Error
 */
HWTEST_F(PlayerServerUnitTest, Player_Media_Error_002, TestSize.Level1)
{
    for (MediaServiceErrCode code = MSERR_IO_CANNOT_FIND_HOST; code <= MSERR_IO_UNSUPPORTTED_REQUEST;
        code = (MediaServiceErrCode)(code + 1)) {
        MediaServiceErrCodeTest(code);
    }
    MediaServiceErrCodeTest(MSERR_EXTEND_START);

    for (auto code = MSERR_EXT_API14_IO_CANNOT_FIND_HOST;
        code <= MSERR_EXT_API14_IO_UNSUPPORTTED_REQUEST; code = (MediaServiceExtErrCodeAPI9)(code + 1)) {
        EXPECT_EQ(MSEXTERRCODE_API9_INFOS.at(code), MSExtAVErrorToString(code));
        MediaServiceExtErrCodeAPI9Test(code);
    }
}

/**
 * @tc.name  : Test SetPlayRangeWithMode
 * @tc.number: Player_SetPlayRangeWithMode_001
 * @tc.desc  : Test Player SetPlayRangeWithMode interface
 */
HWTEST_F(PlayerServerUnitTest, Player_SetPlayRangeWithMode_001, TestSize.Level0)
{
    int32_t duration = 0;
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->SetPlayRange(0, 600));
    EXPECT_EQ(MSERR_OK, player_->PrepareAsync());
    EXPECT_EQ(MSERR_OK, player_->GetDuration(duration));
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_TRUE(player_->IsPlaying());
    EXPECT_EQ(MSERR_OK, player_->Pause());
    EXPECT_EQ(MSERR_OK, player_->SetPlayRangeWithMode(0, duration, SEEK_PREVIOUS_SYNC));
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_EQ(MSERR_OK, player_->Pause());
}

/**
 * @tc.name  : Test SetPlayRangeWithMode
 * @tc.number: Player_SetPlayRangeWithMode_002
 * @tc.desc  : Test Player SetPlayRangeWithMode interface
 */
HWTEST_F(PlayerServerUnitTest, Player_SetPlayRangeWithMode_002, TestSize.Level0)
{
    int32_t duration = 0;
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->PrepareAsync());
    EXPECT_EQ(MSERR_OK, player_->GetDuration(duration));
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_TRUE(player_->IsPlaying());
    EXPECT_EQ(MSERR_OK, player_->Pause());
    EXPECT_EQ(MSERR_OK, player_->SetPlayRangeWithMode(0, duration, SEEK_CLOSEST_SYNC));
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_EQ(MSERR_OK, player_->Pause());
}

/**
 * @tc.name  : Test SetPlayRangeWithMode
 * @tc.number: Player_SetPlayRangeWithMode_003
 * @tc.desc  : Test Player SetPlayRangeWithMode interface
 */
HWTEST_F(PlayerServerUnitTest, Player_SetPlayRangeWithMode_003, TestSize.Level0)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->SetPlayRangeWithMode(0, 600, SEEK_CONTINOUS));
    ASSERT_NE(MSERR_OK, player_->PrepareAsync());
    EXPECT_EQ(MSERR_INVALID_OPERATION, player_->Play());
    EXPECT_EQ(MSERR_INVALID_OPERATION, player_->Pause());
    EXPECT_EQ(MSERR_INVALID_OPERATION, player_->SetPlayRangeWithMode(0, 600, SEEK_CONTINOUS));
}

/**
 * @tc.name  : Test SetPlayRangeWithMode
 * @tc.number: Player_SetPlayRangeWithMode_004
 * @tc.desc  : Test Player SetPlayRangeWithMode interface
 */
HWTEST_F(PlayerServerUnitTest, Player_SetPlayRangeWithMode_004, TestSize.Level0)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->PrepareAsync());
    EXPECT_EQ(MSERR_OK, player_->SetPlayRangeWithMode(0, 600, SEEK_CONTINOUS));
}

/**
 * @tc.name  : Test InnerOnInfo
 * @tc.number: Player_InnerOnInfo_001
 * @tc.desc  : Test Player InnerOnInfo interface
 */
HWTEST_F(PlayerServerUnitTest, Player_InnerOnInfo_001, TestSize.Level0)
{
    std::shared_ptr<PlayerServer> server = std::make_shared<PlayerServer>();
    Format infoBody;
    PlayerOnInfoType type = INFO_TYPE_IS_LIVE_STREAM;
    server->InnerOnInfo(type, 0, infoBody, 0);
    EXPECT_EQ(server->isLiveStream_, true);
}

/**
 * @tc.name  : Test InnerOnInfo
 * @tc.number: Player_InnerOnInfo_002
 * @tc.desc  : Test Player InnerOnInfo interface
 */
HWTEST_F(PlayerServerUnitTest, Player_InnerOnInfo_002, TestSize.Level0)
{
    std::shared_ptr<PlayerServer> server = std::make_shared<PlayerServer>();
    Format infoBody;
    PlayerOnInfoType type = INFO_TYPE_DEFAULTTRACK;
    server->InnerOnInfo(type, 1, infoBody, 0);
    EXPECT_NE(server->isLiveStream_, true);
    type = INFO_TYPE_TRACK_DONE;
    server->InnerOnInfo(type, 1, infoBody, 0);
    EXPECT_NE(server->isLiveStream_, true);
    type = INFO_TYPE_ADD_SUBTITLE_DONE;
    server->InnerOnInfo(type, 1, infoBody, 0);
    EXPECT_NE(server->isLiveStream_, true);
}

/**
 * @tc.name  : Test InnerOnInfo
 * @tc.number: Player_InnerOnInfo_003
 * @tc.desc  : Test Player InnerOnInfo interface
 */
HWTEST_F(PlayerServerUnitTest, Player_InnerOnInfo_003, TestSize.Level0)
{
    std::shared_ptr<PlayerServer> server = std::make_shared<PlayerServer>();
    std::shared_ptr<PlayerCallbackTest> callback = std::make_shared<PlayerCallbackTest>();
    server->SetPlayerCallback(callback);
    Format infoBody;
    PlayerOnInfoType type = INFO_TYPE_SEEKDONE;
    server->InnerOnInfo(type, 0, infoBody, 0);
    EXPECT_EQ(callback->seekDoneFlag_, true);

    server->isBackgroundChanged_ = true;
    callback->seekDoneFlag_ = false;
    server->InnerOnInfo(type, 0, infoBody, 0);
    EXPECT_EQ(callback->seekDoneFlag_, true);

    type = INFO_TYPE_STATE_CHANGE;
    server->InnerOnInfo(type, 2, infoBody, 0);
    EXPECT_EQ(callback->state_, PLAYER_INITIALIZED);

    server->isBackgroundCb_ = true;
    server->isBackgroundChanged_ = true;
    server->InnerOnInfo(type, 1, infoBody, 0);
    EXPECT_FALSE(server->isBackgroundCb_);
}

/**
 * @tc.name  : Test GetStatusDescription
 * @tc.number: Player_GetStatusDescription_001
 * @tc.desc  : Test Player GetStatusDescription interface
 */
HWTEST_F(PlayerServerUnitTest, Player_GetStatusDescription_001, TestSize.Level0)
{
    std::shared_ptr<PlayerServer> server = std::make_shared<PlayerServer>();
    EXPECT_EQ(server->GetStatusDescription(-1), "PLAYER_STATUS_ILLEGAL");
    EXPECT_EQ(server->GetStatusDescription(10), "PLAYER_STATUS_ILLEGAL");
}

/**
 * @tc.name  : Test ChangeState
 * @tc.number: Player_ChangeState_001
 * @tc.desc  : Test Player ChangeState interface
 */
HWTEST_F(PlayerServerUnitTest, Player_ChangeState_001, TestSize.Level0)
{
    std::shared_ptr<PlayerServer> server = std::make_shared<PlayerServer>();
    std::shared_ptr<PlayerServerState> state = nullptr;
    server->ChangeState(state);
    EXPECT_EQ(server->currState_, state);
}

/**
 * @tc.name  : Test CheckSeek
 * @tc.number: Player_CheckSeek_001
 * @tc.desc  : Test Player CheckSeek interface
 */
HWTEST_F(PlayerServerUnitTest, Player_CheckSeek_001, TestSize.Level0)
{
    std::shared_ptr<PlayerServer> server = std::make_shared<PlayerServer>();
    server->SetSource(VIDEO_FILE1);
    server->lastOpStatus_ = PLAYER_PREPARING;
    PlayerSeekMode mode = SEEK_PREVIOUS_SYNC;
    server->isLiveStream_ = true;
    EXPECT_EQ(server->CheckSeek(0, mode), MSERR_INVALID_OPERATION);
}


/**
 * @tc.name  : Test SeekContinuous in prepared with seek -1
 * @tc.number: Player_SeekContinuous_007
 * @tc.desc  : Test Player SeekContinuous
 */
HWTEST_F(PlayerServerUnitTest, Player_SeekContinuous_007, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->PrepareAsync());
    for (int i = 0; i < 10; i++) {
        EXPECT_EQ(MSERR_OK, player_->SeekContinuous(i * 100));
        usleep(SEEK_CONTINUOUS_WAIT_US);
    }
    EXPECT_EQ(MSERR_OK, player_->SeekContinuous(-1));
    EXPECT_EQ(MSERR_OK, player_->Play());
}
 
/**
 * @tc.name  : Test SeekContinuous in playing with seek -1
 * @tc.number: Player_SeekContinuous_008
 * @tc.desc  : Test Player SeekContinuous
 */
HWTEST_F(PlayerServerUnitTest, Player_SeekContinuous_008, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->PrepareAsync());
    EXPECT_EQ(MSERR_OK, player_->Play());
    sleep(PLAYING_TIME_2_SEC);
    for (int i = 0; i < 30; i++) {
        EXPECT_EQ(MSERR_OK, player_->SeekContinuous(i * 100));
        usleep(SEEK_CONTINUOUS_WAIT_US);
    }
    EXPECT_EQ(MSERR_OK, player_->SeekContinuous(-1));
    EXPECT_EQ(MSERR_OK, player_->Stop());
}
 
/**
 * @tc.name  : Test SeekContinuous in paused with seek -1
 * @tc.number: Player_SeekContinuous_009
 * @tc.desc  : Test Player SeekContinuous
 */
HWTEST_F(PlayerServerUnitTest, Player_SeekContinuous_009, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->PrepareAsync());
    EXPECT_EQ(MSERR_OK, player_->Play());
    sleep(PLAYING_TIME_2_SEC);
    EXPECT_EQ(MSERR_OK, player_->Pause());
    for (int i = 0; i < 30; i++) {
        EXPECT_EQ(MSERR_OK, player_->SeekContinuous(i * 100));
        usleep(SEEK_CONTINUOUS_WAIT_US);
    }
    EXPECT_EQ(MSERR_OK, player_->SeekContinuous(-1));
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_EQ(MSERR_OK, player_->Stop());
}
 
/**
 * @tc.name  : Test SeekContinuous in completed with seek -1
 * @tc.number: Player_SeekContinuous_010
 * @tc.desc  : Test Player SeekContinuous
 */
HWTEST_F(PlayerServerUnitTest, Player_SeekContinuous_010, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->PrepareAsync());
    EXPECT_EQ(MSERR_OK, player_->Play());
    sleep(PLAYING_TIME_2_SEC);
    EXPECT_EQ(MSERR_OK, player_->Seek(9000, SEEK_PREVIOUS_SYNC));
    sleep(PLAYING_TIME_10_SEC);
    for (int i = 0; i < 30; i++) {
        EXPECT_EQ(MSERR_OK, player_->SeekContinuous(i * 100));
        usleep(SEEK_CONTINUOUS_WAIT_US);
    }
    EXPECT_EQ(MSERR_OK, player_->SeekContinuous(-1));
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_EQ(MSERR_OK, player_->Stop());
}
 
/**
 * @tc.name  : Test SeekContinuous backward with seek -1
 * @tc.number: Player_SeekContinuous_011
 * @tc.desc  : Test Player SeekContinuous
 */
HWTEST_F(PlayerServerUnitTest, Player_SeekContinuous_011, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->PrepareAsync());
    EXPECT_EQ(MSERR_OK, player_->Play());
    sleep(PLAYING_TIME_2_SEC);
    for (int i = 0; i < 30; i++) {
        EXPECT_EQ(MSERR_OK, player_->SeekContinuous(9000 - i * 100));
        usleep(SEEK_CONTINUOUS_WAIT_US);
    }
    EXPECT_EQ(MSERR_OK, player_->SeekContinuous(-1));
    EXPECT_EQ(MSERR_OK, player_->Stop());
}
 
/**
 * @tc.name  : Test SeekContinuous forward and backward with seek -1
 * @tc.number: Player_SeekContinuous_012
 * @tc.desc  : Test Player SeekContinuous
 */
HWTEST_F(PlayerServerUnitTest, Player_SeekContinuous_012, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->PrepareAsync());
    EXPECT_EQ(MSERR_OK, player_->Play());
    sleep(PLAYING_TIME_2_SEC);
    for (int i = 0; i < 30; i++) {
        EXPECT_EQ(MSERR_OK, player_->SeekContinuous(9000 - i * 100));
        usleep(SEEK_CONTINUOUS_WAIT_US);
    }
    for (int i = 0; i < 30; i++) {
        EXPECT_EQ(MSERR_OK, player_->SeekContinuous(9000 - i * 100));
        usleep(SEEK_CONTINUOUS_WAIT_US);
    }
    EXPECT_EQ(MSERR_OK, player_->SeekContinuous(-1));
    EXPECT_EQ(MSERR_OK, player_->Stop());
}
 
/**
 * @tc.name  : Test SeekContinuous in prepared mkv
 * @tc.number: Player_SeekContinuous_013
 * @tc.desc  : Test Player SeekContinuous
 */
HWTEST_F(PlayerServerUnitTest, Player_SeekContinuous_013, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE3));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->PrepareAsync());
    for (int i = 0; i < 10; i++) {
        EXPECT_EQ(MSERR_OK, player_->SeekContinuous(i * 100));
        usleep(SEEK_CONTINUOUS_WAIT_US);
    }
    EXPECT_EQ(MSERR_OK, player_->Play());
}
 
/**
 * @tc.name  : Test SeekContinuous in playing mkv
 * @tc.number: Player_SeekContinuous_014
 * @tc.desc  : Test Player SeekContinuous
 */
HWTEST_F(PlayerServerUnitTest, Player_SeekContinuous_014, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE3));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->PrepareAsync());
    EXPECT_EQ(MSERR_OK, player_->Play());
    sleep(PLAYING_TIME_2_SEC);
    for (int i = 0; i < 30; i++) {
        EXPECT_EQ(MSERR_OK, player_->SeekContinuous(i * 100));
        usleep(SEEK_CONTINUOUS_WAIT_US);
    }
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_EQ(MSERR_OK, player_->Stop());
}
 
/**
 * @tc.name  : Test SeekContinuous in paused mkv
 * @tc.number: Player_SeekContinuous_015
 * @tc.desc  : Test Player SeekContinuous
 */
HWTEST_F(PlayerServerUnitTest, Player_SeekContinuous_015, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE3));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->PrepareAsync());
    EXPECT_EQ(MSERR_OK, player_->Play());
    sleep(PLAYING_TIME_2_SEC);
    EXPECT_EQ(MSERR_OK, player_->Pause());
    for (int i = 0; i < 30; i++) {
        EXPECT_EQ(MSERR_OK, player_->SeekContinuous(i * 100));
        usleep(SEEK_CONTINUOUS_WAIT_US);
    }
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_EQ(MSERR_OK, player_->Stop());
}
 
/**
 * @tc.name  : Test SeekContinuous in completed mkv
 * @tc.number: Player_SeekContinuous_016
 * @tc.desc  : Test Player SeekContinuous
 */
HWTEST_F(PlayerServerUnitTest, Player_SeekContinuous_016, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE3));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->PrepareAsync());
    EXPECT_EQ(MSERR_OK, player_->Play());
    sleep(PLAYING_TIME_2_SEC);
    EXPECT_EQ(MSERR_OK, player_->Seek(9000, SEEK_PREVIOUS_SYNC));
    sleep(PLAYING_TIME_10_SEC);
    for (int i = 0; i < 30; i++) {
        EXPECT_EQ(MSERR_OK, player_->SeekContinuous(i * 100));
        usleep(SEEK_CONTINUOUS_WAIT_US);
    }
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_EQ(MSERR_OK, player_->Stop());
}
 
/**
 * @tc.name  : Test SeekContinuous backward
 * @tc.number: Player_SeekContinuous_017 mkv
 * @tc.desc  : Test Player SeekContinuous
 */
HWTEST_F(PlayerServerUnitTest, Player_SeekContinuous_017, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE3));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->PrepareAsync());
    EXPECT_EQ(MSERR_OK, player_->Play());
    sleep(PLAYING_TIME_2_SEC);
    for (int i = 0; i < 30; i++) {
        EXPECT_EQ(MSERR_OK, player_->SeekContinuous(9000 - i * 100));
        usleep(SEEK_CONTINUOUS_WAIT_US);
    }
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_EQ(MSERR_OK, player_->Stop());
}
 
/**
 * @tc.name  : Test SeekContinuous forward and backward mkv
 * @tc.number: Player_SeekContinuous_018
 * @tc.desc  : Test Player SeekContinuous
 */
HWTEST_F(PlayerServerUnitTest, Player_SeekContinuous_018, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE3));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->PrepareAsync());
    EXPECT_EQ(MSERR_OK, player_->Play());
    sleep(PLAYING_TIME_2_SEC);
    for (int i = 0; i < 30; i++) {
        EXPECT_EQ(MSERR_OK, player_->SeekContinuous(9000 - i * 100));
        usleep(SEEK_CONTINUOUS_WAIT_US);
    }
    for (int i = 0; i < 30; i++) {
        EXPECT_EQ(MSERR_OK, player_->SeekContinuous(9000 - i * 100));
        usleep(SEEK_CONTINUOUS_WAIT_US);
    }
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_EQ(MSERR_OK, player_->Stop());
}
 
/**
 * @tc.name  : Test SeekContinuous in prepared mkv with seek -1
 * @tc.number: Player_SeekContinuous_019
 * @tc.desc  : Test Player SeekContinuous
 */
HWTEST_F(PlayerServerUnitTest, Player_SeekContinuous_019, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE3));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->PrepareAsync());
    for (int i = 0; i < 10; i++) {
        EXPECT_EQ(MSERR_OK, player_->SeekContinuous(i * 100));
        usleep(SEEK_CONTINUOUS_WAIT_US);
    }
    EXPECT_EQ(MSERR_OK, player_->SeekContinuous(-1));
    EXPECT_EQ(MSERR_OK, player_->Play());
}
 
/**
 * @tc.name  : Test SeekContinuous in playing mkv with seek -1
 * @tc.number: Player_SeekContinuous_020
 * @tc.desc  : Test Player SeekContinuous
 */
HWTEST_F(PlayerServerUnitTest, Player_SeekContinuous_020, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE3));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->PrepareAsync());
    EXPECT_EQ(MSERR_OK, player_->Play());
    sleep(PLAYING_TIME_2_SEC);
    for (int i = 0; i < 30; i++) {
        EXPECT_EQ(MSERR_OK, player_->SeekContinuous(i * 100));
        usleep(SEEK_CONTINUOUS_WAIT_US);
    }
    EXPECT_EQ(MSERR_OK, player_->SeekContinuous(-1));
    EXPECT_EQ(MSERR_OK, player_->Stop());
}
 
/**
 * @tc.name  : Test SeekContinuous in paused mkv with seek -1
 * @tc.number: Player_SeekContinuous_021
 * @tc.desc  : Test Player SeekContinuous
 */
HWTEST_F(PlayerServerUnitTest, Player_SeekContinuous_021, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE3));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->PrepareAsync());
    EXPECT_EQ(MSERR_OK, player_->Play());
    sleep(PLAYING_TIME_2_SEC);
    EXPECT_EQ(MSERR_OK, player_->Pause());
    for (int i = 0; i < 30; i++) {
        EXPECT_EQ(MSERR_OK, player_->SeekContinuous(i * 100));
        usleep(SEEK_CONTINUOUS_WAIT_US);
    }
    EXPECT_EQ(MSERR_OK, player_->SeekContinuous(-1));
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_EQ(MSERR_OK, player_->Stop());
}
 
/**
 * @tc.name  : Test SeekContinuous in completed with seek -1
 * @tc.number: Player_SeekContinuous_022
 * @tc.desc  : Test Player SeekContinuous
 */
HWTEST_F(PlayerServerUnitTest, Player_SeekContinuous_022, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE3));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->PrepareAsync());
    EXPECT_EQ(MSERR_OK, player_->Play());
    sleep(PLAYING_TIME_2_SEC);
    EXPECT_EQ(MSERR_OK, player_->Seek(9000, SEEK_PREVIOUS_SYNC));
    sleep(PLAYING_TIME_10_SEC);
    for (int i = 0; i < 30; i++) {
        EXPECT_EQ(MSERR_OK, player_->SeekContinuous(i * 100));
        usleep(SEEK_CONTINUOUS_WAIT_US);
    }
    EXPECT_EQ(MSERR_OK, player_->SeekContinuous(-1));
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_EQ(MSERR_OK, player_->Stop());
}
 
/**
 * @tc.name  : Test SeekContinuous backward mkv with seek -1
 * @tc.number: Player_SeekContinuous_023
 * @tc.desc  : Test Player SeekContinuous
 */
HWTEST_F(PlayerServerUnitTest, Player_SeekContinuous_023, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE3));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->PrepareAsync());
    EXPECT_EQ(MSERR_OK, player_->Play());
    sleep(PLAYING_TIME_2_SEC);
    for (int i = 0; i < 30; i++) {
        EXPECT_EQ(MSERR_OK, player_->SeekContinuous(9000 - i * 100));
        usleep(SEEK_CONTINUOUS_WAIT_US);
    }
    EXPECT_EQ(MSERR_OK, player_->SeekContinuous(-1));
    EXPECT_EQ(MSERR_OK, player_->Stop());
}
 
/**
 * @tc.name  : Test SeekContinuous forward and backward mkv with seek -1
 * @tc.number: Player_SeekContinuous_024
 * @tc.desc  : Test Player SeekContinuous
 */
HWTEST_F(PlayerServerUnitTest, Player_SeekContinuous_024, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE3));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->PrepareAsync());
    EXPECT_EQ(MSERR_OK, player_->Play());
    sleep(PLAYING_TIME_2_SEC);
    for (int i = 0; i < 30; i++) {
        EXPECT_EQ(MSERR_OK, player_->SeekContinuous(9000 - i * 100));
        usleep(SEEK_CONTINUOUS_WAIT_US);
    }
    for (int i = 0; i < 30; i++) {
        EXPECT_EQ(MSERR_OK, player_->SeekContinuous(9000 - i * 100));
        usleep(SEEK_CONTINUOUS_WAIT_US);
    }
    EXPECT_EQ(MSERR_OK, player_->SeekContinuous(-1));
    EXPECT_EQ(MSERR_OK, player_->Stop());
}

/**
 * @tc.name  : Test EnableReportMediaProgress API
 * @tc.number: Player_EnableReportMediaProgress_001
 * @tc.desc  : Test Player EnableReportMediaProgress on before playing
 */
HWTEST_F(PlayerServerUnitTest, Player_EnableReportMediaProgress_001, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    EXPECT_EQ(MSERR_OK, player_->EnableReportMediaProgress(true));
    EXPECT_EQ(MSERR_OK, player_->Play());
}

/**
 * @tc.name  : Test EnableReportMediaProgress API
 * @tc.number: Player_EnableReportMediaProgress_002
 * @tc.desc  : Test Player EnableReportMediaProgress during playing
 */
HWTEST_F(PlayerServerUnitTest, Player_EnableReportMediaProgress_002, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_EQ(MSERR_OK, player_->EnableReportMediaProgress(true));
    EXPECT_EQ(MSERR_OK, player_->Pause());
    EXPECT_EQ(MSERR_OK, player_->Play());
    ASSERT_EQ(MSERR_OK, player_->EnableReportMediaProgress(false));
}

/**
 * @tc.name  : Test EnableReportMediaProgress API
 * @tc.number: Player_EnableReportMediaProgress_003
 * @tc.desc  : Test Player EnableReportMediaProgress when seek in playing
 */
HWTEST_F(PlayerServerUnitTest, Player_EnableReportMediaProgress_003, TestSize.Level1)
{
    int32_t duration = 0;
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_EQ(MSERR_OK, player_->GetDuration(duration));
    EXPECT_EQ(MSERR_OK, player_->Pause());
    EXPECT_EQ(MSERR_OK, player_->Seek(duration, SEEK_NEXT_SYNC));
    ASSERT_EQ(MSERR_OK, player_->EnableReportMediaProgress(true));
    EXPECT_EQ(MSERR_OK, player_->Play());
}

/**
 * @tc.name  : Test EnableReportMediaProgress API
 * @tc.number: Player_EnableReportMediaProgress_004
 * @tc.desc  : Test Player EnableReportMediaProgress when playing is looping
 */
HWTEST_F(PlayerServerUnitTest, Player_EnableReportMediaProgress_004, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    EXPECT_EQ(MSERR_OK, player_->SetLooping(true));
    EXPECT_EQ(true, player_->IsLooping());
    ASSERT_EQ(MSERR_OK, player_->EnableReportMediaProgress(true));
    EXPECT_EQ(MSERR_OK, player_->Play());
}

/**
 * @tc.name  : Test Freeze API
 * @tc.number: Player_Freeze_001
 * @tc.desc  : Test Player Freeze
 */
HWTEST_F(PlayerServerUnitTest, Player_Freeze_001, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    EXPECT_EQ(MSERR_OK, player_->Freeze());
}

/**
 * @tc.name  : Test Freeze API
 * @tc.number: Player_Freeze_002
 * @tc.desc  : Test Player Freeze
 */
HWTEST_F(PlayerServerUnitTest, Player_Freeze_002, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_EQ(MSERR_OK, player_->Freeze());
    sleep(1);
}

/**
 * @tc.name  : Test UnFreeze API
 * @tc.number: Player_UnFreeze_001
 * @tc.desc  : Test Player UnFreeze
 */
HWTEST_F(PlayerServerUnitTest, Player_UnFreeze_001, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    EXPECT_EQ(MSERR_OK, player_->UnFreeze());
}

/**
 * @tc.name  : Test Freeze API
 * @tc.number: Player_UnFreeze_002
 * @tc.desc  : Test Player UnFreeze
 */
HWTEST_F(PlayerServerUnitTest, Player_UnFreeze_002, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    sptr<Surface> videoSurface = player_->GetVideoSurface();
    ASSERT_NE(nullptr, videoSurface);
    EXPECT_EQ(MSERR_OK, player_->SetVideoSurface(videoSurface));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    EXPECT_EQ(MSERR_OK, player_->Play());
    EXPECT_EQ(MSERR_OK, player_->Freeze());
    sleep(1);
    EXPECT_EQ(MSERR_OK, player_->UnFreeze());
    sleep(1);
}

/**
 * @tc.name  : Test SetLoudnessGain API
 * @tc.number: Player_SetLoudnessGain_002
 * @tc.desc  : Test Player loudnessGain < -90.0 || loudnessGain > 24.0
 */
HWTEST_F(PlayerServerUnitTest, Player_SetLoudnessGain_001, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    ASSERT_EQ(MSERR_INVALID_OPERATION, player_->SetLoudnessGain(-90.1));
    ASSERT_EQ(MSERR_INVALID_OPERATION, player_->SetLoudnessGain(24.1));
}

/**
 * @tc.name  : Test SetLoudnessGain API
 * @tc.number: Player_SetLoudnessGain_002
 * @tc.desc  : Test Player state
 */
HWTEST_F(PlayerServerUnitTest, Player_SetLoudnessGain_002, TestSize.Level1)
{
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    ASSERT_EQ(MSERR_INVALID_OPERATION, player_->SetLoudnessGain(11.0));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    ASSERT_EQ(MSERR_OK, player_->SetLoudnessGain(12.0));
    EXPECT_EQ(MSERR_OK, player_->Play());
    ASSERT_EQ(MSERR_OK, player_->SetLoudnessGain(13.0));
    EXPECT_EQ(MSERR_OK, player_->Pause());
    ASSERT_EQ(MSERR_OK, player_->SetLoudnessGain(14.0));
    int32_t duration = 0;
    ASSERT_EQ(MSERR_OK, player_->GetDuration(duration));
    ASSERT_EQ(MSERR_OK, player_->Seek(duration, PlayerSeekMode::SEEK_NEXT_SYNC));
    ASSERT_EQ(MSERR_OK, player_->Play());
    sleep(1);
    ASSERT_EQ(false, player_->IsPlaying());
    ASSERT_EQ(PlayerStates::PLAYER_PLAYBACK_COMPLETE, player_->GetState());
    ASSERT_EQ(MSERR_OK, player_->SetLoudnessGain(15.0));
    EXPECT_EQ(MSERR_OK, player_->Stop());
    ASSERT_EQ(MSERR_OK, player_->SetLoudnessGain(16.0));
}

/**
 * @tc.name  : Test GetMediaDescription API
 * @tc.number: GetMediaDescription
 * @tc.desc  : Test Player state
 */
HWTEST_F(PlayerServerUnitTest, Player_GetMediaDescription_001, TestSize.Level1)
{
    Format format;
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    ASSERT_NE(MSERR_OK, player_->GetMediaDescription(format));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    ASSERT_EQ(MSERR_OK, player_->GetMediaDescription(format));
    EXPECT_EQ(MSERR_OK, player_->Play());
    ASSERT_EQ(MSERR_OK, player_->GetMediaDescription(format));
    EXPECT_EQ(MSERR_OK, player_->Pause());
    ASSERT_EQ(MSERR_OK, player_->GetMediaDescription(format));
    int32_t duration = 0;
    ASSERT_EQ(MSERR_OK, player_->GetDuration(duration));
    ASSERT_EQ(MSERR_OK, player_->Seek(duration, PlayerSeekMode::SEEK_NEXT_SYNC));
    ASSERT_EQ(MSERR_OK, player_->Play());
    sleep(1);
    ASSERT_EQ(false, player_->IsPlaying());
    ASSERT_EQ(PlayerStates::PLAYER_PLAYBACK_COMPLETE, player_->GetState());
    ASSERT_EQ(MSERR_OK, player_->GetMediaDescription(format));
    EXPECT_EQ(MSERR_OK, player_->Stop());
    ASSERT_EQ(MSERR_OK, player_->GetMediaDescription(format));
}

/**
 * @tc.name  : Test GetTrackDescription API
 * @tc.number: Player_GetTrackDescription_001
 * @tc.desc  : Test Player state
 */
HWTEST_F(PlayerServerUnitTest, Player_GetTrackDescription_001, TestSize.Level1)
{
    Format format;
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    ASSERT_NE(MSERR_OK, player_->GetTrackDescription(format, 0));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    ASSERT_EQ(MSERR_OK, player_->GetTrackDescription(format, 0));
    EXPECT_EQ(MSERR_OK, player_->Play());
    ASSERT_EQ(MSERR_OK, player_->GetTrackDescription(format, 0));
    ASSERT_NE(MSERR_OK, player_->GetTrackDescription(format, -2));
    EXPECT_EQ(MSERR_OK, player_->Pause());
    ASSERT_EQ(MSERR_OK, player_->GetTrackDescription(format, 0));
    int32_t duration = 0;
    ASSERT_EQ(MSERR_OK, player_->GetDuration(duration));
    ASSERT_EQ(MSERR_OK, player_->Seek(duration, PlayerSeekMode::SEEK_NEXT_SYNC));
    ASSERT_EQ(MSERR_OK, player_->Play());
    sleep(1);
    ASSERT_EQ(false, player_->IsPlaying());
    ASSERT_EQ(PlayerStates::PLAYER_PLAYBACK_COMPLETE, player_->GetState());
    ASSERT_EQ(MSERR_OK, player_->GetTrackDescription(format, 0));
    EXPECT_EQ(MSERR_OK, player_->Stop());
    ASSERT_EQ(MSERR_OK, player_->GetTrackDescription(format, 0));
}

/**
 * @tc.name  : Test GetCurrentPresentationTimestamp  API
 * @tc.number: Player_GetCurrentPresentationTimestamp _001
 * @tc.desc  : Test Player state
 */
HWTEST_F(PlayerServerUnitTest, Player_GetCurrentPresentationTimestamp _001, TestSize.Level1)
{
    int64_t currentPresentation;
    EXPECT_NE(MSERR_OK, player_->GetCurrentPresentationTimestamp(currentPresentation));
    ASSERT_EQ(MSERR_OK, player_->SetSource(VIDEO_FILE1));
    ASSERT_EQ(MSERR_OK, player_->GetCurrentPresentationTimestamp(currentPresentation));
    EXPECT_EQ(MSERR_OK, player_->Prepare());
    ASSERT_EQ(MSERR_OK, player_->GetCurrentPresentationTimestamp(currentPresentation));
    EXPECT_EQ(MSERR_OK, player_->Play());
    ASSERT_EQ(MSERR_OK, player_->GetCurrentPresentationTimestamp(currentPresentation));
    EXPECT_EQ(MSERR_OK, player_->Pause());
    ASSERT_EQ(MSERR_OK, player_->GetCurrentPresentationTimestamp(currentPresentation));
    int32_t duration = 0;
    ASSERT_EQ(MSERR_OK, player_->GetDuration(duration));
    ASSERT_EQ(MSERR_OK, player_->Seek(duration, PlayerSeekMode::SEEK_NEXT_SYNC));
    ASSERT_EQ(MSERR_OK, player_->Play());
    sleep(1);
    ASSERT_EQ(false, player_->IsPlaying());
    ASSERT_EQ(PlayerStates::PLAYER_PLAYBACK_COMPLETE, player_->GetState());
    ASSERT_EQ(MSERR_OK, player_->GetCurrentPresentationTimestamp(currentPresentation));
}

/**
 * @tc.name  : Test GetCurrentPresentationTimestamp  API
 * @tc.number: Player_GetCurrentPresentationTimestamp _002
 * @tc.desc  : Test Player state
 */
HWTEST_F(PlayerServerUnitTest, Player_GetCurrentPresentationTimestamp _002, TestSize.Level1)
{
    int64_t currentPresentation;
    std::shared_ptr<PlayerServer> server_ = std::make_shared<PlayerServer>();
    (void)server_->Init();
    server_->lastOpStatus_ = PLAYER_STATE_ERROR;
    EXPECT_NE(MSERR_OK, player_->GetCurrentPresentationTimestamp(currentPresentation));
}
} // namespace Media
} // namespace OHOS

/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "media_enum_napi.h"
#include <map>
#include <vector>
#include "media_log.h"
#include "media_errors.h"
#include "player.h"
#include "meta/video_types.h"
#include "recorder.h"
#include "avmetadatahelper.h"
#include "avcodec_common.h"
#include "recorder_profiles.h"
#include "av_common.h"
#include "mime_type.h"
#include "screen_capture.h"
#include "avscreen_capture_napi.h"

namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "MediaEnumNapi"};
}

namespace OHOS {
namespace Media {
struct JsEnumInt {
    std::string_view enumName;
    int32_t enumInt;
};

struct JsEnumString {
    std::string_view enumName;
    std::string_view enumString;
};

static const std::vector<struct JsEnumInt> g_mediaErrorCode = {
    { "MSERR_OK", MediaServiceExtErrCode::MSERR_EXT_OK },
    { "MSERR_NO_MEMORY", MediaServiceExtErrCode::MSERR_EXT_NO_MEMORY },
    { "MSERR_OPERATION_NOT_PERMIT", MediaServiceExtErrCode::MSERR_EXT_OPERATE_NOT_PERMIT },
    { "MSERR_INVALID_VAL", MediaServiceExtErrCode::MSERR_EXT_INVALID_VAL },
    { "MSERR_IO", MediaServiceExtErrCode::MSERR_EXT_IO },
    { "MSERR_TIMEOUT", MediaServiceExtErrCode::MSERR_EXT_TIMEOUT },
    { "MSERR_UNKNOWN", MediaServiceExtErrCode::MSERR_EXT_UNKNOWN },
    { "MSERR_SERVICE_DIED", MediaServiceExtErrCode::MSERR_EXT_SERVICE_DIED },
    { "MSERR_INVALID_STATE", MediaServiceExtErrCode::MSERR_EXT_INVALID_STATE },
    { "MSERR_UNSUPPORTED", MediaServiceExtErrCode::MSERR_EXT_UNSUPPORT },
};

static const std::vector<struct JsEnumInt> g_AVErrorCode = {
    { "AVERR_OK", MediaServiceExtErrCodeAPI9::MSERR_EXT_API9_OK },
    { "AVERR_NO_PERMISSION", MediaServiceExtErrCodeAPI9::MSERR_EXT_API9_NO_PERMISSION },
    { "AVERR_INVALID_PARAMETER", MediaServiceExtErrCodeAPI9::MSERR_EXT_API9_INVALID_PARAMETER },
    { "AVERR_UNSUPPORT_CAPABILITY", MediaServiceExtErrCodeAPI9::MSERR_EXT_API9_UNSUPPORT_CAPABILITY },
    { "AVERR_NO_MEMORY", MediaServiceExtErrCodeAPI9::MSERR_EXT_API9_NO_MEMORY },
    { "AVERR_OPERATE_NOT_PERMIT", MediaServiceExtErrCodeAPI9::MSERR_EXT_API9_OPERATE_NOT_PERMIT },
    { "AVERR_IO", MediaServiceExtErrCodeAPI9::MSERR_EXT_API9_IO },
    { "AVERR_TIMEOUT", MediaServiceExtErrCodeAPI9::MSERR_EXT_API9_TIMEOUT },
    { "AVERR_SERVICE_DIED", MediaServiceExtErrCodeAPI9::MSERR_EXT_API9_SERVICE_DIED },
    { "AVERR_UNSUPPORT_FORMAT", MediaServiceExtErrCodeAPI9::MSERR_EXT_API9_UNSUPPORT_FORMAT },
    { "AVERR_AUDIO_INTERRUPTED", MediaServiceExtErrCodeAPI9::MSERR_EXT_API9_AUDIO_INTERRUPTED},
};

static const std::vector<struct JsEnumInt> g_avDataSourceError = {
    { "SOURCE_ERROR_IO", MediaDataSourceError::SOURCE_ERROR_IO },
    { "SOURCE_ERROR_EOF", MediaDataSourceError::SOURCE_ERROR_EOF },
};

static const std::vector<struct JsEnumInt> g_bufferingInfoType = {
    { "BUFFERING_START", BufferingInfoType::BUFFERING_START },
    { "BUFFERING_END", BufferingInfoType::BUFFERING_END },
    { "BUFFERING_PERCENT", BufferingInfoType::BUFFERING_PERCENT },
    { "CACHED_DURATION", BufferingInfoType::CACHED_DURATION },
};

static const std::vector<struct JsEnumInt> g_recorderAudioEncoder = {
    { "DEFAULT", AudioCodecFormat::AUDIO_DEFAULT },
    { "AMR_NB", 1 }, // Provides implementation only
    { "AMR_WB", 2 }, // Provides implementation only
    { "AAC_LC", AudioCodecFormat::AAC_LC },
    { "HE_AAC", 4 }, // Provides implementation only
};

static const std::vector<struct JsEnumInt> g_recorderAudioOutputFormat = {
    { "DEFAULT", OutputFormatType::FORMAT_DEFAULT },
    { "MPEG_4", OutputFormatType::FORMAT_MPEG_4 },
    { "AMR_NB", 3 }, // Provides implementation only
    { "AMR_WB", 4 }, // Provides implementation only
    { "AAC_ADTS", OutputFormatType::FORMAT_M4A },
};

static const std::vector<struct JsEnumInt> g_playbackSpeed = {
    { "SPEED_FORWARD_0_75_X", PlaybackRateMode::SPEED_FORWARD_0_75_X },
    { "SPEED_FORWARD_1_00_X", PlaybackRateMode::SPEED_FORWARD_1_00_X },
    { "SPEED_FORWARD_1_25_X", PlaybackRateMode::SPEED_FORWARD_1_25_X },
    { "SPEED_FORWARD_1_75_X", PlaybackRateMode::SPEED_FORWARD_1_75_X },
    { "SPEED_FORWARD_2_00_X", PlaybackRateMode::SPEED_FORWARD_2_00_X },
    { "SPEED_FORWARD_0_50_X", PlaybackRateMode::SPEED_FORWARD_0_50_X },
    { "SPEED_FORWARD_1_50_X", PlaybackRateMode::SPEED_FORWARD_1_50_X },
    { "SPEED_FORWARD_0_25_X", PlaybackRateMode::SPEED_FORWARD_0_25_X },
    { "SPEED_FORWARD_0_125_X", PlaybackRateMode::SPEED_FORWARD_0_125_X },
};

static const std::vector<struct JsEnumInt> g_mediaType = {
    { "MEDIA_TYPE_AUD", MediaType::MEDIA_TYPE_AUD },
    { "MEDIA_TYPE_VID", MediaType::MEDIA_TYPE_VID },
    { "MEDIA_TYPE_SUBTITLE", MediaType::MEDIA_TYPE_SUBTITLE },
};

static const std::vector<struct JsEnumInt> g_videoRecorderQualityLevel = {
    { "RECORDER_QUALITY_LOW", VideoRecorderQualityLevel::RECORDER_QUALITY_LOW },
    { "RECORDER_QUALITY_HIGH", VideoRecorderQualityLevel::RECORDER_QUALITY_HIGH },
    { "RECORDER_QUALITY_QCIF", VideoRecorderQualityLevel::RECORDER_QUALITY_QCIF },
    { "RECORDER_QUALITY_CIF", VideoRecorderQualityLevel::RECORDER_QUALITY_CIF },
    { "RECORDER_QUALITY_480P", VideoRecorderQualityLevel::RECORDER_QUALITY_480P },
    { "RECORDER_QUALITY_720P", VideoRecorderQualityLevel::RECORDER_QUALITY_720P },
    { "RECORDER_QUALITY_1080P", VideoRecorderQualityLevel::RECORDER_QUALITY_1080P },
    { "RECORDER_QUALITY_QVGA", VideoRecorderQualityLevel::RECORDER_QUALITY_QVGA },
    { "RECORDER_QUALITY_2160P", VideoRecorderQualityLevel::RECORDER_QUALITY_2160P },
};

static const std::vector<struct JsEnumInt> g_audioSourceType = {
    { "AUDIO_SOURCE_TYPE_DEFAULT", AudioSourceType::AUDIO_SOURCE_DEFAULT },
    { "AUDIO_SOURCE_TYPE_MIC", AudioSourceType::AUDIO_MIC },
};

static const std::vector<struct JsEnumInt> g_videoSourceType = {
    { "VIDEO_SOURCE_TYPE_SURFACE_YUV", VideoSourceType::VIDEO_SOURCE_SURFACE_YUV },
    { "VIDEO_SOURCE_TYPE_SURFACE_ES", VideoSourceType::VIDEO_SOURCE_SURFACE_ES },
};

static const std::vector<struct JsEnumInt> g_frameFlags = {
    { "EOS_FRAME", AVCodecBufferFlag::AVCODEC_BUFFER_FLAG_EOS },
    { "SYNC_FRAME", AVCodecBufferFlag::AVCODEC_BUFFER_FLAG_SYNC_FRAME },
    { "PARTIAL_FRAME", AVCodecBufferFlag::AVCODEC_BUFFER_FLAG_PARTIAL_FRAME },
    { "CODEC_DATA", AVCodecBufferFlag::AVCODEC_BUFFER_FLAG_CODEC_DATA },
};

static const std::vector<struct JsEnumInt> g_hdrType = {
    { "AV_HDR_TYPE_NONE", HdrType::AV_HDR_TYPE_NONE },
    { "AV_HDR_TYPE_VIVID", HdrType::AV_HDR_TYPE_VIVID },
};

static const std::vector<struct JsEnumInt> g_seekMode = {
    { "SEEK_NEXT_SYNC", PlayerSeekMode::SEEK_NEXT_SYNC },
    { "SEEK_PREV_SYNC", PlayerSeekMode::SEEK_PREVIOUS_SYNC },
    { "SEEK_CLOSEST", 2 }, // 2 is consistent with the SeekMode defination in ohos.multimedia.media.d.ts.
    { "SEEK_CONTINUOUS", 3 }, // 3 is consistent with the SeekMode defination in ohos.multimedia.media.d.ts.
};

static const std::vector<struct JsEnumInt> g_switchMode = {
    { "SMOOTH", PlayerSwitchMode::SWITCH_SMOOTH },
    { "SEGMENT", PlayerSwitchMode::SWITCH_SEGMENT },
    { "CLOSEST", PlayerSwitchMode::SWITCH_CLOSEST },
};

static const std::vector<struct JsEnumInt> g_AVCodecType = {
    { "AVCODEC_TYPE_VIDEO_ENCODER", AVCodecType::AVCODEC_TYPE_VIDEO_ENCODER },
    { "AVCODEC_TYPE_VIDEO_DECODER", AVCodecType::AVCODEC_TYPE_VIDEO_DECODER },
    { "AVCODEC_TYPE_AUDIO_ENCODER", AVCodecType::AVCODEC_TYPE_AUDIO_ENCODER },
    { "AVCODEC_TYPE_AUDIO_DECODER", AVCodecType::AVCODEC_TYPE_AUDIO_DECODER },
};

static const std::vector<struct JsEnumInt> g_AACProfile = {
    { "AAC_PROFILE_LC", AACProfile::AAC_PROFILE_LC },
    { "AAC_PROFILE_ELD", AACProfile::AAC_PROFILE_ELD },
    { "AAC_PROFILE_ERLC", AACProfile::AAC_PROFILE_ERLC },
    { "AAC_PROFILE_HE", AACProfile::AAC_PROFILE_HE },
    { "AAC_PROFILE_HE_V2", AACProfile::AAC_PROFILE_HE_V2 },
    { "AAC_PROFILE_LD", AACProfile::AAC_PROFILE_LD },
    { "AAC_PROFILE_MAIN", AACProfile::AAC_PROFILE_MAIN },
};

static const std::vector<struct JsEnumInt> g_avImageQueryOptions = {
    { "AV_IMAGE_QUERY_NEXT_SYNC", AVMetadataQueryOption::AV_META_QUERY_NEXT_SYNC },
    { "AV_IMAGE_QUERY_PREVIOUS_SYNC", AVMetadataQueryOption::AV_META_QUERY_PREVIOUS_SYNC },
    { "AV_IMAGE_QUERY_CLOSEST_SYNC", AVMetadataQueryOption::AV_META_QUERY_CLOSEST_SYNC },
    { "AV_IMAGE_QUERY_CLOSEST", AVMetadataQueryOption::AV_META_QUERY_CLOSEST },
};

static const std::vector<struct JsEnumInt> g_pixelFormat = {
    { "RGB_565", 2 }, // PixelFormat::RGB_565
    { "RGBA_8888", 3 }, // PixelFormat::RGBA_8888
    { "RGB_888", 5 }, // PixelFormat::RGB_888
};

static const std::vector<struct JsEnumInt> g_videoEncodeBitrateMode = {
    { "CBR", VideoEncodeBitrateMode::CBR },
    { "VBR", VideoEncodeBitrateMode::VBR },
    { "CQ", VideoEncodeBitrateMode::CQ },
};

static const std::vector<struct JsEnumInt> g_videoPixelFormat = {
    { "YUVI420", VideoPixelFormat::YUVI420 },
    { "NV12", VideoPixelFormat::NV12 },
    { "NV21", VideoPixelFormat::NV21 },
    { "SURFACE_FORMAT", VideoPixelFormat::SURFACE_FORMAT },
    { "RGBA", VideoPixelFormat::RGBA },
};

static const std::vector<struct JsEnumInt> g_AVCProfile = {
    { "AVC_PROFILE_BASELINE", AVCProfile::AVC_PROFILE_BASELINE },
    { "AVC_PROFILE_CONSTRAINED_BASELINE", AVCProfile::AVC_PROFILE_CONSTRAINED_BASELINE },
    { "AVC_PROFILE_CONSTRAINED_HIGH", AVCProfile::AVC_PROFILE_CONSTRAINED_HIGH },
    { "AVC_PROFILE_EXTENDED", AVCProfile::AVC_PROFILE_EXTENDED },
    { "AVC_PROFILE_HIGH", AVCProfile::AVC_PROFILE_HIGH },
    { "AVC_PROFILE_HIGH_10", AVCProfile::AVC_PROFILE_HIGH_10 },
    { "AVC_PROFILE_HIGH_422", AVCProfile::AVC_PROFILE_HIGH_422 },
    { "AVC_PROFILE_HIGH_444", AVCProfile::AVC_PROFILE_HIGH_444 },
    { "AVC_PROFILE_MAIN", AVCProfile::AVC_PROFILE_MAIN },
};

static const std::vector<struct JsEnumInt> g_HEVCProfile = {
    { "HEVC_PROFILE_MAIN", HEVCProfile::HEVC_PROFILE_MAIN },
    { "HEVC_PROFILE_MAIN_10", HEVCProfile::HEVC_PROFILE_MAIN_10 },
    { "HEVC_PROFILE_MAIN_STILL", HEVCProfile::HEVC_PROFILE_MAIN_STILL },
};

static const std::vector<struct JsEnumInt> g_MPEG2Profile = {
    { "MPEG2_PROFILE_422", MPEG2Profile::MPEG2_PROFILE_422 },
    { "MPEG2_PROFILE_HIGH", MPEG2Profile::MPEG2_PROFILE_HIGH },
    { "MPEG2_PROFILE_MAIN", MPEG2Profile::MPEG2_PROFILE_MAIN },
    { "MPEG2_PROFILE_SNR", MPEG2Profile::MPEG2_PROFILE_SNR },
    { "MPEG2_PROFILE_SIMPLE", MPEG2Profile::MPEG2_PROFILE_SIMPLE },
    { "MPEG2_PROFILE_SPATIAL", MPEG2Profile::MPEG2_PROFILE_SPATIAL },
};

static const std::vector<struct JsEnumInt> g_MPEG4Profile = {
    { "MPEG4_PROFILE_ADVANCED_CODING", MPEG4Profile::MPEG4_PROFILE_ADVANCED_CODING },
    { "MPEG4_PROFILE_ADVANCED_CORE", MPEG4Profile::MPEG4_PROFILE_ADVANCED_CORE },
    { "MPEG4_PROFILE_ADVANCED_REAL_TIME", MPEG4Profile::MPEG4_PROFILE_ADVANCED_REAL_TIME },
    { "MPEG4_PROFILE_ADVANCED_SCALABLE", MPEG4Profile::MPEG4_PROFILE_ADVANCED_SCALABLE },
    { "MPEG4_PROFILE_ADVANCED_SIMPLE", MPEG4Profile::MPEG4_PROFILE_ADVANCED_SIMPLE },
    { "MPEG4_PROFILE_BASIC_ANIMATED", MPEG4Profile::MPEG4_PROFILE_BASIC_ANIMATED },
    { "MPEG4_PROFILE_CORE", MPEG4Profile::MPEG4_PROFILE_CORE },
    { "MPEG4_PROFILE_CORE_SCALABLE", MPEG4Profile::MPEG4_PROFILE_CORE_SCALABLE },
    { "MPEG4_PROFILE_HYBRID", MPEG4Profile::MPEG4_PROFILE_HYBRID },
    { "MPEG4_PROFILE_MAIN", MPEG4Profile::MPEG4_PROFILE_MAIN },
    { "MPEG4_PROFILE_NBIT", MPEG4Profile::MPEG4_PROFILE_NBIT },
    { "MPEG4_PROFILE_SCALABLE_TEXTURE", MPEG4Profile::MPEG4_PROFILE_SCALABLE_TEXTURE },
    { "MPEG4_PROFILE_SIMPLE", MPEG4Profile::MPEG4_PROFILE_SIMPLE },
    { "MPEG4_PROFILE_SIMPLE_FBA", MPEG4Profile::MPEG4_PROFILE_SIMPLE_FBA },
    { "MPEG4_PROFILE_SIMPLE_FACE", MPEG4Profile::MPEG4_PROFILE_SIMPLE_FACE },
    { "MPEG4_PROFILE_SIMPLE_SCALABLE", MPEG4Profile::MPEG4_PROFILE_SIMPLE_SCALABLE },
};

static const std::vector<struct JsEnumInt> g_H263Profile = {
    { "H263_PROFILE_BACKWARD_COMPATIBLE", H263Profile::H263_PROFILE_BACKWARD_COMPATIBLE },
    { "H263_PROFILE_BASELINE", H263Profile::H263_PROFILE_BASELINE },
    { "H263_PROFILE_H320_CODING", H263Profile::H263_PROFILE_H320_CODING },
    { "H263_PROFILE_HIGH_COMPRESSION", H263Profile::H263_PROFILE_HIGH_COMPRESSION },
    { "H263_PROFILE_HIGH_LATENCY", H263Profile::H263_PROFILE_HIGH_LATENCY },
    { "H263_PROFILE_ISW_V2", H263Profile::H263_PROFILE_ISW_V2 },
    { "H263_PROFILE_ISW_V3", H263Profile::H263_PROFILE_ISW_V3 },
    { "H263_PROFILE_INTERLACE", H263Profile::H263_PROFILE_INTERLACE },
    { "H263_PROFILE_INTERNET", H263Profile::H263_PROFILE_INTERNET },
};

static const std::vector<struct JsEnumInt> g_VP8Profile = {
    { "VP8_PROFILE_MAIN", VP8Profile::VP8_PROFILE_MAIN },
};

static const std::vector<struct JsEnumInt> g_VideoScaleType = {
    { "VIDEO_SCALE_TYPE_FIT", static_cast<int32_t>(Plugins::VideoScaleType::VIDEO_SCALE_TYPE_FIT) },
    { "VIDEO_SCALE_TYPE_FIT_CROP", static_cast<int32_t>(Plugins::VideoScaleType::VIDEO_SCALE_TYPE_FIT_CROP) },
};

static const std::vector<struct JsEnumInt> g_stateChangeReason = {
    { "USER", StateChangeReason::USER },
    { "BACKGROUND", StateChangeReason::BACKGROUND },
};

static const std::vector<struct JsEnumString> g_containerFormatType = {
    { "CFT_MPEG_4", ContainerFormatType::CFT_MPEG_4 },
    { "CFT_MPEG_4A", ContainerFormatType::CFT_MPEG_4A },
};

static const std::vector<struct JsEnumString> g_avMimeTypes = {
    { "APPLICATION_M3U8", "application/m3u8" },
};

static const std::vector<struct JsEnumString> g_codecMimeType = {
    { "VIDEO_H263", OHOS::Media::Plugins::MimeType::VIDEO_H263 },
    { "VIDEO_AVC", OHOS::Media::Plugins::MimeType::VIDEO_AVC },
    { "VIDEO_MPEG2", OHOS::Media::Plugins::MimeType::VIDEO_MPEG2 },
    { "VIDEO_HEVC", OHOS::Media::Plugins::MimeType::VIDEO_HEVC },
    { "VIDEO_MPEG4", OHOS::Media::Plugins::MimeType::VIDEO_MPEG4 },
    { "VIDEO_VP8", OHOS::Media::Plugins::MimeType::VIDEO_VP8 },
    { "VIDEO_VP9", OHOS::Media::Plugins::MimeType::VIDEO_VP9 },
    { "AUDIO_AMR_NB", OHOS::Media::Plugins::MimeType::AUDIO_AMR_NB },
    { "AUDIO_AMR_WB", OHOS::Media::Plugins::MimeType::AUDIO_AMR_WB },
    { "AUDIO_MPEG", OHOS::Media::Plugins::MimeType::AUDIO_MPEG },
    { "AUDIO_AAC", OHOS::Media::Plugins::MimeType::AUDIO_AAC },
    { "AUDIO_VORBIS", OHOS::Media::Plugins::MimeType::AUDIO_VORBIS },
    { "AUDIO_OPUS", OHOS::Media::Plugins::MimeType::AUDIO_OPUS },
    { "AUDIO_FLAC", OHOS::Media::Plugins::MimeType::AUDIO_FLAC },
    { "AUDIO_RAW", OHOS::Media::Plugins::MimeType::AUDIO_RAW },
};

static const std::vector<struct JsEnumString> g_mediaDescriptionKey = {
    { "MD_KEY_TRACK_INDEX", "track_index" },
    { "MD_KEY_TRACK_TYPE", "track_type" },
    { "MD_KEY_CODEC_MIME", "codec_mime" },
    { "MD_KEY_DURATION", "duration" },
    { "MD_KEY_BITRATE", "bitrate" },
    { "MD_KEY_MAX_INPUT_SIZE", "max_input_size" },
    { "MD_KEY_MAX_ENCODER_FPS", "max_encoder_fps" },
    { "MD_KEY_WIDTH", "width" },
    { "MD_KEY_HEIGHT", "height" },
    { "MD_KEY_PIXEL_FORMAT", "pixel_format" },
    { "MD_KEY_AUDIO_SAMPLE_FORMAT", "audio_sample_format" },
    { "MD_KEY_FRAME_RATE", "frame_rate" },
    { "MD_KEY_CAPTURE_RATE", "capture_rate" },
    { "MD_KEY_I_FRAME_INTERVAL", "i_frame_interval" },
    { "MD_KEY_REQUEST_I_FRAME", "req_i_frame" },
    { "MD_KEY_REPEAT_FRAME_AFTER", "repeat_frame_after" },
    { "MD_KEY_SUSPEND_INPUT_SURFACE", "suspend_input_surface" },
    { "MD_KEY_VIDEO_ENCODE_BITRATE_MODE", "video_encode_bitrate_mode" },
    { "MD_KEY_PROFILE", "codec_profile" },
    { "MD_KEY_QUALITY", "codec_quality" },
    { "MD_KEY_RECT_TOP", "rect_top" },
    { "MD_KEY_RECT_BOTTOM", "rect_bottom" },
    { "MD_KEY_RECT_LEFT", "rect_left" },
    { "MD_KEY_RECT_RIGHT", "rect_right" },
    { "MD_KEY_COLOR_STANDARD", "color_standard" },
    { "MD_KEY_AUD_CHANNEL_COUNT", "channel_count" },
    { "MD_KEY_AUD_SAMPLE_RATE", "sample_rate" },
    { "MD_KEY_CUSTOM", "vendor.custom" },
    { "MD_KEY_LANGUAGE", "language" },
    { "MD_KEY_AUD_SAMPLE_DEPTH", "sample_depth" },
};

static const std::vector<struct JsEnumInt> g_screenCaptureRecordPreset = {
    { "SCREEN_RECORD_PRESET_H264_AAC_MP4", AVScreenCaptureRecorderPreset::SCREEN_RECORD_PRESET_H264_AAC_MP4 },
    { "SCREEN_RECORD_PRESET_H265_AAC_MP4", AVScreenCaptureRecorderPreset::SCREEN_RECORD_PRESET_H265_AAC_MP4 }
};

static const std::vector<struct JsEnumInt> g_screenCaptureStateCode = {
    { "SCREENCAPTURE_STATE_STARTED", AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_STARTED },
    { "SCREENCAPTURE_STATE_CANCELED", AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_CANCELED },
    { "SCREENCAPTURE_STATE_STOPPED_BY_USER", AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_STOPPED_BY_USER },
    { "SCREENCAPTURE_STATE_INTERRUPTED_BY_OTHER", AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_INTERRUPTED_BY_OTHER },
    { "SCREENCAPTURE_STATE_STOPPED_BY_CALL", AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_STOPPED_BY_CALL },
    { "SCREENCAPTURE_STATE_MIC_UNAVAILABLE", AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_MIC_UNAVAILABLE },
    { "SCREENCAPTURE_STATE_MIC_MUTED_BY_USER", AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_MIC_MUTED_BY_USER },
    { "SCREENCAPTURE_STATE_MIC_UNMUTED_BY_USER", AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_MIC_UNMUTED_BY_USER },
    { "SCREENCAPTURE_STATE_ENTER_PRIVATE_SCENE", AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_ENTER_PRIVATE_SCENE },
    { "SCREENCAPTURE_STATE_EXIT_PRIVATE_SCENE", AVScreenCaptureStateCode::SCREEN_CAPTURE_STATE_EXIT_PRIVATE_SCENE },
};

static const std::map<std::string_view, const std::vector<struct JsEnumInt>&> g_intEnumClassMap = {
    { "AVErrorCode", g_AVErrorCode},
    { "MediaErrorCode", g_mediaErrorCode },
    { "AVDataSourceError", g_avDataSourceError },
    { "BufferingInfoType", g_bufferingInfoType },
    { "AudioEncoder", g_recorderAudioEncoder },
    { "AudioOutputFormat", g_recorderAudioOutputFormat },
    { "PlaybackSpeed", g_playbackSpeed },
    { "AVImageQueryOptions", g_avImageQueryOptions },
    { "PixelFormat", g_pixelFormat },
    { "MediaType", g_mediaType },
    { "VideoRecorderQualityLevel", g_videoRecorderQualityLevel },
    { "AudioSourceType", g_audioSourceType },
    { "VideoSourceType", g_videoSourceType },
    { "FrameFlags", g_frameFlags },
    { "HdrType", g_hdrType},
    { "SeekMode", g_seekMode },
    { "SwitchMode", g_switchMode },
    { "AVCodecType", g_AVCodecType },
    { "AACProfile", g_AACProfile },
    { "VideoEncodeBitrateMode", g_videoEncodeBitrateMode },
    { "VideoPixelFormat", g_videoPixelFormat },
    { "AVCProfile", g_AVCProfile },
    { "HEVCProfile", g_HEVCProfile },
    { "MPEG2Profile", g_MPEG2Profile },
    { "MPEG4Profile", g_MPEG4Profile },
    { "H263Profile", g_H263Profile},
    { "VP8Profile", g_VP8Profile },
    { "VideoScaleType", g_VideoScaleType},
    { "StateChangeReason", g_stateChangeReason},
    { "AVScreenCaptureRecordPreset", g_screenCaptureRecordPreset},
    { "AVScreenCaptureStateCode", g_screenCaptureStateCode},
};

static const std::map<std::string_view, const std::vector<struct JsEnumString>&> g_stringEnumClassMap = {
    { "MediaDescriptionKey", g_mediaDescriptionKey },
    { "ContainerFormatType", g_containerFormatType },
    { "CodecMimeType", g_codecMimeType },
    { "AVMimeTypes", g_avMimeTypes },
};

napi_value MediaEnumNapi::JsEnumIntInit(napi_env env, napi_value exports)
{
    for (auto it = g_intEnumClassMap.begin(); it != g_intEnumClassMap.end(); it++) {
        auto &enumClassName = it->first;
        auto &enumItemVec = it->second;
        int32_t vecSize = enumItemVec.size();
        std::vector<napi_value> value;
        value.resize(vecSize);
        for (int32_t index = 0; index < vecSize; ++index) {
            napi_create_int32(env, enumItemVec[index].enumInt, &value[index]);
        }

        std::vector<napi_property_descriptor> property;
        property.resize(vecSize);
        for (int32_t index = 0; index < vecSize; ++index) {
            property[index] = napi_property_descriptor DECLARE_NAPI_STATIC_PROPERTY(
                enumItemVec[index].enumName.data(), value[index]);
        }

        auto napiConstructor = [](napi_env env, napi_callback_info info) {
            napi_value jsThis = nullptr;
            napi_get_cb_info(env, info, nullptr, nullptr, &jsThis, nullptr);
            return jsThis;
        };

        napi_value result = nullptr;
        napi_status napiStatus = napi_define_class(env, enumClassName.data(), NAPI_AUTO_LENGTH, napiConstructor,
            nullptr, property.size(), property.data(), &result);
        CHECK_AND_RETURN_RET_LOG(napiStatus == napi_ok, nullptr, "Failed to define enum");

        napiStatus = napi_set_named_property(env, exports, enumClassName.data(), result);
        CHECK_AND_RETURN_RET_LOG(napiStatus == napi_ok, nullptr, "Failed to set result");
    }
    return exports;
}

napi_value MediaEnumNapi::JsEnumStringInit(napi_env env, napi_value exports)
{
    for (auto it = g_stringEnumClassMap.begin(); it != g_stringEnumClassMap.end(); it++) {
        auto &enumType = it->first;
        auto &enumValue = it->second;
        int32_t vecSize = enumValue.size();
        std::vector<napi_value> value;
        value.resize(vecSize);
        for (int32_t index = 0; index < vecSize; ++index) {
            napi_create_string_utf8(env, enumValue[index].enumString.data(), NAPI_AUTO_LENGTH, &value[index]);
        }

        std::vector<napi_property_descriptor> property;
        property.resize(vecSize);
        for (int32_t index = 0; index < vecSize; ++index) {
            property[index] = napi_property_descriptor DECLARE_NAPI_STATIC_PROPERTY(
                enumValue[index].enumName.data(), value[index]);
        }

        auto constructor = [](napi_env env, napi_callback_info info) {
            napi_value jsThis = nullptr;
            napi_get_cb_info(env, info, nullptr, nullptr, &jsThis, nullptr);
            return jsThis;
        };

        napi_value result = nullptr;
        napi_status status = napi_define_class(env, enumType.data(), NAPI_AUTO_LENGTH, constructor,
            nullptr, property.size(), property.data(), &result);
        CHECK_AND_RETURN_RET_LOG(status == napi_ok, nullptr, "Failed to define enum");

        status = napi_set_named_property(env, exports, enumType.data(), result);
        CHECK_AND_RETURN_RET_LOG(status == napi_ok, nullptr, "Failed to set result");
    }
    return exports;
}

napi_value MediaEnumNapi::Init(napi_env env, napi_value exports)
{
    JsEnumIntInit(env, exports);
    JsEnumStringInit(env, exports);
    return exports;
}
} // namespace Media
} // namespace OHOS
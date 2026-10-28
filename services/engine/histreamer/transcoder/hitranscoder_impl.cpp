/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy  of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "hitranscoder_impl.h"
#include "sync_fence.h"
#include <algorithm>
#include <sys/syscall.h>
#include <vector>
#include "directory_ex.h"
#include "osal/task/jobutils.h"
#include "osal/task/task.h"
#include "media_utils.h"
#include "media_dfx.h"
#include "meta/video_types.h"
#include "meta/any.h"
#include "common/log.h"
#include "avcodec_info.h"
#include "osal/task/pipeline_threadpool.h"
#include "surface/native_buffer.h"
#include "water_mark_filter.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_DOMAIN_SYSTEM_PLAYER, "HiTransCoder" };
constexpr int32_t REPORT_PROGRESS_INTERVAL = 100;
constexpr int32_t TRANSCODER_COMPLETE_PROGRESS = 100;
constexpr int32_t MINIMUM_WIDTH_HEIGHT = 240;
constexpr int32_t HEIGHT_480 = 480;
constexpr int32_t HEIGHT_720 = 720;
constexpr int32_t HEIGHT_1080 = 1080;
constexpr int32_t VIDEO_BITRATE_1M = 1024 * 1024;
constexpr int32_t VIDEO_BITRATE_2M = 2 * VIDEO_BITRATE_1M;
constexpr int32_t VIDEO_BITRATE_4M = 4 * VIDEO_BITRATE_1M;
constexpr int32_t VIDEO_BITRATE_8M = 8 * VIDEO_BITRATE_1M;
constexpr int32_t INVALID_AUDIO_BITRATE = INT32_MAX; // Invalid value defined in the napi and capi.
constexpr int32_t DEFAULT_AUDIO_BITRATE = 48000;
const uint32_t ROTATE_90_VALUE = 90;
const uint32_t ROTATE_180_VALUE = 180;
const uint32_t ROTATE_270_VALUE = 270;
constexpr uint32_t MAX_SQR_FACTOR = 51;

// HDR 色彩空间集合，IsHdrColorSpace 据此判定是否 HDR 输出。
const std::vector<int32_t> HDR_COLOR_SPACES = {
    static_cast<int32_t>(OH_NativeBuffer_ColorSpace::OH_COLORSPACE_BT2020_HLG_FULL),
    static_cast<int32_t>(OH_NativeBuffer_ColorSpace::OH_COLORSPACE_BT2020_HLG_LIMIT),
    static_cast<int32_t>(OH_NativeBuffer_ColorSpace::OH_COLORSPACE_BT2020_PQ_FULL),
    static_cast<int32_t>(OH_NativeBuffer_ColorSpace::OH_COLORSPACE_BT2020_PQ_LIMIT),
    static_cast<int32_t>(OH_NativeBuffer_ColorSpace::OH_COLORSPACE_P3_HLG_FULL),
    static_cast<int32_t>(OH_NativeBuffer_ColorSpace::OH_COLORSPACE_P3_HLG_LIMIT),
    static_cast<int32_t>(OH_NativeBuffer_ColorSpace::OH_COLORSPACE_P3_PQ_FULL),
    static_cast<int32_t>(OH_NativeBuffer_ColorSpace::OH_COLORSPACE_P3_PQ_LIMIT),
};

bool IsHdrColorSpace(int32_t colorSpace)
{
    return std::find(HDR_COLOR_SPACES.begin(), HDR_COLOR_SPACES.end(), colorSpace) != HDR_COLOR_SPACES.end();
}
}

namespace OHOS {
namespace Media {
namespace {
// 色彩空间 -> 编码器色彩四元组映射，用于显式 HDR 色彩空间分支的表驱动配置。
struct HdrColorSpaceMapping {
    int32_t colorSpace;
    Plugins::ColorPrimary primaries;
    Plugins::TransferCharacteristic transfer;
    bool isFullRange;
};

// BT2020/P3 系列统一使用 BT2020_NCL 矩阵系数，仅 primaries/transfer/range 随色彩空间变化。
const std::vector<HdrColorSpaceMapping> HDR_COLOR_SPACE_TABLE = {
    { static_cast<int32_t>(OH_NativeBuffer_ColorSpace::OH_COLORSPACE_BT2020_HLG_LIMIT),
      Plugins::ColorPrimary::BT2020, Plugins::TransferCharacteristic::HLG, false },
    { static_cast<int32_t>(OH_NativeBuffer_ColorSpace::OH_COLORSPACE_BT2020_HLG_FULL),
      Plugins::ColorPrimary::BT2020, Plugins::TransferCharacteristic::HLG, true },
    { static_cast<int32_t>(OH_NativeBuffer_ColorSpace::OH_COLORSPACE_BT2020_PQ_LIMIT),
      Plugins::ColorPrimary::BT2020, Plugins::TransferCharacteristic::PQ, false },
    { static_cast<int32_t>(OH_NativeBuffer_ColorSpace::OH_COLORSPACE_BT2020_PQ_FULL),
      Plugins::ColorPrimary::BT2020, Plugins::TransferCharacteristic::PQ, true },
    { static_cast<int32_t>(OH_NativeBuffer_ColorSpace::OH_COLORSPACE_P3_HLG_LIMIT),
      Plugins::ColorPrimary::P3D65, Plugins::TransferCharacteristic::HLG, false },
    { static_cast<int32_t>(OH_NativeBuffer_ColorSpace::OH_COLORSPACE_P3_HLG_FULL),
      Plugins::ColorPrimary::P3D65, Plugins::TransferCharacteristic::HLG, true },
    { static_cast<int32_t>(OH_NativeBuffer_ColorSpace::OH_COLORSPACE_P3_PQ_LIMIT),
      Plugins::ColorPrimary::P3D65, Plugins::TransferCharacteristic::PQ, false },
    { static_cast<int32_t>(OH_NativeBuffer_ColorSpace::OH_COLORSPACE_P3_PQ_FULL),
      Plugins::ColorPrimary::P3D65, Plugins::TransferCharacteristic::PQ, true },
};

const HdrColorSpaceMapping* FindHdrColorSpaceMapping(int32_t colorSpace)
{
    for (const auto& item : HDR_COLOR_SPACE_TABLE) {
        if (item.colorSpace == colorSpace) {
            return &item;
        }
    }
    return nullptr;
}

// 根据编码器色彩四元组反向推导 OH_NativeBuffer_ColorSpace，供 AUTO_HDR_VIVID 分支回写
// AV_TRANSCODER_DST_COLOR_SPACE，使 decoder filter 据此跳过 VPE 色彩转换。
int32_t DeriveColorSpaceFromAspects(Plugins::ColorPrimary primaries,
    Plugins::TransferCharacteristic transfer, bool isFullRange)
{
    constexpr int32_t DEFAULT_COLOR_SPACE =
        static_cast<int32_t>(OH_NativeBuffer_ColorSpace::OH_COLORSPACE_BT2020_HLG_LIMIT);
    bool isBt2020 = (primaries == Plugins::ColorPrimary::BT2020 ||
                     primaries == Plugins::ColorPrimary::UNSPECIFIED);
    bool isP3 = (primaries == Plugins::ColorPrimary::P3DCI ||
                 primaries == Plugins::ColorPrimary::P3D65);
    bool isPq = (transfer == Plugins::TransferCharacteristic::PQ);

    if (isBt2020) {
        return isPq
            ? (isFullRange ? static_cast<int32_t>(OH_NativeBuffer_ColorSpace::OH_COLORSPACE_BT2020_PQ_FULL)
                           : static_cast<int32_t>(OH_NativeBuffer_ColorSpace::OH_COLORSPACE_BT2020_PQ_LIMIT))
            : (isFullRange ? static_cast<int32_t>(OH_NativeBuffer_ColorSpace::OH_COLORSPACE_BT2020_HLG_FULL)
                           : static_cast<int32_t>(OH_NativeBuffer_ColorSpace::OH_COLORSPACE_BT2020_HLG_LIMIT));
    }
    if (isP3) {
        return isPq
            ? (isFullRange ? static_cast<int32_t>(OH_NativeBuffer_ColorSpace::OH_COLORSPACE_P3_PQ_FULL)
                           : static_cast<int32_t>(OH_NativeBuffer_ColorSpace::OH_COLORSPACE_P3_PQ_LIMIT))
            : (isFullRange ? static_cast<int32_t>(OH_NativeBuffer_ColorSpace::OH_COLORSPACE_P3_HLG_FULL)
                           : static_cast<int32_t>(OH_NativeBuffer_ColorSpace::OH_COLORSPACE_P3_HLG_LIMIT));
    }
    return DEFAULT_COLOR_SPACE;
}
} // namespace

static const std::unordered_set<std::string> AVMETA_KEY = {
    { Tag::MEDIA_ALBUM },
    { Tag::MEDIA_ALBUM_ARTIST },
    { Tag::MEDIA_ARTIST },
    { Tag::MEDIA_AUTHOR },
    { Tag::MEDIA_COMPOSER },
    { Tag::MEDIA_DATE },
    { Tag::MEDIA_CREATION_TIME },
    { Tag::MEDIA_DURATION },
    { Tag::MEDIA_GENRE },
    { Tag::MIME_TYPE },
    { Tag::AUDIO_SAMPLE_RATE },
    { Tag::MEDIA_TITLE },
    { Tag::VIDEO_HEIGHT },
    { Tag::VIDEO_WIDTH },
    { Tag::VIDEO_FRAME_RATE },
    { Tag::VIDEO_ROTATION },
    { Tag::VIDEO_IS_HDR_VIVID },
    { Tag::MEDIA_LONGITUDE },
    { Tag::MEDIA_LATITUDE },
    { Tag::MEDIA_BITRATE },
    { Tag::AUDIO_CHANNEL_COUNT },
    { Tag::AUDIO_SAMPLE_FORMAT },
    { Tag::AUDIO_BITS_PER_CODED_SAMPLE },
    { Tag::AUDIO_BITS_PER_RAW_SAMPLE },
    { Tag::MEDIA_AIGC },
    { "customInfo" },
};

static const std::unordered_set<Plugins::VideoEncodeBitrateMode> VIDEO_BITRATE_MODES = {
    Plugins::VideoEncodeBitrateMode::SQR,
    Plugins::VideoEncodeBitrateMode::VBR
};
class TransCoderEventReceiver : public Pipeline::EventReceiver {
public:
    explicit TransCoderEventReceiver(HiTransCoderImpl *hiTransCoderImpl, std::string transcoderId)
    {
        MEDIA_LOG_I("TransCoderEventReceiver ctor called.");
        std::unique_lock<std::shared_mutex> lk(cbMutex_);
        hiTransCoderImpl_ = hiTransCoderImpl;
        task_ = std::make_unique<Task>("TransCoderEventReceiver", transcoderId, TaskType::GLOBAL,
            OHOS::Media::TaskPriority::HIGH, false);
    }

    void OnEvent(const Event &event) override
    {
        MEDIA_LOG_D("TransCoderEventReceiver OnEvent");
        FALSE_RETURN_MSG(task_ != nullptr, "task_ is nullptr");
        task_->SubmitJobOnce([this, event] {
            std::shared_lock<std::shared_mutex> lk(cbMutex_);
            FALSE_RETURN(hiTransCoderImpl_ != nullptr);
            hiTransCoderImpl_->OnEvent(event);
        });
    }

    void NotifyRelease() override
    {
        MEDIA_LOG_D("TransCoderEventReceiver NotifyRelease.");
        std::unique_lock<std::shared_mutex> lk(cbMutex_);
        hiTransCoderImpl_ = nullptr;
    }

private:
    std::shared_mutex cbMutex_ {};
    HiTransCoderImpl *hiTransCoderImpl_;
    std::unique_ptr<Task> task_;
};

class TransCoderFilterCallback : public Pipeline::FilterCallback {
public:
    explicit TransCoderFilterCallback(HiTransCoderImpl *hiTransCoderImpl)
    {
        MEDIA_LOG_I("TransCoderFilterCallback ctor called");
        std::unique_lock<std::shared_mutex> lk(cbMutex_);
        hiTransCoderImpl_ = hiTransCoderImpl;
    }

    Status OnCallback(const std::shared_ptr<Pipeline::Filter>& filter, Pipeline::FilterCallBackCommand cmd,
        Pipeline::StreamType outType) override
    {
        std::shared_lock<std::shared_mutex> lk(cbMutex_);
        FALSE_RETURN_V(hiTransCoderImpl_ != nullptr, Status::OK); // hiTransCoderImpl_ is destructed
        return hiTransCoderImpl_->OnCallback(filter, cmd, outType);
    }

    void NotifyRelease() override
    {
        MEDIA_LOG_D("PlayerEventReceiver NotifyRelease.");
        std::unique_lock<std::shared_mutex> lk(cbMutex_);
        hiTransCoderImpl_ = nullptr;
    }

private:
    std::shared_mutex cbMutex_ {};
    HiTransCoderImpl *hiTransCoderImpl_;
};

HiTransCoderImpl::HiTransCoderImpl(int32_t appUid, int32_t appPid, uint32_t appTokenId, uint64_t appFullTokenId)
    : appUid_(appUid), appPid_(appPid), appTokenId_(appTokenId), appFullTokenId_(appFullTokenId)
{
    MEDIA_LOG_I("HiTransCoderImpl");
    pipeline_ = std::make_shared<Pipeline::Pipeline>();
    transCoderId_ = std::string("Trans_") + std::to_string(OHOS::Media::Pipeline::Pipeline::GetNextPipelineId());
}

HiTransCoderImpl::~HiTransCoderImpl()
{
    if (demuxerFilter_) {
        pipeline_->RemoveHeadFilter(demuxerFilter_);
    }
    if (transCoderEventReceiver_ != nullptr) {
        transCoderEventReceiver_->NotifyRelease();
    }
    if (transCoderFilterCallback_ != nullptr) {
        transCoderFilterCallback_->NotifyRelease();
    }
    PipeLineThreadPool::GetInstance().DestroyThread(transCoderId_);
    MEDIA_LOG_I("~HiTransCoderImpl");
}


void HiTransCoderImpl::SetInstanceId(uint64_t instanceId)
{
    instanceId_ = instanceId;
}

int32_t HiTransCoderImpl::Init()
{
    MEDIA_LOG_I("HiTransCoderImpl::Init()");
    MediaTrace trace("HiTransCoderImpl::Init()");
    transCoderEventReceiver_ = std::make_shared<TransCoderEventReceiver>(this, transCoderId_);
    transCoderFilterCallback_ = std::make_shared<TransCoderFilterCallback>(this);
    FALSE_RETURN_V_MSG_E(transCoderEventReceiver_ != nullptr && transCoderFilterCallback_ != nullptr,
        static_cast<int32_t>(Status::ERROR_NO_MEMORY), "fail to init hiTransCoderImpl");
    pipeline_->Init(transCoderEventReceiver_, transCoderFilterCallback_, transCoderId_);
    callbackLooper_ = std::make_shared<HiTransCoderCallbackLooper>();
    FALSE_RETURN_V_MSG_E(callbackLooper_ != nullptr, static_cast<int32_t>(Status::ERROR_NO_MEMORY),
        "fail to create callbackLooper");
    callbackLooper_->SetTransCoderEngine(this, transCoderId_);
    return static_cast<int32_t>(Status::OK);
}

int32_t HiTransCoderImpl::GetRealPath(const std::string &url, std::string &realUrlPath) const
{
    std::string fileHead = "file://";
    std::string tempUrlPath;

    if (url.find(fileHead) == 0 && url.size() > fileHead.size()) {
        tempUrlPath = url.substr(fileHead.size());
    } else {
        tempUrlPath = url;
    }
    FALSE_RETURN_V_MSG_E(tempUrlPath.find("..") == std::string::npos, MSERR_FILE_ACCESS_FAILED,
        "invalid url. The Url (%{private}s) path may be invalid.", tempUrlPath.c_str());
    bool ret = PathToRealPath(tempUrlPath, realUrlPath);
    FALSE_RETURN_V_MSG_E(ret, MSERR_OPEN_FILE_FAILED, "invalid url. The Url (%{private}s) path may be invalid.",
        url.c_str());
    FALSE_RETURN_V(access(realUrlPath.c_str(), R_OK) == 0, MSERR_FILE_ACCESS_FAILED);
    return MSERR_OK;
}

int32_t HiTransCoderImpl::SetInputFile(const std::string &url)
{
    MEDIA_LOG_I("HiTransCoderImpl::SetInputFile()");
    MediaTrace trace("HiTransCoderImpl::SetInputFile()");
    inputFile_ = url;
    if (url.find("://") == std::string::npos || url.find("file://") == 0) {
        std::string realUriPath;
        int32_t result = GetRealPath(url, realUriPath);
        FALSE_RETURN_V_MSG_E(result == MSERR_OK, result, "SetInputFile error: GetRealPath error");
        inputFile_ = "file://" + realUriPath;
    }
    if (demuxerFilter_ != nullptr) {
        MEDIA_LOG_I("Remove old demuxerFilter_ before creating new one");
        pipeline_->RemoveHeadFilter(demuxerFilter_);
        demuxerFilter_ = nullptr;
    }
    std::shared_ptr<MediaSource> mediaSource = std::make_shared<MediaSource>(inputFile_);
    demuxerFilter_ = Pipeline::FilterFactory::Instance().CreateFilter<Pipeline::DemuxerFilter>("builtin.player.demuxer",
        Pipeline::FilterType::FILTERTYPE_DEMUXER);
    if (demuxerFilter_ == nullptr) {
        MEDIA_LOG_E("demuxerFilter_ is nullptr");
        return MSERR_NO_MEMORY;
    }
    pipeline_->AddHeadFilters({demuxerFilter_});
    demuxerFilter_->Init(transCoderEventReceiver_, transCoderFilterCallback_);
    (void)demuxerFilter_->SetTranscoderMode();
    int32_t ret = TransTranscoderStatus(demuxerFilter_->SetDataSource(mediaSource));
    if (ret != MSERR_OK) {
        MEDIA_LOG_E("SetInputFile error: demuxerFilter_->SetDataSource error");
        CollectionErrorInfo(ret, "SetInputFile error");
        OnEvent({"TranscoderEngine", EventType::EVENT_ERROR, static_cast<int32_t>(MSERR_SET_INPUT_DATA_SOURCE_FAILED)});
        if (demuxerFilter_ != nullptr) {
            pipeline_->RemoveHeadFilter(demuxerFilter_);
            demuxerFilter_ = nullptr;
        }
        return ret;
    }
    int64_t duration = 0;
    if (demuxerFilter_->GetDuration(duration)) {
        durationMs_ = Plugins::HstTime2Us(duration);
    } else {
        MEDIA_LOG_E("Get media duration failed");
    }
    ret = TransTranscoderStatus(ConfigureVideoAudioMetaData());
    CreateMediaInfo(CallType::AVTRANSCODER, appUid_, instanceId_);
    return ret;
}

void HiTransCoderImpl::ConfigureMetaDataToTrackFormat(const std::shared_ptr<Meta> &globalInfo,
    const std::vector<std::shared_ptr<Meta>> &trackInfos)
{
    FALSE_RETURN_MSG(
        globalInfo != nullptr && trackInfos.size() != 0, "globalInfo or trackInfos are invalid.");
   
    bool isInitializeVideoEncFormat = false;
    bool isInitializeAudioEncFormat = false;
    isExistVideoTrack_ = false;
    isExistAudioTrack_ = false;
    (void)SetValueByType(globalInfo, muxerFormat_);
    for (size_t index = 0; index < trackInfos.size(); index++) {
        MEDIA_LOG_I("trackInfos index: %{public}zu", index);
        std::shared_ptr<Meta> meta = trackInfos[index];
        FALSE_RETURN_MSG(meta != nullptr, "meta is invalid, index: %zu", index);
        std::string trackMime;
        if (!meta->GetData(Tag::MIME_TYPE, trackMime)) {
            MEDIA_LOG_W("mimeType not found, index: %zu", index);
            continue;
        }
        if (!isInitializeVideoEncFormat && (trackMime.find("video/") == 0)) {
            (void)SetValueByType(meta, videoEncFormat_);
            (void)SetValueByType(meta, srcVideoFormat_);
            (void)SetValueByType(meta, muxerFormat_);
            // Copy HDR color metadata from source to srcVideoFormat_ for HDR auto-detection.
            // These keys are not in AVMETA_KEY so SetValueByType won't copy them.
            Plugins::ColorPrimary srcColorPrimaries = Plugins::ColorPrimary::UNSPECIFIED;
            if (meta->Get<Tag::VIDEO_COLOR_PRIMARIES>(srcColorPrimaries)) {
                srcVideoFormat_->Set<Tag::VIDEO_COLOR_PRIMARIES>(srcColorPrimaries);
            }
            Plugins::TransferCharacteristic srcTransferCharacteristic = Plugins::TransferCharacteristic::UNSPECIFIED;
            if (meta->Get<Tag::VIDEO_COLOR_TRC>(srcTransferCharacteristic)) {
                srcVideoFormat_->Set<Tag::VIDEO_COLOR_TRC>(srcTransferCharacteristic);
            }
            Plugins::MatrixCoefficient srcMatrixCoeff = Plugins::MatrixCoefficient::UNSPECIFIED;
            if (meta->Get<Tag::VIDEO_COLOR_MATRIX_COEFF>(srcMatrixCoeff)) {
                srcVideoFormat_->Set<Tag::VIDEO_COLOR_MATRIX_COEFF>(srcMatrixCoeff);
            }
            bool srcColorRange = false;
            if (meta->Get<Tag::VIDEO_COLOR_RANGE>(srcColorRange)) {
                srcVideoFormat_->Set<Tag::VIDEO_COLOR_RANGE>(srcColorRange);
            }
            meta->GetData(Tag::VIDEO_WIDTH, inputVideoWidth_);
            meta->GetData(Tag::VIDEO_HEIGHT, inputVideoHeight_);
            meta->GetData(Tag::VIDEO_ORIENTATION_TYPE, orientation_);
            if (orientation_ == ROTATE_270) {
                rotation_ = ROTATE_90_VALUE;
            }
            if (orientation_ == ROTATE_180) {
                rotation_ = ROTATE_180_VALUE;
            }
            if (orientation_ == ROTATE_90) {
                rotation_ = ROTATE_270_VALUE;
            }
            MEDIA_LOG_I("Set the default rotation_ format %{public}d", rotation_);
            isExistVideoTrack_ = true;
            isInitializeVideoEncFormat = true;
        } else if (!isInitializeAudioEncFormat && (trackMime.find("audio/") == 0)) {
            (void)SetValueByType(meta, audioEncFormat_);
            (void)SetValueByType(meta, srcAudioFormat_);
            (void)SetValueByType(meta, muxerFormat_);
            isExistAudioTrack_ = true;
            isInitializeAudioEncFormat = true;
        }
    }
    if (!isExistVideoTrack_ && !isExistAudioTrack_) {
        MEDIA_LOG_E("No video track found.");
        OnEvent({"TranscoderEngine", EventType::EVENT_ERROR, static_cast<int32_t>(MSERR_NO_VALID_TRACK_FOUND)});
    }
}

void HiTransCoderImpl::ConfigureDefaultParameter()
{
    ConfigureVideoDefaultEncFormat();
    ConfigureVideoBitrate();
}
 
void HiTransCoderImpl::ConfigureVideoDefaultEncFormat()
{
    std::string videoMime;
    videoEncFormat_->GetData(Tag::MIME_TYPE, videoMime);
    FALSE_RETURN_NOLOG(videoMime != Plugins::MimeType::VIDEO_HEVC && videoMime != Plugins::MimeType::VIDEO_AVC);
    MEDIA_LOG_I("Set the default videoEnc format, " PUBLIC_LOG_S " to " PUBLIC_LOG_S, videoMime.c_str(),
        Plugins::MimeType::VIDEO_AVC);
    videoEncFormat_->Set<Tag::MIME_TYPE>(Plugins::MimeType::VIDEO_AVC);
    videoEncFormat_->Set<Tag::VIDEO_H264_PROFILE>(Plugins::VideoH264Profile::BASELINE);
    videoEncFormat_->Set<Tag::VIDEO_H264_LEVEL>(32); // 32: LEVEL 3.2
}
 
void HiTransCoderImpl::ConfigureAudioDefaultEncFormat()
{
    audioEncFormat_->GetData(Tag::MIME_TYPE, inputAudioMimeType_);
    FALSE_RETURN_NOLOG(inputAudioMimeType_ != Plugins::MimeType::AUDIO_AAC);
    MEDIA_LOG_I("Set the default audioEnc format, " PUBLIC_LOG_S " to " PUBLIC_LOG_S, inputAudioMimeType_.c_str(),
        Plugins::MimeType::AUDIO_AAC);
    audioEncFormat_->Set<Tag::MIME_TYPE>(Plugins::MimeType::AUDIO_AAC);
}

bool HiTransCoderImpl::SetValueByType(const std::shared_ptr<Meta> &innerMeta, std::shared_ptr<Meta> &outputMeta)
{
    if (innerMeta == nullptr || outputMeta == nullptr) {
        return false;
    }
    bool result = true;
    for (const auto &metaKey : AVMETA_KEY) {
        result &= ProcessMetaKey(innerMeta, outputMeta, metaKey);
    }
    return result;
}

bool HiTransCoderImpl::ProcessMetaKey(
    const std::shared_ptr<Meta> &innerMeta, std::shared_ptr<Meta> &outputMeta, const std::string &metaKey)
{
    Any type = OHOS::Media::GetDefaultAnyValue(metaKey);
    if (Any::IsSameTypeWith<int32_t>(type)) {
        int32_t intVal;
        if (innerMeta->GetData(metaKey, intVal)) {
            outputMeta->SetData(metaKey, intVal);
        }
    } else if (Any::IsSameTypeWith<std::string>(type)) {
        std::string strVal;
        if (innerMeta->GetData(metaKey, strVal)) {
            outputMeta->SetData(metaKey, strVal);
        }
    } else if (Any::IsSameTypeWith<Plugins::VideoRotation>(type)) {
        Plugins::VideoRotation rotation;
        if (innerMeta->GetData(metaKey, rotation)) {
            outputMeta->SetData(metaKey, rotation);
        }
    } else if (Any::IsSameTypeWith<int64_t>(type)) {
        int64_t duration;
        if (innerMeta->GetData(metaKey, duration)) {
            outputMeta->SetData(metaKey, duration);
        }
    } else if (Any::IsSameTypeWith<bool>(type)) {
        bool isTrue;
        if (innerMeta->GetData(metaKey, isTrue)) {
            outputMeta->SetData(metaKey, isTrue);
        }
    } else if (Any::IsSameTypeWith<float>(type)) {
        float value;
        if (innerMeta->GetData(metaKey, value)) {
            outputMeta->SetData(metaKey, value);
        }
    } else if (Any::IsSameTypeWith<double>(type)) {
        double value;
        if (innerMeta->GetData(metaKey, value)) {
            outputMeta->SetData(metaKey, value);
        }
    } else if (Any::IsSameTypeWith<Plugins::AudioSampleFormat>(type)) {
        Plugins::AudioSampleFormat value = Plugins::AudioSampleFormat::INVALID_WIDTH;
        if (innerMeta->GetData(metaKey, value)) {
            outputMeta->SetData(metaKey, value);
        }
    }
    return true;
}

Status HiTransCoderImpl::ConfigureVideoAudioMetaData()
{
    if (demuxerFilter_ == nullptr) {
        MEDIA_LOG_E("demuxerFilter_ is nullptr");
        return Status::ERROR_NULL_POINTER;
    }
    std::shared_ptr<Meta> globalInfo = demuxerFilter_->GetGlobalMetaInfo();
    std::vector<std::shared_ptr<Meta>> trackInfos = demuxerFilter_->GetStreamMetaInfo();
    size_t trackCount = trackInfos.size();
    MEDIA_LOG_I("trackCount: %{public}zu", trackCount);
    if (trackCount == 0) {
        MEDIA_LOG_E("No track found in the source");
        CollectionErrorInfo(TransTranscoderStatus(Status::ERROR_NO_VALID_TRACK_FOUND),
            "ConfigureVideoAudioMetaData error");
        OnEvent({"TranscoderEngine", EventType::EVENT_ERROR, static_cast<int32_t>(MSERR_NO_VALID_TRACK_FOUND)});
        return Status::ERROR_NO_VALID_TRACK_FOUND;
    }
    ConfigureMetaDataToTrackFormat(globalInfo, trackInfos);
    ConfigureDefaultParameter();
    return Status::OK;
}

int32_t HiTransCoderImpl::SetOutputFile(const int32_t fd)
{
    MEDIA_LOG_I("HiTransCoderImpl::SetOutputFile()");
    MEDIA_LOG_I("HiTransCoder SetOutputFile in, fd is %{public}d", fd);
    FALSE_RETURN_V_MSG_E(fd >= 0, MSERR_INVALID_VAL, "Invalid fd: %{public}d", fd);

    fd_.Reset(dup(fd));
    FALSE_RETURN_V_MSG_E(fd_.Get() >= 0, MSERR_INVALID_OPERATION, "dup failed, errno: %{public}d", errno);
    MEDIA_LOG_I("HiTransCoder SetOutputFile dup, fd is %{public}d", fd_.Get());
    return MSERR_OK;
}

int32_t HiTransCoderImpl::SetOutputFormat(OutputFormatType format)
{
    MEDIA_LOG_I("HiTransCoderImpl::SetOutputFormat(), OutputFormatType is %{public}d", static_cast<int32_t>(format));
    outputFormatType_ = format;
    return MSERR_OK;
}

int32_t HiTransCoderImpl::SetObs(const std::weak_ptr<ITransCoderEngineObs> &obs)
{
    MEDIA_LOG_I("HiTransCoderImpl::SetObs()");
    obs_ = obs;
    callbackLooper_->StartWithTransCoderEngineObs(obs);
    return MSERR_OK;
}

void HiTransCoderImpl::ConfigureVideoEncoderFormat(const TransCoderParam &transCoderParam)
{
    VideoEnc videoEnc = static_cast<const VideoEnc&>(transCoderParam);
    MEDIA_LOG_I("HiTransCoderImpl::Configure videoEnc %{public}d", videoEnc.encFmt);
    switch (videoEnc.encFmt) {
        case OHOS::Media::VideoCodecFormat::H264:
            videoEncFormat_->Set<Tag::MIME_TYPE>(Plugins::MimeType::VIDEO_AVC);
            videoEncFormat_->Set<Tag::VIDEO_H264_PROFILE>(Plugins::VideoH264Profile::BASELINE);
            videoEncFormat_->Set<Tag::VIDEO_H264_LEVEL>(32); // 32: LEVEL 3.2
            break;
        case OHOS::Media::VideoCodecFormat::MPEG4:
            videoEncFormat_->Set<Tag::MIME_TYPE>(Plugins::MimeType::VIDEO_MPEG4);
            break;
        case OHOS::Media::VideoCodecFormat::H265:
            videoEncFormat_->Set<Tag::MIME_TYPE>(Plugins::MimeType::VIDEO_HEVC);
            break;
        default:
            break;
    }
}

void HiTransCoderImpl::ConfigureVideoWidthHeight(const TransCoderParam &transCoderParam)
{
    VideoRectangle videoRectangle = static_cast<const VideoRectangle&>(transCoderParam);
    if (videoRectangle.width != -1) {
        videoEncFormat_->Set<Tag::VIDEO_WIDTH>(videoRectangle.width);
    }
    if (videoRectangle.height != -1) {
        videoEncFormat_->Set<Tag::VIDEO_HEIGHT>(videoRectangle.height);
    }
}

Status HiTransCoderImpl::ConfigureColorSpace(const TransCoderParam &transCoderParam)
{
    VideoColorSpace colSpa = static_cast<const VideoColorSpace&>(transCoderParam);
    MEDIA_LOG_I("HiTranscoderImpl::ConfigureColorSpace %{public}d", static_cast<int32_t>(colSpa.colorSpaceFmt));
    if (static_cast<int32_t>(colSpa.colorSpaceFmt) <= 0) {
        return Status::ERROR_INVALID_PARAMETER;
    }
    videoEncFormat_->Set<Tag::AV_TRANSCODER_DST_COLOR_SPACE>(static_cast<int32_t>(colSpa.colorSpaceFmt));
    return Status::OK;
}

Status HiTransCoderImpl::ConfigureVideoBitrateMode(const TransCoderParam &transCoderParam)
{
    VideoBitrateMode bitrateModeParam = static_cast<const VideoBitrateMode&>(transCoderParam);
    videoBitrateMode_ = bitrateModeParam.bitrateMode;
    MEDIA_LOG_I("HiTransCoderImpl::Configure videoBitrateMode %{public}d", videoBitrateMode_);
    if (videoBitrateMode_ != -1) {
        bitrateMode = static_cast<Plugins::VideoEncodeBitrateMode>(videoBitrateMode_);
        if (VIDEO_BITRATE_MODES.find(bitrateMode) != VIDEO_BITRATE_MODES.end()) {
            return Status::OK;
        }
    }
    MEDIA_LOG_E("HiTransCoderImpl::Configure videoBitrateMode %{public}d is not support", videoBitrateMode_);
    return Status::ERROR_INVALID_PARAMETER;
}

Status HiTransCoderImpl::ConfigureSQRFactor(const TransCoderParam &transCoderParam)
{
    VideoSqrFactor sqrFactorParam = static_cast<const VideoSqrFactor&>(transCoderParam);
    videoSqrFactor_ = sqrFactorParam.sqrFactor;
    MEDIA_LOG_I("HiTransCoderImpl::Configure videoSqrFactor %{public}d", videoSqrFactor_);
    FALSE_RETURN_V_MSG(videoSqrFactor_ >= 0 && videoSqrFactor_ <= MAX_SQR_FACTOR, Status::ERROR_SQR_FACTOR_OUT_OF_RANGE,
        "Invalid video SQR factor");
    videoEncFormat_->Set<Tag::VIDEO_ENCODER_SQR_FACTOR>(videoSqrFactor_);
    return Status::OK;
}

Status HiTransCoderImpl::ConfigureEnableBFrameEncoding(const TransCoderParam &transCoderParam)
{
    VideoEnableBFrameEncoding enableBFrameEncoding = static_cast<const VideoEnableBFrameEncoding&>(transCoderParam);
    MEDIA_LOG_I("HiTranscoderImpl::ConfigureEnableBFrameEncoding %{public}d", static_cast<int32_t>(
        enableBFrameEncoding.enableBFrame));
    videoEncFormat_->Set<Tag::AV_TRANSCODER_ENABLE_B_FRAME>(enableBFrameEncoding.enableBFrame);
    return Status::OK;
}

Status HiTransCoderImpl::ConfigureDestHdrMode(const TransCoderParam &transCoderParam)
{
    VideoDestHdrMode destHdrMode = static_cast<const VideoDestHdrMode&>(transCoderParam);
    destHdrMode_ = static_cast<int32_t>(destHdrMode.destHdrMode);
    MEDIA_LOG_I("HiTranscoderImpl::ConfigureDestHdrMode %{public}d", destHdrMode_);
    videoEncFormat_->Set<Tag::AV_TRANSCODER_DEST_HDR_MODE>(destHdrMode_);
    return Status::OK;
}

void HiTransCoderImpl::ConfigureVideoEncoderHdrFormat()
{
    FALSE_RETURN_MSG(videoEncFormat_ != nullptr, "videoEncFormat_ is nullptr, skip HDR configuration");

    int32_t colorSpaceFormat = 0;
    bool hasExplicitColorSpace = videoEncFormat_->GetData(Tag::AV_TRANSCODER_DST_COLOR_SPACE, colorSpaceFormat);

    // 分支 A：用户显式指定了目标色彩空间
    if (hasExplicitColorSpace) {
        if (!IsHdrColorSpace(colorSpaceFormat)) {
            // 显式 SDR 输出，跳过 HDR 配置，由解码器执行 HDR2SDR
            return;
        }
        ConfigureHdrByExplicitColorSpace(colorSpaceFormat);
        return;
    }

    // 分支 B：未显式指定色彩空间，按 destHdrMode_ 决策
    // SDR：跳过 HDR 配置；非 AUTO_HDR_VIVID：警告并跳过
    FALSE_RETURN_MSG_I(destHdrMode_ != static_cast<int32_t>(DestHDRMode::SDR),
        "ConfigureVideoEncoderHdrFormat: destHdrMode=SDR, skip HDR configuration (HDR2SDR path)");
    FALSE_RETURN_MSG_W(destHdrMode_ == static_cast<int32_t>(DestHDRMode::AUTO_HDR_VIVID),
        "ConfigureVideoEncoderHdrFormat: unsupported destHdrMode %{public}d, skip HDR configuration",
        destHdrMode_);
    // AUTO_HDR_VIVID：仅当源为 HDRVivid 时才配置 HDR 输出，否则走 SDR
    FALSE_RETURN_MSG_I(QuerySrcIsHdrVivid(),
        "ConfigureVideoEncoderHdrFormat: destHdrMode=AUTO_HDR_VIVID but source is not HDRVivid, "
        "skip HDR configuration (SDR output)");
    MEDIA_LOG_I("destHdrMode=AUTO_HDR_VIVID, source is HDRVivid, configuring HDR output");
    ConfigureHdrByAutoHdrVivid();
}

void HiTransCoderImpl::ConfigureHdrByExplicitColorSpace(int32_t colorSpace)
{
    MEDIA_LOG_I("ConfigureVideoEncoderHdrFormat: explicit dst color space is HDR(%{public}d)", colorSpace);
    if (QuerySrcIsHdrVivid()) {
        videoEncFormat_->Set<Tag::VIDEO_IS_HDR_VIVID>(true);
    }
    // HEVC 编码强制 Main10 profile 以支持 10bit HDR
    std::string mimeType;
    if (videoEncFormat_->Get<Tag::MIME_TYPE>(mimeType) && mimeType == Plugins::MimeType::VIDEO_HEVC) {
        videoEncFormat_->Set<Tag::VIDEO_H265_PROFILE>(Plugins::HEVCProfile::HEVC_PROFILE_MAIN_10);
    }
    // 表驱动：按映射表填写色彩四元组，矩阵系数统一为 BT2020_NCL
    const HdrColorSpaceMapping* mapping = FindHdrColorSpaceMapping(colorSpace);
    FALSE_RETURN_MSG(mapping != nullptr, "Unsupported HDR color space: %{public}d", colorSpace);
    videoEncFormat_->Set<Tag::VIDEO_COLOR_PRIMARIES>(mapping->primaries);
    videoEncFormat_->Set<Tag::VIDEO_COLOR_TRC>(mapping->transfer);
    videoEncFormat_->Set<Tag::VIDEO_COLOR_MATRIX_COEFF>(Plugins::MatrixCoefficient::BT2020_NCL);
    videoEncFormat_->Set<Tag::VIDEO_COLOR_RANGE>(mapping->isFullRange);
}

void HiTransCoderImpl::ConfigureHdrByAutoHdrVivid()
{
    // HEVC 编码强制 Main10 profile 以支持 10bit HDR
    std::string mimeType;
    if (videoEncFormat_->Get<Tag::MIME_TYPE>(mimeType) && mimeType == Plugins::MimeType::VIDEO_HEVC) {
        videoEncFormat_->Set<Tag::VIDEO_H265_PROFILE>(Plugins::HEVCProfile::HEVC_PROFILE_MAIN_10);
    }
    videoEncFormat_->Set<Tag::VIDEO_IS_HDR_VIVID>(true);

    // 从源拷贝色彩四元组，缺失时使用 HDR 默认值（BT2020/HLG/BT2020_NCL/Limited）
    Plugins::ColorPrimary primaries = Plugins::ColorPrimary::UNSPECIFIED;
    bool hasPrimaries = srcVideoFormat_ != nullptr && srcVideoFormat_->Get<Tag::VIDEO_COLOR_PRIMARIES>(primaries);
    videoEncFormat_->Set<Tag::VIDEO_COLOR_PRIMARIES>(hasPrimaries ? primaries : Plugins::ColorPrimary::BT2020);

    Plugins::TransferCharacteristic transfer = Plugins::TransferCharacteristic::UNSPECIFIED;
    bool hasTransfer = srcVideoFormat_ != nullptr && srcVideoFormat_->Get<Tag::VIDEO_COLOR_TRC>(transfer);
    videoEncFormat_->Set<Tag::VIDEO_COLOR_TRC>(hasTransfer ? transfer : Plugins::TransferCharacteristic::HLG);

    Plugins::MatrixCoefficient matrixCoeff = Plugins::MatrixCoefficient::UNSPECIFIED;
    bool hasMatrix = srcVideoFormat_ != nullptr && srcVideoFormat_->Get<Tag::VIDEO_COLOR_MATRIX_COEFF>(matrixCoeff);
    videoEncFormat_->Set<Tag::VIDEO_COLOR_MATRIX_COEFF>(
        hasMatrix ? matrixCoeff : Plugins::MatrixCoefficient::BT2020_NCL);

    bool colorRange = false;
    bool hasRange = srcVideoFormat_ != nullptr && srcVideoFormat_->Get<Tag::VIDEO_COLOR_RANGE>(colorRange);
    videoEncFormat_->Set<Tag::VIDEO_COLOR_RANGE>(hasRange ? colorRange : false);

    // 反向推导目标色彩空间并回写，使 decoder filter 据此跳过 VPE 色彩转换
    Plugins::ColorPrimary dstPrimaries = hasPrimaries ? primaries : Plugins::ColorPrimary::BT2020;
    Plugins::TransferCharacteristic dstTransfer = hasTransfer ? transfer : Plugins::TransferCharacteristic::HLG;
    int32_t dstColorSpace = DeriveColorSpaceFromAspects(dstPrimaries, dstTransfer, hasRange ? colorRange : false);
    videoEncFormat_->Set<Tag::AV_TRANSCODER_DST_COLOR_SPACE>(dstColorSpace);
    MEDIA_LOG_I("ConfigureVideoEncoderHdrFormat: auto-set dst color space to %{public}d", dstColorSpace);
}

bool HiTransCoderImpl::QuerySrcIsHdrVivid() const
{
    FALSE_RETURN_V_NOLOG(srcVideoFormat_ != nullptr, false);
    bool srcIsHdrVivid = false;
    (void)srcVideoFormat_->Get<Tag::VIDEO_IS_HDR_VIVID>(srcIsHdrVivid);
    return srcIsHdrVivid;
}

bool HiTransCoderImpl::IsHdrOutput() const
{
    FALSE_RETURN_V_NOLOG(videoEncFormat_ != nullptr, false);
    // 1. 用户通过 ConfigureColorSpace 显式设置了目标色彩空间
    int32_t colorSpaceFormat = 0;
    if (videoEncFormat_->GetData(Tag::AV_TRANSCODER_DST_COLOR_SPACE, colorSpaceFormat)) {
        return IsHdrColorSpace(colorSpaceFormat);
    }
    // 2. 未显式设置色彩空间时，根据 destHdrMode_ 和源 HDR Vivid 属性判断
    if (destHdrMode_ == static_cast<int32_t>(DestHDRMode::AUTO_HDR_VIVID)) {
        return QuerySrcIsHdrVivid();
    }
    return false;
}

int32_t HiTransCoderImpl::ValidateHdrCodecCompatibility()
{
    // HDRVivid 输出要求 HEVC 编码器；仅在 AUTO_HDR_VIVID 且源为 HDRVivid 时校验
    FALSE_RETURN_V_NOLOG(destHdrMode_ == static_cast<int32_t>(DestHDRMode::AUTO_HDR_VIVID), MSERR_OK);
    FALSE_RETURN_V_NOLOG(QuerySrcIsHdrVivid(), MSERR_OK);
    std::string mimeType;
    if (videoEncFormat_ != nullptr && videoEncFormat_->Get<Tag::MIME_TYPE>(mimeType) &&
        mimeType != Plugins::MimeType::VIDEO_HEVC) {
        MEDIA_LOG_E("HDR Vivid output requires HEVC codec, but got %{public}s", mimeType.c_str());
        CollectionErrorInfo(MSERR_HDR_VIVID_CODEC_MISMATCH_ERROR_401,
            "Prepare error: HDR Vivid output requires HEVC codec, but got " + mimeType);
        OnEvent({"TranscoderEngine", EventType::EVENT_ERROR,
            static_cast<int32_t>(MSERR_HDR_VIVID_CODEC_MISMATCH_ERROR_401)});
        return MSERR_HDR_VIVID_CODEC_MISMATCH_ERROR_401;
    }
    return MSERR_OK;
}

int32_t HiTransCoderImpl::ValidateHdrWatermarkIncompatibility()
{
    // 水印图片为 8bit RGBA，无法在 HDR 10bit 管线上正确混合。
    // AddWatermark 在 Prepare 之前调用，此时 destHdrMode_ 可能尚未设置，
    // 因此在 Prepare 阶段（所有配置已就绪）统一校验。
    if (IsHdrOutput() && skipProcessFilterFlag_.AddVideoWaterMarkFilter()) {
        MEDIA_LOG_E("Watermark is not supported for HDR output (8bit watermark vs 10bit HDR pipeline)");
        CollectionErrorInfo(MSERR_HDR_VIVID_WATERMARK_ERROR_5400106,
            "Prepare error: watermark is not supported for HDR Vivid output");
        OnEvent({"TranscoderEngine", EventType::EVENT_ERROR,
            static_cast<int32_t>(MSERR_HDR_VIVID_WATERMARK_ERROR_5400106)});
        return MSERR_HDR_VIVID_WATERMARK_ERROR_5400106;
    }
    return MSERR_OK;
}

Status HiTransCoderImpl::ConfigureVideoBitrate()
{
    int64_t videoBitrate = 0;
    if (videoEncFormat_->Find(Tag::MEDIA_BITRATE) != videoEncFormat_->end()) {
        videoEncFormat_->Get<Tag::MEDIA_BITRATE>(videoBitrate);
    }
    MEDIA_LOG_D("get videoBitrate: " PUBLIC_LOG_D64, videoBitrate);
    int32_t width = 0;
    int32_t height = 0;
    videoEncFormat_->GetData(Tag::VIDEO_WIDTH, width);
    videoEncFormat_->GetData(Tag::VIDEO_HEIGHT, height);
    const int32_t &minNum = std::min(width, height);
    int32_t defaultVideoBitrate = videoBitrate;
    if (minNum > HEIGHT_1080) {
        defaultVideoBitrate = VIDEO_BITRATE_8M;
    } else if (minNum > HEIGHT_720) {
        defaultVideoBitrate = VIDEO_BITRATE_4M;
    } else if (minNum > HEIGHT_480) {
        defaultVideoBitrate = VIDEO_BITRATE_2M;
    } else {
        defaultVideoBitrate = VIDEO_BITRATE_1M;
    }
    MEDIA_LOG_D("set videoBitrate: %{public}d", defaultVideoBitrate);
    videoEncFormat_->Set<Tag::MEDIA_BITRATE>(defaultVideoBitrate);
    return Status::OK;
}

int32_t HiTransCoderImpl::Configure(const TransCoderParam &transCoderParam)
{
    MEDIA_LOG_I("HiTransCoderImpl::Configure, type: " PUBLIC_LOG_U32, static_cast<uint32_t>(transCoderParam.type));
    MediaTrace trace("HiTransCoderImpl::Configure()");
    if (transCoderParam.type == TransCoderPublicParamType::TIME_RANGE) {
        const TimeRange &timeRange = static_cast<const TimeRange&>(transCoderParam);
        return SetTimeRange(timeRange.startTime, timeRange.endTime);
    }
    Status ret = ConfigureAudioParam(transCoderParam);
    FALSE_RETURN_V_NOLOG(ret == Status::OK, TransTranscoderStatus(ret));
    ret = ConfigureVideoParam(transCoderParam);
    return TransTranscoderStatus(ret);
}

Status HiTransCoderImpl::ConfigureVideoParam(const TransCoderParam &transCoderParam)
{
    Status ret = Status::OK;
    switch (transCoderParam.type) {
        case TransCoderPublicParamType::VIDEO_ENC_FMT: {
            ConfigureVideoEncoderFormat(transCoderParam);
            break;
        }
        case TransCoderPublicParamType::VIDEO_RECTANGLE: {
            ConfigureVideoWidthHeight(transCoderParam);
            if (!isConfiguredVideoBitrate_) {
                ConfigureVideoBitrate();
            }
            break;
        }
        case TransCoderPublicParamType::VIDEO_BITRATE: {
            VideoBitRate videoBitrate = static_cast<const VideoBitRate&>(transCoderParam);
            FALSE_RETURN_V_MSG(videoBitrate.bitRate > 0, Status::OK, "Invalid video bitrate");
            MEDIA_LOG_I("HiTransCoderImpl::Configure videoBitRate %{public}d", videoBitrate.bitRate);
            videoEncFormat_->Set<Tag::MEDIA_BITRATE>(videoBitrate.bitRate);
            isConfiguredVideoBitrate_ = true;
            break;
        }
        case TransCoderPublicParamType::COLOR_SPACE_FMT: {
            ret = ConfigureColorSpace(transCoderParam);
            break;
        }
        case TransCoderPublicParamType::VIDEO_ENABLE_B_FRAME_ENCODING: {
            ret = ConfigureEnableBFrameEncoding(transCoderParam);
            break;
        }
        case TransCoderPublicParamType::VIDEO_BITRATE_MODE: {
            ret = ConfigureVideoBitrateMode(transCoderParam);
            break;
        }
        case TransCoderPublicParamType::VIDEO_SQR_FACTOR: {
            ret = ConfigureSQRFactor(transCoderParam);
            break;
        }
        case TransCoderPublicParamType::DEST_HDR_MODE: {
            ret = ConfigureDestHdrMode(transCoderParam);
            break;
        }
        default:
            break;
    }
    return ret;
}

const char* HiTransCoderImpl::GetAudioEncFormat(const AudioCodecFormat &encFmt)
{
    MEDIA_LOG_I("GetAudioEncFormat is %{public}d", encFmt);
    const std::map<AudioCodecFormat, const char*> extensionToOutputFormat = {
        { AudioCodecFormat::AUDIO_MPEG, Plugins::MimeType::AUDIO_MPEG },
        { AudioCodecFormat::AUDIO_RAW, Plugins::MimeType::AUDIO_RAW },
        { AudioCodecFormat::AUDIO_AMR_NB, Plugins::MimeType::AUDIO_AMR_NB },
        { AudioCodecFormat::AUDIO_AMR_WB, Plugins::MimeType::AUDIO_AMR_WB },
    };

    auto iter = extensionToOutputFormat.find(encFmt);
    if (iter != extensionToOutputFormat.end()) {
        return iter->second;
    }
    return Plugins::MimeType::AUDIO_AAC;
}

Status HiTransCoderImpl::ConfigureAudioParam(const TransCoderParam &transCoderParam)
{
    std::string audioDecCodec;
    switch (transCoderParam.type) {
        case TransCoderPublicParamType::AUDIO_ENC_FMT: {
            AudioEnc audioEnc = static_cast<const AudioEnc&>(transCoderParam);
            MEDIA_LOG_I("HiTransCoderImpl::Configure audioEnc %{public}d", audioEnc.encFmt);
            if (inputAudioMimeType_ == Plugins::MimeType::AUDIO_AAC) {
                skipProcessFilterFlag_.isSameAudioEncFmt = true;
            }
            srcAudioFormat_->Get<Tag::MIME_TYPE>(audioDecCodec);
            if (audioDecCodec == Plugins::MimeType::AUDIO_RAW && audioEnc.encFmt == AudioCodecFormat::AUDIO_RAW) {
                skipProcessFilterFlag_.isSameAudioEncFmt = true;
                skipProcessFilterFlag_.isSameAudioBitrate = true;
                MEDIA_LOG_I("Configure skip audioEnc %{public}s", audioDecCodec.c_str());
            }
            auto audioSetEnc = GetAudioEncFormat(audioEnc.encFmt);
            audioEncFormat_->Set<Tag::MIME_TYPE>(audioSetEnc);
            break;
        }
        case TransCoderPublicParamType::AUDIO_BITRATE: {
            AudioBitRate audioBitrate = static_cast<const AudioBitRate&>(transCoderParam);
            if (audioBitrate.bitRate <= 0) {
                MEDIA_LOG_E("Invalid audioBitrate.bitRate %{public}d", audioBitrate.bitRate);
                OnEvent({"TranscoderEngine", EventType::EVENT_ERROR,
                    static_cast<int32_t>(MSERR_INVALID_AUDIO_BITRATE)});
                return Status::ERROR_INVALID_AUDIO_BITRATE;
            }
            int64_t bitrate = -1;
            audioEncFormat_->Get<Tag::MEDIA_BITRATE>(bitrate);
            if (audioBitrate.bitRate == INVALID_AUDIO_BITRATE || audioBitrate.bitRate == bitrate) {
                skipProcessFilterFlag_.isSameAudioBitrate = true;
            }
            audioBitrate.bitRate = audioBitrate.bitRate == INVALID_AUDIO_BITRATE ?
                DEFAULT_AUDIO_BITRATE : audioBitrate.bitRate;
            MEDIA_LOG_I("HiTransCoderImpl::Configure audioBitrate %{public}d", audioBitrate.bitRate);
            audioEncFormat_->Set<Tag::MEDIA_BITRATE>(audioBitrate.bitRate);
            break;
        }
        default:
            break;
    }
    return Status::OK;
}

void HiTransCoderImpl::SkipAudioDecAndEnc()
{
    FALSE_RETURN_NOLOG(demuxerFilter_ != nullptr);
    (void)demuxerFilter_->SetSkippingAudioDecAndEnc();
}

int32_t HiTransCoderImpl::SetTimeRange(int64_t startTime, int64_t endTime)
{
    MEDIA_LOG_I("HiTransCoderImpl::SetTimeRange, startTime: " PUBLIC_LOG_D64 ", endTime: " PUBLIC_LOG_D64,
        startTime, endTime);
    startTimeMs_ = startTime;
    endTimeMs_ = endTime;
    if (demuxerFilter_ != nullptr) {
        Status ret = demuxerFilter_->SetTimeRange(startTime, endTime);
        FALSE_RETURN_V_MSG_E(ret == Status::OK, TransTranscoderStatus(ret),
            "DemuxerFilter SetTimeRange failed");
    }
    return MSERR_OK;
}

int32_t HiTransCoderImpl::ValidateTimeRange()
{
    // Both -1 means no time range set, transcode the entire source.
    FALSE_RETURN_V_MSG_E(startTimeMs_ >= 0 || endTimeMs_ >= 0, MSERR_OK, "No time range set, skip validation");
    int64_t sourceDurationMs = durationMs_.load();
    // Validate startTime against source duration.
    if (startTimeMs_ > 0 && sourceDurationMs > 0 && startTimeMs_ >= sourceDurationMs) {
        MEDIA_LOG_E("Invalid time range, startTime: " PUBLIC_LOG_D64 " >= sourceDuration: " PUBLIC_LOG_D64,
            startTimeMs_, sourceDurationMs);
        CollectionErrorInfo(MSERR_TIME_RANGE_START_ERROR_401, "Prepare error: startTime >= duration");
        OnEvent({"TranscoderEngine", EventType::EVENT_ERROR,
            static_cast<int32_t>(MSERR_TIME_RANGE_START_ERROR_401)});
        return MSERR_TIME_RANGE_START_ERROR_401;
    }
    // Validate endTime against source duration.
    if (endTimeMs_ > 0 && sourceDurationMs > 0 && endTimeMs_ > sourceDurationMs) {
        MEDIA_LOG_E("Invalid time range, endTime: " PUBLIC_LOG_D64 " > sourceDuration: " PUBLIC_LOG_D64,
            endTimeMs_, sourceDurationMs);
        CollectionErrorInfo(MSERR_TIME_RANGE_END_ERROR_401, "Prepare error: endTime > duration");
        OnEvent({"TranscoderEngine", EventType::EVENT_ERROR,
            static_cast<int32_t>(MSERR_TIME_RANGE_END_ERROR_401)});
        return MSERR_TIME_RANGE_END_ERROR_401;
    }
    // Validate start-end relationship when both are specified.
    FALSE_RETURN_V_NOLOG(startTimeMs_ < 0 || endTimeMs_ < 0, ValidateTimeRangeStartEnd());
    return MSERR_OK;
}

int32_t HiTransCoderImpl::ValidateTimeRangeStartEnd()
{
    if (startTimeMs_ >= endTimeMs_) {
        MEDIA_LOG_E("Invalid time range, startTime: " PUBLIC_LOG_D64 " >= endTime: " PUBLIC_LOG_D64,
            startTimeMs_, endTimeMs_);
        CollectionErrorInfo(MSERR_TIME_RANGE_INVALID_ERROR_401, "Prepare error: startTime >= endTime");
        OnEvent({"TranscoderEngine", EventType::EVENT_ERROR,
            static_cast<int32_t>(MSERR_TIME_RANGE_INVALID_ERROR_401)});
        return MSERR_TIME_RANGE_INVALID_ERROR_401;
    }
    if ((endTimeMs_ - startTimeMs_) < 100) {
        MEDIA_LOG_E("Invalid time range, slice is less than 100ms, startTime: " PUBLIC_LOG_D64
            ", endTime: " PUBLIC_LOG_D64, startTimeMs_, endTimeMs_);
        CollectionErrorInfo(MSERR_TIME_RANGE_INVALID_ERROR_401, "Prepare error: time slice < 100ms");
        OnEvent({"TranscoderEngine", EventType::EVENT_ERROR,
            static_cast<int32_t>(MSERR_TIME_RANGE_INVALID_ERROR_401)});
        return MSERR_TIME_RANGE_INVALID_ERROR_401;
    }
    return MSERR_OK;
}

void HiTransCoderImpl::PropagateTimeRangeToFilters()
{
    FALSE_RETURN_MSG(startTimeMs_ >= 0 || endTimeMs_ >= 0, "time range unset, skip seeking");
    FALSE_RETURN_MSG(demuxerFilter_ != nullptr, "demuxerFilter_ is nullptr");

    int64_t effectiveStart = (startTimeMs_ > 0) ? startTimeMs_ : 0;
    int64_t sourceDurationMs = durationMs_.load();
    int64_t effectiveEnd = (endTimeMs_ > 0) ? endTimeMs_ : sourceDurationMs;
    int64_t transcoderStartPts = demuxerFilter_->GetTranscoderStartPts();
    int64_t clipStartRelativeUs = effectiveStart * 1000 - transcoderStartPts;
    int64_t clipEndRelativeUs = effectiveEnd * 1000 - transcoderStartPts;
    MEDIA_LOG_I("PropagateTimeRangeToFilters, startTimeMs: " PUBLIC_LOG_D64 ", endTimeMs: " PUBLIC_LOG_D64
        ", effectiveStart: " PUBLIC_LOG_D64 ", effectiveEnd: " PUBLIC_LOG_D64
        ", transcoderStartPts: " PUBLIC_LOG_D64
        ", clipStartRelativeUs: " PUBLIC_LOG_D64 ", clipEndRelativeUs: " PUBLIC_LOG_D64,
        startTimeMs_, endTimeMs_, effectiveStart, effectiveEnd,
        transcoderStartPts, clipStartRelativeUs, clipEndRelativeUs);
    if (videoEncoderFilter_ != nullptr) {
        videoEncoderFilter_->SetTimeRange(effectiveStart, effectiveEnd);
        videoEncoderFilter_->SetClipStartRelativeUs(clipStartRelativeUs);
    }
    if (audioEncoderFilter_ != nullptr) {
        audioEncoderFilter_->SetClipStartTimeUs(clipStartRelativeUs);
    }
    if (muxerFilter_ != nullptr) {
        muxerFilter_->SetClipStartTimeUs(clipStartRelativeUs);
        muxerFilter_->SetClipEndTimeUs(clipEndRelativeUs);
    }
    if (callbackLooper_ != nullptr) {
        callbackLooper_->SetTimeRange(effectiveStart, effectiveEnd);
    }
}

int32_t HiTransCoderImpl::Prepare()
{
    MEDIA_LOG_I("HiTransCoderImpl::Prepare()");
    MediaTrace trace("HiTransCoderImpl::Prepare()");
    AppendMediaKitTranscoderMediaInfo();
    int32_t width = 0;
    int32_t height = 0;
    if (isExistVideoTrack_) {
        if (videoEncFormat_->GetData(Tag::VIDEO_WIDTH, width) &&
            videoEncFormat_->GetData(Tag::VIDEO_HEIGHT, height)) {
            MEDIA_LOG_D("set output video width: %{public}d, height: %{public}d", width, height);
        } else {
            MEDIA_LOG_E("Output video width or height not set");
            CollectionErrorInfo(MSERR_INVALID_VAL, "Prepare error");
            OnEvent({"TranscoderEngine", EventType::EVENT_ERROR, static_cast<int32_t>(MSERR_INVALID_VAL)});
            return MSERR_INVALID_VAL;
        }

        if (width > inputVideoWidth_ || height > inputVideoHeight_ || std::min(width, height) < MINIMUM_WIDTH_HEIGHT) {
            MEDIA_LOG_E("Output video width or height is invalid");
            CollectionErrorInfo(MSERR_INVALID_OUTPUT_RESOLUTION, "Prepare error");
            OnEvent({"TranscoderEngine", EventType::EVENT_ERROR,
                static_cast<int32_t>(MSERR_INVALID_OUTPUT_RESOLUTION)});
            return MSERR_INVALID_OUTPUT_RESOLUTION;
        }
        skipProcessFilterFlag_.isSameVideoResolution = (width == inputVideoWidth_) && (height == inputVideoHeight_);

        // HDR 兼容性校验：HDRVivid 输出必须用 HEVC 编码器
        int32_t hdrCodecRet = ValidateHdrCodecCompatibility();
        FALSE_RETURN_V_MSG_E(hdrCodecRet == MSERR_OK, hdrCodecRet, "HDR codec compatibility check failed");
        // HDR 输出与水印互斥：水印图为 8bit RGBA，无法在 10bit HDR 管线上正确混合
        int32_t hdrWatermarkRet = ValidateHdrWatermarkIncompatibility();
        FALSE_RETURN_V_MSG_E(hdrWatermarkRet == MSERR_OK, hdrWatermarkRet,
            "HDR watermark incompatibility check failed");
    }
    if (skipProcessFilterFlag_.CanSkipAudioDecAndEncFilter()) {
        SkipAudioDecAndEnc();
    }
    Status ret = pipeline_->Prepare();
    if (ret != Status::OK) {
        MEDIA_LOG_E("Prepare failed with error " PUBLIC_LOG_D32, ret);
        int32_t errCode = TransTranscoderStatus(ret);
        CollectionErrorInfo(errCode, "Prepare error");
        OnEvent({"TranscoderEngine", EventType::EVENT_ERROR, static_cast<int32_t>(errCode)});
        return errCode;
    }
    Status errCode = Status::OK;
    if (isExistVideoTrack_) {
        errCode = SetSurfacePipeline(width, height);
        if (errCode == Status::ERROR_UNKNOWN) {
            errCode = Status::ERROR_SET_OUTPUT_SURFACE_FAILED;
        }
    }
    // 判断所设时间范围的有效性
    int32_t timeRangeErr = ValidateTimeRange();
    FALSE_RETURN_V_MSG_E(timeRangeErr == MSERR_OK, timeRangeErr, "Time range validation failed");

    PropagateTimeRangeToFilters();

    return TransTranscoderStatus(errCode);
}

Status HiTransCoderImpl::SetSurfacePipeline(int32_t outputVideoWidth, int32_t outputVideoHeight)
{
    MEDIA_LOG_I("Prepare SetSurfacePipeline");
    auto mode = DetermineProcessMode();
    return BuildPipeline(mode, outputVideoWidth, outputVideoHeight);
}

int32_t HiTransCoderImpl::Start()
{
    MEDIA_LOG_I("HiTransCoderImpl::Start()");
    MediaTrace trace("HiTransCoderImpl::Start()");
    // Seek to time range start before starting the pipeline
    if (startTimeMs_ > 0 && demuxerFilter_ != nullptr) {
        Status seekRet = demuxerFilter_->SeekToClipStartTime();
        if (seekRet != Status::OK) {
            MEDIA_LOG_W("Seek to clip start time failed, continue anyway");
        }
    }
    startTime_.store(GetCurrentMillisecond());
    int32_t ret = TransTranscoderStatus(pipeline_->Start());
    if (ret != MSERR_OK) {
        MEDIA_LOG_E("Start pipeline failed");
        CollectionErrorInfo(ret, "Start error");
        OnEvent({"TranscoderEngine", EventType::EVENT_ERROR, static_cast<int32_t>(ret)});
        return ret;
    }
    callbackLooper_->StartReportMediaProgress(REPORT_PROGRESS_INTERVAL);
    return MSERR_OK;
}

int32_t HiTransCoderImpl::Pause()
{
    MEDIA_LOG_I("HiTransCoderImpl::Pause()");
    MediaTrace trace("HiTransCoderImpl::Pause()");
    callbackLooper_->StopReportMediaProgress();
    int32_t ret = TransTranscoderStatus(pipeline_->Pause());
    if (ret != MSERR_OK) {
        MEDIA_LOG_E("Pause pipeline failed");
        CollectionErrorInfo(ret, "Pause error");
        OnEvent({"TranscoderEngine", EventType::EVENT_ERROR, static_cast<int32_t>(ret)});
    }
    if (startTime_.load() != -1) {
        transcoderTotalDuration_.fetch_add(GetCurrentMillisecond() - startTime_.load());
    }
    startTime_.store(-1);
    return ret;
}

int32_t HiTransCoderImpl::Resume()
{
    MEDIA_LOG_I("HiTransCoderImpl::Resume()");
    MediaTrace trace("HiTransCoderImpl::Resume()");
    int32_t ret = TransTranscoderStatus(pipeline_->Resume());
    if (ret != MSERR_OK) {
        MEDIA_LOG_E("Resume pipeline failed");
        CollectionErrorInfo(ret, "Resume error");
        OnEvent({"TranscoderEngine", EventType::EVENT_ERROR, static_cast<int32_t>(ret)});
        return ret;
    }
    callbackLooper_->StartReportMediaProgress(REPORT_PROGRESS_INTERVAL);
    startTime_.store(GetCurrentMillisecond());
    return MSERR_OK;
}

int32_t HiTransCoderImpl::Cancel()
{
    MEDIA_LOG_I("HiTransCoderImpl::Cancel enter");
    MediaTrace trace("HiTransCoderImpl::Cancel()");
    callbackLooper_->StopReportMediaProgress();
    int32_t ret = TransTranscoderStatus(pipeline_->Stop());
    {
        std::lock_guard<std::mutex> lock(handleCompleteMutex_);
        callbackLooper_->Stop();
    }
    if (ret != MSERR_OK) {
        MEDIA_LOG_E("Stop pipeline failed");
        CollectionErrorInfo(ret, "Cancel error");
        OnEvent({"TranscoderEngine", EventType::EVENT_ERROR, static_cast<int32_t>(ret)});
    }
    if (fd_.Get() >= 0) {
        fd_.Reset();
    }
    if (ret != MSERR_OK) {
        return ret;
    }
    MEDIA_LOG_I("HiTransCoderImpl::Cancel done");
    if (startTime_.load() != -1) {
        transcoderTotalDuration_.fetch_add(GetCurrentMillisecond() - startTime_.load());
    }
    startTime_.store(-1);
    AppendTranscoderMediaInfo();
    ReportMediaInfo(instanceId_);
    return MSERR_OK;
}

int32_t HiTransCoderImpl::AddWatermark(std::shared_ptr<AVBuffer> &waterMarkBuffer, int32_t width, int32_t height)
{
    MEDIA_LOG_I("HiTransCoderImpl::AddWatermark()");
    if (!skipProcessFilterFlag_.AddVideoWaterMarkFilter()) {
        skipProcessFilterFlag_.isAddWaterMark = true;
        waterMarkFilter_ = Pipeline::FilterFactory::Instance().CreateFilter<Pipeline::WaterMarkFilter>(
            "Watermark", Pipeline::FilterType::WATERMARK);
    }
    FALSE_RETURN_V_MSG_E(waterMarkFilter_ != nullptr, MSERR_INVALID_OPERATION, "Watermark filter is nullptr");
    FALSE_RETURN_V_MSG_E(waterMarkBuffer != nullptr, MSERR_INVALID_VAL, "Param waterMarkBuffer is nullptr");
    auto filter = static_cast<Pipeline::WaterMarkFilter*>(waterMarkFilter_.get());
    filter->SetVideoResize(inputVideoWidth_, inputVideoHeight_);
    auto ret = filter->SetWatermark(waterMarkBuffer, width, height);
    FALSE_RETURN_V_MSG_E(ret == Status::OK, TransTranscoderStatus(ret), "Watermark filter error");
    return MSERR_OK;
}

int32_t HiTransCoderImpl::AddVideoResize(int32_t width, int32_t height)
{
    MEDIA_LOG_I("HiTransCoderImpl::AddVideoResize()");
    if (skipProcessFilterFlag_.AddVideoWaterMarkFilter()) {
        // Watermark path already created the WaterMarkFilter; reuse it for resize+watermark
        auto filter = static_cast<Pipeline::WaterMarkFilter*>(waterMarkFilter_.get());
        FALSE_RETURN_V_MSG_E(filter != nullptr, MSERR_INVALID_OPERATION, "WaterMark filter is nullptr");
        filter->SetVideoResize(inputVideoWidth_, inputVideoHeight_);
        return MSERR_OK;
    }
    // Pure resize path: create VideoResizeOpenGLFilter (decoupled from WaterMarkFilter)
    if (videoResizeOpenGLFilter_ == nullptr) {
        videoResizeOpenGLFilter_ = Pipeline::FilterFactory::Instance()
            .CreateFilter<Pipeline::VideoResizeOpenGLFilter>(
                "VideoResizeOpenGL", Pipeline::FilterType::FILTERTYPE_VIDRESIZE_OPENGL);
    }
    FALSE_RETURN_V_MSG_E(videoResizeOpenGLFilter_ != nullptr, MSERR_INVALID_OPERATION,
        "VideoResizeOpenGL filter is nullptr");
    videoResizeOpenGLFilter_->SetVideoResize(inputVideoWidth_, inputVideoHeight_);
    return MSERR_OK;
}

void HiTransCoderImpl::AppendTranscoderMediaInfo()
{
    MEDIA_LOG_I("HiTransCoderImplAppendTranscoderMediaInfo");
    
    std::shared_ptr<Meta> meta = std::make_shared<Meta>();
    meta->SetData(Tag::AV_TRANSCODER_ERR_CODE, errCode_);
    meta->SetData(Tag::AV_TRANSCODER_ERR_MSG, errMsg_);
    meta->SetData(Tag::AV_TRANSCODER_SOURCE_DURATION, durationMs_.load());
    meta->SetData(Tag::AV_TRANSCODER_TRANSCODER_DURATION, static_cast<int32_t>(transcoderTotalDuration_.load()));

    AppendSrcMediaInfo(meta);
    AppendDstMediaInfo(meta);
    AppendMediaInfo(meta, instanceId_);
}

void HiTransCoderImpl::AppendSrcMediaInfo(std::shared_ptr<Meta> meta)
{
    FALSE_RETURN_MSG(meta != nullptr, "meta is invalid.");
    std::string srcAudioMime;
    srcAudioFormat_->Get<Tag::MIME_TYPE>(srcAudioMime);
    meta->SetData(Tag::AV_TRANSCODER_SRC_AUDIO_MIME, srcAudioMime);
    std::string srcVideoMime;
    srcVideoFormat_->Get<Tag::MIME_TYPE>(srcVideoMime);
    meta->SetData(Tag::AV_TRANSCODER_SRC_VIDEO_MIME, srcVideoMime);

    int64_t srcVideoBitrate = 0;
    (void)srcVideoFormat_->Get<Tag::MEDIA_BITRATE>(srcVideoBitrate);
    meta->SetData(Tag::AV_TRANSCODER_SRC_VIDEO_BITRATE, static_cast<int32_t>(srcVideoBitrate));

    bool isHdrVivid = false;
    (void)srcVideoFormat_->Get<Tag::VIDEO_IS_HDR_VIVID>(isHdrVivid);
    if (isHdrVivid) {
        meta->SetData(Tag::AV_TRANSCODER_SRC_HDR_TYPE, 1);
    } else {
        meta->SetData(Tag::AV_TRANSCODER_SRC_HDR_TYPE, 0);
    }
    int32_t srcAudioSampleRate = 0;
    (void)srcAudioFormat_->Get<Tag::AUDIO_SAMPLE_RATE>(srcAudioSampleRate);
    meta->SetData(Tag::AV_TRANSCODER_SRC_AUDIO_SAMPLE_RATE, srcAudioSampleRate);
    int32_t srcAudiohannels = 0;
    (void)srcAudioFormat_->Get<Tag::AUDIO_CHANNEL_COUNT>(srcAudiohannels);
    meta->SetData(Tag::AV_TRANSCODER_SRC_AUDIO_CHANNEL_COUNT, srcAudiohannels);
    int64_t srcAudioBitrate = 0;
    (void)srcAudioFormat_->Get<Tag::MEDIA_BITRATE>(srcAudioBitrate);
    meta->SetData(Tag::AV_TRANSCODER_SRC_AUDIO_BITRATE, static_cast<int32_t>(srcAudioBitrate));
}

void HiTransCoderImpl::AppendDstMediaInfo(std::shared_ptr<Meta> meta)
{
    FALSE_RETURN_MSG(meta != nullptr, "meta is invalid.");
    std::string dstAudioMime;
    audioEncFormat_->Get<Tag::MIME_TYPE>(dstAudioMime);
    meta->SetData(Tag::AV_TRANSCODER_DST_AUDIO_MIME, dstAudioMime);
    std::string dstVideoMime;
    videoEncFormat_->Get<Tag::MIME_TYPE>(dstVideoMime);
    meta->SetData(Tag::AV_TRANSCODER_DST_VIDEO_MIME, dstVideoMime);
    int64_t dstVideoBitrate = 0;
    (void)videoEncFormat_->Get<Tag::MEDIA_BITRATE>(dstVideoBitrate);
    meta->SetData(Tag::AV_TRANSCODER_DST_VIDEO_BITRATE, static_cast<int32_t>(dstVideoBitrate));
    meta->SetData(Tag::AV_TRANSCODER_DST_HDR_TYPE, 0);
    int32_t colorSpaceFormat = 0;
    (void)videoEncFormat_->Get<Tag::AV_TRANSCODER_DST_COLOR_SPACE>(colorSpaceFormat);
    meta->SetData(Tag::AV_TRANSCODER_DST_COLOR_SPACE, colorSpaceFormat);
    if (IsHdrColorSpace(colorSpaceFormat)) {
        meta->SetData(Tag::AV_TRANSCODER_DST_HDR_TYPE, 1);
    }
    bool enableBFrame = false;
    (void)videoEncFormat_->Get<Tag::AV_TRANSCODER_ENABLE_B_FRAME>(enableBFrame);
    meta->SetData(Tag::VIDEO_ENCODER_ENABLE_B_FRAME, enableBFrame);
    int32_t dstAudioSampleRate = 0;
    (void)audioEncFormat_->Get<Tag::AUDIO_SAMPLE_RATE>(dstAudioSampleRate);
    meta->SetData(Tag::AV_TRANSCODER_DST_AUDIO_SAMPLE_RATE, dstAudioSampleRate);
    int32_t dstAudiohannels = 0;
    (void)audioEncFormat_->Get<Tag::AUDIO_CHANNEL_COUNT>(dstAudiohannels);
    meta->SetData(Tag::AV_TRANSCODER_DST_AUDIO_CHANNEL_COUNT, dstAudiohannels);
    int64_t dstAudioBitrate = 0;
    (void)audioEncFormat_->Get<Tag::MEDIA_BITRATE>(dstAudioBitrate);
    meta->SetData(Tag::AV_TRANSCODER_DST_AUDIO_BITRATE, static_cast<int32_t>(dstAudioBitrate));
}

void HiTransCoderImpl::AppendMediaKitTranscoderMediaInfo()
{
    MEDIA_LOG_I("HiTransCoderImpl::AppendMediaKitTranscoderMediaInfo");
    
    std::vector<std::pair<std::string, std::string>> mediaInfo_;

    std::string srcAudioMime;
    srcAudioFormat_->Get<Tag::MIME_TYPE>(srcAudioMime);
    mediaInfo_.push_back({"SrcAudioMime", srcAudioMime});
    std::string srcVideoMime;
    srcVideoFormat_->Get<Tag::MIME_TYPE>(srcVideoMime);
    mediaInfo_.push_back({"SrcVideoMime", srcVideoMime});
    mediaInfo_.push_back({"SrcVideoWidth", std::to_string(inputVideoWidth_)});
    mediaInfo_.push_back({"SrcVideoHeight", std::to_string(inputVideoHeight_)});
    FALSE_RETURN_MSG(demuxerFilter_ != nullptr, "demuxerFilter_ is nullptr");
    std::shared_ptr<Meta> globalInfo = demuxerFilter_->GetGlobalMetaInfo();
    FALSE_RETURN_MSG(globalInfo != nullptr, "globalInfo is nullptr");
    FileType fileType_ = FileType::UNKNOW;
    globalInfo->GetData(Tag::MEDIA_FILE_TYPE, fileType_);
    mediaInfo_.push_back({"SrcFormat", std::to_string(static_cast<int32_t>(fileType_))});

    std::string dstAudioMime;
    audioEncFormat_->Get<Tag::MIME_TYPE>(dstAudioMime);
    mediaInfo_.push_back({"DstAudioMime", dstAudioMime});
    std::string dstVideoMime;
    videoEncFormat_->Get<Tag::MIME_TYPE>(dstVideoMime);
    mediaInfo_.push_back({"DstVideoMime", dstVideoMime});
    int64_t dstVideoBitrate = 0;
    (void)videoEncFormat_->Get<Tag::MEDIA_BITRATE>(dstVideoBitrate);
    mediaInfo_.push_back({"DstVideoBit", std::to_string(dstVideoBitrate)});
    int64_t dstAudioBitrate = 0;
    (void)audioEncFormat_->Get<Tag::MEDIA_BITRATE>(dstAudioBitrate);
    mediaInfo_.push_back({"DstAudioBit", std::to_string(dstAudioBitrate)});
    mediaInfo_.push_back({"DstFormat", std::to_string(static_cast<int32_t>(outputFormatType_))});
    int32_t outputVideoWidth = inputVideoWidth_;
    int32_t outputVideoHeight = inputVideoHeight_;
    (void)videoEncFormat_->GetData(Tag::VIDEO_WIDTH, outputVideoWidth);
    mediaInfo_.push_back({"DstVideoWidth", std::to_string(outputVideoWidth)});
    (void)videoEncFormat_->GetData(Tag::VIDEO_HEIGHT, outputVideoHeight);
    mediaInfo_.push_back({"DstVideoHeight", std::to_string(outputVideoHeight)});
    ReportTranscoderMediaInfo(appUid_, instanceId_, mediaInfo_, errCode_);
}

void HiTransCoderImpl::AppendMediaKitTranscoderMediaError(int32_t errCode)
{
    MEDIA_LOG_I("HiTransCoderImpl::AppendMediaKitTranscoderMediaError");
    
    std::vector<std::pair<std::string, std::string>> mediaInfo_;
    mediaInfo_.push_back({"ErrorCode", std::to_string(errCode)});

    ReportTranscoderMediaInfo(appUid_, instanceId_, mediaInfo_, errCode);
}

void HiTransCoderImpl::OnEvent(const Event &event)
{
    switch (event.type) {
        case EventType::EVENT_ERROR: {
            HandleErrorEvent(AnyCast<int32_t>(event.param));
            break;
        }
        case EventType::EVENT_COMPLETE: {
            MEDIA_LOG_I("HiTransCoderImpl EVENT_COMPLETE");
            HandleCompleteEvent();
            break;
        }
        default:
            break;
    }
}

void HiTransCoderImpl::HandleErrorEvent(int32_t errorCode)
{
    {
        std::unique_lock<std::mutex> lock(ignoreErrorMutex_);
        FALSE_RETURN_MSG(!ignoreError_, "igore this error event!");
        ignoreError_ = true;
    }
    MEDIA_LOG_W("OnError, errorCode: " PUBLIC_LOG_D32, errorCode);
    AppendMediaKitTranscoderMediaError(errorCode);
    FALSE_RETURN_MSG(callbackLooper_ != nullptr, "callbackLooper is nullptr");
    callbackLooper_->StopReportMediaProgress();
    if (pipeline_ != nullptr) {
        pipeline_->Pause();
    }
    callbackLooper_->OnError(TRANSCODER_ERROR_INTERNAL, errorCode);
}

void HiTransCoderImpl::HandleCompleteEvent()
{
    FALSE_RETURN_MSG(callbackLooper_ != nullptr, "callbackLooper is nullptr");
    callbackLooper_->StopReportMediaProgress();
    auto ptr = obs_.lock();
    if (ptr != nullptr) {
        ptr->OnInfo(TransCoderOnInfoType::INFO_TYPE_PROGRESS_UPDATE, TRANSCODER_COMPLETE_PROGRESS);
        ptr->OnInfo(TransCoderOnInfoType::INFO_TYPE_TRANSCODER_COMPLETED, 0);
    }
    if (pipeline_ != nullptr) {
        MEDIA_LOG_I("complete, stop in");
        int32_t ret = TransTranscoderStatus(pipeline_->Stop());
        MEDIA_LOG_I("complete, stop out, ret: " PUBLIC_LOG_D32, ret);
    }
    {
        std::lock_guard<std::mutex> lock(handleCompleteMutex_);
        callbackLooper_->Stop();
    }
}

Status HiTransCoderImpl::LinkAudioDecoderFilter(const std::shared_ptr<Pipeline::Filter>& preFilter,
    Pipeline::StreamType type)
{
    MEDIA_LOG_I("HiTransCoderImpl::LinkAudioDecoderFilter()");
    audioDecoderFilter_ = Pipeline::FilterFactory::Instance().CreateFilter<Pipeline::AudioDecoderFilter>(
        "audioDecoderFilter", Pipeline::FilterType::FILTERTYPE_ADEC);
    FALSE_RETURN_V_MSG_E(audioDecoderFilter_ != nullptr, Status::ERROR_NULL_POINTER,
        "audioDecoderFilter is nullptr");
    audioDecoderFilter_->Init(transCoderEventReceiver_, transCoderFilterCallback_);
    Status ret = pipeline_->LinkFilters(preFilter, {audioDecoderFilter_}, type);
    FALSE_RETURN_V_MSG_E(ret == Status::OK, ret, "Add audioDecoderFilter to pipeline fail");
    std::string audioEncCodec;
    audioEncFormat_->Get<Tag::MIME_TYPE>(audioEncCodec);
    if (audioEncCodec == Plugins::MimeType::AUDIO_RAW) {
        MEDIA_LOG_I("Audio decoder to muxer, outType: %{public}s", audioEncCodec.c_str());
        audioDecoderFilter_->ResetOutputAudioMime(audioEncCodec);
    }
    return Status::OK;
}

Status HiTransCoderImpl::LinkAudioEncoderFilter(const std::shared_ptr<Pipeline::Filter>& preFilter,
    Pipeline::StreamType type)
{
    MEDIA_LOG_I("HiTransCoderImpl::LinkAudioEncoderFilter()");
    audioEncoderFilter_ = Pipeline::FilterFactory::Instance().CreateFilter<Pipeline::AudioEncoderFilter>
        ("audioEncoderFilter", Pipeline::FilterType::FILTERTYPE_AENC);
    FALSE_RETURN_V_MSG_E(audioEncoderFilter_ != nullptr, Status::ERROR_NULL_POINTER,
        "audioEncoderFilter is nullptr");
    audioEncFormat_->Set<Tag::APP_TOKEN_ID>(appTokenId_);
    audioEncFormat_->Set<Tag::APP_UID>(appUid_);
    audioEncFormat_->Set<Tag::APP_PID>(appPid_);
    audioEncFormat_->Set<Tag::APP_FULL_TOKEN_ID>(appFullTokenId_);
    audioEncFormat_->Set<Tag::AUDIO_ENCODE_PTS_MODE>(FIRST_INPUT_START_ENCODE_PTS_MODE);
    Status ret = audioEncoderFilter_->SetCodecFormat(audioEncFormat_);
    FALSE_RETURN_V_MSG_E(ret == Status::OK, ret, "audioEncoderFilter SetCodecFormat fail");
    ret = audioEncoderFilter_->SetTranscoderMode();
    FALSE_RETURN_V_MSG_E(ret == Status::OK, ret, "audioEncoderFilter SetTranscoderMode fail");
    if (startTimeMs_ > 0 || endTimeMs_ > 0) {
        audioEncoderFilter_->SetClipTimeFilterNeeded();
    }
    if (!isExistVideoTrack_ && isExistAudioTrack_) {
        ret = audioEncoderFilter_->SetPureAudioMode();
        FALSE_RETURN_V_MSG_E(ret == Status::OK, ret, "audioEncoderFilter SetPureAudioMode fail");
    }
    audioEncoderFilter_->Init(transCoderEventReceiver_, transCoderFilterCallback_);
    ret = audioEncoderFilter_->Configure(audioEncFormat_);
    if (ret == Status::ERROR_UNKNOWN) {
        ret = Status::ERROR_AUD_ENC_FAILED;
    }
    FALSE_RETURN_V_MSG_E(ret == Status::OK, ret, "audioEncoderFilter Configure fail");
    ret = pipeline_->LinkFilters(preFilter, {audioEncoderFilter_}, type);
    FALSE_RETURN_V_MSG_E(ret == Status::OK, ret, "Add audioEncoderFilter to pipeline fail");
    return Status::OK;
}

Status HiTransCoderImpl::LinkVideoDecoderFilter(const std::shared_ptr<Pipeline::Filter>& preFilter,
    Pipeline::StreamType type)
{
    MEDIA_LOG_I("HiTransCoderImpl::LinkVideoDecoderFilter()");
    videoDecoderFilter_ = Pipeline::FilterFactory::Instance().CreateFilter<Pipeline::SurfaceDecoderFilter>(
        "surfacedecoder", Pipeline::FilterType::FILTERTYPE_VIDEODEC);
    FALSE_RETURN_V_MSG_E(videoDecoderFilter_ != nullptr, Status::ERROR_NULL_POINTER,
        "videoDecoderFilter is nullptr");
    std::string bundleName_ = GetClientBundleName(appUid_);
    videoDecoderFilter_->SetCallingInfo(appUid_, appPid_, bundleName_, instanceId_);
    // Configure HDR format before SetCodecFormat so that AV_TRANSCODER_DST_COLOR_SPACE
    // is set in videoEncFormat_ and the decoder filter can read it to skip VPE conversion.
    ConfigureVideoEncoderHdrFormat();
    videoDecoderFilter_->SetCodecFormat(videoEncFormat_);
    videoDecoderFilter_->Init(transCoderEventReceiver_, transCoderFilterCallback_);
    videoDecoderFilter_->SetTransCoderMode();
    Status ret = pipeline_->LinkFilters(preFilter, {videoDecoderFilter_}, type);
    FALSE_RETURN_V_MSG_E(ret == Status::OK, ret, "Add videoDecoderFilter to pipeline failed");
    return Status::OK;
}

Status HiTransCoderImpl::LinkVideoEncoderFilter(const std::shared_ptr<Pipeline::Filter>& preFilter,
    Pipeline::StreamType type)
{
    MEDIA_LOG_I("HiTransCoderImpl::LinkVideoEncoderFilter()");
    videoEncoderFilter_ = Pipeline::FilterFactory::Instance().CreateFilter<Pipeline::SurfaceEncoderFilter>
        ("videoEncoderFilter", Pipeline::FilterType::FILTERTYPE_VENC);
    FALSE_RETURN_V_MSG_E(videoEncoderFilter_ != nullptr, Status::ERROR_NULL_POINTER,
        "videoEncoderFilter is nullptr");
    FALSE_RETURN_V_MSG_E(videoEncFormat_ != nullptr, Status::ERROR_NULL_POINTER,
        "videoEncFormat is nullptr");
    std::string bundleName_ = GetClientBundleName(appUid_);
    videoEncoderFilter_->SetCallingInfo(appUid_, appPid_, bundleName_, instanceId_);
    if (bitrateMode == Plugins::VideoEncodeBitrateMode::SQR) {
        std::string videoMime;
        videoEncFormat_->GetData(Tag::MIME_TYPE, videoMime);
        if (videoMime != Plugins::MimeType::VIDEO_HEVC) {
            MEDIA_LOG_W("SQR mode is only supported for HEVC output, current mime: %{public}s, fallback to VBR",
                videoMime.c_str());
            bitrateMode = Plugins::VideoEncodeBitrateMode::VBR;
        }
    }
    videoEncFormat_->Set<Tag::VIDEO_ENCODE_BITRATE_MODE>(bitrateMode);
    ConfigureVideoEncoderHdrFormat();
    Status ret = videoEncoderFilter_->SetCodecFormat(videoEncFormat_);
    FALSE_RETURN_V_MSG_E(ret == Status::OK, ret, "videoEncoderFilter SetCodecFormat fail");
    videoEncoderFilter_->Init(transCoderEventReceiver_, transCoderFilterCallback_);
    ret = videoEncoderFilter_->SetTransCoderMode();
    FALSE_RETURN_V_MSG_E(ret == Status::OK, ret, "videoEncoderFilter SetTransCoderMode fail");
    int32_t encWidth = 0;
    int32_t encHeight = 0;
    videoEncFormat_->GetData(Tag::VIDEO_WIDTH, encWidth);
    videoEncFormat_->GetData(Tag::VIDEO_HEIGHT, encHeight);
    videoEncoderFilter_->SetTransCoderCapabilityCheckInfo(encWidth, encHeight);
    ret = videoEncoderFilter_->Configure(videoEncFormat_);
    FALSE_RETURN_V_MSG_E(ret == Status::OK, ret, "videoEncoderFilter Configure fail");
    ret = pipeline_->LinkFilters(preFilter, {videoEncoderFilter_}, type);
    FALSE_RETURN_V_MSG_E(ret == Status::OK, ret, "Add videoEncoderFilter to pipeline fail");
    return Status::OK;
}

Status HiTransCoderImpl::LinkVideoResizeFilter(const std::shared_ptr<Pipeline::Filter>& preFilter,
    Pipeline::StreamType type)
{
    MEDIA_LOG_I("HiTransCoderImpl::LinkVideoResizeFilter()");
    videoResizeFilter_ = Pipeline::FilterFactory::Instance().CreateFilter<Pipeline::VideoResizeFilter>
        ("videoResizeFilter", Pipeline::FilterType::FILTERTYPE_VIDRESIZE);
    FALSE_RETURN_V_MSG_E(videoResizeFilter_ != nullptr, Status::ERROR_NULL_POINTER,
        "videoResizeFilter_ is nullptr");
    videoResizeFilter_->Init(transCoderEventReceiver_, transCoderFilterCallback_);
    Status ret = videoResizeFilter_->Configure(videoEncFormat_);
    if (ret == Status::ERROR_UNKNOWN) {
        ret = Status::ERROR_VID_RESIZE_FAILED;
    }
    FALSE_RETURN_V_MSG_E(ret == Status::OK, ret, "videoEncoderFilter Configure fail");
    ret = pipeline_->LinkFilters(preFilter, {videoResizeFilter_}, type);
    FALSE_RETURN_V_MSG_E(ret == Status::OK, ret, "Add videoResizeFilter to pipeline fail");
    return Status::OK;
}

Status HiTransCoderImpl::LinkMuxerFilter(const std::shared_ptr<Pipeline::Filter>& preFilter,
    Pipeline::StreamType type)
{
    MEDIA_LOG_I("HiTransCoderImpl::LinkMuxerFilter()");
    Status ret = Status::OK;
    {
        std::lock_guard<std::mutex> lk(muxerMutex_);
        if (muxerFilter_ == nullptr) {
            muxerFilter_ = Pipeline::FilterFactory::Instance().CreateFilter<Pipeline::MuxerFilter>
                ("muxerFilter", Pipeline::FilterType::FILTERTYPE_MUXER);
            FALSE_RETURN_V_MSG_E(muxerFilter_ != nullptr, Status::ERROR_NULL_POINTER,
                "muxerFilter is nullptr");
            muxerFilter_->Init(transCoderEventReceiver_, transCoderFilterCallback_);
            ret = muxerFilter_->SetOutputParameter(appUid_, appPid_, fd_.Get(), outputFormatType_);
            if (ret != Status::OK) {
                MEDIA_LOG_E("muxerFilter SetOutputParameter fail");
                if (fd_.Get() >= 0) {
                    fd_.Reset();
                }
                return ret;
            }
            muxerFilter_->SetParameter(muxerFormat_);
            muxerFilter_->SetTransCoderMode();
            MEDIA_LOG_I("HiTransCoder CloseFd, fd is %{public}d", fd_.Get());
            if (fd_.Get() >= 0) {
                fd_.Reset();
            }
        }
    }
    ret = pipeline_->LinkFilters(preFilter, {muxerFilter_}, type);
    FALSE_RETURN_V_MSG_E(ret == Status::OK, ret, "Add muxerFilter to pipeline fail");
    return Status::OK;
}

Status HiTransCoderImpl::OnCallback(std::shared_ptr<Pipeline::Filter> filter, const Pipeline::FilterCallBackCommand cmd,
    Pipeline::StreamType outType)
{
    FALSE_RETURN_V_MSG_E(filter != nullptr, Status::ERROR_NULL_POINTER, "filter is nullptr");
    MEDIA_LOG_I("HiTransCoderImpl::OnCallback filter, outType: %{public}d  %{public}d",
        static_cast<int32_t>(outType), static_cast<int32_t>(filter->GetFilterType()));
    std::string audioEncCodec;
    if (cmd == Pipeline::FilterCallBackCommand::NEXT_FILTER_NEEDED) {
        switch (outType) {
            case Pipeline::StreamType::STREAMTYPE_RAW_AUDIO:
                if (filter->GetFilterType() == Pipeline::FilterType::FILTERTYPE_DEMUXER) {
                    FALSE_RETURN_V(!isAudioTrackLinked_, Status::OK);
                    isAudioTrackLinked_ = true;
                }
                audioEncFormat_->Get<Tag::MIME_TYPE>(audioEncCodec);
                if (audioEncCodec == Plugins::MimeType::AUDIO_RAW) {
                    MEDIA_LOG_I("Audio encoder type is %{public}s, link to muxer", audioEncCodec.c_str());
                    return LinkMuxerFilter(filter, Pipeline::StreamType::STREAMTYPE_RAW_AUDIO);
                }
                return LinkAudioEncoderFilter(filter, outType);
            case Pipeline::StreamType::STREAMTYPE_ENCODED_AUDIO:
                if (filter->GetFilterType() == Pipeline::FilterType::FILTERTYPE_DEMUXER) {
                    FALSE_RETURN_V(!isAudioTrackLinked_, Status::OK);
                    isAudioTrackLinked_ = true;
                    FALSE_RETURN_V_NOLOG(skipProcessFilterFlag_.CanSkipAudioDecAndEncFilter(),
                        LinkAudioDecoderFilter(filter, outType));
                }
                return LinkMuxerFilter(filter, outType);
            case Pipeline::StreamType::STREAMTYPE_RAW_VIDEO: {
                Pipeline::FilterType filterType = filter->GetFilterType();
                if (filterType == Pipeline::FilterType::FILTERTYPE_VIDEODEC &&
                    skipProcessFilterFlag_.AddVideoWaterMarkFilter()) {
                    MEDIA_LOG_I("Pipeline build mode: add watermark");
                    return LinkWaterMark(filter, outType);
                }
 
                // 解码器特殊处理：可能需要先链接resize
                if (filterType == Pipeline::FilterType::FILTERTYPE_VIDEODEC &&
                    !skipProcessFilterFlag_.CanSkipVideoResizeFilter() &&
                    !skipProcessFilterFlag_.AddVideoWaterMarkFilter()) {
                    MEDIA_LOG_I("Pipeline build mode: video resize (OpenGL)");
                    int32_t resizeRet = AddVideoResize(inputVideoWidth_, inputVideoHeight_);
                    FALSE_RETURN_V_MSG_E(resizeRet == MSERR_OK, Status::ERROR_NULL_POINTER,
                        "AddVideoResize failed, ret: %{public}d", resizeRet);
                    return LinkVideoResizeOpenGLFilter(filter, outType);
                }
                // 水印或其他：直接链接编码器
                return LinkVideoEncoderFilter(filter, outType);
            }
            case Pipeline::StreamType::STREAMTYPE_ENCODED_VIDEO:
                if (filter->GetFilterType() == Pipeline::FilterType::FILTERTYPE_DEMUXER) {
                    FALSE_RETURN_V(!isVideoTrackLinked_, Status::OK);
                    isVideoTrackLinked_ = true;
                    return LinkVideoDecoderFilter(filter, outType);
                }
                return LinkMuxerFilter(filter, outType);
            default:
                break;
        }
    }
    return Status::OK;
}

int32_t HiTransCoderImpl::GetCurrentTime(int32_t& currentPositionMs)
{
    FALSE_RETURN_V(muxerFilter_ != nullptr, MSERR_UNKNOWN);
    int64_t currentPts = muxerFilter_->GetCurrentPtsMs();
    if (startTimeMs_ > 0 || endTimeMs_ > 0) {
        // In time range mode, MuxerFilter adjusts PTS to start from 0,
        // so currentPts is already in the range-relative domain (0 ~ effectiveDuration).
        currentPositionMs = (currentPts > 0) ? static_cast<int32_t>(currentPts) : 0;
    } else {
        currentPositionMs = (int32_t)currentPts;
    }
    return MSERR_OK;
}

int32_t HiTransCoderImpl::GetDuration(int32_t& durationMs)
{
    // In time range mode, report the effective slice duration (effectiveEnd - effectiveStart).
    if (startTimeMs_ >= 0 || endTimeMs_ >= 0) {
        int64_t effectiveStart = (startTimeMs_ > 0) ? startTimeMs_ : 0;
        int64_t sourceDurationMs = durationMs_.load();
        int64_t effectiveEnd = (endTimeMs_ > 0) ? endTimeMs_ : sourceDurationMs;
        durationMs = static_cast<int32_t>(effectiveEnd - effectiveStart);
    } else {
        durationMs = durationMs_.load();
    }
    return MSERR_OK;
}

int64_t HiTransCoderImpl::GetCurrentMillisecond()
{
    std::chrono::system_clock::duration duration = std::chrono::system_clock::now().time_since_epoch();
    int64_t time = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
    return time;
}

void HiTransCoderImpl::CollectionErrorInfo(int32_t errCode, const std::string& errMsg)
{
    MEDIA_LOG_E_SHORT("Error: " PUBLIC_LOG_S, errMsg.c_str());
    errCode_ = errCode;
    errMsg_ = errMsg;
}

Status HiTransCoderImpl::BuildPipeline(VideoProcessMode mode, int32_t outputVideoWidth, int32_t outputVideoHeight)
{
    MEDIA_LOG_I("Building video pipeline: %{public}s", GetModeString(mode).c_str());
 
    switch (mode) {
        case VideoProcessMode::DECODER_TO_ENCODER:
            return ConnectDecoderToEncoder();
 
        case VideoProcessMode::DECODER_RESIZE_ENCODER:
            return ConnectDecoderResizeOpenGLEncoder(outputVideoWidth, outputVideoHeight);
 
        case VideoProcessMode::DECODER_WATERMARK_ENCODER:
        case VideoProcessMode::DECODER_RESIZE_WATERMARK_ENCODER:
            return ConnectDecoderWatermarkEncoder(outputVideoWidth, outputVideoHeight);

        default:
            MEDIA_LOG_E("Invalid video process mode: %{public}d", static_cast<int>(mode));
            return ConnectDecoderToEncoder();
    }
}
 
VideoProcessMode HiTransCoderImpl::DetermineProcessMode()
{
    bool hasResize = (videoResizeFilter_ != nullptr || videoResizeOpenGLFilter_ != nullptr) &&
                     !skipProcessFilterFlag_.CanSkipVideoResizeFilter();
    bool hasWatermark = waterMarkFilter_ != nullptr && skipProcessFilterFlag_.AddVideoWaterMarkFilter();
    if (hasResize && hasWatermark) {
        MEDIA_LOG_I("ProcessMode is DECODER_RESIZE_WATERMARK_ENCODER");
        return VideoProcessMode::DECODER_RESIZE_WATERMARK_ENCODER;
    } else if (hasResize) {
        MEDIA_LOG_I("ProcessMode is DECODER_RESIZE_ENCODER");
        return VideoProcessMode::DECODER_RESIZE_ENCODER;
    } else if (hasWatermark) {
        MEDIA_LOG_I("ProcessMode is DECODER_WATERMARK_ENCODER");
        return VideoProcessMode::DECODER_WATERMARK_ENCODER;
    }
    MEDIA_LOG_I("ProcessMode is DECODER_TO_ENCODER");
    return VideoProcessMode::DECODER_TO_ENCODER;
}
 
std::string HiTransCoderImpl::GetModeString(VideoProcessMode mode)
{
    switch (mode) {
        case VideoProcessMode::DECODER_TO_ENCODER:
            return "Decoder -> Encoder";
        case VideoProcessMode::DECODER_RESIZE_ENCODER:
            return "Decoder -> Resize -> Encoder";
        case VideoProcessMode::DECODER_WATERMARK_ENCODER:
        case VideoProcessMode::DECODER_RESIZE_WATERMARK_ENCODER:
            return "Decoder(RESIZE) -> Watermark -> Encoder";
        default:
            return "Unknown Mode";
    }
}

Status HiTransCoderImpl::LinkWaterMark(const std::shared_ptr<Pipeline::Filter>& preFilter,
    Pipeline::StreamType type)
{
    MEDIA_LOG_I("HiTransCoderImpl::LinkWaterMark()");
    auto filter = static_cast<Pipeline::WaterMarkFilter*>(waterMarkFilter_.get());
    FALSE_RETURN_V_MSG_E(filter != nullptr, Status::ERROR_NULL_POINTER,
        "WaterMarkFilter is nullptr");
    // 将HDR编码格式传递给WaterMarkFilter，使其感知HDR模式并配置10bit管线
    filter->SetCodecFormat(videoEncFormat_);
    filter->SetCallingInfo(appUid_, appPid_, GetClientBundleName(appUid_), instanceId_);
    filter->Init(transCoderEventReceiver_, transCoderFilterCallback_);
    FALSE_RETURN_V_MSG_E(pipeline_ != nullptr, Status::ERROR_NULL_POINTER,
        "pipeline_ is nullptr");
    pipeline_->LinkFilters(preFilter, {waterMarkFilter_}, type);
    return Status::OK;
}

Status HiTransCoderImpl::LinkVideoResizeOpenGLFilter(const std::shared_ptr<Pipeline::Filter>& preFilter,
    Pipeline::StreamType type)
{
    MEDIA_LOG_I("HiTransCoderImpl::LinkVideoResizeOpenGLFilter()");
    FALSE_RETURN_V_MSG_E(videoResizeOpenGLFilter_ != nullptr, Status::ERROR_NULL_POINTER,
        "VideoResizeOpenGLFilter is nullptr");
    // 将HDR编码格式传递给VideoResizeOpenGLFilter，使其感知HDR模式并配置10bit管线
    videoResizeOpenGLFilter_->SetCodecFormat(videoEncFormat_);
    videoResizeOpenGLFilter_->SetCallingInfo(appUid_, appPid_, GetClientBundleName(appUid_), instanceId_);
    videoResizeOpenGLFilter_->Init(transCoderEventReceiver_, transCoderFilterCallback_);
    FALSE_RETURN_V_MSG_E(pipeline_ != nullptr, Status::ERROR_NULL_POINTER, "pipeline_ is nullptr");
    pipeline_->LinkFilters(preFilter, {videoResizeOpenGLFilter_}, type);
    return Status::OK;
}


/**
 *  连接：解码器 -> 编码器
 */
Status HiTransCoderImpl::ConnectDecoderToEncoder()
{
    FALSE_RETURN_V_MSG_E(videoEncoderFilter_ != nullptr && videoDecoderFilter_ != nullptr,
    Status::ERROR_NULL_POINTER, "VideoDecoder or VideoEncoder is nullptr");
    sptr<Surface> encoderFilterSurface = videoEncoderFilter_->GetInputSurface();
    FALSE_RETURN_V_MSG_E(encoderFilterSurface != nullptr, Status::ERROR_GET_INPUT_SURFACE_FAILED,
        "encoderFilterSurface is nullptr");
    return videoDecoderFilter_->SetOutputSurface(encoderFilterSurface);
}
 
/**
 *  连接：解码器 -> 分辨率修改 -> 编码器
 */
Status HiTransCoderImpl::ConnectDecoderResizeEncoder(int32_t outputVideoWidth, int32_t outputVideoHeight)
{
    FALSE_RETURN_V_MSG_E(videoEncoderFilter_ != nullptr && videoDecoderFilter_ != nullptr &&
        videoResizeFilter_ != nullptr, Status::ERROR_NULL_POINTER,
        "VideoDecoder, VideoEncoder or VideoResizeFilter is nullptr");
 
    // 解码器 -> 分辨率修改
    sptr<Surface> resizeSurface = videoResizeFilter_->GetInputSurface();
    FALSE_RETURN_V_MSG_E(resizeSurface != nullptr, Status::ERROR_GET_INPUT_SURFACE_FAILED,
        "resizeSurface is nullptr");
    Status ret = videoDecoderFilter_->SetOutputSurface(resizeSurface);
    FALSE_RETURN_V_MSG_E(ret == Status::OK, ret, "videoDecoderFilter_ setOutputSurface failed");
 
    // 分辨率修改 -> 编码器
    sptr<Surface> encoderSurface = videoEncoderFilter_->GetInputSurface();
    FALSE_RETURN_V_MSG_E(encoderSurface != nullptr, Status::ERROR_GET_INPUT_SURFACE_FAILED,
        "encoderSurface is nullptr");
 
    return videoResizeFilter_->SetOutputSurface(encoderSurface, outputVideoWidth, outputVideoHeight);
}

/**
*  连接：解码器 -> OpenGL分辨率修改 -> 编码器
*/
Status HiTransCoderImpl::ConnectDecoderResizeOpenGLEncoder(int32_t outputVideoWidth, int32_t outputVideoHeight)
{
    FALSE_RETURN_V_MSG_E(videoEncoderFilter_ != nullptr && videoDecoderFilter_ != nullptr &&
        videoResizeOpenGLFilter_ != nullptr, Status::ERROR_NULL_POINTER,
        "VideoDecoder, VideoEncoder or VideoResizeOpenGLFilter is nullptr");
    auto filter = videoResizeOpenGLFilter_.get();

    // 解码器 -> OpenGL分辨率修改
    sptr<Surface> resizeSurface = filter->GetInputSurface();
    FALSE_RETURN_V_MSG_E(resizeSurface != nullptr, Status::ERROR_GET_INPUT_SURFACE_FAILED,
        "resizeSurface is nullptr");
    Status ret = videoDecoderFilter_->SetOutputSurface(resizeSurface);
    FALSE_RETURN_V_MSG_E(ret == Status::OK, ret, "videoDecoderFilter_ setOutputSurface failed");

    // OpenGL分辨率修改 -> 编码器
    sptr<Surface> encoderSurface = videoEncoderFilter_->GetInputSurface();
    FALSE_RETURN_V_MSG_E(encoderSurface != nullptr, Status::ERROR_GET_INPUT_SURFACE_FAILED,
        "encoderSurface is nullptr");

    return filter->SetOutputSurface(encoderSurface, outputVideoWidth, outputVideoHeight, rotation_);
}
 
/**
*  连接：解码器 -> 水印 -> 编码器
*/
Status HiTransCoderImpl::ConnectDecoderWatermarkEncoder(int32_t outputVideoWidth, int32_t outputVideoHeight)
{
    FALSE_RETURN_V_MSG_E(videoEncoderFilter_ != nullptr && videoDecoderFilter_ != nullptr,
        Status::ERROR_NULL_POINTER, "VideoEncoder or VideoDecoder is nullptr");
    auto filter = static_cast<Pipeline::WaterMarkFilter*>(waterMarkFilter_.get());
    FALSE_RETURN_V_MSG_E(filter != nullptr,
        Status::ERROR_NULL_POINTER, "waterMarkFilter is nullptr");
 
    // 解码器 -> 水印
    sptr<Surface> waterMarkFilterSurface = filter->GetInputSurface();
    FALSE_RETURN_V_MSG_E(waterMarkFilterSurface != nullptr, Status::ERROR_GET_INPUT_SURFACE_FAILED,
        "waterMarkFilterSurface is nullptr");
    Status ret = videoDecoderFilter_->SetOutputSurface(waterMarkFilterSurface);
    FALSE_RETURN_V_MSG_E(ret == Status::OK, ret, "videoDecoderFilter_ setOutputSurface failed");
 
    // 水印 -> 编码器
    sptr<Surface> encoderSurface = videoEncoderFilter_->GetInputSurface();
    FALSE_RETURN_V_MSG_E(encoderSurface != nullptr, Status::ERROR_GET_INPUT_SURFACE_FAILED,
        "encoderSurface is nullptr");
 
    return filter->SetOutputSurface(encoderSurface, outputVideoWidth, outputVideoHeight, rotation_);
}
} // namespace MEDIA
} // namespace OHOS
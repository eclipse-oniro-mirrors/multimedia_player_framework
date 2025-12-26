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
#include <sys/syscall.h>
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
}

namespace OHOS {
namespace Media {
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
        OnEvent({"TranscoderEngine", EventType::EVENT_ERROR, MSERR_UNSUPPORT_SOURCE});
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
            meta->GetData(Tag::VIDEO_WIDTH, inputVideoWidth_);
            meta->GetData(Tag::VIDEO_HEIGHT, inputVideoHeight_);
            isExistVideoTrack_ = true;
            isInitializeVideoEncFormat = true;
        } else if (!isInitializeAudioEncFormat && (trackMime.find("audio/") == 0)) {
            (void)SetValueByType(meta, audioEncFormat_);
            (void)SetValueByType(meta, srcAudioFormat_);
            (void)SetValueByType(meta, muxerFormat_);
            isInitializeAudioEncFormat = true;
        }
    }
    if (!isExistVideoTrack_) {
        MEDIA_LOG_E("No video track found.");
        OnEvent({"TranscoderEngine", EventType::EVENT_ERROR, MSERR_UNSUPPORT_VID_SRC_TYPE});
    }
}

void HiTransCoderImpl::ConfigureDefaultParameter()
{
    ConfigureVideoDefaultEncFormat();
    ConfigureVideoBitrate();
    ConfigureAudioDefaultEncFormat();
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
    MEDIA_LOG_I("trackCount: %{public}d", trackCount);
    if (trackCount == 0) {
        MEDIA_LOG_E("No track found in the source");
        CollectionErrorInfo(TransTranscoderStatus(Status::ERROR_NO_TRACK),
            "ConfigureVideoAudioMetaData error");
        OnEvent({"TranscoderEngine", EventType::EVENT_ERROR, MSERR_UNSUPPORT_VID_SRC_TYPE});
        return Status::ERROR_NO_TRACK;
    }
    ConfigureMetaDataToTrackFormat(globalInfo, trackInfos);
    ConfigureDefaultParameter();
    return Status::OK;
}

int32_t HiTransCoderImpl::SetOutputFile(const int32_t fd)
{
    MEDIA_LOG_I("HiTransCoderImpl::SetOutputFile()");
    MEDIA_LOG_I("HiTransCoder SetOutputFile in, fd is %{public}d", fd);
    fd_ = dup(fd);
    MEDIA_LOG_I("HiTransCoder SetOutputFile dup, fd is %{public}d", fd_);
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

Status HiTransCoderImpl::ConfigureEnableBFrameEncoding(const TransCoderParam &transCoderParam)
{
    VideoEnableBFrameEncoding enableBFrameEncoding = static_cast<const VideoEnableBFrameEncoding&>(transCoderParam);
    MEDIA_LOG_I("HiTranscoderImpl::ConfigureEnableBFrameEncoding %{public}d", static_cast<int32_t>(
        enableBFrameEncoding.enableBFrame));
    videoEncFormat_->Set<Tag::AV_TRANSCODER_ENABLE_B_FRAME>(enableBFrameEncoding.enableBFrame);
    return Status::OK;
}

Status HiTransCoderImpl::ConfigureVideoBitrate()
{
    int64_t videoBitrate = 0;
    if (videoEncFormat_->Find(Tag::MEDIA_BITRATE) != videoEncFormat_->end()) {
        videoEncFormat_->Get<Tag::MEDIA_BITRATE>(videoBitrate);
    }
    MEDIA_LOG_D("get videoBitrate: %{public}d", videoBitrate);
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
        default:
            break;
    }
    return ret;
}

Status HiTransCoderImpl::ConfigureAudioParam(const TransCoderParam &transCoderParam)
{
    switch (transCoderParam.type) {
        case TransCoderPublicParamType::AUDIO_ENC_FMT: {
            AudioEnc audioEnc = static_cast<const AudioEnc&>(transCoderParam);
            MEDIA_LOG_I("HiTransCoderImpl::Configure audioEnc %{public}d", audioEnc.encFmt);
            if (inputAudioMimeType_ == Plugins::MimeType::AUDIO_AAC) {
                skipProcessFilterFlag_.isSameAudioEncFmt = true;
            }
            audioEncFormat_->Set<Tag::MIME_TYPE>(Plugins::MimeType::AUDIO_AAC);
            break;
        }
        case TransCoderPublicParamType::AUDIO_BITRATE: {
            AudioBitRate audioBitrate = static_cast<const AudioBitRate&>(transCoderParam);
            if (audioBitrate.bitRate <= 0) {
                MEDIA_LOG_E("Invalid audioBitrate.bitRate %{public}d", audioBitrate.bitRate);
                OnEvent({"TranscoderEngine", EventType::EVENT_ERROR, MSERR_PARAMETER_VERIFICATION_FAILED});
                return Status::ERROR_INVALID_PARAMETER;
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
            OnEvent({"TranscoderEngine", EventType::EVENT_ERROR, MSERR_INVALID_VAL});
            AppendMediaKitTranscoderMediaInfo();
            return MSERR_INVALID_VAL;
        }
        if (width > inputVideoWidth_ || height > inputVideoHeight_ || std::min(width, height) < MINIMUM_WIDTH_HEIGHT) {
            MEDIA_LOG_E("Output video width or height is invalid");
            CollectionErrorInfo(MSERR_PARAMETER_VERIFICATION_FAILED, "Prepare error");
            OnEvent({"TranscoderEngine", EventType::EVENT_ERROR, MSERR_PARAMETER_VERIFICATION_FAILED});
            AppendMediaKitTranscoderMediaInfo();
            return MSERR_PARAMETER_VERIFICATION_FAILED;
        }
        skipProcessFilterFlag_.isSameVideoResolution = (width == inputVideoWidth_) && (height == inputVideoHeight_);
    }
    if (skipProcessFilterFlag_.CanSkipAudioDecAndEncFilter()) {
        SkipAudioDecAndEnc();
    }
    Status ret = pipeline_->Prepare();
    if (ret != Status::OK) {
        MEDIA_LOG_E("Prepare failed with error " PUBLIC_LOG_D32, ret);
        auto errCode = TransTranscoderStatus(ret);
        CollectionErrorInfo(errCode, "Prepare error");
        AppendMediaKitTranscoderMediaInfo();
        OnEvent({"TranscoderEngine", EventType::EVENT_ERROR, errCode});
        return errCode;
    }
    Status errCode = SetSurfacePipeline(width, height);
    if (errCode == Status::ERROR_UNKNOWN) {
        errCode = Status::ERROR_SET_OUTPUT_SURFACE_FAILED;
    }
    return TransTranscoderStatus(errCode);
}

Status HiTransCoderImpl::SetSurfacePipeline(int32_t outputVideoWidth, int32_t outputVideoHeight)
{
    FALSE_RETURN_V_MSG_E(videoEncoderFilter_ != nullptr && videoDecoderFilter_ != nullptr,
        Status::ERROR_NULL_POINTER, "VideoDecoder setOutputSurface failed");
    if (!skipProcessFilterFlag_.CanSkipVideoResizeFilter() && videoResizeFilter_ != nullptr) {
        sptr<Surface> resizeFilterSurface = videoResizeFilter_->GetInputSurface();
        FALSE_RETURN_V_MSG_E(resizeFilterSurface != nullptr, Status::ERROR_GET_INPUT_SURFACE_FAILED,
            "resizeFilterSurface is nullptr");
        Status ret = videoDecoderFilter_->SetOutputSurface(resizeFilterSurface);
        FALSE_RETURN_V_MSG_E(ret == Status::OK, ret, "VideoDecoder setOutputSurface failed");
        sptr<Surface> encoderFilterSurface = videoEncoderFilter_->GetInputSurface();
        FALSE_RETURN_V_MSG_E(encoderFilterSurface != nullptr, Status::ERROR_GET_INPUT_SURFACE_FAILED,
            "encoderFilterSurface is nullptr");
        return videoResizeFilter_->SetOutputSurface(encoderFilterSurface, outputVideoWidth, outputVideoHeight);
    }
    sptr<Surface> encoderFilterSurface = videoEncoderFilter_->GetInputSurface();
    FALSE_RETURN_V_MSG_E(encoderFilterSurface != nullptr, Status::ERROR_GET_INPUT_SURFACE_FAILED,
        "encoderFilterSurface is nullptr");
    return videoDecoderFilter_->SetOutputSurface(encoderFilterSurface);
}

int32_t HiTransCoderImpl::Start()
{
    MEDIA_LOG_I("HiTransCoderImpl::Start()");
    MediaTrace trace("HiTransCoderImpl::Start()");
    startTime_ = GetCurrentMillisecond();
    int32_t ret = TransTranscoderStatus(pipeline_->Start());
    if (ret != MSERR_OK) {
        MEDIA_LOG_E("Start pipeline failed");
        CollectionErrorInfo(ret, "Start error");
        OnEvent({"TranscoderEngine", EventType::EVENT_ERROR, ret});
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
        OnEvent({"TranscoderEngine", EventType::EVENT_ERROR, ret});
    }
    if (startTime_ != -1) {
        transcoderTotalDuration_ += GetCurrentMillisecond() - startTime_;
    }
    startTime_ = -1;
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
        OnEvent({"TranscoderEngine", EventType::EVENT_ERROR, ret});
        return ret;
    }
    callbackLooper_->StartReportMediaProgress(REPORT_PROGRESS_INTERVAL);
    startTime_ = GetCurrentMillisecond();
    return MSERR_OK;
}

int32_t HiTransCoderImpl::Cancel()
{
    MEDIA_LOG_I("HiTransCoderImpl::Cancel enter");
    MediaTrace trace("HiTransCoderImpl::Cancel()");
    callbackLooper_->StopReportMediaProgress();
    int32_t ret = TransTranscoderStatus(pipeline_->Stop());
    callbackLooper_->Stop();
    if (ret != MSERR_OK) {
        MEDIA_LOG_E("Stop pipeline failed");
        CollectionErrorInfo(ret, "Cancel error");
        OnEvent({"TranscoderEngine", EventType::EVENT_ERROR, ret});
        return ret;
    }
    MEDIA_LOG_I("HiTransCoderImpl::Cancel done");
    if (startTime_ != -1) {
        transcoderTotalDuration_ += GetCurrentMillisecond() - startTime_;
    }
    startTime_ = -1;
    AppendTranscoderMediaInfo();
    ReportMediaInfo(instanceId_);
    return MSERR_OK;
}

void HiTransCoderImpl::AppendTranscoderMediaInfo()
{
    MEDIA_LOG_I("HiTransCoderImplAppendTranscoderMediaInfo");
    
    std::shared_ptr<Meta> meta = std::make_shared<Meta>();
    meta->SetData(Tag::AV_TRANSCODER_ERR_CODE, errCode_);
    meta->SetData(Tag::AV_TRANSCODER_ERR_MSG, errMsg_);
    meta->SetData(Tag::AV_TRANSCODER_SOURCE_DURATION, durationMs_.load());
    meta->SetData(Tag::AV_TRANSCODER_TRANSCODER_DURATION, static_cast<int32_t>(transcoderTotalDuration_));

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

    int64_t srcVideoBitrate;
    srcVideoFormat_->Get<Tag::MEDIA_BITRATE>(srcVideoBitrate);
    meta->SetData(Tag::AV_TRANSCODER_SRC_VIDEO_BITRATE, static_cast<int32_t>(srcVideoBitrate));

    bool isHdrVivid;
    srcVideoFormat_->Get<Tag::VIDEO_IS_HDR_VIVID>(isHdrVivid);
    if (isHdrVivid) {
        meta->SetData(Tag::AV_TRANSCODER_SRC_HDR_TYPE, 1);
    } else {
        meta->SetData(Tag::AV_TRANSCODER_SRC_HDR_TYPE, 0);
    }
    int32_t srcAudioSampleRate;
    srcAudioFormat_->Get<Tag::AUDIO_SAMPLE_RATE>(srcAudioSampleRate);
    meta->SetData(Tag::AV_TRANSCODER_SRC_AUDIO_SAMPLE_RATE, srcAudioSampleRate);
    int32_t srcAudiohannels;
    srcAudioFormat_->Get<Tag::AUDIO_CHANNEL_COUNT>(srcAudiohannels);
    meta->SetData(Tag::AV_TRANSCODER_SRC_AUDIO_CHANNEL_COUNT, srcAudiohannels);
    int64_t srcAudioBitrate;
    srcAudioFormat_->Get<Tag::MEDIA_BITRATE>(srcAudioBitrate);
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
    int64_t dstVideoBitrate;
    videoEncFormat_->Get<Tag::MEDIA_BITRATE>(dstVideoBitrate);
    meta->SetData(Tag::AV_TRANSCODER_DST_VIDEO_BITRATE, static_cast<int32_t>(dstVideoBitrate));
    meta->SetData(Tag::AV_TRANSCODER_DST_HDR_TYPE, 0);
    int32_t colorSpaceFormat = 0;
    videoEncFormat_->Get<Tag::AV_TRANSCODER_DST_COLOR_SPACE>(colorSpaceFormat);
    meta->SetData(Tag::AV_TRANSCODER_DST_COLOR_SPACE, colorSpaceFormat);
    bool enableBFrame = false;
    videoEncFormat_->Get<Tag::AV_TRANSCODER_ENABLE_B_FRAME>(enableBFrame);
    meta->SetData(Tag::VIDEO_ENCODER_ENABLE_B_FRAME, enableBFrame);
    int32_t dstAudioSampleRate;
    audioEncFormat_->Get<Tag::AUDIO_SAMPLE_RATE>(dstAudioSampleRate);
    meta->SetData(Tag::AV_TRANSCODER_DST_AUDIO_SAMPLE_RATE, dstAudioSampleRate);
    int32_t dstAudiohannels;
    audioEncFormat_->Get<Tag::AUDIO_CHANNEL_COUNT>(dstAudiohannels);
    meta->SetData(Tag::AV_TRANSCODER_DST_AUDIO_CHANNEL_COUNT, dstAudiohannels);
    int64_t dstAudioBitrate;
    audioEncFormat_->Get<Tag::MEDIA_BITRATE>(dstAudioBitrate);
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
    std::shared_ptr<Meta> globalInfo = demuxerFilter_->GetGlobalMetaInfo();
    FileType fileType_ = FileType::UNKNOW;
    globalInfo->GetData(Tag::MEDIA_FILE_TYPE, fileType_);
    mediaInfo_.push_back({"SrcFormat", std::to_string(static_cast<int32_t>(fileType_))});

    std::string dstAudioMime;
    audioEncFormat_->Get<Tag::MIME_TYPE>(dstAudioMime);
    mediaInfo_.push_back({"DstAudioMime", dstAudioMime});
    std::string dstVideoMime;
    videoEncFormat_->Get<Tag::MIME_TYPE>(dstVideoMime);
    mediaInfo_.push_back({"DstVideoMime", dstVideoMime});
    int64_t dstVideoBitrate;
    videoEncFormat_->Get<Tag::MEDIA_BITRATE>(dstVideoBitrate);
    mediaInfo_.push_back({"DstVideoBit", std::to_string(dstVideoBitrate)});
    int64_t dstAudioBitrate;
    audioEncFormat_->Get<Tag::MEDIA_BITRATE>(dstAudioBitrate);
    mediaInfo_.push_back({"DstAudioBit", std::to_string(dstAudioBitrate)});
    mediaInfo_.push_back({"DstFormat", std::to_string(static_cast<int32_t>(outputFormatType_))});
    int32_t outputVideoWidth = inputVideoWidth_;
    int32_t outputVideoHeight = inputVideoHeight_;
    videoEncFormat_->GetData(Tag::VIDEO_WIDTH, outputVideoWidth);
    mediaInfo_.push_back({"DstVideoWidth", std::to_string(outputVideoWidth)});
    videoEncFormat_->GetData(Tag::VIDEO_HEIGHT, outputVideoHeight);
    mediaInfo_.push_back({"DstVideoHeight", std::to_string(outputVideoHeight)});
    ReportTranscoderMediaInfo(appUid_, instanceId_, mediaInfo_, errCode_);
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
    callbackLooper_->Stop();
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
    audioEncFormat_->Set<Tag::AUDIO_ENCODE_PTS_MODE>(GENERATE_ENCODE_PTS_BY_INPUT_MODE);
    Status ret = audioEncoderFilter_->SetCodecFormat(audioEncFormat_);
    FALSE_RETURN_V_MSG_E(ret == Status::OK, ret, "audioEncoderFilter SetCodecFormat fail");
    ret = audioEncoderFilter_->SetTranscoderMode();
    FALSE_RETURN_V_MSG_E(ret == Status::OK, ret, "audioEncoderFilter SetTranscoderMode fail");
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
    videoDecoderFilter_->SetCodecFormat(videoEncFormat_);
    videoDecoderFilter_->Init(transCoderEventReceiver_, transCoderFilterCallback_);
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
    videoEncFormat_->Set<Tag::VIDEO_ENCODE_BITRATE_MODE>(Plugins::VideoEncodeBitrateMode::VBR);
    Status ret = videoEncoderFilter_->SetCodecFormat(videoEncFormat_);
    FALSE_RETURN_V_MSG_E(ret == Status::OK, ret, "videoEncoderFilter SetCodecFormat fail");
    videoEncoderFilter_->Init(transCoderEventReceiver_, transCoderFilterCallback_);
    ret = videoEncoderFilter_->SetTransCoderMode();
    FALSE_RETURN_V_MSG_E(ret == Status::OK, ret, "videoEncoderFilter SetTransCoderMode fail");
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
    if (muxerFilter_ == nullptr) {
        muxerFilter_ = Pipeline::FilterFactory::Instance().CreateFilter<Pipeline::MuxerFilter>
            ("muxerFilter", Pipeline::FilterType::FILTERTYPE_MUXER);
        FALSE_RETURN_V_MSG_E(muxerFilter_ != nullptr, Status::ERROR_NULL_POINTER,
            "muxerFilter is nullptr");
        muxerFilter_->Init(transCoderEventReceiver_, transCoderFilterCallback_);
        ret = muxerFilter_->SetOutputParameter(appUid_, appPid_, fd_, outputFormatType_);
        FALSE_RETURN_V_MSG_E(ret == Status::OK, ret, "muxerFilter SetOutputParameter fail");
        muxerFilter_->SetParameter(muxerFormat_);
        muxerFilter_->SetTransCoderMode();
        MEDIA_LOG_I("HiTransCoder CloseFd, fd is %{public}d", fd_);
        if (fd_ >= 0) {
            (void)::close(fd_);
            fd_ = -1;
        }
    }
    ret = pipeline_->LinkFilters(preFilter, {muxerFilter_}, type);
    FALSE_RETURN_V_MSG_E(ret == Status::OK, ret, "Add muxerFilter to pipeline fail");
    return Status::OK;
}

Status HiTransCoderImpl::OnCallback(std::shared_ptr<Pipeline::Filter> filter, const Pipeline::FilterCallBackCommand cmd,
    Pipeline::StreamType outType)
{
    MEDIA_LOG_I("HiPlayerImpl::OnCallback filter, outType: %{public}d", static_cast<int32_t>(outType));
    FALSE_RETURN_V_MSG_E(filter != nullptr, Status::ERROR_NULL_POINTER, "filter is nullptr");
    if (cmd == Pipeline::FilterCallBackCommand::NEXT_FILTER_NEEDED) {
        switch (outType) {
            case Pipeline::StreamType::STREAMTYPE_RAW_AUDIO:
                if (filter->GetFilterType() == Pipeline::FilterType::FILTERTYPE_DEMUXER) {
                    FALSE_RETURN_V(!isAudioTrackLinked_, Status::OK);
                    isAudioTrackLinked_ = true;
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
            case Pipeline::StreamType::STREAMTYPE_RAW_VIDEO:
                if (skipProcessFilterFlag_.CanSkipVideoResizeFilter() ||
                    filter->GetFilterType() == Pipeline::FilterType::FILTERTYPE_VIDRESIZE) {
                    return LinkVideoEncoderFilter(filter, outType);
                }
                return LinkVideoResizeFilter(filter, outType);
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
    currentPositionMs = (int32_t)currentPts;
    return MSERR_OK;
}

int32_t HiTransCoderImpl::GetDuration(int32_t& durationMs)
{
    durationMs = durationMs_.load();
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
} // namespace MEDIA
} // namespace OHOS

/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "sink/audio_sampleformat.h"
#include "osal/task/pipeline_threadpool.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_ONLY_PRERELEASE, LOG_DOMAIN_SYSTEM_PLAYER, "HiTransCoder" };
constexpr int32_t SAMPLE_RATE_48K = 48000;
constexpr int32_t SAMPLE_FORMAT_BIT_DEPTH_16 = 16;
}

namespace OHOS {
namespace Media {
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
        FALSE_RETURN_V(hiTransCoderImpl_ != nullptr, Status::OK); //hiTransCoderImpl_ is destructed
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
        return MSERR_UNKNOWN;
    }
    pipeline_->AddHeadFilters({demuxerFilter_});
    demuxerFilter_->Init(transCoderEventReceiver_, transCoderFilterCallback_);
    Status ret = demuxerFilter_->SetDataSource(mediaSource);
    if (ret != Status::OK) {
        MEDIA_LOG_E("SetInputFile error: demuxerFilter_->SetDataSource error");
        CollectionErrorInfo(static_cast<int32_t>(ret), "SetInputFile error");
        OnEvent({"TranscoderEngine", EventType::EVENT_ERROR, MSERR_UNSUPPORT_SOURCE});
        return static_cast<int32_t>(ret);
    }
    int64_t duration = 0;
    if (demuxerFilter_->GetDuration(duration)) {
        durationMs_ = Plugins::HstTime2Us(duration);
    } else {
        MEDIA_LOG_E("Get media duration failed");
    }
    ret = ConfigureVideoAudioMetaData();
    CreateMediaInfo(CallType::AVTRANSCODER, appUid_, instanceId_);
    return static_cast<int32_t>(ret);
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
            UpdateVideoEncFormat(meta);
            isExistVideoTrack_ = true;
            isInitializeVideoEncFormat = true;
        } else if (!isInitializeAudioEncFormat && (trackMime.find("audio/") == 0)) {
            (void)SetValueByType(meta, audioEncFormat_);
            (void)SetValueByType(meta, srcAudioFormat_);
            (void)SetValueByType(meta, muxerFormat_);
            UpdateAudioSampleFormat(trackMime, meta);
            isInitializeAudioEncFormat = true;
        }
    }
    if (!isExistVideoTrack_) {
        MEDIA_LOG_E("No video track found.");
        OnEvent({"TranscoderEngine", EventType::EVENT_ERROR, MSERR_UNSUPPORT_VID_SRC_TYPE});
    }
}

void HiTransCoderImpl::UpdateVideoEncFormat(const std::shared_ptr<Meta> &meta)
{
    std::string videoMime;
    meta->GetData(Tag::MIME_TYPE, videoMime);
    MEDIA_LOG_I("videoMime is: " PUBLIC_LOG_S, videoMime.c_str());
    FALSE_RETURN_NOLOG(dstVideoMime != Plugins::MimeType::VIDEO_HEVC);
    MEDIA_LOG_I("set the default videoEnc format to AVC");
    videoEncFormat_->Set<Tag::MIME_TYPE>(Plugins::MimeType::VIDEO_AVC);
    videoEncFormat_->Set<Tag::VIDEO_H264_PROFILE>(Plugins::VideoH264Profile::BASELINE);
    videoEncFormat_->Set<Tag::VIDEO_H264_LEVEL>(32); // 32: LEVEL 3.2
}

void HiTransCoderImpl::UpdateAudioSampleFormat(const std::string& mime, const std::shared_ptr<Meta> &meta)
{
    // The update strategy of the sample format needs to be consistent with audio_decoder_filter.
    MEDIA_LOG_I_SHORT("UpdateTrackInfoSampleFormat mime: " PUBLIC_LOG_S, mime.c_str());
    Plugins::AudioSampleFormat sampleFormat = Plugins::INVALID_WIDTH;
    if (meta->GetData(Tag::AUDIO_SAMPLE_FORMAT, sampleFormat)) {
        MEDIA_LOG_I("sampleFormat: " PUBLIC_LOG_D32, static_cast<int32_t>(sampleFormat));
        audioEncFormat_->SetData(Tag::AUDIO_SAMPLE_FORMAT, sampleFormat);
        muxerFormat_->SetData(Tag::AUDIO_SAMPLE_FORMAT, sampleFormat);
    } else {
        MEDIA_LOG_W("get sampleFormat failed");
    }
    FALSE_RETURN_NOLOG(mime.find(MediaAVCodec::CodecMimeType::AUDIO_RAW) != 0);
    if (mime.find(MediaAVCodec::CodecMimeType::AUDIO_APE) != 0 &&
        mime.find(MediaAVCodec::CodecMimeType::AUDIO_FLAC) != 0) {
        MEDIA_LOG_I_SHORT("non-ape and non-flac sampleFormat after is: " PUBLIC_LOG_D32, Plugins::SAMPLE_S16LE);
        audioEncFormat_->SetData(Tag::AUDIO_SAMPLE_FORMAT, Plugins::SAMPLE_S16LE);
        muxerFormat_->SetData(Tag::AUDIO_SAMPLE_FORMAT, Plugins::SAMPLE_S16LE);
        return;
    }

    int32_t sampleRate = 0;
    if (!meta->GetData(Tag::AUDIO_SAMPLE_RATE, sampleRate) || sampleRate < SAMPLE_RATE_48K) {
        MEDIA_LOG_I_SHORT("less than 48K sampleFormat after is: " PUBLIC_LOG_D32, Plugins::SAMPLE_S16LE);
        audioEncFormat_->SetData(Tag::AUDIO_SAMPLE_FORMAT, Plugins::SAMPLE_S16LE);
        muxerFormat_->SetData(Tag::AUDIO_SAMPLE_FORMAT, Plugins::SAMPLE_S16LE);
        return;
    }

    int32_t codedSampleDepth = 0;
    int32_t rawSampleDepth = 0;
    if ((meta->GetData(Tag::AUDIO_SAMPLE_FORMAT, sampleFormat) &&
        Pipeline::AudioSampleFormatToBitDepth(sampleFormat) > SAMPLE_FORMAT_BIT_DEPTH_16) ||
        (meta->GetData(Tag::AUDIO_BITS_PER_CODED_SAMPLE, codedSampleDepth) &&
        codedSampleDepth > SAMPLE_FORMAT_BIT_DEPTH_16) ||
        (meta->GetData(Tag::AUDIO_BITS_PER_RAW_SAMPLE, rawSampleDepth) &&
        rawSampleDepth > SAMPLE_FORMAT_BIT_DEPTH_16)) {
        MEDIA_LOG_I_SHORT("sampleFormat after is: " PUBLIC_LOG_D32, Plugins::SAMPLE_S32LE);
        audioEncFormat_->SetData(Tag::AUDIO_SAMPLE_FORMAT, Plugins::SAMPLE_S32LE);
        muxerFormat_->SetData(Tag::AUDIO_SAMPLE_FORMAT, Plugins::SAMPLE_S32LE);
        return;
    }

    MEDIA_LOG_I_SHORT("default sampleFormat after is: " PUBLIC_LOG_D32, Plugins::SAMPLE_S16LE);
    audioEncFormat_->SetData(Tag::AUDIO_SAMPLE_FORMAT, Plugins::SAMPLE_S16LE);
    muxerFormat_->SetData(Tag::AUDIO_SAMPLE_FORMAT, Plugins::SAMPLE_S16LE);
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
        CollectionErrorInfo(static_cast<int32_t>(Status::ERROR_INVALID_PARAMETER),
            "ConfigureVideoAudioMetaData error");
        OnEvent({"TranscoderEngine", EventType::EVENT_ERROR, MSERR_DEMUXER_FAILED});
        return Status::ERROR_INVALID_PARAMETER;
    }
    ConfigureMetaDataToTrackFormat(globalInfo, trackInfos);
    ConfigureVideoBitrate();
    return Status::OK;
}

int32_t HiTransCoderImpl::SetOutputFile(const int32_t fd)
{
    MEDIA_LOG_I("HiTransCoderImpl::SetOutputFile()");
    MEDIA_LOG_I("HiTransCoder SetOutputFile in, fd is %{public}d", fd);
    fd_ = dup(fd);
    MEDIA_LOG_I("HiTransCoder SetOutputFile dup, fd is %{public}d", fd_);
    return static_cast<int32_t>(Status::OK);
}

int32_t HiTransCoderImpl::SetOutputFormat(OutputFormatType format)
{
    MEDIA_LOG_I("HiTransCoderImpl::SetOutputFormat(), OutputFormatType is %{public}d", static_cast<int32_t>(format));
    outputFormatType_ = format;
    return static_cast<int32_t>(Status::OK);
}

int32_t HiTransCoderImpl::SetObs(const std::weak_ptr<ITransCoderEngineObs> &obs)
{
    MEDIA_LOG_I("HiTransCoderImpl::SetObs()");
    obs_ = obs;
    callbackLooper_->StartWithTransCoderEngineObs(obs);
    return static_cast<int32_t>(Status::OK);
}

Status HiTransCoderImpl::ConfigureVideoEncoderFormat(const TransCoderParam &transCoderParam)
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
    return Status::OK;
}

Status HiTransCoderImpl::ConfigureVideoWidthHeight(const TransCoderParam &transCoderParam)
{
    VideoRectangle videoRectangle = static_cast<const VideoRectangle&>(transCoderParam);
    if (videoRectangle.width != -1) {
        videoEncFormat_->Set<Tag::VIDEO_WIDTH>(videoRectangle.width);
        }
    if (videoRectangle.height != -1) {
        videoEncFormat_->Set<Tag::VIDEO_HEIGHT>(videoRectangle.height);
        }
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
    MEDIA_LOG_I("HiTransCoderImpl::Configure()");
    MediaTrace trace("HiTransCoderImpl::Configure()");
    Status ret = Status::OK;
    switch (transCoderParam.type) {
        case TransCoderPublicParamType::VIDEO_ENC_FMT: {
            ret = ConfigureVideoEncoderFormat(transCoderParam);
            break;
        }
        case TransCoderPublicParamType::VIDEO_RECTANGLE: {
            ret = ConfigureVideoWidthHeight(transCoderParam);
            ConfigureVideoBitrate();
            break;
        }
        case TransCoderPublicParamType::VIDEO_BITRATE: {
            VideoBitRate videoBitrate = static_cast<const VideoBitRate&>(transCoderParam);
            if (videoBitrate.bitRate <= 0) {
                return static_cast<int32_t>(Status::OK);
            }
            MEDIA_LOG_I("HiTransCoderImpl::Configure videoBitRate %{public}d", videoBitrate.bitRate);
            videoEncFormat_->Set<Tag::MEDIA_BITRATE>(videoBitrate.bitRate);
            break;
        }
        case TransCoderPublicParamType::AUDIO_ENC_FMT: {
            AudioEnc audioEnc = static_cast<const AudioEnc&>(transCoderParam);
            MEDIA_LOG_I("HiTransCoderImpl::Configure audioEnc %{public}d", audioEnc.encFmt);
            audioEncFormat_->Set<Tag::MIME_TYPE>(Plugins::MimeType::AUDIO_AAC);
            break;
        }
        case TransCoderPublicParamType::AUDIO_BITRATE: {
            AudioBitRate audioBitrate = static_cast<const AudioBitRate&>(transCoderParam);
            if (audioBitrate.bitRate <= 0) {
                MEDIA_LOG_E("Invalid audioBitrate.bitRate %{public}d", audioBitrate.bitRate);
                OnEvent({"TranscoderEngine", EventType::EVENT_ERROR, MSERR_INVALID_VAL});
                return static_cast<int32_t>(Status::ERROR_INVALID_PARAMETER);
            }
            MEDIA_LOG_I("HiTransCoderImpl::Configure audioBitrate %{public}d", audioBitrate.bitRate);
            audioEncFormat_->Set<Tag::MEDIA_BITRATE>(audioBitrate.bitRate);
            break;
        }
        default:
            break;
    }
    return static_cast<int32_t>(ret);
}

int32_t HiTransCoderImpl::Prepare()
{
    MEDIA_LOG_I("HiTransCoderImpl::Prepare()");
    MediaTrace trace("HiTransCoderImpl::Prepare()");
    int32_t width = 0;
    int32_t height = 0;
    if (isExistVideoTrack_) {
        if (videoEncFormat_->GetData(Tag::VIDEO_WIDTH, width) &&
            videoEncFormat_->GetData(Tag::VIDEO_HEIGHT, height)) {
            MEDIA_LOG_D("set output video width: %{public}d, height: %{public}d", width, height);
        } else {
            MEDIA_LOG_E("Output video width or height not set");
            CollectionErrorInfo(static_cast<int32_t>(Status::ERROR_INVALID_PARAMETER), "Prepare error");
            OnEvent({"TranscoderEngine", EventType::EVENT_ERROR, MSERR_INVALID_VAL});
            return static_cast<int32_t>(Status::ERROR_INVALID_PARAMETER);
        }
        if (width > inputVideoWidth_ || height > inputVideoHeight_ || std::min(width, height) < MINIMUM_WIDTH_HEIGHT) {
            MEDIA_LOG_E("Output video width or height is invalid");
            CollectionErrorInfo(static_cast<int32_t>(Status::ERROR_INVALID_PARAMETER), "Prepare error");
            OnEvent({"TranscoderEngine", EventType::EVENT_ERROR, MSERR_INVALID_VAL});
            return static_cast<int32_t>(Status::ERROR_INVALID_PARAMETER);
        }
        isNeedVideoResizeFilter_ = width != inputVideoWidth_ || height != inputVideoHeight_;
    }
    Status ret = pipeline_->Prepare();
    if (ret != Status::OK) {
        MEDIA_LOG_E("Prepare failed with error " PUBLIC_LOG_D32, ret);
        auto errCode = TransStatus(ret);
        CollectionErrorInfo(errCode, "Prepare error");
        OnEvent({"TranscoderEngine", EventType::EVENT_ERROR, errCode});
        return static_cast<int32_t>(errCode);
    }
    return static_cast<int32_t>(SetSurfacePipeline(width, height));
}

Status HiTransCoderImpl::SetSurfacePipeline(int32_t outputVideoWidth, int32_t outputVideoHeight)
{
    FALSE_RETURN_V_MSG_E(videoEncoderFilter_ != nullptr && videoDecoderFilter_ != nullptr,
        Status::ERROR_NULL_POINTER, "VideoDecoder setOutputSurface failed");
    if (isNeedVideoResizeFilter_ && videoResizeFilter_ != nullptr) {
        sptr<Surface> resizeFilterSurface = videoResizeFilter_->GetInputSurface();
        FALSE_RETURN_V_MSG_E(resizeFilterSurface != nullptr, Status::ERROR_NULL_POINTER,
            "resizeFilterSurface is nullptr");
        Status ret = videoDecoderFilter_->SetOutputSurface(resizeFilterSurface);
        FALSE_RETURN_V_MSG_E(ret == Status::OK, ret, "VideoDecoder setOutputSurface failed");
        sptr<Surface> encoderFilterSurface = videoEncoderFilter_->GetInputSurface();
        FALSE_RETURN_V_MSG_E(encoderFilterSurface != nullptr, Status::ERROR_NULL_POINTER,
            "encoderFilterSurface is nullptr");
        return videoResizeFilter_->SetOutputSurface(encoderFilterSurface, outputVideoWidth, outputVideoHeight);
    }
    sptr<Surface> encoderFilterSurface = videoEncoderFilter_->GetInputSurface();
    FALSE_RETURN_V_MSG_E(encoderFilterSurface != nullptr, Status::ERROR_NULL_POINTER,
        "encoderFilterSurface is nullptr");
    return videoDecoderFilter_->SetOutputSurface(encoderFilterSurface);
}

int32_t HiTransCoderImpl::Start()
{
    MEDIA_LOG_I("HiTransCoderImpl::Start()");
    MediaTrace trace("HiTransCoderImpl::Start()");
    startTime_ = GetCurrentMillisecond();
    int32_t ret = TransStatus(pipeline_->Start());
    if (ret != MSERR_OK) {
        MEDIA_LOG_E("Start pipeline failed");
        CollectionErrorInfo(static_cast<int32_t>(ret), "Start error");
        OnEvent({"TranscoderEngine", EventType::EVENT_ERROR, ret});
        return ret;
    }
    callbackLooper_->StartReportMediaProgress(REPORT_PROGRESS_INTERVAL);
    return ret;
}

int32_t HiTransCoderImpl::Pause()
{
    MEDIA_LOG_I("HiTransCoderImpl::Pause()");
    MediaTrace trace("HiTransCoderImpl::Pause()");
    callbackLooper_->StopReportMediaProgress();
    Status ret = pipeline_->Pause();
    if (ret != Status::OK) {
        MEDIA_LOG_E("Pause pipeline failed");
        CollectionErrorInfo(static_cast<int32_t>(ret), "Pause error");
        OnEvent({"TranscoderEngine", EventType::EVENT_ERROR, MSERR_UNKNOWN});
    }
    if (startTime_ != -1) {
        transcoderTotalDuration_ += GetCurrentMillisecond() - startTime_;
    }
    startTime_ = -1;
    return static_cast<int32_t>(ret);
}

int32_t HiTransCoderImpl::Resume()
{
    MEDIA_LOG_I("HiTransCoderImpl::Resume()");
    MediaTrace trace("HiTransCoderImpl::Resume()");
    Status ret = pipeline_->Resume();
    if (ret != Status::OK) {
        MEDIA_LOG_E("Resume pipeline failed");
        CollectionErrorInfo(static_cast<int32_t>(ret), "Resume error");
        OnEvent({"TranscoderEngine", EventType::EVENT_ERROR, MSERR_UNKNOWN});
        return static_cast<int32_t>(ret);
    }
    callbackLooper_->StartReportMediaProgress(REPORT_PROGRESS_INTERVAL);
    startTime_ = GetCurrentMillisecond();
    return static_cast<int32_t>(ret);
}

int32_t HiTransCoderImpl::Cancel()
{
    MEDIA_LOG_I("HiTransCoderImpl::Cancel enter");
    MediaTrace trace("HiTransCoderImpl::Cancel()");
    callbackLooper_->StopReportMediaProgress();
    Status ret = pipeline_->Stop();
    callbackLooper_->Stop();
    if (ret != Status::OK) {
        MEDIA_LOG_E("Stop pipeline failed");
        CollectionErrorInfo(static_cast<int32_t>(ret), "Cancel error");
        OnEvent({"TranscoderEngine", EventType::EVENT_ERROR, MSERR_UNKNOWN});
        return static_cast<int32_t>(ret);
    }
    MEDIA_LOG_I("HiTransCoderImpl::Cancel done");
    if (startTime_ != -1) {
        transcoderTotalDuration_ += GetCurrentMillisecond() - startTime_;
    }
    startTime_ = -1;
    AppendTranscoderMediaInfo();
    ReportMediaInfo(instanceId_);
    return static_cast<int32_t>(ret);
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
    MEDIA_LOG_I("complete event pipeline stop begin");
    pipeline_->Stop();
    MEDIA_LOG_I("complete event pipeline stop end");
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
    FALSE_RETURN_V_MSG_E(pipeline_->LinkFilters(preFilter, {audioDecoderFilter_}, type) == Status::OK,
        Status::ERROR_UNKNOWN, "Add audioDecoderFilter to pipeline fail");
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
    FALSE_RETURN_V_MSG_E(audioEncoderFilter_->SetCodecFormat(audioEncFormat_) == Status::OK,
        Status::ERROR_UNKNOWN, "audioEncoderFilter SetCodecFormat fail");
    FALSE_RETURN_V_MSG_E(audioEncoderFilter_->SetTranscoderMode() == Status::OK,
        Status::ERROR_UNKNOWN, "audioEncoderFilter SetTranscoderMode fail");
    audioEncoderFilter_->Init(transCoderEventReceiver_, transCoderFilterCallback_);
    FALSE_RETURN_V_MSG_E(audioEncoderFilter_->Configure(audioEncFormat_) == Status::OK,
        Status::ERROR_UNKNOWN, "audioEncoderFilter Configure fail");
    FALSE_RETURN_V_MSG_E(pipeline_->LinkFilters(preFilter, {audioEncoderFilter_}, type) == Status::OK,
        Status::ERROR_UNKNOWN, "Add audioEncoderFilter to pipeline fail");
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
    videoDecoderFilter_->Init(transCoderEventReceiver_, transCoderFilterCallback_);
    FALSE_RETURN_V_MSG_E(pipeline_->LinkFilters(preFilter, {videoDecoderFilter_}, type) == Status::OK,
        Status::ERROR_UNKNOWN, "Add videoDecoderFilter_ to pipeline fail");
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
    FALSE_RETURN_V_MSG_E(videoEncoderFilter_->SetCodecFormat(videoEncFormat_) == Status::OK,
        Status::ERROR_UNKNOWN, "videoEncoderFilter SetCodecFormat fail");
    videoEncoderFilter_->Init(transCoderEventReceiver_, transCoderFilterCallback_);
    FALSE_RETURN_V_MSG_E(videoEncoderFilter_->SetTransCoderMode() == Status::OK,
        Status::ERROR_UNKNOWN, "videoEncoderFilter SetTransCoderMode fail");
    FALSE_RETURN_V_MSG_E(videoEncoderFilter_->Configure(videoEncFormat_) == Status::OK,
        Status::ERROR_UNKNOWN, "videoEncoderFilter Configure fail");
    FALSE_RETURN_V_MSG_E(pipeline_->LinkFilters(preFilter, {videoEncoderFilter_}, type) == Status::OK,
        Status::ERROR_UNKNOWN, "Add videoEncoderFilter to pipeline fail");
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
    FALSE_RETURN_V_MSG_E(videoResizeFilter_->Configure(videoEncFormat_) == Status::OK,
        Status::ERROR_UNKNOWN, "videoEncoderFilter Configure fail");
    FALSE_RETURN_V_MSG_E(pipeline_->LinkFilters(preFilter, {videoResizeFilter_}, type) == Status::OK,
        Status::ERROR_UNKNOWN, "Add videoResizeFilter to pipeline fail");
    return Status::OK;
}

Status HiTransCoderImpl::LinkMuxerFilter(const std::shared_ptr<Pipeline::Filter>& preFilter,
    Pipeline::StreamType type)
{
    MEDIA_LOG_I("HiTransCoderImpl::LinkMuxerFilter()");
    if (muxerFilter_ == nullptr) {
        muxerFilter_ = Pipeline::FilterFactory::Instance().CreateFilter<Pipeline::MuxerFilter>
            ("muxerFilter", Pipeline::FilterType::FILTERTYPE_MUXER);
        FALSE_RETURN_V_MSG_E(muxerFilter_ != nullptr, Status::ERROR_NULL_POINTER,
            "muxerFilter is nullptr");
        muxerFilter_->Init(transCoderEventReceiver_, transCoderFilterCallback_);
        FALSE_RETURN_V_MSG_E(muxerFilter_->SetOutputParameter(appUid_, appPid_, fd_, outputFormatType_) == Status::OK,
            Status::ERROR_UNKNOWN, "muxerFilter SetOutputParameter fail");
        muxerFilter_->SetParameter(muxerFormat_);
        muxerFilter_->SetTransCoderMode();
        MEDIA_LOG_I("HiTransCoder CloseFd, fd is %{public}d", fd_);
        if (fd_ >= 0) {
            (void)::close(fd_);
            fd_ = -1;
        }
    }
    FALSE_RETURN_V_MSG_E(pipeline_->LinkFilters(preFilter, {muxerFilter_}, type) == Status::OK,
        Status::ERROR_UNKNOWN, "Add muxerFilter to pipeline fail");
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
                    return LinkAudioDecoderFilter(filter, outType);
                }
                return LinkMuxerFilter(filter, outType);
            case Pipeline::StreamType::STREAMTYPE_RAW_VIDEO:
                if (!isNeedVideoResizeFilter_ ||
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
    FALSE_RETURN_V(muxerFilter_ != nullptr, static_cast<int32_t>(Status::ERROR_UNKNOWN));
    int64_t currentPts = muxerFilter_->GetCurrentPtsMs();
    currentPositionMs = (int32_t)currentPts;
    return static_cast<int32_t>(Status::OK);
}

int32_t HiTransCoderImpl::GetDuration(int32_t& durationMs)
{
    durationMs = durationMs_.load();
    return static_cast<int32_t>(Status::OK);
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

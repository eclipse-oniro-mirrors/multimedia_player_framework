/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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
#include "hirecorder_impl.h"
#include "meta/audio_types.h"
#include "osal/task/pipeline_threadpool.h"
#include "sync_fence.h"
#include "media_dfx.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_DOMAIN_RECORDER, "HiRecorder" };
}

namespace OHOS {
namespace Media {
using namespace OHOS::HiviewDFX;
class RecorderEventReceiver : public Pipeline::EventReceiver {
public:
    explicit RecorderEventReceiver(HiRecorderImpl *hiRecorderImpl)
    {
        MEDIA_LOG_I("RecorderEventReceiver ctor called.");
        std::lock_guard<std::recursive_mutex> lock(cbMutex_);
        hiRecorderImpl_ = hiRecorderImpl;
    }

    void OnEvent(const Event &event) override
    {
        MEDIA_LOG_D("RecorderEventReceiver OnEvent.");
        std::lock_guard<std::recursive_mutex> lock(cbMutex_);
        FALSE_RETURN_MSG(hiRecorderImpl_ != nullptr, "hiRecorderImpl_ is nullptr");
        hiRecorderImpl_->OnEvent(event);
    }
    
    void NotifyRelease() override
    {
        MEDIA_LOG_D("RecorderEventReceiver NotifyRelease.");
        std::lock_guard<std::recursive_mutex> lock(cbMutex_);
        hiRecorderImpl_ = nullptr;
    }

private:
    std::recursive_mutex cbMutex_ {};
    HiRecorderImpl *hiRecorderImpl_;
};

class RecorderFilterCallback : public Pipeline::FilterCallback {
public:
    explicit RecorderFilterCallback(HiRecorderImpl *hiRecorderImpl)
    {
        MEDIA_LOG_I("RecorderFilterCallback ctor called.");
        std::lock_guard<std::recursive_mutex> lock(cbMutex_);
        hiRecorderImpl_ = hiRecorderImpl;
    }

    Status OnCallback(const std::shared_ptr<Pipeline::Filter>& filter, Pipeline::FilterCallBackCommand cmd,
        Pipeline::StreamType outType) override
    {
        MEDIA_LOG_D("RecorderFilterCallback OnCallBack.");
        std::lock_guard<std::recursive_mutex> lock(cbMutex_);
        FALSE_RETURN_V_MSG(hiRecorderImpl_ != nullptr, Status::OK, "hiRecorderImpl_ is nullptr");
        return hiRecorderImpl_->OnCallback(filter, cmd, outType);
    }
    
    void NotifyRelease() override
    {
        MEDIA_LOG_D("RecorderFilterCallback NotifyRelease.");
        std::lock_guard<std::recursive_mutex> lock(cbMutex_);
        hiRecorderImpl_ = nullptr;
    }

private:
    std::recursive_mutex cbMutex_ {};
    HiRecorderImpl *hiRecorderImpl_;
};

class CapturerInfoChangeCallback : public AudioStandard::AudioCapturerInfoChangeCallback {
public:
    explicit CapturerInfoChangeCallback(HiRecorderImpl *hiRecorderImpl)
    {
        MEDIA_LOG_I("CapturerInfoChangeCallback ctor called.");
        std::lock_guard<std::recursive_mutex> lock(cbMutex_);
        hiRecorderImpl_ = hiRecorderImpl;
    }

    void OnStateChange(const AudioStandard::AudioCapturerChangeInfo &capturerChangeInfo)
    {
        MEDIA_LOG_I("CapturerInfoChangeCallback hiRecorderImpl_->OnAudioCaptureChange start.");
        std::lock_guard<std::recursive_mutex> lock(cbMutex_);
        FALSE_RETURN_MSG(hiRecorderImpl_ != nullptr, "hiRecorderImpl_ is nullptr");
        hiRecorderImpl_->OnAudioCaptureChange(capturerChangeInfo);
    }
    
    void NotifyRelease()
    {
        MEDIA_LOG_D("CapturerInfoChangeCallback NotifyRelease.");
        std::lock_guard<std::recursive_mutex> lock(cbMutex_);
        hiRecorderImpl_ = nullptr;
    }

private:
    HiRecorderImpl *hiRecorderImpl_;
    std::recursive_mutex cbMutex_ {};
};

static inline MetaSourceType GetMetaSourceType(int32_t sourceId)
{
    return static_cast<MetaSourceType>(sourceId - SourceIdGenerator::META_MASK);
}

HiRecorderImpl::HiRecorderImpl(int32_t appUid, int32_t appPid, uint32_t appTokenId, uint64_t appFullTokenId)
    : appUid_(appUid), appPid_(appPid), appTokenId_(appTokenId), appFullTokenId_(appFullTokenId)
{
    pipeline_ = std::make_shared<Pipeline::Pipeline>();
    recorderId_ = std::string("HiRecorder_") + std::to_string(OHOS::Media::Pipeline::Pipeline::GetNextPipelineId());
}

HiRecorderImpl::~HiRecorderImpl()
{
    if (recorderCallback_ != nullptr) {
        recorderCallback_->NotifyRelease();
    }
    if (recorderEventReceiver_ != nullptr) {
        recorderEventReceiver_->NotifyRelease();
    }
    if (capturerInfoChangeCallback_ != nullptr) {
        capturerInfoChangeCallback_->NotifyRelease();
    }
    Stop(false);
    PipeLineThreadPool::GetInstance().DestroyThread(recorderId_);
}

int32_t HiRecorderImpl::Init()
{
    MediaTrace trace("HiRecorderImpl::Init");
    MEDIA_LOG_I("HiRecorderImpl Init enter.");
    recorderEventReceiver_ = std::make_shared<RecorderEventReceiver>(this);
    recorderCallback_ = std::make_shared<RecorderFilterCallback>(this);
    pipeline_->Init(recorderEventReceiver_, recorderCallback_, recorderId_);
    return (int32_t)Status::OK;
}

int32_t HiRecorderImpl::SetVideoSource(VideoSourceType source, int32_t &sourceId)
{
    MediaTrace trace("HiRecorderImpl::SetVideoSource");
    MEDIA_LOG_I(PUBLIC_LOG_S "SetVideoSource enter, sourceType:" PUBLIC_LOG_D32, avRecorderTag_.c_str(),
        static_cast<int32_t>(source));
    sourceId = INVALID_SOURCE_ID;
    FALSE_RETURN_V(source != VideoSourceType::VIDEO_SOURCE_BUTT,
        (int32_t)Status::ERROR_INVALID_PARAMETER);
    FALSE_RETURN_V(videoCount_ < static_cast<uint32_t>(VIDEO_SOURCE_MAX_COUNT),
        (int32_t)Status::ERROR_INVALID_OPERATION);
    auto tempSourceId = SourceIdGenerator::GenerateVideoSourceId(videoCount_);
    Status ret;
    if (source == VideoSourceType::VIDEO_SOURCE_SURFACE_YUV ||
        source == VideoSourceType::VIDEO_SOURCE_SURFACE_RGBA) {
        videoSourceIsYuv_ = true;
        if (!videoEncoderFilter_) {
            videoEncoderFilter_ = Pipeline::FilterFactory::Instance().CreateFilter<Pipeline::SurfaceEncoderFilter>
                ("videoEncoderFilter", Pipeline::FilterType::FILTERTYPE_VENC);
        }
        FALSE_RETURN_V_MSG_E(videoEncoderFilter_ != nullptr, (int32_t)Status::ERROR_NULL_POINTER,
            "create videoEncoderFilter failed");
        videoEncoderFilter_->SetCallingInfo(appUid_, appPid_, bundleName_, instanceId_);
        ret = pipeline_->AddHeadFilters({videoEncoderFilter_});
        if (source == VideoSourceType::VIDEO_SOURCE_SURFACE_RGBA) {
            videoSourceIsRGBA_ = true;
        } else {
            videoSourceIsRGBA_ = false;
        }
        MEDIA_LOG_I("SetVideoSource VIDEO_SOURCE_SURFACE_YUV.");
    } else if (source == VideoSourceType::VIDEO_SOURCE_SURFACE_ES) {
        videoSourceIsYuv_ = false;
        videoSourceIsRGBA_ = false;
        videoCaptureFilter_ = Pipeline::FilterFactory::Instance().CreateFilter<Pipeline::VideoCaptureFilter>
            ("videoEncoderFilter", Pipeline::FilterType::VIDEO_CAPTURE);
        FALSE_RETURN_V_MSG_E(videoCaptureFilter_ != nullptr, (int32_t)Status::ERROR_NULL_POINTER,
            "create videoCaptureFilter failed");
        ret = pipeline_->AddHeadFilters({videoCaptureFilter_});
        MEDIA_LOG_I("SetVideoSource VIDEO_SOURCE_SURFACE_ES.");
    } else {
        ret = Status::OK;
    }
    FALSE_RETURN_V_MSG_E(ret == Status::OK, (int32_t)ret, "AddFilters videoEncoder to pipeline fail");

    MEDIA_LOG_I("SetVideoSource success.");
    videoCount_++;
    videoSourceId_ = tempSourceId;
    sourceId = videoSourceId_;
    OnStateChanged(StateId::RECORDING_SETTING);

    return (int32_t)ret;
}

int32_t HiRecorderImpl::SetMetaSource(MetaSourceType source, int32_t &sourceId)
{
    MediaTrace trace("HiRecorderImpl::SetMetaSource");
    MEDIA_LOG_I("SetMetaSource enter, sourceType:" PUBLIC_LOG_D32, static_cast<int32_t>(source));
    sourceId = INVALID_SOURCE_ID;
    FALSE_RETURN_V(
        source > MetaSourceType::VIDEO_META_SOURCE_INVALID && source < MetaSourceType::VIDEO_META_SOURCE_BUTT,
        (int32_t)Status::ERROR_INVALID_PARAMETER
    );
    auto tempSourceId = SourceIdGenerator::GenerateMetaSourceId(static_cast<int32_t>(source));
    Status ret;
    if (metaDataFilters_.find(tempSourceId) == metaDataFilters_.end()) {
        auto filter = Pipeline::FilterFactory::Instance().CreateFilter<Pipeline::MetaDataFilter>
            ("MetaDataFilter", Pipeline::FilterType::TIMED_METADATA);
        ret = pipeline_->AddHeadFilters({filter});
        FALSE_RETURN_V_MSG_E(ret == Status::OK, (int32_t)ret, "AddFilters MetaDataFilter to pipeline fail");
        if (filter && ret == Status::OK) {
            metaDataFilters_.emplace(std::make_pair(tempSourceId, filter));
        }
    } else {
        ret = pipeline_->AddHeadFilters({metaDataFilters_.at(tempSourceId)});
    }
    FALSE_RETURN_V(ret == Status::OK, (int32_t)ret);
    
    MEDIA_LOG_I("SetMetaSource success.");
    sourceId = tempSourceId;
    OnStateChanged(StateId::RECORDING_SETTING);
    return (int32_t)ret;
}

int32_t HiRecorderImpl::SetAudioSource(AudioSourceType source, int32_t &sourceId)
{
    MediaTrace trace("HiRecorderImpl::SetAudioSource");
    MEDIA_LOG_I(PUBLIC_LOG_S "SetAudioSource enter, sourceType:" PUBLIC_LOG_D32, avRecorderTag_.c_str(),
        static_cast<int32_t>(source));
    sourceId = INVALID_SOURCE_ID;
    FALSE_RETURN_V(CheckAudioSourceType(source), (int32_t)Status::ERROR_INVALID_PARAMETER);
    FALSE_RETURN_V(audioCount_ < static_cast<uint32_t>(AUDIO_SOURCE_MAX_COUNT),
        (int32_t)Status::ERROR_INVALID_OPERATION);
    auto tempSourceId = SourceIdGenerator::GenerateAudioSourceId(audioCount_);

    audioCaptureFilter_ = Pipeline::FilterFactory::Instance().CreateFilter<Pipeline::AudioCaptureFilter>
        ("audioCaptureFilter", Pipeline::FilterType::AUDIO_CAPTURE);
    FALSE_RETURN_V_MSG_E(audioCaptureFilter_ != nullptr,
        (int32_t)Status::ERROR_NULL_POINTER, "audioCaptureFilter_ is null");
    audioCaptureFilter_->SetCallingInfo(appUid_, appPid_, bundleName_, instanceId_);
    audioCaptureFilter_->SetAudioSource(source);
    Status ret = pipeline_->AddHeadFilters({audioCaptureFilter_});
    FALSE_RETURN_V_MSG_E(ret == Status::OK, (int32_t)ret, "AddFilters audioCapture to pipeline fail");

    MEDIA_LOG_I("SetAudioSource success.");
    audioCount_++;
    audioSourceId_ = tempSourceId;
    sourceId = audioSourceId_;
    OnStateChanged(StateId::RECORDING_SETTING);

    return (int32_t)ret;
}

int32_t HiRecorderImpl::SetAudioDataSource(const std::shared_ptr<IAudioDataSource>& audioSource, int32_t& sourceId)
{
    MEDIA_LOG_I("HiRecorderImpl SetAudioDataSource enter.");
    sourceId = INVALID_SOURCE_ID;
    auto tempSourceId = SourceIdGenerator::GenerateAudioSourceId(audioCount_);
    audioDataSourceFilter_ = Pipeline::FilterFactory::Instance().CreateFilter<Pipeline::AudioDataSourceFilter>
        ("audioDataSourceFilter", Pipeline::FilterType::AUDIO_DATA_SOURCE);
    FALSE_RETURN_V_MSG_E(audioDataSourceFilter_ != nullptr,
        (int32_t)Status::ERROR_NULL_POINTER, "audioDataSourceFilter_ is null");
    audioDataSourceFilter_->SetAudioDataSource(audioSource);
    Status ret = pipeline_->AddHeadFilters({audioDataSourceFilter_});
    FALSE_RETURN_V_MSG_E(ret == Status::OK, (int32_t)ret, "AddFilters audioDataSource to pipeline fail");

    MEDIA_LOG_I(PUBLIC_LOG_S "SetAudioSource success.", avRecorderTag_.c_str());
    audioCount_++;
    audioSourceId_ = tempSourceId;
    sourceId = audioSourceId_;
    OnStateChanged(StateId::RECORDING_SETTING);

    return (int32_t)ret;
}

int32_t HiRecorderImpl::SetOutputFormat(OutputFormatType format)
{
    MEDIA_LOG_I("HiRecorderImpl SetOutputFormat enter. " PUBLIC_LOG_D32, static_cast<int32_t>(format));
    outputFormatType_ = format;
    OnStateChanged(StateId::RECORDING_SETTING);
    return (int32_t)Status::OK;
}

int32_t HiRecorderImpl::SetObs(const std::weak_ptr<IRecorderEngineObs> &obs)
{
    MEDIA_LOG_I("SetObs enter.");
    obs_ = obs;
    return (int32_t)Status::OK;
}

int32_t HiRecorderImpl::Configure(int32_t sourceId, const RecorderParam &recParam)
{
    MEDIA_LOG_I("HiRecorderImpl Configure enter.");
    FALSE_RETURN_V(outputFormatType_ != OutputFormatType::FORMAT_BUTT,
        (int32_t)Status::ERROR_INVALID_OPERATION);
    FALSE_RETURN_V(CheckParamType(sourceId, recParam), (int32_t)Status::ERROR_INVALID_PARAMETER);
    switch (recParam.type) {
        case RecorderPublicParamType::AUD_SAMPLERATE:
        case RecorderPublicParamType::AUD_CHANNEL:
        case RecorderPublicParamType::AUD_BITRATE:
        case RecorderPublicParamType::AUD_ENC_FMT:
        case RecorderPublicParamType::AUD_AAC_FMT:
            ConfigureAudio(recParam);
            break;
        case RecorderPublicParamType::VID_CAPTURERATE:
        case RecorderPublicParamType::VID_RECTANGLE:
        case RecorderPublicParamType::VID_BITRATE:
        case RecorderPublicParamType::VID_FRAMERATE:
        case RecorderPublicParamType::VID_ENC_FMT:
        case RecorderPublicParamType::VID_IS_HDR:
        case RecorderPublicParamType::VID_ENABLE_TEMPORAL_SCALE:
        case RecorderPublicParamType::VID_ENABLE_STABLE_QUALITY_MODE:
        case RecorderPublicParamType::VID_ENABLE_B_FRAME:
            ConfigureVideo(recParam);
            break;
        case RecorderPublicParamType::OUT_PATH:
        case RecorderPublicParamType::OUT_FD:
        case RecorderPublicParamType::VID_ORIENTATION_HINT:
        case RecorderPublicParamType::GEO_LOCATION:
        case RecorderPublicParamType::GENRE_INFO:
        case RecorderPublicParamType::CUSTOM_INFO:
        case RecorderPublicParamType::MAX_DURATION:
            ConfigureMuxer(recParam);
            break;
        case RecorderPublicParamType::META_MIME_TYPE:
        case RecorderPublicParamType::META_TIMED_KEY:
        case RecorderPublicParamType::META_SOURCE_TRACK_MIME:
            ConfigureMeta(sourceId, recParam);
            break;
        default:
            break;
    }
    if (metaDataFormats_.size() != 0 && muxerFilter_) {
        muxerFormat_->SetData("use_timed_meta_track", 1);
        muxerFilter_->SetParameter(muxerFormat_);
    }
    OnStateChanged(StateId::RECORDING_SETTING);
    return (int32_t)Status::OK;
}

sptr<Surface> HiRecorderImpl::GetSurface(int32_t sourceId)
{
    MEDIA_LOG_I("HiRecorderImpl GetSurface enter.");
    if (videoEncoderFilter_) {
        producerSurface_ = videoEncoderFilter_->GetInputSurface();
    }
    if (videoCaptureFilter_) {
        producerSurface_ = videoCaptureFilter_->GetInputSurface();
    }
    return producerSurface_;
}

sptr<Surface> HiRecorderImpl::GetMetaSurface(int32_t sourceId)
{
    MEDIA_LOG_I("HiRecorderImpl GetMetaSurface enter.");

    if (SourceIdGenerator::IsMeta(sourceId) &&
        (GetMetaSourceType(sourceId) > VIDEO_META_SOURCE_INVALID &&
        GetMetaSourceType(sourceId) < VIDEO_META_SOURCE_BUTT)) {
        producerMetaSurface_ = metaDataFilters_.at(sourceId)->GetInputMetaSurface();
    }
    return producerMetaSurface_;
}

int32_t HiRecorderImpl::Prepare()
{
    MediaTrace trace("HiRecorderImpl::Prepare");
    MEDIA_LOG_I("Prepare enter.");
    FALSE_RETURN_V_MSG_E(lseek(fd_, 0, SEEK_CUR) != -1,
        (int32_t)Status::ERROR_UNKNOWN, "The fd is invalid.");

    int32_t result = ERR_NONE;
    result = PrepareAudioCapture();
    FALSE_RETURN_V_MSG_E(result == ERR_NONE, result, "PrepareAudioCapture fail");
    result = PrepareAudioDataSource();
    FALSE_RETURN_V_MSG_E(result == ERR_NONE, result, "PrepareAudioDataSource fail");
    result = PrepareVideoEncoder();
    FALSE_RETURN_V_MSG_E(result == ERR_NONE, result, "PrepareVideoEncoder fail");
    result = PrepareMetaData();
    FALSE_RETURN_V_MSG_E(result == ERR_NONE, result, "PrepareMetaData fail");
    result = PrepareVideoCapture();
    FALSE_RETURN_V_MSG_E(result == ERR_NONE, result, "PrepareVideoCapture fail");
    Status ret = pipeline_->Prepare();
    return (int32_t)ret;
}

int32_t HiRecorderImpl::PrepareAudioCapture()
{
    if (audioCaptureFilter_) {
        audioEncFormat_->Set<Tag::APP_TOKEN_ID>(appTokenId_);
        audioEncFormat_->Set<Tag::APP_UID>(appUid_);
        audioEncFormat_->Set<Tag::APP_PID>(appPid_);
        audioEncFormat_->Set<Tag::APP_FULL_TOKEN_ID>(appFullTokenId_);
        audioEncFormat_->Set<Tag::AUDIO_SAMPLE_FORMAT>(Plugins::AudioSampleFormat::SAMPLE_S16LE);
        audioCaptureFilter_->SetParameter(audioEncFormat_);
        audioCaptureFilter_->Init(recorderEventReceiver_, recorderCallback_);
        capturerInfoChangeCallback_ = std::make_shared<CapturerInfoChangeCallback>(this);
        audioCaptureFilter_->SetAudioCaptureChangeCallback(capturerInfoChangeCallback_);
        if (videoEncoderFilter_) {
            audioCaptureFilter_->SetWithVideo(true);
        } else {
            audioCaptureFilter_->SetWithVideo(false);
        }
        if (muteWhenInterrupted_) {
            audioCaptureFilter_->SetWillMuteWhenInterrupted(muteWhenInterrupted_);
        }
    }
    return ERR_NONE;
}

int32_t HiRecorderImpl::PrepareAudioDataSource()
{
    if (audioDataSourceFilter_) {
        audioEncFormat_->Set<Tag::APP_TOKEN_ID>(appTokenId_);
        audioEncFormat_->Set<Tag::APP_UID>(appUid_);
        audioEncFormat_->Set<Tag::APP_PID>(appPid_);
        audioEncFormat_->Set<Tag::APP_FULL_TOKEN_ID>(appFullTokenId_);
        audioEncFormat_->Set<Tag::AUDIO_SAMPLE_FORMAT>(Plugins::AudioSampleFormat::SAMPLE_S16LE);
        audioDataSourceFilter_->Init(recorderEventReceiver_, recorderCallback_);
    }
    return ERR_NONE;
}

int32_t HiRecorderImpl::PrepareVideoEncoder()
{
    if (videoEncoderFilter_) {
        if (videoSourceIsRGBA_) {
            videoEncFormat_->Set<Tag::VIDEO_PIXEL_FORMAT>(Plugins::VideoPixelFormat::RGBA);
        }
        ConfigureVidEncBitrateMode();
        videoEncoderFilter_->SetCodecFormat(videoEncFormat_);
        videoEncoderFilter_->Init(recorderEventReceiver_, recorderCallback_);
        videoEncoderFilter_->SetVideoEnableBFrame(enableBFrame_);
        FALSE_RETURN_V_MSG_E(videoEncoderFilter_->Configure(videoEncFormat_) == Status::OK,
            ERR_UNKNOWN_REASON, "videoEncoderFilter Configure fail");
    }
    return ERR_NONE;
}

int32_t HiRecorderImpl::PrepareMetaData()
{
    MEDIA_LOG_I("HiRecorderImpl PrepareMeta enter.");
    if (metaDataFilters_.size()) {
        for (auto iter : metaDataFilters_) {
            if (metaDataFormats_.find(iter.first) != metaDataFormats_.end()) {
                FALSE_RETURN_V_MSG_E(iter.second->Configure(metaDataFormats_.at(iter.first)) == Status::OK,
                    ERR_UNKNOWN_REASON, "MetaDataFilter Configure fail MetaType(%{public}d)", iter.first);
                iter.second->SetCodecFormat(metaDataFormats_.at(iter.first));
            }
            iter.second->Init(recorderEventReceiver_, recorderCallback_);
        }
    }
    return ERR_NONE;
}

int32_t HiRecorderImpl::PrepareVideoCapture()
{
    if (videoCaptureFilter_) {
        videoCaptureFilter_->SetCodecFormat(videoEncFormat_);
        videoCaptureFilter_->Init(recorderEventReceiver_, recorderCallback_);
        FALSE_RETURN_V_MSG_E(videoCaptureFilter_->Configure(videoEncFormat_) == Status::OK,
            ERR_UNKNOWN_REASON, "videoCaptureFilter Configure fail");
    }
    return ERR_NONE;
}

int32_t HiRecorderImpl::Start()
{
    MediaTrace trace("HiRecorderImpl::Start");
    MEDIA_LOG_I("Start enter.");
    Status ret = Status::OK;
    if (curState_ == StateId::PAUSE) {
        ret = pipeline_->Resume();
    } else {
        ret = pipeline_->Start();
    }
    FALSE_RETURN_V_MSG_E(ret == Status::OK, (int32_t)ret, "HiRecorderImpl Start fail");
    OnStateChanged(StateId::RECORDING);
    return (int32_t)ret;
}

int32_t HiRecorderImpl::Pause()
{
    MediaTrace trace("HiRecorderImpl::Pause");
    MEDIA_LOG_I("Pause enter.");
    Status ret = Status::OK;
    if (curState_ != StateId::READY) {
        ret = pipeline_->Pause();
        FALSE_RETURN_V_MSG_E(ret == Status::OK, (int32_t)ret, "HiRecorderImpl Pause fail");
    }
    OnStateChanged(StateId::PAUSE);
    return (int32_t)ret;
}

int32_t HiRecorderImpl::Resume()
{
    MediaTrace trace("HiRecorderImpl::Resume");
    MEDIA_LOG_I("Resume enter.");
    Status ret = Status::OK;
    ret = pipeline_->Resume();
    FALSE_RETURN_V_MSG_E(ret == Status::OK, (int32_t)ret, "HiRecorderImpl Resume fail");
    OnStateChanged(StateId::RECORDING);
    return (int32_t)ret;
}

Status HiRecorderImpl::HandleStopOperation()
{
    Status ret = Status::OK;
    outputFormatType_ = OutputFormatType::FORMAT_BUTT;
    if (videoEncoderFilter_) {
        ret = videoEncoderFilter_->SetStopTime();
    }
    if (audioCaptureFilter_) {
        ret = audioCaptureFilter_->SendEos();
    }
    if (audioDataSourceFilter_) {
        ret = audioDataSourceFilter_->SendEos();
    }
    ret = pipeline_->Stop();
    if (ret == Status::OK) {
        OnStateChanged(StateId::INIT);
        MEDIA_LOG_I("HiRecorderImpl HandleStopOperation done.");
    }
    return ret;
}

void HiRecorderImpl::ClearAllConfiguration()
{
    std::lock_guard<std::mutex> lock(configurationMutex_);
    MEDIA_LOG_I("HiRecorderImpl ClearAllConfiguration remove filter enter.");
    audioCount_ = 0;
    videoCount_ = 0;
    audioSourceId_ = 0;
    videoSourceId_ = 0;
    muxerFilter_ = nullptr;
    isWatermarkSupported_ = false;
    codecMimeType_ = "";
    if (audioEncFormat_) {
        audioEncFormat_->Clear();
    }
    if (videoEncFormat_) {
        videoEncFormat_->Clear();
    }
    if (muxerFormat_) {
        muxerFormat_->Clear();
    }
    
    auto RemoveFilterAction = [this](auto& filter) {
        if (filter && pipeline_) {
            pipeline_->RemoveHeadFilter(filter);
        }
    };

    RemoveFilterAction(audioDataSourceFilter_);
    RemoveFilterAction(audioCaptureFilter_);
    RemoveFilterAction(videoEncoderFilter_);
    RemoveFilterAction(videoCaptureFilter_);

    for (auto iter : metaDataFilters_) {
        if (metaDataFormats_.find(iter.first) != metaDataFormats_.end()) {
            metaDataFormats_.at(iter.first)->Clear();
        }
        RemoveFilterAction(iter.second);
    }
}

int32_t HiRecorderImpl::Stop(bool isDrainAll)
{
    MediaTrace trace("HiRecorderImpl::Stop");
    MEDIA_LOG_I("Stop enter.");
    if (curState_ == StateId::INIT) {
        MEDIA_LOG_I("Stop exit.the reason is state = INIT");
        return static_cast<int32_t>(Status::OK);
    }
    // real stop operations
    Status ret = HandleStopOperation();
    // clear all configurations and remove all filters
    ClearAllConfiguration();
    FALSE_RETURN_V_MSG_E(curState_ == StateId::INIT, ERR_UNKNOWN_REASON, "stop fail");
    return (int32_t)ret;
}

int32_t HiRecorderImpl::Reset()
{
    MediaTrace trace("HiRecorderImpl::Reset");
    MEDIA_LOG_I("Reset enter.");
    return Stop(false);
}

int32_t HiRecorderImpl::SetParameter(int32_t sourceId, const RecorderParam &recParam)
{
    MEDIA_LOG_I("SetParameter enter.");
    return Configure(sourceId, recParam);
}

void HiRecorderImpl::UpdateVideoFirstFramePts(const Event &event)
{
    if (audioCaptureFilter_) {
        int64_t firstFramePts = AnyCast<int64_t>(event.param);
        audioCaptureFilter_->SetVideoFirstFramePts(firstFramePts);
    }
    if (audioDataSourceFilter_) {
        int64_t firstFramePts = AnyCast<int64_t>(event.param);
        audioDataSourceFilter_->SetVideoFirstFramePts(firstFramePts);
    }
}

void HiRecorderImpl::OnEvent(const Event &event)
{
    switch (event.type) {
        case EventType::EVENT_ERROR: {
            MEDIA_LOG_I("EVENT_ERROR.");
            auto ptr = obs_.lock();
            if (ptr != nullptr) {
                switch (AnyCast<Status>(event.param)) {
                    case Status::ERROR_AUDIO_INTERRUPT:
                        // audio interrupted, recorder first stop then error
                        Stop(true);
                        ptr->OnError(IRecorderEngineObs::ErrorType::ERROR_INTERNAL, MSERR_AUD_INTERRUPT);
                        break;
                    default:
                        ptr->OnError(IRecorderEngineObs::ErrorType::ERROR_INTERNAL, MSERR_EXT_API9_INVALID_PARAMETER);
                        OnStateChanged(StateId::ERROR);
                        break;
                }
            }
            break;
        }
        case EventType::EVENT_READY: {
            OnStateChanged(StateId::READY);
            break;
        }
        case EventType::EVENT_COMPLETE: {
            MEDIA_LOG_I("EVENT_COMPLETE.");
            if (curState_ == StateId::INIT) {
                MEDIA_LOG_I("EVENT_COMPLETE exit. the reason is already stopped");
                break;
            }
            Stop(true);
            auto ptr = obs_.lock();
            if (ptr != nullptr) {
                MEDIA_LOG_I("EVENT_COMPLETE ptr->OnInfo MAX_DURATION_REACHED BACKGROUND");
                ptr->OnInfo(IRecorderEngineObs::InfoType::MAX_DURATION_REACHED, BACKGROUND);
            }
            break;
        }
        case EventType::EVENT_VIDEO_FIRST_FRAME: {
            UpdateVideoFirstFramePts(event);
            break;
        }
        default:
            break;
    }
}

void HiRecorderImpl::CloseFd()
{
    MEDIA_LOG_I("HiRecorderImpl: 0x%{public}06" PRIXPTR " CloseFd, fd is %{public}d", FAKE_POINTER(this), fd_);
    FALSE_RETURN(fd_ >= 0);

    (void)::close(fd_);
    fd_ = -1;
}

Status HiRecorderImpl::OnCallback(std::shared_ptr<Pipeline::Filter> filter, const Pipeline::FilterCallBackCommand cmd,
    Pipeline::StreamType outType)
{
    MEDIA_LOG_I("OnCallback enter.");
    
    FALSE_RETURN_V(cmd == Pipeline::FilterCallBackCommand::NEXT_FILTER_NEEDED, Status::OK);

    switch (outType) {
        case Pipeline::StreamType::STREAMTYPE_RAW_AUDIO:
            audioEncoderFilter_ = Pipeline::FilterFactory::Instance().CreateFilter<Pipeline::AudioEncoderFilter>
                ("audioEncoderFilter", Pipeline::FilterType::FILTERTYPE_AENC);
            FALSE_RETURN_V_MSG_E(audioEncoderFilter_ != nullptr,
                Status::ERROR_NULL_POINTER, "audioEncoderFilter_ is null");
            audioEncoderFilter_->SetCallingInfo(appUid_, appPid_, bundleName_, instanceId_);
            audioEncoderFilter_->SetCodecFormat(audioEncFormat_);
            audioEncoderFilter_->Init(recorderEventReceiver_, recorderCallback_);
            FALSE_RETURN_V_MSG_E(audioEncoderFilter_->Configure(audioEncFormat_) == Status::OK,
                Status::ERROR_INVALID_DATA, "audioEncoderFilter_ Configure fail");
            pipeline_->LinkFilters(filter, {audioEncoderFilter_}, outType);
            break;
        case Pipeline::StreamType::STREAMTYPE_ENCODED_AUDIO:
        case Pipeline::StreamType::STREAMTYPE_ENCODED_VIDEO:
            if (muxerFilter_ == nullptr) {
                muxerFilter_ = Pipeline::FilterFactory::Instance().CreateFilter<Pipeline::MuxerFilter>
                    ("muxerFilter", Pipeline::FilterType::FILTERTYPE_MUXER);
                FALSE_RETURN_V_MSG_E(muxerFilter_ != nullptr,
                    Status::ERROR_NULL_POINTER, "muxerFilter_ is null");
                muxerFilter_->SetCallingInfo(appUid_, appPid_, bundleName_, instanceId_);
                muxerFilter_->Init(recorderEventReceiver_, recorderCallback_);
                muxerFilter_->SetOutputParameter(appUid_, appPid_, fd_, outputFormatType_);
                muxerFilter_->SetParameter(muxerFormat_);
                muxerFilter_->SetUserMeta(userMeta_);
                muxerFilter_->SetMaxDuration(maxDuration_);
                CloseFd();
            }
            pipeline_->LinkFilters(filter, {muxerFilter_}, outType);
            break;
        default:
            break;
    }
    return Status::OK;
}

void HiRecorderImpl::OnAudioCaptureChange(const AudioStandard::AudioCapturerChangeInfo &capturerChangeInfo)
{
    MEDIA_LOG_I("HiRecorderImpl OnAudioCaptureChange enter.");
    auto ptr = obs_.lock();
    FALSE_RETURN_MSG(ptr != nullptr, "HiRecorderImpl OnAudioCaptureChange obs_ is null");
    
    MEDIA_LOG_I("HiRecorderImpl OnAudioCaptureChange start.");
    ptr->OnAudioCaptureChange(ConvertCapturerChangeInfo(capturerChangeInfo));
}

int32_t HiRecorderImpl::GetCurrentCapturerChangeInfo(AudioRecorderChangeInfo &changeInfo)
{
    FALSE_RETURN_V_MSG_E(audioCaptureFilter_ != nullptr,
        (int32_t)Status::ERROR_INVALID_OPERATION,
        "audioCaptureFilter_ is nullptr, cannot get audio capturer change info");

    AudioStandard::AudioCapturerChangeInfo audioChangeInfo;
    Status ret = audioCaptureFilter_->GetCurrentCapturerChangeInfo(audioChangeInfo);
    changeInfo = ConvertCapturerChangeInfo(audioChangeInfo);
    return (int32_t)ret;
}

int32_t HiRecorderImpl::GetAvailableEncoder(std::vector<EncoderCapabilityData> &encoderInfo)
{
    if (!codecCapabilityAdapter_) {
        codecCapabilityAdapter_ = std::make_shared<Pipeline::CodecCapabilityAdapter>();
    }
    codecCapabilityAdapter_->Init();

    std::vector<MediaAVCodec::CapabilityData*> encoderCapData;
    Status ret = codecCapabilityAdapter_->GetAvailableEncoder(encoderCapData);

    encoderInfo = ConvertEncoderInfo(encoderCapData);
    return (int32_t)ret;
}

int32_t HiRecorderImpl::GetMaxAmplitude()
{
    FALSE_RETURN_V_MSG_E(audioCaptureFilter_ != nullptr,
        (int32_t)Status::ERROR_INVALID_OPERATION, "audioCaptureFilter_ is null, cannot get audio max amplitude");

    return audioCaptureFilter_->GetMaxAmplitude();
}

void HiRecorderImpl::ConfigureAudio(const RecorderParam &recParam)
{
    MEDIA_LOG_I("ConfigureAudio enter.");
    switch (recParam.type) {
        case RecorderPublicParamType::AUD_SAMPLERATE: {
            AudSampleRate audSampleRate = static_cast<const AudSampleRate&>(recParam);
            audioEncFormat_->Set<Tag::AUDIO_SAMPLE_RATE>(audSampleRate.sampleRate);
            break;
        }
        case RecorderPublicParamType::AUD_CHANNEL: {
            AudChannel audChannel = static_cast<const AudChannel&>(recParam);
            audioEncFormat_->Set<Tag::AUDIO_CHANNEL_COUNT>(audChannel.channel);
            break;
        }
        case RecorderPublicParamType::AUD_BITRATE: {
            AudBitRate audBitRate = static_cast<const AudBitRate&>(recParam);
            if (audBitRate.bitRate <= 0) {
                OnEvent({"audioBitRate", EventType::EVENT_ERROR, Status::ERROR_INVALID_PARAMETER});
            }
            audioEncFormat_->Set<Tag::MEDIA_BITRATE>(audBitRate.bitRate);
            break;
        }
        case RecorderPublicParamType::AUD_ENC_FMT: {
            ConfigureAudioCodecFormat(recParam);
            break;
        }
        case RecorderPublicParamType::AUD_AAC_FMT: {
            ConfigureAudioAacProfile(recParam);
            break;
        }
        default: {
            break;
        }
    }
}

void HiRecorderImpl::ConfigureAudioAacProfile(const RecorderParam &recParam)
{
    MEDIA_LOG_I("ConfigureAudioAacProfile enter.");
    AacEnc aacEnc = static_cast<const AacEnc&>(recParam);
    switch (aacEnc.encFmt) {
        case OHOS::Media::AacProfile::AAC_LC:
            audioEncFormat_->Set<Tag::MIME_TYPE>(Plugins::MimeType::AUDIO_AAC);
            audioEncFormat_->Set<Tag::MEDIA_PROFILE>(Plugins::AACProfile::AAC_PROFILE_LC);
            break;
        case OHOS::Media::AacProfile::AAC_HE:
            audioEncFormat_->Set<Tag::MIME_TYPE>(Plugins::MimeType::AUDIO_AAC);
            audioEncFormat_->Set<Tag::MEDIA_PROFILE>(Plugins::AACProfile::AAC_PROFILE_HE);
            break;
        case OHOS::Media::AacProfile::AAC_HE_V2:
            audioEncFormat_->Set<Tag::MIME_TYPE>(Plugins::MimeType::AUDIO_AAC);
            audioEncFormat_->Set<Tag::MEDIA_PROFILE>(Plugins::AACProfile::AAC_PROFILE_HE_V2);
            break;
        default:
            break;
    }
}

void HiRecorderImpl::ConfigureAudioCodecFormat(const RecorderParam &recParam)
{
    AudEnc audEnc = static_cast<const AudEnc&>(recParam);
    switch (audEnc.encFmt) {
        case OHOS::Media::AudioCodecFormat::AUDIO_DEFAULT:
        case OHOS::Media::AudioCodecFormat::AAC_LC:
            audioEncFormat_->Set<Tag::MIME_TYPE>(Plugins::MimeType::AUDIO_AAC);
            audioEncFormat_->Set<Tag::AUDIO_AAC_PROFILE>(Plugins::AudioAacProfile::LC);
            break;
        case OHOS::Media::AudioCodecFormat::AUDIO_MPEG:
            audioEncFormat_->Set<Tag::MIME_TYPE>(Plugins::MimeType::AUDIO_MPEG);
            break;
        case OHOS::Media::AudioCodecFormat::AUDIO_G711MU:
            audioEncFormat_->Set<Tag::MIME_TYPE>(Plugins::MimeType::AUDIO_G711MU);
            break;
        case OHOS::Media::AudioCodecFormat::AUDIO_AMR_NB:
            audioEncFormat_->Set<Tag::MIME_TYPE>(Plugins::MimeType::AUDIO_AMR_NB);
            break;
        case OHOS::Media::AudioCodecFormat::AUDIO_AMR_WB:
            audioEncFormat_->Set<Tag::MIME_TYPE>(Plugins::MimeType::AUDIO_AMR_WB);
            break;
        default:
            break;
    }
}

void HiRecorderImpl::ConfigureVideo(const RecorderParam &recParam)
{
    MEDIA_LOG_I("ConfigureVideo enter.");
    switch (recParam.type) {
        case RecorderPublicParamType::VID_RECTANGLE: {
            ConfigureVidRectangle(recParam);
            break;
        }
        case RecorderPublicParamType::VID_CAPTURERATE: {
            ConfigureVidCaptureRate(recParam);
            break;
        }
        case RecorderPublicParamType::VID_BITRATE: {
            ConfigureVidBitRate(recParam);
            break;
        }
        case RecorderPublicParamType::VID_FRAMERATE: {
            ConfigureVidFrameRate(recParam);
            break;
        }
        case RecorderPublicParamType::VID_ENC_FMT: {
            ConfigureVidEncFmt(recParam);
            break;
        }
        case RecorderPublicParamType::VID_IS_HDR: {
            ConfigureVidIsHdr(recParam);
            break;
        }
        case RecorderPublicParamType::VID_ENABLE_TEMPORAL_SCALE: {
            ConfigureVideoEnableTemporalScale(recParam);
            break;
        }
        case RecorderPublicParamType::VID_ENABLE_STABLE_QUALITY_MODE: {
            ConfigureVidEnableStableQualityMode(recParam);
            break;
        }
        case RecorderPublicParamType::VID_ENABLE_B_FRAME: {
            ConfigureVidEnableBFrame(recParam);
            break;
        }
        default:
            break;
    }
}

void HiRecorderImpl::ConfigureMeta(int32_t sourceId, const RecorderParam &recParam)
{
    MEDIA_LOG_I("HiRecorderImpl ConfigureMeta enter");
    if (metaDataFormats_.find(sourceId) == metaDataFormats_.end()) {
        auto format = std::make_shared<Meta>();
        metaDataFormats_.emplace(std::make_pair(sourceId, format));
    }
    auto metaFormat = metaDataFormats_.at(sourceId);
    switch (recParam.type) {
        case RecorderPublicParamType::META_MIME_TYPE: {
            MetaMimeType mimeType = static_cast<const MetaMimeType&>(recParam);
            metaFormat->Set<Tag::MIME_TYPE>(mimeType.mimeType);
            break;
        }
        case RecorderPublicParamType::META_TIMED_KEY: {
            MetaTimedKey timedKey = static_cast<const MetaTimedKey&>(recParam);
            metaFormat->Set<Tag::TIMED_METADATA_KEY>(timedKey.timedKey);
            break;
        }
        case RecorderPublicParamType::META_SOURCE_TRACK_MIME: {
            MetaSourceTrackMime sourceTrackMime = static_cast<const MetaSourceTrackMime&>(recParam);
            metaFormat->Set<Tag::TIMED_METADATA_SRC_TRACK_MIME>(sourceTrackMime.sourceMime);
            break;
        }
        default:
            break;
    }
}

void HiRecorderImpl::ConfigureVidEncBitrateMode()
{
    if (enableStableQualityMode_) {
        MEDIA_LOG_I("enableStableQualityMode: true, SQR mode in!");
        videoEncFormat_->Set<Tag::VIDEO_ENCODE_BITRATE_MODE>(Plugins::VideoEncodeBitrateMode::SQR);
        int64_t vidBitRate = -1;
        videoEncFormat_->Get<Tag::MEDIA_BITRATE>(vidBitRate);
        FALSE_RETURN_MSG(vidBitRate != -1, "Get vidBitRate fail!");
        std::string vidEncParamValue = "video_encode_bitrate_mode=SQR:bitrate=" + std::to_string(vidBitRate);
        userMeta_->SetData("com.openharmony.encParam", vidEncParamValue);
    } else {
        MEDIA_LOG_I("enableStableQualityMode: false, VBR mode in!");
        videoEncFormat_->Set<Tag::VIDEO_ENCODE_BITRATE_MODE>(Plugins::VideoEncodeBitrateMode::VBR);
    }
}

void HiRecorderImpl::ConfigureVidRectangle(const RecorderParam &recParam)
{
    VidRectangle vidRectangle = static_cast<const VidRectangle&>(recParam);
    videoEncFormat_->Set<Tag::VIDEO_WIDTH>(vidRectangle.width);
    videoEncFormat_->Set<Tag::VIDEO_HEIGHT>(vidRectangle.height);
}

void HiRecorderImpl::ConfigureVidCaptureRate(const RecorderParam &recParam)
{
    CaptureRate captureRate = static_cast<const CaptureRate&>(recParam);
    videoEncFormat_->Set<Tag::VIDEO_CAPTURE_RATE>(captureRate.capRate);
}

void HiRecorderImpl::ConfigureVidBitRate(const RecorderParam &recParam)
{
    VidBitRate vidBitRate = static_cast<const VidBitRate&>(recParam);
    if (vidBitRate.bitRate <= 0) {
        OnEvent({"videoBitRate", EventType::EVENT_ERROR, Status::ERROR_INVALID_PARAMETER});
    }
    videoEncFormat_->Set<Tag::MEDIA_BITRATE>(vidBitRate.bitRate);
}

void HiRecorderImpl::ConfigureVidFrameRate(const RecorderParam &recParam)
{
    VidFrameRate vidFrameRate = static_cast<const VidFrameRate&>(recParam);
    videoEncFormat_->Set<Tag::VIDEO_FRAME_RATE>(vidFrameRate.frameRate);
}

void HiRecorderImpl::ConfigureVidEncFmt(const RecorderParam &recParam)
{
    videoEncFormat_ = std::make_shared<Meta>();
    userMeta_ = std::make_shared<Meta>();
    ConfigureVideoEncoderFormat(recParam);
}

void HiRecorderImpl::ConfigureVidIsHdr(const RecorderParam &recParam)
{
    VidIsHdr vidIsHdr = static_cast<const VidIsHdr&>(recParam);
    if (vidIsHdr.isHdr) {
        videoEncFormat_->Set<Tag::VIDEO_H265_PROFILE>(Plugins::HEVCProfile::HEVC_PROFILE_MAIN_10);
    }
}

void HiRecorderImpl::ConfigureVideoEnableTemporalScale(const RecorderParam &recParam)
{
    VidEnableTemporalScale vidEnableTemporalScale = static_cast<const VidEnableTemporalScale&>(recParam);
    if (vidEnableTemporalScale.enableTemporalScale) {
        videoEncFormat_->Set<Tag::VIDEO_ENCODER_ENABLE_TEMPORAL_SCALABILITY>(
            vidEnableTemporalScale.enableTemporalScale);
    }
}

void HiRecorderImpl::ConfigureVidEnableStableQualityMode(const RecorderParam &recParam)
{
    VidEnableStableQualityMode vidEnableStableQualityMode =
        static_cast<const VidEnableStableQualityMode&>(recParam);
    enableStableQualityMode_ = vidEnableStableQualityMode.enableStableQualityMode;
}

void HiRecorderImpl::ConfigureVidEnableBFrame(const RecorderParam &recParam)
{
    VidEnableBFrame vidEnableBFrame =
        static_cast<const VidEnableBFrame&>(recParam);
    enableBFrame_ = vidEnableBFrame.enableBFrame;
}

void HiRecorderImpl::ConfigureVideoEncoderFormat(const RecorderParam &recParam)
{
    VidEnc vidEnc = static_cast<const VidEnc&>(recParam);
    switch (vidEnc.encFmt) {
        case OHOS::Media::VideoCodecFormat::VIDEO_DEFAULT:
        case OHOS::Media::VideoCodecFormat::H264:
            videoEncFormat_->Set<Tag::MIME_TYPE>(Plugins::MimeType::VIDEO_AVC);
            videoEncFormat_->Set<Tag::VIDEO_H264_PROFILE>(Plugins::VideoH264Profile::BASELINE);
            videoEncFormat_->Set<Tag::VIDEO_H264_LEVEL>(32); // 32: LEVEL 3.2
            codecMimeType_ = MediaAVCodec::CodecMimeType::VIDEO_AVC;
            break;
        case OHOS::Media::VideoCodecFormat::MPEG4:
            videoEncFormat_->Set<Tag::MIME_TYPE>(Plugins::MimeType::VIDEO_MPEG4);
            codecMimeType_ = MediaAVCodec::CodecMimeType::VIDEO_MPEG4;
            break;
        case OHOS::Media::VideoCodecFormat::H265:
            MEDIA_LOG_I("ConfigureVideo H265 enter");
            videoEncFormat_->Set<Tag::MIME_TYPE>(Plugins::MimeType::VIDEO_HEVC);
            codecMimeType_ = MediaAVCodec::CodecMimeType::VIDEO_HEVC;
            break;
        default:
            break;
    }
}

bool HiRecorderImpl::CheckAudioSourceType(AudioSourceType sourceType)
{
    switch (sourceType) {
        case AUDIO_SOURCE_DEFAULT:
        case AUDIO_MIC:
        case AUDIO_SOURCE_VOICE_CALL:
        case AUDIO_INNER:
        case AUDIO_SOURCE_VOICE_RECOGNITION:
        case AUDIO_SOURCE_VOICE_COMMUNICATION:
        case AUDIO_SOURCE_VOICE_MESSAGE:
        case AUDIO_SOURCE_CAMCORDER:
            return true;
        case AUDIO_SOURCE_INVALID:
        default:
            break;
    }
    return false;
}

void HiRecorderImpl::ConfigureRotation(const RecorderParam &recParam)
{
    RotationAngle rotationAngle = static_cast<const RotationAngle&>(recParam);
    if (rotationAngle.rotation == Plugins::VideoRotation::VIDEO_ROTATION_0) {
        muxerFormat_->Set<Tag::VIDEO_ROTATION>(Plugins::VideoRotation::VIDEO_ROTATION_0);
    } else if (rotationAngle.rotation == Plugins::VideoRotation::VIDEO_ROTATION_90) {
        muxerFormat_->Set<Tag::VIDEO_ROTATION>(Plugins::VideoRotation::VIDEO_ROTATION_90);
    } else if (rotationAngle.rotation == Plugins::VideoRotation::VIDEO_ROTATION_180) {
        muxerFormat_->Set<Tag::VIDEO_ROTATION>(Plugins::VideoRotation::VIDEO_ROTATION_180);
    } else if (rotationAngle.rotation == Plugins::VideoRotation::VIDEO_ROTATION_270) {
        muxerFormat_->Set<Tag::VIDEO_ROTATION>(Plugins::VideoRotation::VIDEO_ROTATION_270);
    }
}

void HiRecorderImpl::ConfigureMuxer(const RecorderParam &recParam)
{
    MEDIA_LOG_I("HiRecorderImpl ConfigureMuxer enter");
    switch (recParam.type) {
        case RecorderPublicParamType::OUT_FD: {
            OutFd outFd = static_cast<const OutFd&>(recParam);
            fd_ = dup(outFd.fd);
            muxerFormat_->Set<Tag::MEDIA_CREATION_TIME>("now");
            MEDIA_LOG_I("ConfigureMuxer enter " PUBLIC_LOG_D32, fd_);
            break;
        }
        case RecorderPublicParamType::MAX_DURATION: {
            MaxDuration maxDuration = static_cast<const MaxDuration&>(recParam);
            maxDuration_ = maxDuration.duration;
            break;
        }
        case RecorderPublicParamType::MAX_SIZE: {
            MaxFileSize maxFileSize = static_cast<const MaxFileSize&>(recParam);
            maxSize_ = maxFileSize.size;
            if (muxerFilter_) {
                muxerFilter_->SetMaxDuration(maxDuration_);
            }
            break;
        }
        case RecorderPublicParamType::VID_ORIENTATION_HINT: {
            ConfigureRotation(recParam);
            if (muxerFilter_) {
                muxerFilter_->SetParameter(muxerFormat_);
            }
            break;
        }
        case RecorderPublicParamType::GEO_LOCATION: {
            GeoLocation geoLocation = static_cast<const GeoLocation&>(recParam);
            muxerFormat_->Set<Tag::MEDIA_LATITUDE>(geoLocation.latitude);
            muxerFormat_->Set<Tag::MEDIA_LONGITUDE>(geoLocation.longitude);
            break;
        }
        case RecorderPublicParamType::CUSTOM_INFO: {
            CustomInfo customInfo = static_cast<const CustomInfo&>(recParam);
            userMeta_ = std::make_shared<Meta>(customInfo.userCustomInfo);
            break;
        }
        case RecorderPublicParamType::GENRE_INFO: {
            GenreInfo genreInfo = static_cast<const GenreInfo&>(recParam);
            muxerFormat_->SetData("genre", genreInfo.genre);
            break;
        }
        default:
            break;
    }
}

bool HiRecorderImpl::CheckParamType(int32_t sourceId, const RecorderParam &recParam)
{
    FALSE_RETURN_V((recParam.type == RecorderPublicParamType::AUD_AAC_FMT) ||
        (SourceIdGenerator::IsAudio(sourceId) && recParam.IsAudioParam() && audioSourceId_ == sourceId) ||
        (SourceIdGenerator::IsVideo(sourceId) && recParam.IsVideoParam() && videoSourceId_ == sourceId) ||
        (SourceIdGenerator::IsMeta(sourceId) && recParam.IsMetaParam() &&
        (GetMetaSourceType(sourceId) > VIDEO_META_SOURCE_INVALID &&
        GetMetaSourceType(sourceId) < VIDEO_META_SOURCE_BUTT)) ||
        ((sourceId == DUMMY_SOURCE_ID) && !(recParam.IsAudioParam() || recParam.IsVideoParam())), false);
    return true;
}

void HiRecorderImpl::OnStateChanged(StateId state)
{
    curState_ = state;
}

/**
 * CapturerChangeInfo to AudioRecorderChangeInfo
*/
AudioRecorderChangeInfo HiRecorderImpl::ConvertCapturerChangeInfo(
    const AudioStandard::AudioCapturerChangeInfo &capturerChangeInfo)
{
    MEDIA_LOG_I("HiRecorderImpl ConvertCapturerChangeInfo start.");
    AudioRecorderChangeInfo audioRecorderChangeInfo;
    audioRecorderChangeInfo.createrUID = capturerChangeInfo.createrUID;
    audioRecorderChangeInfo.clientUID = capturerChangeInfo.clientUID;
    audioRecorderChangeInfo.clientPid = capturerChangeInfo.clientPid;
    audioRecorderChangeInfo.sessionId = capturerChangeInfo.sessionId;
    audioRecorderChangeInfo.capturerState = capturerChangeInfo.capturerState;

    audioRecorderChangeInfo.capturerInfo.sourceType = capturerChangeInfo.capturerInfo.sourceType;
    audioRecorderChangeInfo.capturerInfo.capturerFlags = capturerChangeInfo.capturerInfo.capturerFlags;

    audioRecorderChangeInfo.inputDeviceInfo.deviceName = capturerChangeInfo.inputDeviceInfo.deviceName_;
    audioRecorderChangeInfo.inputDeviceInfo.deviceId = capturerChangeInfo.inputDeviceInfo.deviceId_;
    audioRecorderChangeInfo.inputDeviceInfo.channelMasks = capturerChangeInfo.inputDeviceInfo.channelMasks_;
    audioRecorderChangeInfo.inputDeviceInfo.deviceRole = capturerChangeInfo.inputDeviceInfo.deviceRole_;
    audioRecorderChangeInfo.inputDeviceInfo.deviceType = capturerChangeInfo.inputDeviceInfo.deviceType_;
    audioRecorderChangeInfo.inputDeviceInfo.displayName = capturerChangeInfo.inputDeviceInfo.displayName_;
    audioRecorderChangeInfo.inputDeviceInfo.interruptGroupId =
        capturerChangeInfo.inputDeviceInfo.interruptGroupId_;
    audioRecorderChangeInfo.inputDeviceInfo.isLowLatencyDevice =
        capturerChangeInfo.inputDeviceInfo.isLowLatencyDevice_;
    audioRecorderChangeInfo.inputDeviceInfo.macAddress = capturerChangeInfo.inputDeviceInfo.macAddress_;
    audioRecorderChangeInfo.inputDeviceInfo.channelIndexMasks =
        capturerChangeInfo.inputDeviceInfo.channelIndexMasks_;
    AudioStandard::DeviceStreamInfo audioStreamInfo = capturerChangeInfo.inputDeviceInfo.GetDeviceStreamInfo();
    std::set<AudioStandard::AudioChannel> channelSet = audioStreamInfo.GetChannels();
    for (auto item : channelSet) {
        audioRecorderChangeInfo.inputDeviceInfo.audioStreamInfo.channels.insert(static_cast<int32_t>(item));
    }
    for (auto item : audioStreamInfo.samplingRate) {
        audioRecorderChangeInfo.inputDeviceInfo.audioStreamInfo.samplingRate.insert(static_cast<int32_t>(item));
    }
    audioRecorderChangeInfo.inputDeviceInfo.audioStreamInfo.encoding =
        audioStreamInfo.encoding;
    audioRecorderChangeInfo.inputDeviceInfo.audioStreamInfo.format =
        audioStreamInfo.format;
    return audioRecorderChangeInfo;
}

EncoderCapabilityData HiRecorderImpl::ConvertVideoEncoderInfo(MediaAVCodec::CapabilityData *capabilityData)
{
    EncoderCapabilityData encoderInfo;
    encoderInfo.mimeType = capabilityData->mimeType;
    encoderInfo.type = VIDEO_TYPE;
    encoderInfo.bitrate = CodecRange(capabilityData->bitrate.minVal, capabilityData->bitrate.maxVal);
    encoderInfo.frameRate = CodecRange(capabilityData->frameRate.minVal, capabilityData->frameRate.maxVal);
    encoderInfo.width = CodecRange(capabilityData->width.minVal, capabilityData->width.maxVal);
    encoderInfo.height = CodecRange(capabilityData->height.minVal, capabilityData->height.maxVal);
    encoderInfo.channels = CodecRange();
    encoderInfo.sampleRate = std::vector<int32_t>();
    return encoderInfo;
}

EncoderCapabilityData HiRecorderImpl::ConvertAudioEncoderInfo(MediaAVCodec::CapabilityData *capabilityData)
{
    EncoderCapabilityData encoderInfo;
    encoderInfo.mimeType = capabilityData->mimeType;
    encoderInfo.type = AUIDO_TYPE;
    encoderInfo.bitrate = CodecRange(capabilityData->bitrate.minVal, capabilityData->bitrate.maxVal);
    encoderInfo.frameRate = CodecRange();
    encoderInfo.width = CodecRange();
    encoderInfo.height = CodecRange();
    encoderInfo.channels = CodecRange(capabilityData->channels.minVal, capabilityData->channels.maxVal);
    encoderInfo.sampleRate = capabilityData->sampleRate;
    return encoderInfo;
}

std::vector<EncoderCapabilityData> HiRecorderImpl::ConvertEncoderInfo(
    std::vector<MediaAVCodec::CapabilityData*> &capData)
{
    std::vector<EncoderCapabilityData> encoderInfoVector;
    for (int32_t i = 0; i < (int32_t)capData.size(); i++) {
        EncoderCapabilityData encoderInfo;
        if (capData[i]->codecType == MediaAVCodec::AVCodecType::AVCODEC_TYPE_VIDEO_ENCODER) {
            encoderInfo = ConvertVideoEncoderInfo(capData[i]);
            encoderInfoVector.push_back(encoderInfo);
        } else if (capData[i]->codecType == MediaAVCodec::AVCodecType::AVCODEC_TYPE_AUDIO_ENCODER) {
            encoderInfo = ConvertAudioEncoderInfo(capData[i]);
            encoderInfoVector.push_back(encoderInfo);
        } else {
            MEDIA_LOG_W("codecType is not encoder, skip convert");
        }
    }
    return encoderInfoVector;
}

void HiRecorderImpl::SetCallingInfo(const std::string &bundleName, uint64_t instanceId)
{
    bundleName_ = bundleName;
    instanceId_ = instanceId;
}

int32_t HiRecorderImpl::IsWatermarkSupported(bool &isWatermarkSupported)
{
    MEDIA_LOG_D("IsWatermarkSupported enter, codecMimeType:" PUBLIC_LOG_S, codecMimeType_.c_str());
    if (isWatermarkSupported_) {
        isWatermarkSupported = isWatermarkSupported_;
        return (int32_t)Status::OK;
    }
    FALSE_RETURN_V_MSG_E(codecMimeType_ != "", static_cast<int32_t>(Status::ERROR_INVALID_OPERATION),
        "codecMimeType is nullptr, cannot get isWatermarkSupported");
    if (!codecCapabilityAdapter_) {
        codecCapabilityAdapter_ = std::make_shared<Pipeline::CodecCapabilityAdapter>();
    }
    codecCapabilityAdapter_->Init();
    Status ret = codecCapabilityAdapter_->IsWatermarkSupported(codecMimeType_, isWatermarkSupported);
    return static_cast<int32_t>(ret);
}

int32_t HiRecorderImpl::SetWatermark(std::shared_ptr<AVBuffer> &waterMarkBuffer)
{
    FALSE_RETURN_V_MSG_E(videoEncoderFilter_ != nullptr, static_cast<int32_t>(Status::ERROR_NULL_POINTER),
        "videoEncoderFilter is nullptr, cannot set watermark");
    return static_cast<int32_t>(videoEncoderFilter_->SetWatermark(waterMarkBuffer));
}

int32_t HiRecorderImpl::SetUserMeta(const std::shared_ptr<Meta> &userMeta)
{
    FALSE_RETURN_V_MSG_E(muxerFilter_ != nullptr, static_cast<int32_t>(Status::ERROR_NULL_POINTER),
        "muxerFilter is nullptr, cannot set usermeta");
    muxerFilter_->SetUserMeta(userMeta);
    return static_cast<int32_t>(Status::OK);
}

int32_t HiRecorderImpl::SetWillMuteWhenInterrupted(bool muteWhenInterrupted)
{
    muteWhenInterrupted_ = muteWhenInterrupted;
    return static_cast<int32_t>(Status::OK);
}
} // namespace MEDIA
} // namespace OHOS

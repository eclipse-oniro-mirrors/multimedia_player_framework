/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "avmetadatahelper_impl.h"

#include "common/media_source.h"
#include "media_errors.h"
#include "media_log.h"
#include "media_description.h"
#include "meta_utils.h"
#include "uri_helper.h"
#include "osal/task/pipeline_threadpool.h"
#include "pts_and_index_conversion.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_DOMAIN_METADATA, "MetaHelperImpl" };
}

namespace OHOS {
namespace Media {
void AVMetadataHelperImpl::OnError(MediaAVCodec::AVCodecErrorType errorType, int32_t errorCode)
{
    MEDIA_LOGE("OnError errorType:%{public}d, errorCode:%{public}d", static_cast<int32_t>(errorType), errorCode);
    stopProcessing_ = true;
}

AVMetadataHelperImpl::AVMetadataHelperImpl(int32_t appUid, int32_t appPid, uint32_t appTokenId,
    std::string appName) : appUid_(appUid), appPid_(appPid), appTokenId_(appTokenId), appName_(appName)
{
    MEDIA_LOGD("Constructor, instance: 0x%{public}06" PRIXPTR "", FAKE_POINTER(this));
    groupId_ = std::string("AVMeta_") + std::to_string(OHOS::Media::Pipeline::Pipeline::GetNextPipelineId());
    interruptMonitor_ = std::make_shared<InterruptMonitor>();
    if (interruptMonitor_ == nullptr) {
        MEDIA_LOGE("fail to allocate memory for InterruptMonitor");
    }
}

AVMetadataHelperImpl::~AVMetadataHelperImpl()
{
    MEDIA_LOGD("Destructor, instance: 0x%{public}06" PRIXPTR "", FAKE_POINTER(this));
    Destroy();
}

int32_t AVMetadataHelperImpl::SetSource(const std::string &uri, int32_t usage)
{
    UriHelper uriHelper(uri);
    if (uriHelper.UriType() != UriHelper::URI_TYPE_FILE && uriHelper.UriType() != UriHelper::URI_TYPE_FD) {
        MEDIA_LOGE("Unsupported uri type : %{private}s", uri.c_str());
        return MSERR_UNSUPPORT;
    }

    MEDIA_LOGD("0x%{public}06" PRIXPTR " SetSource uri: %{private}s, type:%{public}d", FAKE_POINTER(this), uri.c_str(),
        uriHelper.UriType());

    auto ret = SetSourceInternel(uri, usage == AVMetadataUsage::AV_META_USAGE_FRAME_INDEX_CONVERT);
    CHECK_AND_RETURN_RET_LOG(usage != AVMetadataUsage::AV_META_USAGE_FRAME_INDEX_CONVERT, static_cast<int32_t>(ret),
                             "ret = %{public}d", static_cast<int32_t>(ret));
    CHECK_AND_RETURN_RET_LOG(ret == Status::OK, MSERR_INVALID_VAL,
        "0x%{public}06" PRIXPTR " Failed to call SetSourceInternel", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(MetaUtils::CheckFileType(mediaDemuxer_->GetGlobalMetaInfo()),
        MSERR_UNSUPPORT, "0x%{public}06" PRIXPTR "SetSource unsupport", FAKE_POINTER(this));
    return MSERR_OK;
}

int32_t AVMetadataHelperImpl::SetAVMetadataCaller(AVMetadataCaller caller)
{
    metadataCaller_ = caller;
    MEDIA_LOGI("0x%{public}06" PRIXPTR " SetAVMetadataCaller caller: %{public}d", FAKE_POINTER(this),
        static_cast<int32_t>(metadataCaller_));
    return MSERR_OK;
}

int32_t AVMetadataHelperImpl::SetUrlSource(const std::string &uri, const std::map<std::string, std::string> &header)
{
    MEDIA_LOGD("0x%{public}06" PRIXPTR " SetUrlSource uri: %{private}s", FAKE_POINTER(this), uri.c_str());

    auto ret = SetSourceInternel(uri, header);
    CHECK_AND_RETURN_RET_LOG(ret == Status::OK, MSERR_INVALID_VAL,
        "0x%{public}06" PRIXPTR " Failed to call SetSourceInternel", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(MetaUtils::CheckFileType(mediaDemuxer_->GetGlobalMetaInfo()),
        MSERR_UNSUPPORT, "0x%{public}06" PRIXPTR "SetSource unsupport", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(!mediaDemuxer_->IsSeekToTimeSupported(),
        MSERR_UNSUPPORT, "0x%{public}06" PRIXPTR " hls/dash unsupport", FAKE_POINTER(this));
    CHECK_AND_RETURN_RET_LOG(GetDurationMs() > 0,
        MSERR_UNSUPPORT, "0x%{public}06" PRIXPTR " live stream unsupport", FAKE_POINTER(this));
    return MSERR_OK;
}

int64_t AVMetadataHelperImpl::GetDurationMs()
{
    CHECK_AND_RETURN_RET_LOG(mediaDemuxer_ != nullptr,
        Plugins::HST_TIME_NONE, "Get media duration failed, demuxer is not ready");
    int64_t duration = 0;
    CHECK_AND_RETURN_RET_LOG(mediaDemuxer_->GetDuration(duration),
        Plugins::HST_TIME_NONE, "Get media duration failed");
    CHECK_AND_RETURN_RET_NOLOG(duration > 0, Plugins::HST_TIME_NONE);
    return Plugins::HstTime2Us(duration);
}

int32_t AVMetadataHelperImpl::SetSource(const std::shared_ptr<IMediaDataSource> &dataSrc)
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR "SetSource dataSrc", FAKE_POINTER(this));
    Status ret = SetSourceInternel(dataSrc);
    CHECK_AND_RETURN_RET_LOG(ret == Status::OK, MSERR_INVALID_VAL, "Failed to call SetSourceInternel");

    CHECK_AND_RETURN_RET_LOG(MetaUtils::CheckFileType(mediaDemuxer_->GetGlobalMetaInfo()),
        MSERR_UNSUPPORT, "0x%{public}06" PRIXPTR "SetSource unsupport", FAKE_POINTER(this));
    MEDIA_LOGI("0x%{public}06" PRIXPTR "set source success", FAKE_POINTER(this));
    return MSERR_OK;
}

Status AVMetadataHelperImpl::SetSourceInternel(const std::string &uri, bool isForFrameConvert)
{
    CHECK_AND_RETURN_RET_LOG(!isForFrameConvert, SetSourceForFrameConvert(uri), "SetSource for frame convert");
    Reset();
    mediaDemuxer_ = std::make_shared<MediaDemuxer>();
    CHECK_AND_RETURN_RET_LOG(
        mediaDemuxer_ != nullptr, Status::ERROR_INVALID_DATA, "SetSourceInternel demuxer is nullptr");
    mediaDemuxer_->SetEnableOnlineFdCache(false);
    mediaDemuxer_->SetPlayerId(groupId_);
    if (interruptMonitor_) {
        interruptMonitor_->RegisterListener(mediaDemuxer_);
        interruptMonitor_->SetInterruptState(isInterruptNeeded_.load());
    }
    Status ret = mediaDemuxer_->SetDataSource(std::make_shared<MediaSource>(uri));
    CHECK_AND_RETURN_RET_LOG(ret == Status::OK, ret,
        "0x%{public}06" PRIXPTR " SetSourceInternel demuxer failed to call SetDataSource", FAKE_POINTER(this));
    return Status::OK;
}

Status AVMetadataHelperImpl::SetSourceForFrameConvert(const std::string &uri)
{
    Reset();
    isForFrameConvert_ = true;
    conversion_ = std::make_shared<TimeAndIndexConversion>();
    CHECK_AND_RETURN_RET_LOG(
        conversion_ != nullptr, Status::ERROR_NO_MEMORY, "SetSourceInternel conversion_ is nullptr");
    Status ret = conversion_->SetDataSource(std::make_shared<MediaSource>(uri));
    CHECK_AND_RETURN_RET_LOG(ret == Status::OK, ret,
        "0x%{public}06" PRIXPTR " SetSourceInternel conversion_ failed", FAKE_POINTER(this));
    return Status::OK;
}

Status AVMetadataHelperImpl::SetSourceInternel(const std::shared_ptr<IMediaDataSource> &dataSrc)
{
    Reset();
    mediaDemuxer_ = std::make_shared<MediaDemuxer>();
    CHECK_AND_RETURN_RET_LOG(
        mediaDemuxer_ != nullptr, Status::ERROR_INVALID_DATA, "SetSourceInternel demuxer is nullptr");
    mediaDemuxer_->SetEnableOnlineFdCache(false);
    mediaDemuxer_->SetPlayerId(groupId_);
    if (interruptMonitor_) {
        interruptMonitor_->RegisterListener(mediaDemuxer_);
    }
    Status ret = mediaDemuxer_->SetDataSource(std::make_shared<MediaSource>(dataSrc));
    CHECK_AND_RETURN_RET_LOG(ret == Status::OK, ret, "Failed to call SetDataSource");
    return Status::OK;
}

Status AVMetadataHelperImpl::SetSourceInternel(const std::string &uri,
    const std::map<std::string, std::string> &header)
{
    Reset();
    mediaDemuxer_ = std::make_shared<MediaDemuxer>();
    CHECK_AND_RETURN_RET_LOG(
        mediaDemuxer_ != nullptr, Status::ERROR_INVALID_DATA, "SetSourceInternel demuxer is nullptr");
    mediaDemuxer_->SetPlayerId(groupId_);
    if (interruptMonitor_) {
        interruptMonitor_->RegisterListener(mediaDemuxer_);
        interruptMonitor_->SetInterruptState(isInterruptNeeded_.load());
    }
    Status ret = Status::OK;
    if (!header.empty()) {
        MEDIA_LOGI("DoSetSource header");
        ret = mediaDemuxer_->SetDataSource(std::make_shared<MediaSource>(uri, header));
    } else {
        MEDIA_LOGI("DoSetSource url");
        ret = mediaDemuxer_->SetDataSource(std::make_shared<MediaSource>(uri));
    }
    CHECK_AND_RETURN_RET_LOG(ret == Status::OK, ret,
        "0x%{public}06" PRIXPTR " SetSourceInternel demuxer failed to call SetDataSource", FAKE_POINTER(this));
    return Status::OK;
}

std::string AVMetadataHelperImpl::ResolveMetadata(int32_t key)
{
    MEDIA_LOGI("enter ResolveMetadata with key: %{public}d", key);
    auto res = InitMetadataCollector();
    CHECK_AND_RETURN_RET(res == Status::OK, "");
    return metadataCollector_->ExtractMetadata(key);
}

std::unordered_map<int32_t, std::string> AVMetadataHelperImpl::ResolveMetadata()
{
    MEDIA_LOGD("enter ResolveMetadata");
    auto res = InitMetadataCollector();
    CHECK_AND_RETURN_RET(res == Status::OK, {});
    return metadataCollector_->ExtractMetadata();
}

std::shared_ptr<AVSharedMemory> AVMetadataHelperImpl::FetchArtPicture()
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR " enter FetchArtPicture", FAKE_POINTER(this));
    auto res = InitMetadataCollector();
    CHECK_AND_RETURN_RET(res == Status::OK, nullptr);
    return metadataCollector_->GetArtPicture();
}

std::shared_ptr<Meta> AVMetadataHelperImpl::GetAVMetadata()
{
    MEDIA_LOGE("enter GetAVMetadata");
    auto res = InitMetadataCollector();
    CHECK_AND_RETURN_RET(res == Status::OK, nullptr);
    return metadataCollector_->GetAVMetadata();
}

std::shared_ptr<AVSharedMemory> AVMetadataHelperImpl::FetchFrameAtTime(
    int64_t timeUs, int32_t option, const OutputConfiguration &param)
{
    MEDIA_LOGD("enter FetchFrameAtTime");
    auto res = InitThumbnailGenerator();
    CHECK_AND_RETURN_RET(res == Status::OK, nullptr);
    return thumbnailGenerator_->FetchFrameAtTime(timeUs, option, param);
}

std::shared_ptr<AVBuffer> AVMetadataHelperImpl::FetchFrameYuv(
    int64_t timeUs, int32_t option, const OutputConfiguration &param)
{
    MEDIA_LOGD("enter FetchFrameAtTime");
    auto res = InitThumbnailGenerator();
    CHECK_AND_RETURN_RET_NOLOG(res == Status::OK, nullptr);
    std::shared_ptr<AVBuffer> avBuffer = thumbnailGenerator_->FetchFrameYuv(timeUs, option, param);
    Plugins::FileType fileType =  Plugins::FileType::UNKNOW;
    if (mediaDemuxer_ != nullptr) {
        const std::shared_ptr<Meta> globalInfo = mediaDemuxer_->GetGlobalMetaInfo();
        globalInfo->GetData(Tag::MEDIA_FILE_TYPE, fileType);
    }
    CHECK_AND_RETURN_RET_NOLOG(avBuffer != nullptr, nullptr);
    bool isEosBuffer = avBuffer->flag_ & (uint32_t)(AVBufferFlag::EOS);
    if (fileType == Plugins::FileType::MPEGTS) {
        if (isEosBuffer) {
            avBuffer = thumbnailGenerator_->FetchFrameYuv(succTimeUs_, option, param);
            CHECK_AND_RETURN_RET_NOLOG(avBuffer != nullptr, nullptr);
            MEDIA_LOGI("dtsTime %{public}" PRId64 " ptsTime %{public}" PRId64, avBuffer->dts_, avBuffer->pts_);
        } else {
            succTimeUs_ = timeUs;
            MEDIA_LOGI("last succTime %{public}" PRId64, succTimeUs_);
        }
    }
    CHECK_AND_RETURN_RET_NOLOG(metadataCaller_ != AVMetadataCaller::AV_METADATA_EXTRACTOR || avBuffer == nullptr ||
        !(avBuffer->flag_ & (uint32_t)(AVBufferFlag::EOS)), nullptr);
    return avBuffer;
}

std::shared_ptr<AVBuffer> AVMetadataHelperImpl::FetchFrameYuvs(
    int64_t timeUs, int32_t option, const OutputConfiguration &param, bool &errCallback)
{
    MEDIA_LOGD("enter FetchFrameYuvs");
    auto res = InitThumbnailGenerator();
    CHECK_AND_RETURN_RET_NOLOG(res == Status::OK, nullptr);
    CHECK_AND_RETURN_RET_NOLOG(thumbnailGenerator_ != nullptr, nullptr);
    std::shared_ptr<AVBuffer> avBuffer = thumbnailGenerator_->FetchFrameYuvs(timeUs, option, param, errCallback);
    CHECK_AND_RETURN_RET_NOLOG(metadataCaller_ != AVMetadataCaller::AV_METADATA_EXTRACTOR || avBuffer == nullptr ||
        !(avBuffer->flag_ & (uint32_t)(AVBufferFlag::EOS)), nullptr);
    return avBuffer;
}

int32_t AVMetadataHelperImpl::GetTimeByFrameIndex(uint32_t index, uint64_t &time)
{
    CHECK_AND_RETURN_RET(!isForFrameConvert_, GetTimeForFrameConvert(index, time));
    auto res = InitMetadataCollector();
    CHECK_AND_RETURN_RET_LOG(res == Status::OK, MSERR_INVALID_STATE, "Create collector failed");
    return metadataCollector_->GetTimeByFrameIndex(index, time);
}

int32_t AVMetadataHelperImpl::GetFrameIndexByTime(uint64_t time, uint32_t &index)
{
    CHECK_AND_RETURN_RET(!isForFrameConvert_, GetIndexForFrameConvert(time, index));
    auto res = InitMetadataCollector();
    CHECK_AND_RETURN_RET_LOG(res == Status::OK, MSERR_INVALID_STATE, "Create collector failed");
    return metadataCollector_->GetFrameIndexByTime(time, index);
}

int32_t AVMetadataHelperImpl::GetTimeForFrameConvert(uint32_t index, uint64_t &time)
{
    CHECK_AND_RETURN_RET_LOG(conversion_ != nullptr, MSERR_INVALID_STATE, "conversion_ is nullptr");
    uint32_t trackIndex = 0;
    auto res = conversion_->GetFirstVideoTrackIndex(trackIndex);
    CHECK_AND_RETURN_RET_LOG(res == Status::OK, MSERR_UNSUPPORT_FILE, "GetFirstVideoTrackIndex failed");
    res = conversion_->GetRelativePresentationTimeUsByIndex(trackIndex, index, time);
    MEDIA_LOGI("trackIndex: %{public}" PRIu32 ", index: %{public}" PRIu32 ", time: %{public}" PRIu64
                ", res: %{public}d", trackIndex, index, time, res);
    return res == Status::OK ? MSERR_OK : MSERR_UNSUPPORT_FILE;
}

int32_t AVMetadataHelperImpl::GetIndexForFrameConvert(uint64_t time, uint32_t &index)
{
    CHECK_AND_RETURN_RET_LOG(conversion_ != nullptr, MSERR_INVALID_STATE, "conversion_ is nullptr");
    uint32_t trackIndex = 0;
    auto res = conversion_->GetFirstVideoTrackIndex(trackIndex);
    CHECK_AND_RETURN_RET_LOG(res == Status::OK, MSERR_UNSUPPORT_FILE, "GetFirstVideoTrackIndex failed");
    res = conversion_->GetIndexByRelativePresentationTimeUs(trackIndex, time, index);
    MEDIA_LOGI("trackIndex: %{public}" PRIu32 ", index: %{public}" PRIu32 ", time: %{public}" PRIu64
                ", res: %{public}d", trackIndex, index, time, res);
    return res == Status::OK ? MSERR_OK : MSERR_UNSUPPORT_FILE;
}

void AVMetadataHelperImpl::Reset()
{
    if (metadataCollector_ != nullptr) {
        metadataCollector_->Reset();
    }

    if (thumbnailGenerator_ != nullptr) {
        thumbnailGenerator_->Reset();
    }

    if (mediaDemuxer_ != nullptr) {
        mediaDemuxer_->Reset();
    }

    isForFrameConvert_ = false;
}

void AVMetadataHelperImpl::Destroy()
{
    if (metadataCollector_ != nullptr) {
        metadataCollector_->Destroy();
    }

    if (thumbnailGenerator_ != nullptr) {
        thumbnailGenerator_->Destroy();
    }

    metadataCollector_ = nullptr;
    thumbnailGenerator_ = nullptr;
    PipeLineThreadPool::GetInstance().DestroyThread(groupId_);
    if (interruptMonitor_) {
        interruptMonitor_->DeregisterListener(mediaDemuxer_);
    }
    MEDIA_LOGD("0x%{public}06" PRIXPTR " Finish Destroy.", FAKE_POINTER(this));
}

Status AVMetadataHelperImpl::InitMetadataCollector()
{
    CHECK_AND_RETURN_RET_LOG(
        mediaDemuxer_ != nullptr, Status::ERROR_INVALID_STATE, "mediaDemuxer_ is nullptr");
    if (metadataCollector_ == nullptr) {
        metadataCollector_ = std::make_shared<AVMetaDataCollector>(mediaDemuxer_);
    }
    CHECK_AND_RETURN_RET_LOG(
        metadataCollector_ != nullptr, Status::ERROR_INVALID_STATE, "Init metadata collector failed.");
    return Status::OK;
}

Status AVMetadataHelperImpl::InitThumbnailGenerator()
{
    CHECK_AND_RETURN_RET_LOG(
        mediaDemuxer_ != nullptr, Status::ERROR_INVALID_STATE, "mediaDemuxer_ is nullptr");
    if (thumbnailGenerator_ == nullptr) {
        thumbnailGenerator_ = std::make_shared<AVThumbnailGenerator>(mediaDemuxer_, appUid_, appPid_, appTokenId_, 0);
        CHECK_AND_RETURN_RET_LOG(
            thumbnailGenerator_ != nullptr, Status::ERROR_INVALID_STATE, "create thumbnail generator failed.");
        auto res = thumbnailGenerator_->Init();
        if (res != MSERR_OK) {
            MEDIA_LOGI("Init thumbnail generator failed");
            thumbnailGenerator_ = nullptr;
            return Status::ERROR_INVALID_STATE;
        }
        thumbnailGenerator_->SetClientBundleName(appName_);
    }
    return Status::OK;
}

void AVMetadataHelperImpl::SetInterruptState(bool isInterruptNeeded)
{
    MEDIA_LOGI("Metadata set interrupt state %{public}d", isInterruptNeeded);
    isInterruptNeeded_ = isInterruptNeeded;
    if (interruptMonitor_) {
        interruptMonitor_->SetInterruptState(isInterruptNeeded);
    }
}
}  // namespace Media
}  // namespace OHOS
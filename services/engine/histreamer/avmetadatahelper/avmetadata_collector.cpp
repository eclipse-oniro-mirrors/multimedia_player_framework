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

#include "avmetadata_collector.h"

#include <string>
#include <regex>

#include "avmetadatahelper.h"
#include "buffer/avsharedmemorybase.h"
#include "media_log.h"
#include "meta/video_types.h"
#include "meta/any.h"
#include "time_format_utils.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_DOMAIN_METADATA, "AVMetaDataCollector" };
}  // namespace

namespace OHOS {
namespace Media {
const int32_t FRAME_RATE_UNIT_MULTIPLE = 100; // the unit of frame rate is frames per 100s
static constexpr int PICTURE_MAX_SIZE = 1024 * 1024;
static constexpr int SECOND_DEVIDE_MS = 1000;
const int32_t NUMBER_OF_CHARACTERS_IN_VALID_VIDEOROTATEORIENTATIONTYPE = 2;

static const std::unordered_map<Plugins::FileType, std::string> fileTypeMap = {
    { Plugins::FileType::UNKNOW, "uknown" },
    { Plugins::FileType::MP4, "mp4" },
    { Plugins::FileType::MPEGTS, "mpeg" },
    { Plugins::FileType::MKV, "mkv" },
    { Plugins::FileType::AMR, "amr" },
    { Plugins::FileType::AAC, "aac-adts" },
    { Plugins::FileType::MP3, "mpeg" },
    { Plugins::FileType::FLAC, "flac" },
    { Plugins::FileType::OGG, "ogg" },
    { Plugins::FileType::M4A, "mp4" },
    { Plugins::FileType::WAV, "wav" },
    { Plugins::FileType::MOV, "mov" },
    { Plugins::FileType::AVI, "avi" },
    { Plugins::FileType::MPEGPS, "mpg" }
};

static const std::unordered_map<Plugins::VideoOrientationType, int32_t> videoOrientationTypeMap = {
    { Plugins::VideoOrientationType::ROTATE_NONE, VideoRotateOrientationType::TOP_LEFT },
    { Plugins::VideoOrientationType::ROTATE_90, VideoRotateOrientationType::LEFT_BOTTOM },
    { Plugins::VideoOrientationType::ROTATE_180, VideoRotateOrientationType::BOTTOM_RIGHT },
    { Plugins::VideoOrientationType::ROTATE_270, VideoRotateOrientationType::RIGHT_TOP },
    { Plugins::VideoOrientationType::FLIP_H, VideoRotateOrientationType::TOP_RIGHT },
    { Plugins::VideoOrientationType::FLIP_V, VideoRotateOrientationType::BOTTOM_LEFT },
    { Plugins::VideoOrientationType::FLIP_H_ROT90, VideoRotateOrientationType::LEFT_TOP },
    { Plugins::VideoOrientationType::FLIP_V_ROT90, VideoRotateOrientationType::RIGHT_BOTTOM },
    { Plugins::VideoOrientationType::FLIP_H_ROT180, VideoRotateOrientationType::BOTTOM_LEFT },
    { Plugins::VideoOrientationType::FLIP_V_ROT180, VideoRotateOrientationType::TOP_RIGHT },
    { Plugins::VideoOrientationType::FLIP_H_ROT270, VideoRotateOrientationType::RIGHT_BOTTOM },
    { Plugins::VideoOrientationType::FLIP_V_ROT270, VideoRotateOrientationType::LEFT_TOP },
};

static const std::unordered_map<int32_t, std::string> AVMETA_KEY_TO_X_MAP = {
    { AV_KEY_ALBUM, Tag::MEDIA_ALBUM },
    { AV_KEY_ALBUM_ARTIST, Tag::MEDIA_ALBUM_ARTIST },
    { AV_KEY_ARTIST, Tag::MEDIA_ARTIST },
    { AV_KEY_AUTHOR, Tag::MEDIA_AUTHOR },
    { AV_KEY_COMPOSER, Tag::MEDIA_COMPOSER },
    { AV_KEY_DATE_TIME, Tag::MEDIA_DATE },
    { AV_KEY_DATE_TIME_FORMAT, Tag::MEDIA_CREATION_TIME },
    { AV_KEY_DURATION, Tag::MEDIA_DURATION },
    { AV_KEY_GENRE, Tag::MEDIA_GENRE },
    { AV_KEY_HAS_AUDIO, Tag::MEDIA_HAS_AUDIO },
    { AV_KEY_HAS_VIDEO, Tag::MEDIA_HAS_VIDEO },
    { AV_KEY_MIME_TYPE, Tag::MIME_TYPE },
    { AV_KEY_NUM_TRACKS, Tag::MEDIA_TRACK_COUNT },
    { AV_KEY_SAMPLE_RATE, Tag::AUDIO_SAMPLE_RATE },
    { AV_KEY_TITLE, Tag::MEDIA_TITLE },
    { AV_KEY_VIDEO_HEIGHT, Tag::VIDEO_HEIGHT },
    { AV_KEY_VIDEO_WIDTH, Tag::VIDEO_WIDTH },
    { AV_KEY_VIDEO_ORIENTATION, Tag::VIDEO_ROTATION },
    { AV_KEY_VIDEO_ROTATE_ORIENTATION, Tag::VIDEO_ORIENTATION_TYPE },
    { AV_KEY_VIDEO_IS_HDR_VIVID, Tag::VIDEO_IS_HDR_VIVID },
    { AV_KEY_LOCATION_LONGITUDE, Tag::MEDIA_LONGITUDE },
    { AV_KEY_LOCATION_LATITUDE, Tag::MEDIA_LATITUDE },
    { AV_KEY_CUSTOMINFO, "customInfo" },
    { AV_KEY_DATE_TIME_ISO8601, "ISO8601 time" },
    { AV_KEY_GLTF_OFFSET, Tag::GLTF_OFFSET },
    { AV_KEY_VIDEO_COLOR_TRC, Tag::VIDEO_COLOR_TRC },
    { AV_KEY_VIDEO_DESCRIPTION, Tag::MEDIA_DESCRIPTION },
};

AVMetaDataCollector::AVMetaDataCollector(std::shared_ptr<MediaDemuxer> &mediaDemuxer) : mediaDemuxer_(mediaDemuxer)
{
    MEDIA_LOGD("enter ctor, instance: 0x%{public}06" PRIXPTR "", FAKE_POINTER(this));
}

AVMetaDataCollector::~AVMetaDataCollector()
{
    MEDIA_LOGD("enter dtor, instance: 0x%{public}06" PRIXPTR "", FAKE_POINTER(this));
}

std::unordered_map<int32_t, std::string> AVMetaDataCollector::ExtractMetadata()
{
    if (collectedMeta_.size() != 0) {
        return collectedMeta_;
    }
    const std::shared_ptr<Meta> globalInfo = mediaDemuxer_->GetGlobalMetaInfo();
    const std::vector<std::shared_ptr<Meta>> trackInfos = mediaDemuxer_->GetStreamMetaInfo();
    collectedMeta_ = GetMetadata(globalInfo, trackInfos);
    return collectedMeta_;
}

Status AVMetaDataCollector::GetVideoTrackId(uint32_t &trackId)
{
    if (hasVideo_) {
        trackId = videoTrackId_;
        return Status::OK;
    }
    const std::vector<std::shared_ptr<Meta>> trackInfos = mediaDemuxer_->GetStreamMetaInfo();
    size_t trackCount = trackInfos.size();
    CHECK_AND_RETURN_RET_LOG(trackCount > 0, Status::ERROR_INVALID_DATA, "GetTargetTrackInfo trackCount is invalid");
    for (size_t index = 0; index < trackCount; index++) {
        std::string trackMime = "";
        if (!(trackInfos[index]->GetData(Tag::MIME_TYPE, trackMime))) {
            continue;
        }
        if (trackMime.find("video/") == 0) {
            videoTrackId_ = index;
            trackId = index;
            hasVideo_ = true;
            return Status::OK;
        }
    }
    return Status::ERROR_INVALID_DATA;
}

void AVMetaDataCollector::GetAudioTrackInfo(const std::shared_ptr<Meta> &trackInfo,
    const std::string& mime, size_t index)
{
    MEDIA_LOGD("GetAudioTrackInfo in");
    Format audioTrackInfo {};
    audioTrackInfo.PutIntValue("track_index", static_cast<int32_t>(index));
    audioTrackInfo.PutIntValue("track_type", static_cast<int32_t>(Plugins::MediaType::AUDIO));
    audioTrackInfo.PutStringValue("codec_mime", mime);
    audioTrackInfo.PutStringValue("mime_type", mime);

    int32_t audioChannels = 0;
    trackInfo->GetData(Tag::AUDIO_CHANNEL_COUNT, audioChannels);
    audioTrackInfo.PutIntValue("channel_count", audioChannels);

    int32_t audioSampleRate = 0;
    trackInfo->GetData(Tag::AUDIO_SAMPLE_RATE, audioSampleRate);
    audioTrackInfo.PutIntValue("sample_rate", audioSampleRate);

    int64_t audioBitrate = 0;
    trackInfo->GetData(Tag::MEDIA_BITRATE, audioBitrate);
    audioTrackInfo.PutLongValue("bitrate", audioBitrate);

    int32_t sampleDepth = 0;
    bool isHasData = trackInfo->GetData(Tag::AUDIO_BITS_PER_CODED_SAMPLE, sampleDepth);
    if (!isHasData || sampleDepth <= 0) {
        trackInfo->GetData(Tag::AUDIO_BITS_PER_RAW_SAMPLE, sampleDepth);
    }
    if (sampleDepth > 0) {
        audioTrackInfo.PutLongValue("sample_depth", sampleDepth);
    }
    
    std::vector<int32_t> trackIds;
    if (trackInfo->GetData(Tag::REFERENCE_TRACK_IDS, trackIds)) {
        std::string stringTrackIds = VectorToString(trackIds);
        audioTrackInfo.PutStringValue("ref_track_ids", stringTrackIds);
    }
    
    trackInfoVec_.emplace_back(std::move(audioTrackInfo));
}

void AVMetaDataCollector::GetVideoTrackInfo(const std::shared_ptr<Meta> &trackInfo,
    const std::string& mime, size_t index)
{
    MEDIA_LOGD("GetVideoTrackInfo in");
    Format videoTrackInfo {};
    videoTrackInfo.PutIntValue("track_index", index);
    videoTrackInfo.PutIntValue("track_type", static_cast<int32_t>(Plugins::MediaType::VIDEO));
    videoTrackInfo.PutStringValue("codec_mime", mime);
    videoTrackInfo.PutStringValue("mime_type", mime);

    int32_t originalWidth = 0;
    trackInfo->GetData(Tag::VIDEO_WIDTH, originalWidth);
    videoTrackInfo.PutIntValue("original_width", originalWidth);
    int32_t width = GetSarVideoWidth(trackInfo, originalWidth);
    videoTrackInfo.PutIntValue("width", width);

    int32_t originalHeight = 0;
    trackInfo->GetData(Tag::VIDEO_HEIGHT, originalHeight);
    videoTrackInfo.PutIntValue("original_height", originalHeight);
    int32_t height = GetSarVideoHeight(trackInfo, originalHeight);
    videoTrackInfo.PutIntValue("height", height);

    double frameRate = 0;
    if (trackInfo->GetData(Tag::VIDEO_FRAME_RATE, frameRate)) {
        videoTrackInfo.PutDoubleValue("frame_rate", frameRate * FRAME_RATE_UNIT_MULTIPLE);
    }
    
    bool isHdr = false;
    trackInfo->GetData(Tag::VIDEO_IS_HDR_VIVID, isHdr);
    videoTrackInfo.PutIntValue("hdr_type", static_cast<int32_t>(isHdr));

    std::vector<int32_t> trackIds;
    if (trackInfo->GetData(Tag::REFERENCE_TRACK_IDS, trackIds)) {
        std::string stringTrackIds = VectorToString(trackIds);
        videoTrackInfo.PutStringValue("ref_track_ids", stringTrackIds);
    }
    
    trackInfoVec_.emplace_back(std::move(videoTrackInfo));
}

void AVMetaDataCollector::GetSubtitleTrackInfo(const std::shared_ptr<Meta> &trackInfo,
    const std::string& mime, size_t index)
{
    (void)trackInfo;
    (void)mime;
    MEDIA_LOGD("GetSubtitleTrackInfo in");
    Format subtitleTrackInfo {};
    subtitleTrackInfo.PutIntValue("track_index", index);
    subtitleTrackInfo.PutIntValue("track_type", static_cast<int32_t>(Plugins::MediaType::SUBTITLE));
    trackInfoVec_.emplace_back(std::move(subtitleTrackInfo));
}

void AVMetaDataCollector::GetOtherTrackInfo(const std::shared_ptr<Meta> &trackInfo, size_t index)
{
    MEDIA_LOGD("GetOtherTrackInfo in");
    std::string mime = "";
    trackInfo->GetData(Tag::MIME_TYPE, mime);
    Format otherTrackInfo {};
    otherTrackInfo.PutIntValue("track_index", index);
    Plugins::MediaType mediaType = Plugins::MediaType::UNKNOWN;
    trackInfo->GetData(Tag::MEDIA_TYPE, mediaType);
    otherTrackInfo.PutIntValue("track_type", static_cast<int32_t>(mediaType));
    otherTrackInfo.PutStringValue("codec_mime", mime);
    otherTrackInfo.PutStringValue("mime_type", mime);

    std::vector<int32_t> trackIds;
    if (trackInfo->GetData(Tag::REFERENCE_TRACK_IDS, trackIds)) {
        std::string stringTrackIds = VectorToString(trackIds);
        otherTrackInfo.PutStringValue("ref_track_ids", stringTrackIds);
    }

    if (mediaType == Plugins::MediaType::AUXILIARY || mediaType == Plugins::MediaType::TIMEDMETA) {
        std::string referenceType = "";
        if (trackInfo->GetData(Tag::TRACK_REFERENCE_TYPE, referenceType)) {
            otherTrackInfo.PutStringValue("track_ref_type", referenceType);
        }
    }

    trackInfoVec_.emplace_back(std::move(otherTrackInfo));
}

std::string AVMetaDataCollector::VectorToString(const std::vector<int32_t> &vec) const
{
    std::stringstream ss;
    for (size_t i = 0; i < vec.size(); i++) {
        if (i != 0) {
            ss << ",";
        }
        ss << vec[i];
    }
    return ss.str();
}

int32_t AVMetaDataCollector::GetSarVideoWidth(std::shared_ptr<Meta> trackInfo, int32_t originalWidth) const
{
    int32_t width = originalWidth;
    double videoSar = 0;
    bool ret = trackInfo->GetData(Tag::VIDEO_SAR, videoSar);
    if (ret && videoSar < 1) {
        width = static_cast<int32_t>(originalWidth * videoSar);
    }
    return width;
}

int32_t AVMetaDataCollector::GetSarVideoHeight(std::shared_ptr<Meta> trackInfo, int32_t originalHeight) const
{
    int32_t height = originalHeight;
    double videoSar = 0;
    bool ret = trackInfo->GetData(Tag::VIDEO_SAR, videoSar);
    if (ret && videoSar > 1) {
        height = static_cast<int32_t>(originalHeight / videoSar);
    }
    return height;
}

bool AVMetaDataCollector::IsVideoMime(const std::string& mime) const
{
    return mime.find("video/") == 0;
}

bool AVMetaDataCollector::IsAudioMime(const std::string& mime) const
{
    return mime.find("audio/") == 0;
}

bool AVMetaDataCollector::IsSubtitleMime(const std::string& mime) const
{
    return mime == "application/x-subrip" || mime == "text/vtt";
}

std::shared_ptr<Meta> AVMetaDataCollector::GetAVMetadata()
{
    if (collectedAVMetaData_ != nullptr) {
        return collectedAVMetaData_;
    }
    collectedAVMetaData_ = std::make_shared<Meta>();
    trackInfoVec_.clear();
    ExtractMetadata();
    CHECK_AND_RETURN_RET_LOG(collectedMeta_.size() != 0, nullptr, "globalInfo or trackInfos are invalid.");
    for (const auto &[avKey, value] : collectedMeta_) {
        if (avKey == AV_KEY_LOCATION_LATITUDE || avKey == AV_KEY_LOCATION_LONGITUDE) {
            continue;
        }
        if (avKey == AV_KEY_VIDEO_IS_HDR_VIVID) {
            int32_t hdr;
            if (value == "yes") {
                hdr = static_cast<int32_t>(HdrType::AV_HDR_TYPE_VIVID);
            } else {
                hdr = static_cast<int32_t>(HdrType::AV_HDR_TYPE_NONE);
            }
            collectedAVMetaData_->SetData("hdrType", hdr);
            continue;
        }
        auto iter = g_MetadataCodeMap.find(avKey);
        if (iter != g_MetadataCodeMap.end()) {
            collectedAVMetaData_->SetData(iter->second, value);
        }
    }

    customInfo_ = mediaDemuxer_->GetUserMeta();
    if (customInfo_ == nullptr) {
        MEDIA_LOGW("No valid user data");
    } else {
        if (AVMETA_KEY_TO_X_MAP.find(AV_KEY_CUSTOMINFO) != AVMETA_KEY_TO_X_MAP.end()) {
            collectedAVMetaData_->SetData(AVMETA_KEY_TO_X_MAP.find(AV_KEY_CUSTOMINFO)->second, customInfo_);
        }
    }
    collectedAVMetaData_->SetData("tracks", trackInfoVec_);
    return collectedAVMetaData_;
}

std::string AVMetaDataCollector::ExtractMetadata(int32_t key)
{
    auto metadata = GetAVMetadata();
    CHECK_AND_RETURN_RET_LOG(collectedMeta_.size() != 0, "", "Failed to call ExtractMetadata");

    auto it = collectedMeta_.find(key);
    if (it == collectedMeta_.end() || it->second.empty()) {
        MEDIA_LOGE("The specified metadata %{public}d cannot be obtained from the specified stream.", key);
        return "";
    }
    return collectedMeta_[key];
}

std::unordered_map<int32_t, std::string> AVMetaDataCollector::GetMetadata(
    const std::shared_ptr<Meta> &globalInfo, const std::vector<std::shared_ptr<Meta>> &trackInfos)
{
    CHECK_AND_RETURN_RET_LOG(
        globalInfo != nullptr && trackInfos.size() != 0, {}, "globalInfo or trackInfos are invalid.");

    Metadata metadata;
    metadata.SetMeta(AV_KEY_GLTF_OFFSET, "-1");
    ConvertToAVMeta(globalInfo, metadata);

    int32_t imageTrackCount = 0;
    size_t trackCount = trackInfos.size();
    bool isFirstVideoTrack = true;
    for (size_t index = 0; index < trackCount; index++) {
        std::shared_ptr<Meta> meta = trackInfos[index];
        CHECK_AND_RETURN_RET_LOG(meta != nullptr, metadata.tbl_, "meta is invalid, index: %zu", index);

        std::string mime;
        meta->Get<Tag::MIME_TYPE>(mime);
        InitTracksInfoVector(meta, index);
        if (mime.find("video") == 0) {
            if (!isFirstVideoTrack) {
                continue;
            }
            isFirstVideoTrack = false;
        }
        Plugins::MediaType mediaType;
        CHECK_AND_CONTINUE(meta->GetData(Tag::MEDIA_TYPE, mediaType));
        ConvertToAVMeta(meta, metadata);
    }
    FormatAVMeta(metadata, imageTrackCount, globalInfo);
    auto it = metadata.tbl_.begin();
    while (it != metadata.tbl_.end()) {
        MEDIA_LOGD("metadata tbl, key: %{public}d, keyName: %{public}s, val: %{public}s", it->first,
            AVMETA_KEY_TO_X_MAP.find(it->first)->second.c_str(), it->second.c_str());
        it++;
    }
    return metadata.tbl_;
}

void AVMetaDataCollector::InitTracksInfoVector(const std::shared_ptr<Meta> &meta, size_t index)
{
    Plugins::MediaType mediaType;
    bool hasMediaType = meta->GetData(Tag::MEDIA_TYPE, mediaType);
    if (hasMediaType && mediaType == Plugins::MediaType::AUXILIARY) {
        GetOtherTrackInfo(meta, index);
        return;
    }
    std::string mime = "";
    meta->GetData(Tag::MIME_TYPE, mime);
    if (IsAudioMime(mime)) {
        GetAudioTrackInfo(meta, mime, index);
    } else if (IsVideoMime(mime)) {
        GetVideoTrackInfo(meta, mime, index);
    } else if (IsSubtitleMime(mime)) {
        GetSubtitleTrackInfo(meta, mime, index);
    } else {
        GetOtherTrackInfo(meta, index);
    }
}

std::shared_ptr<AVSharedMemory> AVMetaDataCollector::GetArtPicture()
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR " GetArtPicture In", FAKE_POINTER(this));

    if (collectedArtPicture_ != nullptr) {
        return collectedArtPicture_;
    }
    const std::vector<std::shared_ptr<Meta>> trackInfos = mediaDemuxer_->GetStreamMetaInfo();
    size_t trackCount = trackInfos.size();
    for (size_t index = 0; index < trackCount; index++) {
        std::shared_ptr<Meta> meta = trackInfos[index];
        if (meta == nullptr) {
            MEDIA_LOGW("meta is invalid, index: %zu", index);
            continue;
        }

        std::vector<uint8_t> coverAddr;
        auto mapIt = meta->Find(Tag::MEDIA_COVER);
        if (mapIt == meta->end()) {
            continue;
        }
        if (Any::IsSameTypeWith<std::vector<uint8_t>>(mapIt->second)) {
            coverAddr = AnyCast<std::vector<uint8_t>>(mapIt->second);
        }
        CHECK_AND_RETURN_RET_LOG(!(coverAddr.size() == 0 || static_cast<int>(coverAddr.size()) > PICTURE_MAX_SIZE),
            nullptr, "InvalidArtPictureSize %zu", coverAddr.size());
        uint8_t *addr = coverAddr.data();
        size_t size = coverAddr.size();
        auto artPicMem =
            AVSharedMemoryBase::CreateFromLocal(static_cast<int32_t>(size), AVSharedMemory::FLAGS_READ_ONLY, "artpic");
        if (artPicMem == nullptr) {
            MEDIA_LOGE("artPicMem is nullptr");
            return nullptr;
        }
        errno_t rc = memcpy_s(artPicMem->GetBase(), static_cast<size_t>(artPicMem->GetSize()), addr, size);
        if (rc != EOK) {
            MEDIA_LOGE("memcpy_s failed, trackCount no %{public}zu", index);
            return nullptr;
        }
        collectedArtPicture_ = artPicMem;
        return collectedArtPicture_;
    }
    MEDIA_LOGE("GetArtPicture Failed");
    return nullptr;
}

int32_t AVMetaDataCollector::GetTimeByFrameIndex(uint32_t index, uint64_t &timeUs)
{
    uint32_t trackId = 0;
    CHECK_AND_RETURN_RET_LOG(GetVideoTrackId(trackId) == Status::OK, MSERR_UNSUPPORT_FILE, "No video track!");
    CHECK_AND_RETURN_RET_LOG(mediaDemuxer_->GetRelativePresentationTimeUsByIndex(trackId, index, timeUs) == Status::OK,
        MSERR_UNSUPPORT_FILE, "Get time by frame failed");
    return MSERR_OK;
}

int32_t AVMetaDataCollector::GetFrameIndexByTime(uint64_t timeUs, uint32_t &index)
{
    uint32_t trackId = 0;
    CHECK_AND_RETURN_RET_LOG(GetVideoTrackId(trackId) == Status::OK, MSERR_UNSUPPORT_FILE, "No video track!");
    CHECK_AND_RETURN_RET_LOG(mediaDemuxer_->GetIndexByRelativePresentationTimeUs(trackId, timeUs, index) == Status::OK,
        MSERR_UNSUPPORT_FILE, "Get frame by time failed");
    return MSERR_OK;
}

void AVMetaDataCollector::ConvertToAVMeta(const std::shared_ptr<Meta> &innerMeta, Metadata &avmeta) const
{
    for (const auto &[avKey, innerKey] : AVMETA_KEY_TO_X_MAP) {
        if (innerKey.compare("customInfo") == 0) {
            continue;
        }
        if (innerKey.compare("transfer_characteristics") == 0) {
            Plugins::TransferCharacteristic trc;
            if (innerMeta->GetData(innerKey, trc)) {
                avmeta.SetMeta(avKey, std::to_string(static_cast<int32_t>(trc)));
            }
            continue;
        }
        if (!SetStringByValueType(innerMeta, avmeta, avKey, innerKey)) {
            break;
        }
        SetEmptyStringIfNoData(avmeta, avKey);
    }
}

void AVMetaDataCollector::FormatAVMeta(
    Metadata &avmeta, int32_t imageTrackCount, const std::shared_ptr<Meta> &globalInfo)
{
    FormatDuration(avmeta);
    FormatMimeType(avmeta, globalInfo);
    FormatDateTime(avmeta, globalInfo);
    FormatVideoRotateOrientation(avmeta);
}

void AVMetaDataCollector::FormatDuration(Metadata &avmeta)
{
    std::string durationStr = avmeta.GetMeta(AV_KEY_DURATION);
    std::stringstream ss(durationStr);
    int64_t duration = 0;
    ss >> duration;
    avmeta.SetMeta(AV_KEY_DURATION, std::to_string(duration / SECOND_DEVIDE_MS));
}

void AVMetaDataCollector::FormatMimeType(Metadata &avmeta, const std::shared_ptr<Meta> &globalInfo)
{
    Plugins::FileType fileType = Plugins::FileType::UNKNOW;
    globalInfo->GetData(Tag::MEDIA_FILE_TYPE, fileType);
    CHECK_AND_RETURN_LOG(fileType != Plugins::FileType::UNKNOW, "unknown file type");
    if (fileTypeMap.find(fileType) == fileTypeMap.end()) {
        return;
    }
    if (avmeta.GetMeta(AV_KEY_HAS_VIDEO).compare("yes") == 0) {
        avmeta.SetMeta(AV_KEY_MIME_TYPE, "video/" + fileTypeMap.at(fileType));
        return;
    }
    if (avmeta.GetMeta(AV_KEY_HAS_AUDIO).compare("yes") == 0) {
        avmeta.SetMeta(AV_KEY_MIME_TYPE, "audio/" + fileTypeMap.at(fileType));
    }
}

void AVMetaDataCollector::FormatDateTime(Metadata &avmeta, const std::shared_ptr<Meta> &globalInfo)
{
    std::string date;
    std::string creationTime;
    globalInfo->GetData(Tag::MEDIA_DATE, date);
    globalInfo->GetData(Tag::MEDIA_CREATION_TIME, creationTime);
    std::string formattedDateTime;
    if (!date.empty()) {
        formattedDateTime = TimeFormatUtils::FormatDateTimeByTimeZone(date);
        avmeta.SetMeta(AV_KEY_DATE_TIME_ISO8601, date);
    } else if (!creationTime.empty()) {
        formattedDateTime = TimeFormatUtils::FormatDateTimeByTimeZone(creationTime);
        avmeta.SetMeta(AV_KEY_DATE_TIME_ISO8601, creationTime);
    }
    avmeta.SetMeta(AV_KEY_DATE_TIME, formattedDateTime);
    avmeta.SetMeta(AV_KEY_DATE_TIME_FORMAT,
        formattedDateTime.compare(date) != 0 ? formattedDateTime : TimeFormatUtils::FormatDateTimeByString(date));
}

void AVMetaDataCollector::FormatVideoRotateOrientation(Metadata &avmeta)
{
    std::string videoRotateOrientationType = avmeta.GetMeta(AV_KEY_VIDEO_ROTATE_ORIENTATION);
    MEDIA_LOGI("VideoRotateOrientationType is %{public}s", videoRotateOrientationType.c_str());
    int32_t videoRotateOrientationTypeRet = Plugins::VideoOrientationType::ROTATE_NONE;
    if (videoRotateOrientationType.size() > NUMBER_OF_CHARACTERS_IN_VALID_VIDEOROTATEORIENTATIONTYPE ||
        !IsAllDigits(videoRotateOrientationType)) {
        MEDIA_LOGE("videoRotateOrientationType is invalid");
        avmeta.SetMeta(AV_KEY_VIDEO_ROTATE_ORIENTATION, std::to_string(VideoRotateOrientationType::TOP_LEFT));
        return;
    }
    videoRotateOrientationTypeRet = std::stoi(videoRotateOrientationType);
    Plugins::VideoOrientationType videoOrientationType =
        static_cast<Plugins::VideoOrientationType>(videoRotateOrientationTypeRet);
    auto it = videoOrientationTypeMap.find(videoOrientationType);
    CHECK_AND_RETURN_LOG(it != videoOrientationTypeMap.end(),
        "can't find mapped videoOrientationType name in videoOrientationTypeMap");
    avmeta.SetMeta(AV_KEY_VIDEO_ROTATE_ORIENTATION, std::to_string(it->second));
}

bool AVMetaDataCollector::IsAllDigits(const std::string& str)
{
    if (str.empty()) {
        return false;
    }
    return std::all_of(str.begin(), str.end(), [](char c) {
        return c >= '0' && c <= '9';
    });
}

void AVMetaDataCollector::SetEmptyStringIfNoData(Metadata &avmeta, int32_t avKey) const
{
    if (!avmeta.HasMeta(avKey)) {
        avmeta.SetMeta(avKey, "");
    }
}

bool AVMetaDataCollector::SetStringByValueType(const std::shared_ptr<Meta> &innerMeta,
    Metadata &avmeta, int32_t avKey, std::string innerKey) const
{
    Any type = OHOS::Media::GetDefaultAnyValue(innerKey);
    if (Any::IsSameTypeWith<int32_t>(type)) {
        int32_t intVal;
        if (innerMeta->GetData(innerKey, intVal) && intVal != 0) {
            avmeta.SetMeta(avKey, std::to_string(intVal));
        }
    } else if (Any::IsSameTypeWith<std::string>(type)) {
        std::string strVal;
        if (innerMeta->GetData(innerKey, strVal)) {
            avmeta.SetMeta(avKey, strVal);
        }
    } else if (Any::IsSameTypeWith<Plugins::VideoRotation>(type)) {
        Plugins::VideoRotation rotation;
        if (innerMeta->GetData(innerKey, rotation)) {
            avmeta.SetMeta(avKey, std::to_string(rotation));
        }
    } else if (Any::IsSameTypeWith<Plugins::VideoOrientationType>(type)) {
        Plugins::VideoOrientationType orientation;
        if (innerMeta->GetData(innerKey, orientation)) {
            avmeta.SetMeta(avKey, std::to_string(orientation));
        }
    } else if (Any::IsSameTypeWith<int64_t>(type)) {
        int64_t value;
        if (innerMeta->GetData(innerKey, value)) {
            avmeta.SetMeta(avKey, std::to_string(value));
        }
    } else if (Any::IsSameTypeWith<bool>(type)) {
        bool isTrue;
        if (innerMeta->GetData(innerKey, isTrue)) {
            avmeta.SetMeta(avKey, isTrue ? "yes" : "");
        }
    } else if (Any::IsSameTypeWith<float>(type)) {
        float value;
        if (innerMeta->GetData(innerKey, value) && collectedAVMetaData_ != nullptr) {
            collectedAVMetaData_->SetData(innerKey, value);
        }
    } else {
        MEDIA_LOGE("not found type matched with innerKey: %{public}s", innerKey.c_str());
        return false;
    }
    return true;
}

void AVMetaDataCollector::Reset()
{
    mediaDemuxer_->Reset();
    collectedMeta_.clear();
    videoTrackId_ = 0;
    hasVideo_ = false;
    collectedArtPicture_ = nullptr;
}

void AVMetaDataCollector::Destroy()
{
    mediaDemuxer_ = nullptr;
}
}  // namespace Media
}  // namespace OHOS
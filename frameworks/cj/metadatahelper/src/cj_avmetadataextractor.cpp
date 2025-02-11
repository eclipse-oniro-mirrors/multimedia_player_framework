/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "cj_avmetadataextractor.h"
#include "media_log.h"
#include "pixel_map_impl.h"

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_DOMAIN_METADATA, "CJAVMetadataExtractorImpl" };
}

namespace OHOS {
namespace Media {

bool CreateCString(std::string value, char** result)
{
    *result = static_cast<char *>(malloc((value.size() + 1) * sizeof(char)));
    if (*result == nullptr) {
        return false;
    }
    if (memcpy_s(*result, value.size() + 1, value.c_str(), value.size()) != 0) {
        MEDIA_LOGE("Failed to create string.");
        free(*result);
        return false;
    }
    (*result)[value.size()] = 0;
    return true;
}

bool CreateMapPair(std::string key, std::string value, char** keyPtr, char** valuePtr)
{
    bool ret = CreateCString(key, keyPtr);
    CHECK_AND_RETURN_RET_LOG(ret, ret, "Create map key failed, key %{public}s", key.c_str());
    ret = CreateCString(value, valuePtr);
    if (ret == false) {
        free(*keyPtr);
    }
    return ret;
}

bool CreateCustomInfo(std::shared_ptr<Meta>& meta, CCustomInfo& info)
{
    bool ret = true;
    int64_t index = 0;
    for (auto iter = meta->begin(); iter != meta->end(); iter++) { index++; }
    info.size = index;
    info.key = static_cast<char **>(malloc(index * sizeof(char*)));
    if (info.key == nullptr) {
        info.size = 0;
        return false;
    }
    info.value = static_cast<char **>(malloc(index * sizeof(char*)));
    if (info.value == nullptr) {
        free(info.key);
        info.size = 0;
        return false;
    }
    index = 0;
    for (auto iter = meta->begin(); iter != meta->end(); iter++) {
        AnyValueType type = meta->GetValueType(iter->first);
        CHECK_AND_CONTINUE_LOG(type == AnyValueType::STRING, "key %{public}s is not string", iter->first.c_str());
        std::string sValue;
        ret = meta->GetData(iter->first, sValue);
        CHECK_AND_CONTINUE_LOG(ret, "GetData failed, key %{public}s", iter->first.c_str());
        ret = CreateMapPair(iter->first, sValue, &(info.key[index]), &(info.value[index]));
        CHECK_AND_CONTINUE_LOG(ret, "Create data failed, key %{public}s", iter->first.c_str());
        index++;
    }
    return true;
}

bool CreateLocation(std::shared_ptr<Meta>& meta, CLocation& loc, std::string key)
{
    bool ret = true;
    float dValue;
    ret = meta->GetData(key, dValue);
    CHECK_AND_RETURN_RET_LOG(ret, ret, "GetData failed, key %{public}s", key.c_str());
    if (key == "latitude") {
        loc.latitude = dValue;
    }
    if (key == "longitude") {
        loc.longitude = dValue;
    }
    return ret;
}

bool SetHdrType(std::shared_ptr<Meta>& meta, std::string key, CAVMetadata& result)
{
    bool ret = true;
    int32_t value;
    ret = meta->GetData(key, value);
    CHECK_AND_RETURN_RET_LOG(ret, ret, "GetData failed, key %{public}s", key.c_str());
    result.hdrType = value;
    return ret;
}

char** CAVMetadataGetStrValue(CAVMetadata& data, const std::string key)
{
    char** ret = nullptr;
    if (key == "album") { ret = &(data.album); }
    if (key == "albumArtist") { ret = &(data.albumArtist); }
    if (key == "artist") { ret = &(data.artist); }
    if (key == "author") { ret = &(data.author); }
    if (key == "dateTime") { ret = &(data.dateTime); }
    if (key == "dateTimeFormat") { ret = &(data.dateTimeFormat); }
    if (key == "composer") { ret = &(data.composer); }
    if (key == "duration") { ret = &(data.duration); }
    if (key == "genre") { ret = &(data.genre); }
    if (key == "hasAudio") { ret = &(data.hasAudio); }
    if (key == "hasVideo") { ret = &(data.hasVideo); }
    if (key == "mimeType") { ret = &(data.mimeType); }
    if (key == "trackCount") { ret = &(data.trackCount); }
    if (key == "sampleRate") { ret = &(data.sampleRate); }
    if (key == "title") { ret = &(data.title); }
    if (key == "videoHeight") { ret = &(data.videoHeight); }
    if (key == "videoWidth") { ret = &(data.videoWidth); }
    if (key == "videoOrientation") { ret = &(data.videoOrientation); }
    return ret;
}

bool SetMetadata(std::shared_ptr<Meta>& meta, std::string key, CAVMetadata& result)
{
    bool ret = true;
    std::string sValue;
    ret = meta->GetData(key, sValue);
    CHECK_AND_RETURN_RET_LOG(ret, ret, "GetData failed, key %{public}s", key.c_str());
    auto ptr = CAVMetadataGetStrValue(result, key);
    if (ptr == nullptr) {
        MEDIA_LOGE("GetValue failed, key %{public}s", key.c_str());
        return false;
    }
    CHECK_AND_RETURN_RET_LOG(CreateCString(sValue, ptr), false,
        "Failed to set value, key %{public}s", key.c_str());
    return ret;
}

static std::unique_ptr<PixelMap> ConvertMemToPixelMap(std::shared_ptr<AVSharedMemory> sharedMemory)
{
    CHECK_AND_RETURN_RET_LOG(sharedMemory != nullptr, nullptr, "SharedMem is nullptr");
    MEDIA_LOGI("FetchArtPicture size: %{public}d", sharedMemory->GetSize());
    SourceOptions sourceOptions;
    uint32_t errorCode = 0;
    std::unique_ptr<ImageSource> imageSource =
        ImageSource::CreateImageSource(sharedMemory->GetBase(), sharedMemory->GetSize(), sourceOptions, errorCode);
    CHECK_AND_RETURN_RET_LOG(imageSource != nullptr, nullptr, "Failed to create imageSource.");
    DecodeOptions decodeOptions;
    std::unique_ptr<PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOptions, errorCode);
    CHECK_AND_RETURN_RET_LOG(pixelMap != nullptr, nullptr, "Failed to decode imageSource");
    return pixelMap;
}

void InitAVMetadata(CAVMetadata* data)
{
    data->album = nullptr;
    data->albumArtist = nullptr;
    data->artist = nullptr;
    data->author = nullptr;
    data->dateTime = nullptr;
    data->dateTimeFormat = nullptr;
    data->composer = nullptr;
    data->duration = nullptr;
    data->genre = nullptr;
    data->hasAudio = nullptr;
    data->hasVideo = nullptr;
    data->mimeType = nullptr;
    data->trackCount = nullptr;
    data->sampleRate = nullptr;
    data->title = nullptr;
    data->videoHeight = nullptr;
    data->videoWidth = nullptr;
    data->videoOrientation = nullptr;
    data->hdrType = 0;
    data->location.latitude = 0.0;
    data->location.longitude = 0.0;
    data->customInfo.key = nullptr;
    data->customInfo.value = nullptr;
    data->customInfo.size = 0;
}

sptr<CJAVMetadataExtractorImpl> CJAVMetadataExtractorImpl::Create()
{
    auto instance = FFI::FFIData::Create<CJAVMetadataExtractorImpl>();
    if (instance == nullptr) {
        MEDIA_LOGE("Failed to new CJAVMetadataExtractorImpl");
        return nullptr;
    }
    instance->helper_ = AVMetadataHelperFactory::CreateAVMetadataHelper();
    if (instance->helper_ == nullptr) {
        MEDIA_LOGE("Failed to CreateMetadataHelper");
        FFI::FFIData::Release(instance->GetID());
        return nullptr;
    }
    return instance;
}

CJAVMetadataExtractorImpl::CJAVMetadataExtractorImpl()
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
}

CJAVMetadataExtractorImpl::~CJAVMetadataExtractorImpl()
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Instances destroy", FAKE_POINTER(this));
}

int32_t CJAVMetadataExtractorImpl::FetchMetadata(CAVMetadata* data)
{
    bool ret = true;
    if (data == nullptr) {
        return MSERR_INVALID_VAL;
    }
    InitAVMetadata(data);
    if (state_ != HelperState::HELPER_STATE_RUNNABLE) {
        MEDIA_LOGE("Current state is not runnable, can't fetchFrame.");
        return MSERR_EXT_API9_OPERATE_NOT_PERMIT;
    }
    auto metadata = helper_->GetAVMetadata();
    for (const auto &key : g_Metadata) {
        if (metadata->Find(key) == metadata->end()) {
            MEDIA_LOGE("failed to find key: %{public}s", key.c_str());
            continue;
        }
        MEDIA_LOGI("success to find key: %{public}s", key.c_str());
        if (key == "latitude" || key == "longitude") {
            ret = CreateLocation(metadata, data->location, key);
            CHECK_AND_CONTINUE_LOG(ret, "GetData failed, key %{public}s", key.c_str());
            continue;
        }
        if (key == "hdrType") {
            ret = SetHdrType(metadata, key, *data);
            CHECK_AND_CONTINUE_LOG(ret, "GetData failed, key hdrType");
            continue;
        }
        if (key == "customInfo") {
            std::shared_ptr<Meta> customData = std::make_shared<Meta>();
            ret = metadata->GetData(key, customData);
            CHECK_AND_CONTINUE_LOG(ret, "GetData failed, key %{public}s", key.c_str());
            ret = CreateCustomInfo(customData, data->customInfo);
            continue;
        }
        ret = SetMetadata(metadata, key, *data);
        CHECK_AND_CONTINUE_LOG(ret, "GetData failed, key %{public}s", key.c_str());
    }
    return MSERR_OK;
}

int64_t CJAVMetadataExtractorImpl::FetchAlbumCover()
{
    if (state_ != HelperState::HELPER_STATE_RUNNABLE) {
        MEDIA_LOGE("Current state is not runnable, can't fetchFrame.");
        return 0;
    }
    auto sharedMemory = helper_->FetchArtPicture();
    auto pixelMap = ConvertMemToPixelMap(sharedMemory);
    if (pixelMap == nullptr) {
        MEDIA_LOGE("Failed to fetchAlbumCover.");
        return 0;
    }
    auto result = FFI::FFIData::Create<PixelMapImpl>(move(pixelMap));
    if (result == nullptr) {
        return 0;
    }
    return result->GetID();
}

int32_t CJAVMetadataExtractorImpl::SetAVFileDescriptor(CAVFileDescriptor file)
{
    fileDescriptor_.fd = file.fd;
    fileDescriptor_.offset = file.offset;
    fileDescriptor_.length = file.length;
    MEDIA_LOGD("get fd argument, fd = %{public}d, offset = %{public}" PRIi64 ", size = %{public}" PRIi64 "",
        fileDescriptor_.fd, fileDescriptor_.offset, fileDescriptor_.length);
    auto res = helper_->SetSource(fileDescriptor_.fd, fileDescriptor_.offset, fileDescriptor_.length);
    state_ = res == MSERR_OK ? HelperState::HELPER_STATE_RUNNABLE : HelperState::HELPER_ERROR;
    return MSERR_OK;
}

int32_t CJAVMetadataExtractorImpl::GetAVFileDescriptor(CAVFileDescriptor* file)
{
    if (file == nullptr) {
        return MSERR_INVALID_VAL;
    }
    file->fd = fileDescriptor_.fd;
    file->offset = fileDescriptor_.offset;
    file->length = fileDescriptor_.length;
    return MSERR_OK;
}

int32_t CJAVMetadataExtractorImpl::SetAVDataSrcDescriptor(CAVDataSrcDescriptor data)
{
    if (state_ != HelperState::HELPER_STATE_IDLE) {
        MEDIA_LOGE("Has set source once, unsupport set again.");
        return MSERR_OK;
    }
    if (helper_ == nullptr) {
        MEDIA_LOGE("Invalid CJAVMetadataExtractorImpl.");
        return MSERR_UNKNOWN;
    }
    dataSrcDescriptor_.fileSize = data.fileSize;
    if (dataSrcDescriptor_.fileSize <= 0) {
        return MSERR_OK;
    }
    MEDIA_LOGI("Recvive filesize is %{public}" PRId64 "", dataSrcDescriptor_.fileSize);
    dataSrcDescriptor_.callback = data.callback;
    dataSrcCb_ = std::make_shared<CJHelperDataSourceCallback>(dataSrcDescriptor_.fileSize);
    const std::string callbackName = "readAt";
    if (dataSrcCb_->SaveCallbackReference(callbackName, dataSrcDescriptor_.callback) != MSERR_OK) {
        MEDIA_LOGE("Set callback failed.");
        return MSERR_UNKNOWN;
    }
    auto res = helper_->SetSource(dataSrcCb_);
    state_ = res == MSERR_OK ? HelperState::HELPER_STATE_RUNNABLE : HelperState::HELPER_ERROR;
    MEDIA_LOGI("SetAVDataSrcDescriptor Out");
    return MSERR_OK;
}

int32_t CJAVMetadataExtractorImpl::GetAVDataSrcDescriptor(CAVDataSrcDescriptor* data)
{
    if (data == nullptr) {
        return MSERR_INVALID_VAL;
    }
    dataSrcCb_->GetSize(dataSrcDescriptor_.fileSize);
    dataSrcCb_->GetCallbackId(dataSrcDescriptor_.callback);
    data->fileSize = dataSrcDescriptor_.fileSize;
    data->callback = dataSrcDescriptor_.callback;
    return MSERR_OK;
}

void CJAVMetadataExtractorImpl::Release()
{
    if (state_ == HelperState::HELPER_STATE_RELEASED) {
        MEDIA_LOGE("Has released once, can't release again.");
        return;
    }
    if (dataSrcCb_ != nullptr) {
        dataSrcCb_->ClearCallbackReference();
        dataSrcCb_ = nullptr;
    }
    helper_->Release();
}

} // namespace Media
} // namespace OHOS

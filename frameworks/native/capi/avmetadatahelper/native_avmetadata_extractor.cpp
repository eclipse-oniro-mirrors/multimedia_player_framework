/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "media_log.h"
#include "media_errors.h"
#include "native_mfmagic.h"
#include "image_source.h"
#include "native_player_magic.h"
#include "avmetadata_extractor.h"
#include "avmetadatahelper.h"
#include "pixelmap_native_impl.h"
#include <unordered_set>

namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_METADATA, "NativeAVMetadataExtractor"};
    const std::string AV_KEY_STR_CUSTOMINFO = "customInfo";
}

using namespace OHOS::Media;

struct AVMetadataExtractorObject : public OH_AVMetadataExtractor {
    explicit AVMetadataExtractorObject(const std::shared_ptr<AVMetadataHelper> &aVMetadataHelper)
        : aVMetadataHelper_(aVMetadataHelper) {}
    ~AVMetadataExtractorObject() = default;

    const std::shared_ptr<AVMetadataHelper> aVMetadataHelper_ = nullptr;
    std::atomic<HelperState> state_ = HelperState::HELPER_STATE_IDLE;
};

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

template<typename T, typename = std::enable_if_t<std::is_same_v<int64_t, T> || std::is_same_v<int32_t, T>>>
bool StrToInt(const std::string_view& str, T& value)
{
    CHECK_AND_RETURN_RET(!str.empty() && (isdigit(str.front()) || (str.front() == '-')), false);
    std::string valStr(str);
    char* end = nullptr;
    errno = 0;
    const char* addr = valStr.c_str();
    long long result = strtoll(addr, &end, 10); /* 10 means decimal */
    CHECK_AND_RETURN_RET_LOG(result >= LLONG_MIN && result <= LLONG_MAX, false,
        "call StrToInt func false,  input str is: %{public}s!", valStr.c_str());
    CHECK_AND_RETURN_RET_LOG(end != addr && end[0] == '\0' && errno != ERANGE, false,
        "call StrToInt func false,  input str is: %{public}s!", valStr.c_str());
    if constexpr (std::is_same<int32_t, T>::value) {
        CHECK_AND_RETURN_RET_LOG(result >= INT_MIN && result <= INT_MAX, false,
            "call StrToInt func false,  input str is: %{public}s!", valStr.c_str());
        value = static_cast<int32_t>(result);
        return true;
    }
    value = result;
    return true;
}

void ConvertMetaForValueTypeConversion(const std::shared_ptr<Meta>& srcMeta,
                                       const std::shared_ptr<Meta>& destMeta,
                                       const std::string key, const std::string value)
{
    if (key == OH_AVMETADATA_EXTRACTOR_HAS_AUDIO || key == OH_AVMETADATA_EXTRACTOR_HAS_VIDEO) {
        // Special case handling for hasAudio/hasVideo
        int32_t newValue = value == "yes" ? 1 : 0;
        destMeta->SetData(key, newValue);
    } else {
        CHECK_AND_RETURN_LOG(!value.empty(),
                             "value is empty, key = %{public}s ", key.c_str());

        if (key == OH_AVMETADATA_EXTRACTOR_DURATION) {
            // Handle int64_t conversion
            int64_t intVal;
            CHECK_AND_RETURN_LOG(StrToInt(value, intVal),
                                 "Failed to convert %{public}s to int64_t for key %{public}s",
                                 value.c_str(), key.c_str());
            destMeta->SetData(key, intVal);
        } else {
            // Handle int32_t conversion
            int32_t intVal;
            CHECK_AND_RETURN_LOG(StrToInt(value, intVal),
                                 "Failed to convert %{public}s to int32_t for key %{public}s",
                                 value.c_str(), key.c_str());
            destMeta->SetData(key, intVal);
        }
    }
}

void ConvertMeta(const std::shared_ptr<Meta>& srcMeta, const std::shared_ptr<Meta>& destMeta)
{
    CHECK_AND_RETURN_LOG(srcMeta != nullptr, "srcMeta is nullptr");
    CHECK_AND_RETURN_LOG(destMeta != nullptr, "destMeta is nullptr");

    // Predefined keys for special handling
    const std::unordered_set<std::string> keysRequiringValueTypeConversion = {
        OH_AVMETADATA_EXTRACTOR_TRACK_COUNT,
        OH_AVMETADATA_EXTRACTOR_SAMPLE_RATE,
        OH_AVMETADATA_EXTRACTOR_VIDEO_HEIGHT,
        OH_AVMETADATA_EXTRACTOR_VIDEO_WIDTH,
        OH_AVMETADATA_EXTRACTOR_VIDEO_ORIENTATION,
        OH_AVMETADATA_EXTRACTOR_HAS_AUDIO,
        OH_AVMETADATA_EXTRACTOR_HAS_VIDEO,
        OH_AVMETADATA_EXTRACTOR_DURATION,
    };

    for (const auto& key : g_Metadata) {
        CHECK_AND_CONTINUE_LOG(srcMeta->Find(key) != srcMeta->end(),
                               "failed to find key: %{public}s", key.c_str());
    
        AnyValueType type = srcMeta->GetValueType(key);
        if (type == AnyValueType::STRING) {
            std::string sValue;
            CHECK_AND_CONTINUE_LOG(srcMeta->GetData(key, sValue), "GetData failed, key %{public}s", key.c_str());
            if (keysRequiringValueTypeConversion.count(key)) {
                ConvertMetaForValueTypeConversion(srcMeta, destMeta, key, sValue);
            } else {
                CHECK_AND_CONTINUE_LOG(!sValue.empty(),
                                       "value is empty, key = %{public}s ", key.c_str());
                destMeta->SetData(key, sValue);
            }
        } else if (type == AnyValueType::INT32_T) {
            int32_t value;
            CHECK_AND_CONTINUE_LOG(srcMeta->GetData(key, value), "GetData failed, key %{public}s", key.c_str());
            destMeta->SetData(key, value);
        } else if (type == AnyValueType::FLOAT) {
            float dValue;
            CHECK_AND_CONTINUE_LOG(srcMeta->GetData(key, dValue), "GetData failed, key %{public}s", key.c_str());
            destMeta->SetData(key, dValue);
        } else {
            MEDIA_LOGE("not supported value type");
        }
    }
}

OH_AVMetadataExtractor* OH_AVMetadataExtractor_Create(void)
{
    std::shared_ptr<AVMetadataHelper> aVMetadataHelper =  AVMetadataHelperFactory::CreateAVMetadataHelper();
    CHECK_AND_RETURN_RET_LOG(aVMetadataHelper != nullptr, nullptr,
                             "failed to AVMetadataHelperFactory::CreateAVMetadataHelper");

    struct AVMetadataExtractorObject *object = new(std::nothrow) AVMetadataExtractorObject(aVMetadataHelper);
    CHECK_AND_RETURN_RET_LOG(object != nullptr, nullptr, "failed to new AVMetadataExtractorObject");
    MEDIA_LOGI("0x%{public}06" PRIXPTR " OH_AVMetadataExtractor", FAKE_POINTER(object));

    return object;
}

OH_AVErrCode OH_AVMetadataExtractor_SetFDSource(OH_AVMetadataExtractor* extractor,
    int32_t fd, int64_t offset, int64_t size)
{
    CHECK_AND_RETURN_RET_LOG(extractor != nullptr, AV_ERR_INPUT_DATA_ERROR, "input extractor is nullptr");
    struct AVMetadataExtractorObject *extractorObj = reinterpret_cast<AVMetadataExtractorObject *>(extractor);
    CHECK_AND_RETURN_RET_LOG(extractorObj->aVMetadataHelper_ != nullptr, AV_ERR_INPUT_DATA_ERROR,
                             "aVMetadataHelper_ is nullptr");

    CHECK_AND_RETURN_RET_LOG(fd >= 0, AV_ERR_INPUT_DATA_ERROR, "fd is invalid");

    CHECK_AND_RETURN_RET_LOG(extractorObj->state_ == HelperState::HELPER_STATE_IDLE,
                             AV_ERR_OPERATE_NOT_PERMIT, "Has set source once, unsupport set again");

    int32_t ret = extractorObj->aVMetadataHelper_->SetSource(fd, offset, size);
    extractorObj->state_ = ret == MSERR_OK ? HelperState::HELPER_STATE_RUNNABLE : HelperState::HELPER_ERROR;
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret == MSERR_NO_MEMORY ? AV_ERR_NO_MEMORY : AV_ERR_INPUT_DATA_ERROR,
                             "aVMetadataExtractor setFdSource failed");
    return AV_ERR_OK;
}

OH_AVErrCode OH_AVMetadataExtractor_FetchMetadata(OH_AVMetadataExtractor* extractor, OH_AVFormat* avMetadata)
{
    CHECK_AND_RETURN_RET_LOG(extractor != nullptr, AV_ERR_INPUT_DATA_ERROR, "input extractor is nullptr");
    CHECK_AND_RETURN_RET_LOG(avMetadata != nullptr, AV_ERR_INPUT_DATA_ERROR, "input OH_AVFormat is nullptr");
    struct AVMetadataExtractorObject *extractorObj = reinterpret_cast<AVMetadataExtractorObject *>(extractor);
    CHECK_AND_RETURN_RET_LOG(extractorObj->aVMetadataHelper_ != nullptr, AV_ERR_INPUT_DATA_ERROR,
                             "aVMetadataHelper_ is nullptr");
    
    CHECK_AND_RETURN_RET_LOG(extractorObj->state_ == HelperState::HELPER_STATE_RUNNABLE,
                             AV_ERR_OPERATE_NOT_PERMIT, "Current state is not runnable, can't fetchMetadata.");

    std::shared_ptr<Meta> srcMeta = extractorObj->aVMetadataHelper_->GetAVMetadata();
    CHECK_AND_RETURN_RET_LOG(srcMeta != nullptr, AV_ERR_UNSUPPORTED_FORMAT, "Metadata get failed");

    std::shared_ptr<Meta> destMeta = std::make_shared<Meta>();
    CHECK_AND_RETURN_RET_LOG(destMeta != nullptr, AV_ERR_NO_MEMORY, "no memory to create Meta");

    ConvertMeta(srcMeta, destMeta);

    auto ret = avMetadata->format_.SetMeta(destMeta);
    CHECK_AND_RETURN_RET_LOG(ret, AV_ERR_NO_MEMORY, "AvMetadata set failed");
    return AV_ERR_OK;
}

OH_AVErrCode OH_AVMetadataExtractor_FetchAlbumCover(OH_AVMetadataExtractor* extractor, OH_PixelmapNative** pixelMap)
{
    CHECK_AND_RETURN_RET_LOG(extractor != nullptr, AV_ERR_INPUT_DATA_ERROR, "input extractor is nullptr");
    CHECK_AND_RETURN_RET_LOG(pixelMap != nullptr, AV_ERR_INPUT_DATA_ERROR, "input pixelMap is nullptr");
    struct AVMetadataExtractorObject *extractorObj = reinterpret_cast<AVMetadataExtractorObject *>(extractor);
    CHECK_AND_RETURN_RET_LOG(extractorObj->aVMetadataHelper_ != nullptr, AV_ERR_INPUT_DATA_ERROR,
                             "aVMetadataHelper_ is nullptr");

    CHECK_AND_RETURN_RET_LOG(extractorObj->state_ == HelperState::HELPER_STATE_RUNNABLE,
                             AV_ERR_OPERATE_NOT_PERMIT, "Current state is not runnable, can't fetchAlbumCover.");

    std::shared_ptr<AVSharedMemory> sharedMemPtr = extractorObj->aVMetadataHelper_->FetchArtPicture();
    CHECK_AND_RETURN_RET_LOG(sharedMemPtr != nullptr, AV_ERR_UNSUPPORTED_FORMAT, "Album cover fetch failed");

    std::shared_ptr<PixelMap> pixelMapInner = ConvertMemToPixelMap(sharedMemPtr);
    CHECK_AND_RETURN_RET_LOG(pixelMapInner != nullptr, AV_ERR_UNSUPPORTED_FORMAT, "ConvertMemToPixelMap failed");

    *pixelMap = new(std::nothrow) OH_PixelmapNative(pixelMapInner);
    CHECK_AND_RETURN_RET_LOG(*pixelMap != nullptr, AV_ERR_NO_MEMORY, "create OH_PixelmapNative failed");
    return AV_ERR_OK;
}

OH_AVErrCode OH_AVMetadataExtractor_Release(OH_AVMetadataExtractor* extractor)
{
    CHECK_AND_RETURN_RET_LOG(extractor != nullptr, AV_ERR_INPUT_DATA_ERROR, "input extractor is nullptr");
    struct AVMetadataExtractorObject *extractorObj = reinterpret_cast<AVMetadataExtractorObject *>(extractor);
    CHECK_AND_RETURN_RET_LOG(extractorObj->aVMetadataHelper_ != nullptr, AV_ERR_INPUT_DATA_ERROR,
                             "aVMetadataHelper_ is nullptr");
    extractorObj->aVMetadataHelper_->Release();
    delete extractorObj;
    return AV_ERR_OK;
}
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
#include "avmedia_source.h"
#include "native_media_source_impl.h"
#include "native_avmetadata_helper_callback.h"
#include <unordered_set>

namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_METADATA, "NativeAVMetadataExtractor"};
    const std::string AV_KEY_STR_CUSTOMINFO = "customInfo";
}

using namespace OHOS::Media;

typedef struct OH_AVMetadataExtractor_OutputParam {
    int32_t dstWidth = -1;
    int32_t dstHeight = -1;
    PixelFormat colorFormat = PixelFormat::RGB_565;
    bool isSupportFlip = false;
    bool convertColorSpace = true;
} OH_AVMetadataExtractor_OutputParam;

struct AVMetadataExtractorObject : public OH_AVMetadataExtractor {
    explicit AVMetadataExtractorObject(const std::shared_ptr<AVMetadataHelper> &aVMetadataHelper,
        const std::shared_ptr<NativeAVMetadataHelperCallback> &callback)
        : aVMetadataHelper_(aVMetadataHelper), helperCb_(callback) {}
    ~AVMetadataExtractorObject() = default;

    const std::shared_ptr<AVMetadataHelper> aVMetadataHelper_ = nullptr;
    std::atomic<HelperState> state_ = HelperState::HELPER_STATE_IDLE;
    const std::shared_ptr<NativeAVMetadataHelperCallback> helperCb_ = nullptr;
};

class OnFrameFetchedCallback : public BaseCallback {
public:
    OnFrameFetchedCallback(OH_AVMetadataExtractor *extractor, OH_AVMetadataExtractor_OnFrameFetched callback,
        void *userData): extractor_(extractor), callback_(callback), userData_(userData) {}
    void OnInfo(const NativeCallbackOnInfo &info) override;

private:
    OH_AVMetadataExtractor *extractor_ = nullptr;
    OH_AVMetadataExtractor_OnFrameFetched callback_ = nullptr;
    void *userData_ = nullptr;
};

void OnFrameFetchedCallback::OnInfo(const NativeCallbackOnInfo &info)
{
    CHECK_AND_RETURN_LOG(callback_ != nullptr, "OnFrameFetchedCallback callback_ is nullptr");
    OH_AVMetadataExtractor_FrameInfo frameInfo {
        .requestTimeUs = info.frameInfo.requestedTimeUs,
        .actualTimeUs = info.frameInfo.actualTimeUs,
        .result = static_cast<OH_AVMetadataExtractor_FetchState>(info.frameInfo.fetchResult)
    };

    OH_AVErrCode code = AV_ERR_OK;
    switch (info.frameInfo.err) {
        case OPERATION_NOT_ALLOWED:
            code = AV_ERR_OPERATE_NOT_PERMIT;
            break;
        case FETCH_TIMEOUT:
            code = AV_ERR_TIMEOUT;
            break;
        case UNSUPPORTED_FORMAT:
            code = AV_ERR_UNSUPPORTED_FORMAT;
            break;
        default:
            code = AV_ERR_OK;
    }

    frameInfo.image = new(std::nothrow) OH_PixelmapNative(info.pixelMap);
    if (frameInfo.image == nullptr) {
        MEDIA_LOGE("create OH_PixelmapNative failed");
        code = AV_ERR_NO_MEMORY;
    }
    callback_(extractor_, &frameInfo, code, userData_);
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
    std::shared_ptr<NativeAVMetadataHelperCallback> callback = std::make_shared<NativeAVMetadataHelperCallback>();
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, nullptr,
                             "failed to create NativeAVMetadataHelperCallback");

    callback->SetHelper(aVMetadataHelper);
    int32_t res = aVMetadataHelper->SetHelperCallback(callback);
    CHECK_AND_RETURN_RET_LOG(res == MSERR_OK, nullptr, "failed to SetHelperCallback");

    struct AVMetadataExtractorObject *object = new(std::nothrow) AVMetadataExtractorObject(aVMetadataHelper, callback);
    CHECK_AND_RETURN_RET_LOG(object != nullptr, nullptr, "failed to new AVMetadataExtractorObject");
    MEDIA_LOGI("0x%{public}06" PRIXPTR " OH_AVMetadataExtractor", FAKE_POINTER(object));

    return object;
}

OH_AVErrCode OH_AVMetadataExtractor_SetFDSource(OH_AVMetadataExtractor* extractor,
    int32_t fd, int64_t offset, int64_t size)
{
    CHECK_AND_RETURN_RET_LOG(extractor != nullptr, AV_ERR_INVALID_VAL, "input extractor is nullptr");
    struct AVMetadataExtractorObject *extractorObj = reinterpret_cast<AVMetadataExtractorObject *>(extractor);
    CHECK_AND_RETURN_RET_LOG(extractorObj->aVMetadataHelper_ != nullptr, AV_ERR_INVALID_VAL,
                             "aVMetadataHelper_ is nullptr");

    CHECK_AND_RETURN_RET_LOG(fd >= 0, AV_ERR_INVALID_VAL, "fd is invalid");

    CHECK_AND_RETURN_RET_LOG(extractorObj->state_ == HelperState::HELPER_STATE_IDLE,
                             AV_ERR_OPERATE_NOT_PERMIT, "Has set source once, unsupport set again");

    int32_t ret = extractorObj->aVMetadataHelper_->SetSource(fd, offset, size);
    extractorObj->state_ = ret == MSERR_OK ? HelperState::HELPER_STATE_RUNNABLE : HelperState::HELPER_ERROR;
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, ret == MSERR_NO_MEMORY ? AV_ERR_NO_MEMORY : AV_ERR_INVALID_VAL,
                             "aVMetadataExtractor setFdSource failed");
    return AV_ERR_OK;
}

OH_AVErrCode OH_AVMetadataExtractor_FetchMetadata(OH_AVMetadataExtractor* extractor, OH_AVFormat* avMetadata)
{
    CHECK_AND_RETURN_RET_LOG(extractor != nullptr, AV_ERR_INVALID_VAL, "input extractor is nullptr");
    CHECK_AND_RETURN_RET_LOG(avMetadata != nullptr, AV_ERR_INVALID_VAL, "input OH_AVFormat is nullptr");
    struct AVMetadataExtractorObject *extractorObj = reinterpret_cast<AVMetadataExtractorObject *>(extractor);
    CHECK_AND_RETURN_RET_LOG(extractorObj->aVMetadataHelper_ != nullptr, AV_ERR_INVALID_VAL,
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
    CHECK_AND_RETURN_RET_LOG(extractor != nullptr, AV_ERR_INVALID_VAL, "input extractor is nullptr");
    CHECK_AND_RETURN_RET_LOG(pixelMap != nullptr, AV_ERR_INVALID_VAL, "input pixelMap is nullptr");
    struct AVMetadataExtractorObject *extractorObj = reinterpret_cast<AVMetadataExtractorObject *>(extractor);
    CHECK_AND_RETURN_RET_LOG(extractorObj->aVMetadataHelper_ != nullptr, AV_ERR_INVALID_VAL,
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

OH_AVMetadataExtractor_OutputParam* OH_AVMetadataExtractor_OutputParam_Create()
{
    OH_AVMetadataExtractor_OutputParam *params = new(std::nothrow) OH_AVMetadataExtractor_OutputParam();
    CHECK_AND_RETURN_RET_LOG(params != nullptr, nullptr, "create OH_AVMetadataExtractor_OutputParam failed!");
    return params;
}

void OH_AVMetadataExtractor_OutputParam_Destroy(OH_AVMetadataExtractor_OutputParam* outputParam)
{
    CHECK_AND_RETURN_LOG(outputParam != nullptr, "input outputParam is nullptr!");
    delete outputParam;
}

bool OH_AVMetadataExtractor_OutputParam_SetSize(OH_AVMetadataExtractor_OutputParam* outputParam,
    int32_t width, int32_t height)
{
    CHECK_AND_RETURN_RET_LOG(outputParam != nullptr, false, "input outputParam is nullptr");
    outputParam->dstWidth = width;
    outputParam->dstHeight = height;
    return true;
}

OH_AVErrCode OH_AVMetadataExtractor_FetchFrameByTime(OH_AVMetadataExtractor* extractor,
    int64_t timeUs, OH_AVMedia_SeekMode seekMode,
    const OH_AVMetadataExtractor_OutputParam* outputParam, OH_PixelmapNative** pixelMap)
{
    CHECK_AND_RETURN_RET_LOG(extractor != nullptr, AV_ERR_INVALID_VAL, "input aVMetadataExtractor is nullptr");
    CHECK_AND_RETURN_RET_LOG(timeUs >= 0, AV_ERR_INVALID_VAL, "input timeUs is invalid, must be non-negative");
    CHECK_AND_RETURN_RET_LOG(outputParam != nullptr, AV_ERR_INVALID_VAL, "input outputParam is nullptr");
    CHECK_AND_RETURN_RET_LOG(pixelMap != nullptr, AV_ERR_INVALID_VAL, "input pixelMap is nullptr");
    struct AVMetadataExtractorObject *extractorObj = reinterpret_cast<AVMetadataExtractorObject *>(extractor);
    CHECK_AND_RETURN_RET_LOG(extractorObj->aVMetadataHelper_ != nullptr, AV_ERR_INVALID_VAL,
                             "aVMetadataHelper_ is nullptr");

    CHECK_AND_RETURN_RET_LOG(extractorObj->state_ != HelperState::HELPER_STATE_HTTP_INTERCEPTED,
                             AV_ERR_IO_CLEARTEXT_NOT_PERMITTED, "Http plaintext access is not allowed.");
    CHECK_AND_RETURN_RET_LOG(extractorObj->state_ == HelperState::HELPER_STATE_RUNNABLE,
                             AV_ERR_OPERATE_NOT_PERMIT, "Current state is not runnable, can't fetchFrame.");

    bool isValidFormat = (outputParam->colorFormat == PixelFormat::RGB_565 ||
                          outputParam->colorFormat == PixelFormat::RGB_888 ||
                          outputParam->colorFormat == PixelFormat::RGBA_8888);
    CHECK_AND_RETURN_RET_LOG(isValidFormat, AV_ERR_INVALID_VAL, "input colorFormat is invalid");

    PixelMapParams param = {
        .dstWidth = outputParam->dstWidth,
        .dstHeight = outputParam->dstHeight,
        .colorFormat = outputParam->colorFormat,
        .isSupportFlip = outputParam->isSupportFlip,
    };

    auto pixelMapInner =
        extractorObj->aVMetadataHelper_->FetchScaledFrameYuv(timeUs, static_cast<int32_t>(seekMode), param);
    CHECK_AND_RETURN_RET_LOG(pixelMapInner != nullptr, AV_ERR_SERVICE_DIED, "aVMetadataHelper FetchFrame failed");

    *pixelMap = new(std::nothrow) OH_PixelmapNative(pixelMapInner);
    CHECK_AND_RETURN_RET_LOG(*pixelMap != nullptr, AV_ERR_INVALID_VAL, "create OH_PixelmapNative failed");
    return AV_ERR_OK;
}

OH_AVFormat *OH_AVMetadataExtractor_GetTrackDescription(OH_AVMetadataExtractor *extractor, uint32_t index)
{
    CHECK_AND_RETURN_RET_LOG(extractor != nullptr, nullptr, "input extractor is nullptr");
    struct AVMetadataExtractorObject *extractorObj = reinterpret_cast<AVMetadataExtractorObject *>(extractor);
    CHECK_AND_RETURN_RET_LOG(extractorObj->aVMetadataHelper_ != nullptr, nullptr,
                             "aVMetadataHelper_ is nullptr");

    CHECK_AND_RETURN_RET_LOG(extractorObj->state_ == HelperState::HELPER_STATE_RUNNABLE,
                             nullptr, "Current state is not runnable, can't fetchMetadata.");

    std::shared_ptr<Meta> srcMeta = extractorObj->aVMetadataHelper_->GetAVMetadata();
    CHECK_AND_RETURN_RET_LOG(srcMeta != nullptr, nullptr, "Metadata get failed");

    std::string key = "tracks";
    CHECK_AND_RETURN_RET_LOG(srcMeta->Find(key) != srcMeta->end(), nullptr, "failed to find key: tracks");

    std::vector<Format> trackInfoVec;
    bool res = srcMeta->GetData(key, trackInfoVec);
    CHECK_AND_RETURN_RET_LOG(res, nullptr, "GetData failed, key %{public}s", key.c_str());

    bool checkIndex = static_cast<size_t>(index) < trackInfoVec.size();
    CHECK_AND_RETURN_RET_LOG(checkIndex, nullptr, "index out of range");

    OH_AVFormat *avFormat = new (std::nothrow) OH_AVFormat();
    CHECK_AND_RETURN_RET_LOG(avFormat != nullptr, nullptr, "OH_AVFormat is nullptr");

    Format format = trackInfoVec.at(index);
    avFormat->format_ = format;

    return avFormat;
}

OH_AVFormat *OH_AVMetadataExtractor_GetCustomInfo(OH_AVMetadataExtractor *extractor)
{
    CHECK_AND_RETURN_RET_LOG(extractor != nullptr, nullptr, "input extractor is nullptr");
    struct AVMetadataExtractorObject *extractorObj = reinterpret_cast<AVMetadataExtractorObject *>(extractor);
    CHECK_AND_RETURN_RET_LOG(extractorObj->aVMetadataHelper_ != nullptr, nullptr,
                             "aVMetadataHelper_ is nullptr");

    CHECK_AND_RETURN_RET_LOG(extractorObj->state_ == HelperState::HELPER_STATE_RUNNABLE,
                             nullptr, "Current state is not runnable, can't fetchMetadata.");

    std::shared_ptr<Meta> srcMeta = extractorObj->aVMetadataHelper_->GetAVMetadata();
    CHECK_AND_RETURN_RET_LOG(srcMeta != nullptr, nullptr, "Metadata get failed");

    std::string key = "customInfo";
    CHECK_AND_RETURN_RET_LOG(srcMeta->Find(key) != srcMeta->end(), nullptr, "failed to find key: customInfo");

    std::shared_ptr<Meta> customData = std::make_shared<Meta>();
    bool res = srcMeta->GetData(key, customData);
    CHECK_AND_RETURN_RET_LOG(res, nullptr, "GetData failed, key %{public}s", key.c_str());
    CHECK_AND_RETURN_RET_LOG(customData != nullptr, nullptr, "customData == nullptr");

    OH_AVFormat *avFormat = new (std::nothrow) OH_AVFormat();
    CHECK_AND_RETURN_RET_LOG(avFormat != nullptr, nullptr, "OH_AVFormat is nullptr");

    auto ret = avFormat->format_.SetMeta(customData);
    if (!ret) {
        MEDIA_LOGE("AvMetadata set failed");
        OH_AVFormat_Destroy(avFormat);
        return nullptr;
    }
    return avFormat;
}

OH_AVErrCode OH_AVMetadataExtractor_Release(OH_AVMetadataExtractor* extractor)
{
    CHECK_AND_RETURN_RET_LOG(extractor != nullptr, AV_ERR_INVALID_VAL, "input extractor is nullptr");
    struct AVMetadataExtractorObject *extractorObj = reinterpret_cast<AVMetadataExtractorObject *>(extractor);
    CHECK_AND_RETURN_RET_LOG(extractorObj->aVMetadataHelper_ != nullptr, AV_ERR_INVALID_VAL,
                             "aVMetadataHelper_ is nullptr");
    extractorObj->aVMetadataHelper_->Release();
    if (extractorObj->helperCb_ != nullptr) {
        extractorObj->helperCb_->ClearCallbackReference();
    }
    delete extractorObj;
    return AV_ERR_OK;
}

OH_AVErrCode OH_AVMetadataExtractor_SetMediaSource(OH_AVMetadataExtractor *extractor, OH_AVMediaSource *source)
{
    CHECK_AND_RETURN_RET_LOG(extractor != nullptr, AV_ERR_INVALID_VAL, "input extractor is nullptr");
    CHECK_AND_RETURN_RET_LOG(source != nullptr, AV_ERR_INVALID_VAL, "input source is nullptr");
    struct AVMetadataExtractorObject *extractorObj = reinterpret_cast<AVMetadataExtractorObject *>(extractor);
    CHECK_AND_RETURN_RET_LOG(extractorObj->aVMetadataHelper_ != nullptr, AV_ERR_INVALID_VAL,
                             "aVMetadataHelper_ is nullptr");
    CHECK_AND_RETURN_RET_LOG(extractorObj->state_ == HelperState::HELPER_STATE_IDLE, AV_ERR_INVALID_VAL,
                             "Has set source once, unsupport set again");
    MediaSourceObject *mediaSourceObj = reinterpret_cast<MediaSourceObject *>(source);
    CHECK_AND_RETURN_RET_LOG(mediaSourceObj->mediasource_ != nullptr, AV_ERR_INVALID_VAL,
                             "media source is nullptr");

    int32_t ret = MSERR_OK;
    if (mediaSourceObj->mediasource_->IsDataSourceSet()) {
        std::shared_ptr<IMediaDataSource> dataSrc = mediaSourceObj->mediasource_->GetDataSource();
        ret = extractorObj->aVMetadataHelper_->SetSource(dataSrc);
        extractorObj->state_ = ret == MSERR_OK ? HelperState::HELPER_STATE_RUNNABLE : HelperState::HELPER_ERROR;
    } else if (mediaSourceObj->mediasource_->IsFileDescriptorSet()) {
        MEDIA_LOGE("OH_AVMetadataExtractor_SetMediaSource into fd branch");
        return AV_ERR_INVALID_VAL;
    } else {
        ret = extractorObj->aVMetadataHelper_->SetUrlSource(
            mediaSourceObj->mediasource_->url, mediaSourceObj->mediasource_->header);

        if (ret != MSERR_OK) {
            extractorObj->state_ = ret == MSERR_CLEARTEXT_NOT_PERMITTED ?
                HelperState::HELPER_STATE_HTTP_INTERCEPTED : HelperState::HELPER_ERROR;
        } else {
            extractorObj->state_ = HelperState::HELPER_STATE_RUNNABLE;
        }
        extractorObj->aVMetadataHelper_->SetAVMetadataCaller(AVMetadataCaller::AV_METADATA_EXTRACTOR);
    }
    return ret == MSERR_OK ? AV_ERR_OK : AV_ERR_INVALID_VAL;
}

OH_AVErrCode OH_AVMetadataExtractor_FetchFramesByTimes(OH_AVMetadataExtractor* extractor, int64_t timesUs[],
    uint16_t timesUsSize, OH_AVMedia_SeekMode seekMode, const OH_AVMetadataExtractor_OutputParam* outputParam,
    OH_AVMetadataExtractor_OnFrameFetched onFrameInfoCallback, void* userData)
{
    CHECK_AND_RETURN_RET_LOG(extractor != nullptr, AV_ERR_INVALID_VAL, "input extractor is nullptr");

    struct AVMetadataExtractorObject *extractorObj = reinterpret_cast<AVMetadataExtractorObject *>(extractor);
    CHECK_AND_RETURN_RET_LOG(extractorObj->aVMetadataHelper_ != nullptr, AV_ERR_INVALID_VAL,
        "aVMetadataHelper_ is nullptr");
    CHECK_AND_RETURN_RET_LOG(extractorObj->helperCb_ != nullptr, AV_ERR_INVALID_VAL,
        "helperCb_ is nullptr");
    CHECK_AND_RETURN_RET_LOG(extractorObj->state_ != HelperState::HELPER_STATE_HTTP_INTERCEPTED,
        AV_ERR_IO_CLEARTEXT_NOT_PERMITTED, "Http plaintext access is not allowed.");
    CHECK_AND_RETURN_RET_LOG(extractorObj->state_ == HelperState::HELPER_STATE_RUNNABLE,
        AV_ERR_SERVICE_DIED, "Service died");

    CHECK_AND_RETURN_RET_LOG(timesUs != nullptr, AV_ERR_INVALID_VAL, "input timesUs is empty");
    CHECK_AND_RETURN_RET_LOG(timesUsSize > 0, AV_ERR_INVALID_VAL, "input timesUsSize is invalid");
    CHECK_AND_RETURN_RET_LOG(outputParam != nullptr, AV_ERR_INVALID_VAL, "input outputParam is nullptr");

    std::shared_ptr<OnFrameFetchedCallback> callback =
        std::make_shared<OnFrameFetchedCallback>(extractor, onFrameInfoCallback, userData);
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, AV_ERR_INVALID_VAL, "failed to create callback");

    extractorObj->helperCb_->SaveCallbackReference(NativeAVMetadataHelperEvent::EVENT_PIXEL_COMPLETE, callback);
    std::vector<int64_t> timeUsVector(timesUs, timesUs + timesUsSize);
    PixelMapParams param = {
        .dstWidth = outputParam->dstWidth,
        .dstHeight = outputParam->dstHeight,
        .colorFormat = outputParam->colorFormat,
        .isSupportFlip = outputParam->isSupportFlip,
        .convertColorSpace = outputParam->convertColorSpace
    };
    int32_t fetchRes = extractorObj->aVMetadataHelper_->
        FetchScaledFrameYuvs(timeUsVector, static_cast<int32_t>(seekMode), param);
    CHECK_AND_RETURN_RET_LOG(fetchRes == MSERR_OK, AV_ERR_SERVICE_DIED, "Service died");
    return AV_ERR_OK;
}

void OH_AVMetadataExtractor_CancelAllFetchFrames(OH_AVMetadataExtractor* extractor)
{
    CHECK_AND_RETURN_LOG(extractor != nullptr, "input aVMetadataExtractor is nullptr");
    struct AVMetadataExtractorObject *extractorObj = reinterpret_cast<AVMetadataExtractorObject *>(extractor);
    CHECK_AND_RETURN_LOG(extractorObj->aVMetadataHelper_ != nullptr, "aVMetadataHelper_ is nullptr");

    (void)extractorObj->aVMetadataHelper_->CancelAllFetchFrames();
    return;
}

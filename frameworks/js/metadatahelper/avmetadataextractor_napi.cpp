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

#include "avmetadataextractor_napi.h"
#include "media_log.h"
#include "media_errors.h"
#include "common_napi.h"
#include "pixel_map_napi.h"
#include "string_ex.h"
#include "player_xcollie.h"
#include "media_dfx.h"
#ifdef SUPPORT_JSSTACK
#include "xpower_event_js.h"
#endif
#include "av_common.h"
#include "ipc_skeleton.h"
#include "tokenid_kit.h"

using namespace OHOS::AudioStandard;

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_METADATA, "AVMetadataExtractorNapi"};
constexpr uint8_t ARG_ZERO = 0;
constexpr uint8_t ARG_ONE = 1;
constexpr uint8_t ARG_TWO = 2;
constexpr uint8_t ARG_THREE = 3;
constexpr uint8_t ARG_FOUR = 4;
}

namespace OHOS {
namespace Media {
thread_local napi_ref AVMetadataExtractorNapi::constructor_ = nullptr;
const std::string CLASS_NAME = "AVMetadataExtractor";

AVMetadataExtractorNapi::AVMetadataExtractorNapi()
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Instances create", FAKE_POINTER(this));
}

AVMetadataExtractorNapi::~AVMetadataExtractorNapi()
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Instances destroy", FAKE_POINTER(this));
}

napi_value AVMetadataExtractorNapi::Init(napi_env env, napi_value exports)
{
    napi_property_descriptor staticProperty[] = {
        DECLARE_NAPI_STATIC_FUNCTION("createAVMetadataExtractor", JsCreateAVMetadataExtractor),
    };

    napi_property_descriptor properties[] = {
        DECLARE_NAPI_FUNCTION("setUrlSource", JsSetUrlSource),
        DECLARE_NAPI_FUNCTION("fetchMetadata", JsResolveMetadata),
        DECLARE_NAPI_FUNCTION("fetchAlbumCover", JsFetchArtPicture),
        DECLARE_NAPI_FUNCTION("fetchFrameByTime", JsFetchFrameAtTime),
        DECLARE_NAPI_FUNCTION("release", JsRelease),
        DECLARE_NAPI_FUNCTION("getTimeByFrameIndex", JSGetTimeByFrameIndex),
        DECLARE_NAPI_FUNCTION("getFrameIndexByTime", JSGetFrameIndexByTime),
        DECLARE_NAPI_GETTER_SETTER("fdSrc", JsGetAVFileDescriptor, JsSetAVFileDescriptor),
        DECLARE_NAPI_GETTER_SETTER("dataSrc", JsGetDataSrc, JsSetDataSrc),
    };

    napi_value constructor = nullptr;
    napi_status status = napi_define_class(env, CLASS_NAME.c_str(), NAPI_AUTO_LENGTH, Constructor, nullptr,
        sizeof(properties) / sizeof(properties[0]), properties, &constructor);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, nullptr, "Failed to define AVMetadataHelper class");

    status = napi_create_reference(env, constructor, 1, &constructor_);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, nullptr, "Failed to create reference of constructor");

    status = napi_set_named_property(env, exports, CLASS_NAME.c_str(), constructor);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, nullptr, "Failed to set constructor");

    status = napi_define_properties(env, exports, sizeof(staticProperty) / sizeof(staticProperty[0]), staticProperty);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, nullptr, "Failed to define static function");

    MEDIA_LOGD("AVMetadataExtractorNapi Init success");
    return exports;
}

napi_value AVMetadataExtractorNapi::Constructor(napi_env env, napi_callback_info info)
{
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    size_t argCount = 0;
    napi_value jsThis = nullptr;
    napi_status status = napi_get_cb_info(env, info, &argCount, nullptr, &jsThis, nullptr);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, result, "failed to napi_get_cb_info");

    AVMetadataExtractorNapi *extractor = new(std::nothrow) AVMetadataExtractorNapi();
    CHECK_AND_RETURN_RET_LOG(extractor != nullptr, result, "failed to new AVMetadataExtractorNapi");

    extractor->env_ = env;
    extractor->helper_ = AVMetadataHelperFactory::CreateAVMetadataHelper();
    if (extractor->helper_ == nullptr) {
        delete extractor;
        MEDIA_LOGE("failed to CreateMetadataHelper");
        return result;
    }

    status = napi_wrap(env, jsThis, reinterpret_cast<void *>(extractor),
        AVMetadataExtractorNapi::Destructor, nullptr, nullptr);
    if (status != napi_ok) {
        delete extractor;
        MEDIA_LOGE("Failed to wrap native instance");
        return result;
    }

    MEDIA_LOGI("0x%{public}06" PRIXPTR " Constructor", FAKE_POINTER(extractor));
    return jsThis;
}

void AVMetadataExtractorNapi::Destructor(napi_env env, void *nativeObject, void *finalize)
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Destructor", FAKE_POINTER(nativeObject));
    (void)finalize;
    CHECK_AND_RETURN(nativeObject != nullptr);
    AVMetadataExtractorNapi *napi = reinterpret_cast<AVMetadataExtractorNapi *>(nativeObject);
    std::thread([napi]() -> void {
        MEDIA_LOGD("Destructor Release enter");
        if (napi != nullptr && napi->helper_ != nullptr) {
            napi->helper_->Release();
        }
        delete napi;
    }).detach();
    MEDIA_LOGD("Destructor success");
}

napi_value AVMetadataExtractorNapi::JsCreateAVMetadataExtractor(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVMetadataExtractorNapi::JsCreateAVMetadataExtractor");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGI("JsCreateAVMetadataExtractor In");

    std::unique_ptr<MediaAsyncContext> asyncContext = std::make_unique<MediaAsyncContext>(env);

    // get args
    napi_value jsThis = nullptr;
    napi_value args[1] = { nullptr };
    size_t argCount = 1;
    napi_status status = napi_get_cb_info(env, info, &argCount, args, &jsThis, nullptr);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && jsThis != nullptr, nullptr, "failed to napi_get_cb_info");

    asyncContext->callbackRef = CommonNapi::CreateReference(env, args[0]);
    asyncContext->deferred = CommonNapi::CreatePromise(env, asyncContext->callbackRef, result);
    asyncContext->JsResult = std::make_unique<MediaJsResultInstance>(constructor_);
    asyncContext->ctorFlag = true;

    auto ret = MediaAsyncContext::SendCompleteEvent(env, asyncContext.get(), napi_eprio_high);
    if (ret != napi_status::napi_ok) {
        MEDIA_LOGE("failed to SendEvent, ret = %{public}d", ret);
    } else {
        asyncContext.release();
    }
    MEDIA_LOGI("JsCreateAVMetadataExtractor Out");
    return result;
}

napi_value AVMetadataExtractorNapi::JsResolveMetadata(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVMetadataExtractorNapi::resolveMetadata");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGI("JsResolveMetadata In");

    auto promiseCtx = std::make_unique<AVMetadataExtractorAsyncContext>(env);
    napi_value args[1] = { nullptr };
    size_t argCount = 1;

    AVMetadataExtractorNapi* extractor
        = AVMetadataExtractorNapi::GetJsInstanceWithParameter(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(extractor != nullptr, result, "failed to GetJsInstance");
    promiseCtx->innerHelper_ = extractor->helper_;
    promiseCtx->callbackRef = CommonNapi::CreateReference(env, args[0]);
    promiseCtx->deferred = CommonNapi::CreatePromise(env, promiseCtx->callbackRef, result);

    if (extractor->state_ != HelperState::HELPER_STATE_RUNNABLE) {
        promiseCtx->SignError(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "Can't fetchMetadata, please set source.");
    }

    if (extractor->state_ == HelperState::HELPER_STATE_HTTP_INTERCEPTED) {
        promiseCtx->SignError(MSERR_EXT_API20_IO_CLEARTEXT_NOT_PERMITTED, "Http plaintext access is not allowed.");
    }

    // async work
    napi_value resource = nullptr;
    napi_create_string_utf8(env, "JsResolveMetadata", NAPI_AUTO_LENGTH, &resource);
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, [](napi_env env, void *data) {
        auto promiseCtx = reinterpret_cast<AVMetadataExtractorAsyncContext *>(data);
        CHECK_AND_RETURN_LOG(promiseCtx && !promiseCtx->errFlag && promiseCtx->innerHelper_, "Invalid promiseCtx.");
        promiseCtx->metadata_ = promiseCtx->innerHelper_->GetAVMetadata();
        CHECK_AND_RETURN(promiseCtx->metadata_ == nullptr);
        MEDIA_LOGE("ResolveMetadata AVMetadata is nullptr");
        promiseCtx->SignError(MSERR_EXT_API9_UNSUPPORT_FORMAT, "failed to ResolveMetadata, AVMetadata is nullptr!");
    }, ResolveMetadataComplete, static_cast<void *>(promiseCtx.get()), &promiseCtx->work));
    NAPI_CALL(env, napi_queue_async_work(env, promiseCtx->work));
    promiseCtx.release();
    MEDIA_LOGI("JsResolveMetadata Out");
    return result;
}

void AVMetadataExtractorNapi::ResolveMetadataComplete(napi_env env, napi_status status, void *data)
{
    MEDIA_LOGI("ResolveMetadataComplete In");
    auto promiseCtx = static_cast<AVMetadataExtractorAsyncContext*>(data);
    CHECK_AND_RETURN_LOG(promiseCtx != nullptr, "promiseCtx is nullptr!");

    napi_value result = nullptr;
    napi_create_object(env, &result);
    if (status != napi_ok || promiseCtx->errCode != napi_ok) {
        promiseCtx->status = promiseCtx->errCode == napi_ok ? MSERR_INVALID_VAL : promiseCtx->errCode;
        MEDIA_LOGI("Resolve meta data failed");
        napi_get_undefined(env, &result);
        CommonCallbackRoutine(env, promiseCtx, result);
        return;
    }
    HandleMetaDataResult(env, promiseCtx, result);
    promiseCtx->status = ERR_OK;
    CommonCallbackRoutine(env, promiseCtx, result);
}

void AVMetadataExtractorNapi::HandleMetaDataResult(napi_env env, AVMetadataExtractorAsyncContext* &promiseCtx,
    napi_value &result)
{
    napi_value location = nullptr;
    napi_value customInfo = nullptr;
    napi_value tracks = nullptr;
    napi_value gltfOffset = nullptr;
    napi_create_object(env, &location);
    napi_create_object(env, &customInfo);
    napi_get_undefined(env, &tracks);
    napi_get_undefined(env, &gltfOffset);
    std::shared_ptr<Meta> metadata = promiseCtx->metadata_;
    std::string notFoundKey = {};
    for (const auto &key : g_Metadata) {
        if (metadata->Find(key) == metadata->end()) {
            notFoundKey += (std::string{" "} + key);
            continue;
        }

        if (key == "latitude" || key == "longitude") {
            CHECK_AND_CONTINUE_LOG(ParseMetadataOfLocation(env, location, metadata, key),
                "SetProperty failed, key: %{public}s", key.c_str());
            continue;
        }
        if (key == "customInfo") {
            CHECK_AND_CONTINUE(ParseMetadataOfCustomInfo(env, customInfo, metadata, key));
            continue;
        }
        if (key == "tracks") {
            CHECK_AND_CONTINUE(ParseMetadataOfTracks(env, tracks, metadata, key, promiseCtx));
            continue;
        }
        if (key == "gltf_offset") {
            CHECK_AND_CONTINUE(ParseMetadataOfGltfOffset(env, result, gltfOffset, metadata, key));
        }
        CHECK_AND_CONTINUE_LOG(CommonNapi::SetPropertyByValueType(env, result, metadata, key),
            "SetProperty failed, key: %{public}s", key.c_str());
    }
    MEDIA_LOGE("keys not found:%{public}s", notFoundKey.c_str());
    napi_set_named_property(env, result, "location", location);
    napi_set_named_property(env, result, "customInfo", customInfo);
    napi_set_named_property(env, result, "tracks", tracks);
}

bool AVMetadataExtractorNapi::ParseMetadataOfLocation(napi_env env, napi_value &location,
    std::shared_ptr<Meta> &metadata, std::string key)
{
    return CommonNapi::SetPropertyByValueType(env, location, metadata, key);
}

bool AVMetadataExtractorNapi::ParseMetadataOfCustomInfo(napi_env env, napi_value &customInfo,
    std::shared_ptr<Meta> &metadata, std::string key)
{
    std::shared_ptr<Meta> customData = std::make_shared<Meta>();
    bool ret = metadata->GetData(key, customData);
    CHECK_AND_RETURN_RET_LOG(ret, false, "GetData failed, key %{public}s", key.c_str());
    CHECK_AND_RETURN_RET_LOG(customData != nullptr, false, "customData == nullptr");
    for (auto iter = customData->begin(); iter != customData->end(); ++iter) {
        std::string curKey = iter->first;
        std::string curValue = StringifyMeta(iter->second);
        CHECK_AND_CONTINUE_LOG(CommonNapi::SetPropertyString(env, customInfo, curKey, curValue),
            "SetPropertyString failed, key: %{public}s", key.c_str());
    }
    return true;
}

bool AVMetadataExtractorNapi::ParseMetadataOfTracks(napi_env env, napi_value &tracks,
    std::shared_ptr<Meta> &metadata, std::string key, AVMetadataExtractorAsyncContext* &promiseCtx)
{
    std::vector<Format> trackInfoVec;
    bool ret = metadata->GetData(key, trackInfoVec);
    CHECK_AND_RETURN_RET_LOG(ret, false, "GetData failed, key %{public}s", key.c_str());
    promiseCtx->JsResult = std::make_unique<MediaJsResultArray>(trackInfoVec);
    CHECK_AND_RETURN_RET_LOG(promiseCtx->JsResult, false, "failed to GetJsResult");
    promiseCtx->JsResult->GetJsResult(env, tracks);
    return true;
}

bool AVMetadataExtractorNapi::ParseMetadataOfGltfOffset(napi_env env, napi_value &gltfOffset, napi_value &result,
    std::shared_ptr<Meta> &metadata, std::string key)
{
    std::string value;
    bool ret = metadata->GetData(key, value);
    CHECK_AND_RETURN_RET_LOG(ret, false, "GetData failed, key %{public}s", key.c_str());
    MEDIA_LOGI("gltf_offset is %{public}s", value.c_str());
    if (value == "-1") {
        napi_set_named_property(env, result, "gltf_offset", gltfOffset);
        return false;
    }
    return true;
}

std::string AVMetadataExtractorNapi::StringifyMeta(const Any& value)
{
    static const std::unordered_map<std::string, std::function<std::string(const Any&)>> valueType2ConvertFunc = {
        { "bool", [](const Any& value) {return std::to_string(AnyCast<bool>(value)); } },
        { "int8_t", [](const Any& value) {return std::to_string(AnyCast<int8_t>(value)); } },
        { "uint8_t", [](const Any& value) {return std::to_string(AnyCast<uint8_t>(value)); } },
        { "int32_t", [](const Any& value) {return std::to_string(AnyCast<int32_t>(value)); } },
        { "uint32_t", [](const Any& value) {return std::to_string(AnyCast<uint32_t>(value)); } },
        { "int64_t", [](const Any& value) {return std::to_string(AnyCast<int64_t>(value)); } },
        { "uint64_t", [](const Any& value) {return std::to_string(AnyCast<uint64_t>(value)); } },
        { "float", [](const Any& value) {return std::to_string(AnyCast<float>(value)); } },
        { "double", [](const Any& value) {return std::to_string(AnyCast<double>(value)); } },
        { "std::string", [](const Any& value) {return AnyCast<std::string>(value); } }
    };
    std::string valueType(value.TypeName());
    auto it = valueType2ConvertFunc.find(valueType);
    CHECK_AND_RETURN_RET_LOG(it != valueType2ConvertFunc.end(), "",
        "can't find mapped valueType in valueType2ConvertFunc, valueType is %{public}s", valueType.c_str());
    std::function<std::string(const Any&)> func = it->second;
    return func(value);
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

napi_value AVMetadataExtractorNapi::JsFetchArtPicture(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVMetadataExtractorNapi::fetchArtPicture");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGI("JsFetchArtPicture In");

    auto promiseCtx = std::make_unique<AVMetadataExtractorAsyncContext>(env);
    napi_value args[1] = { nullptr };
    size_t argCount = 1;

    AVMetadataExtractorNapi* extractor
        = AVMetadataExtractorNapi::GetJsInstanceWithParameter(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(extractor != nullptr, result, "failed to GetJsInstance");
    promiseCtx->innerHelper_ = extractor->helper_;
    promiseCtx->callbackRef = CommonNapi::CreateReference(env, args[0]);
    promiseCtx->deferred = CommonNapi::CreatePromise(env, promiseCtx->callbackRef, result);

    if (extractor->state_ != HelperState::HELPER_STATE_RUNNABLE) {
        promiseCtx->SignError(
            MSERR_EXT_API9_OPERATE_NOT_PERMIT, "Can't fetchAlbumCover, please set fdSrc or dataSrc.");
    }

    // async work
    napi_value resource = nullptr;
    napi_create_string_utf8(env, "JsFetchArtPicture", NAPI_AUTO_LENGTH, &resource);
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, [](napi_env env, void *data) {
        MEDIA_LOGI("JsFetchArtPicture task start");
        auto promiseCtx = reinterpret_cast<AVMetadataExtractorAsyncContext *>(data);
        CHECK_AND_RETURN_LOG(promiseCtx && !promiseCtx->errFlag && promiseCtx->innerHelper_, "Invalid context.");
        auto sharedMemory = promiseCtx->innerHelper_->FetchArtPicture();
        promiseCtx->artPicture_ = ConvertMemToPixelMap(sharedMemory);
        if (promiseCtx->artPicture_ == nullptr) {
            promiseCtx->SignError(MSERR_EXT_API9_UNSUPPORT_FORMAT, "Failed to fetchAlbumCover");
        }
    }, FetchArtPictureComplete, static_cast<void *>(promiseCtx.get()), &promiseCtx->work));
    NAPI_CALL(env, napi_queue_async_work(env, promiseCtx->work));
    promiseCtx.release();
    MEDIA_LOGI("JsFetchArtPicture Out");
    return result;
}

void AVMetadataExtractorNapi::FetchArtPictureComplete(napi_env env, napi_status status, void *data)
{
    napi_value result = nullptr;

    MEDIA_LOGI("FetchArtPictureComplete In");
    auto context = static_cast<AVMetadataExtractorAsyncContext*>(data);

    if (status == napi_ok && context->errCode == napi_ok) {
        result = Media::PixelMapNapi::CreatePixelMap(env, context->artPicture_);
        context->status = ERR_OK;
    } else {
        context->status = context->errCode == napi_ok ? MSERR_INVALID_VAL : context->errCode;
        napi_get_undefined(env, &result);
    }

    CommonCallbackRoutine(env, context, result);
}

void AVMetadataExtractorNapi::CommonCallbackRoutine(napi_env env, AVMetadataExtractorAsyncContext* &asyncContext,
    const napi_value &valueParam)
{
    napi_value result[ARG_TWO] = {0};
    napi_value retVal;
    napi_value callback = nullptr;

    napi_get_undefined(env, &result[0]);
    napi_get_undefined(env, &result[1]);

    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(env, &scope);
    CHECK_AND_RETURN(scope != nullptr && asyncContext != nullptr);
    if (asyncContext->status == ERR_OK) {
        result[1] = valueParam;
    }
    napi_create_uint32(env, asyncContext->status, &result[0]);

    if (asyncContext->errFlag) {
        (void)CommonNapi::CreateError(env, asyncContext->errCode, asyncContext->errMessage, callback);
        result[0] = callback;
    }
    if (asyncContext->deferred) {
        if (asyncContext->status == ERR_OK) {
            napi_resolve_deferred(env, asyncContext->deferred, result[1]);
        } else {
            napi_reject_deferred(env, asyncContext->deferred, result[0]);
        }
    } else {
        napi_get_reference_value(env, asyncContext->callbackRef, &callback);
        napi_call_function(env, nullptr, callback, ARG_TWO, result, &retVal); // 2
        napi_delete_reference(env, asyncContext->callbackRef);
    }

    napi_delete_async_work(env, asyncContext->work);
    napi_close_handle_scope(env, scope);

    delete asyncContext;
    asyncContext = nullptr;
}

napi_value AVMetadataExtractorNapi::JsFetchFrameAtTime(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVMetadataExtractorNapi::JsFetchFrameAtTime");
    MEDIA_LOGI("JsFetchFrameAtTime  in");
    const int32_t maxArgs = ARG_FOUR;  // args + callback
    const int32_t argCallback = ARG_THREE;  // index three, the 4th param if exist
    const int32_t argPixelParam = ARG_TWO;  // index 2, the 3rd param
    size_t argCount = maxArgs;
    napi_value args[maxArgs] = { nullptr };
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    AVMetadataExtractorNapi* extractor
        = AVMetadataExtractorNapi::GetJsInstanceWithParameter(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(extractor != nullptr, result, "failed to GetJsInstance");

    auto asyncCtx = std::make_unique<AVMetadataExtractorAsyncContext>(env);
    CHECK_AND_RETURN_RET_LOG(asyncCtx, result, "failed to GetAsyncContext");
    asyncCtx->innerHelper_ = extractor->helper_;
    asyncCtx->callbackRef = CommonNapi::CreateReference(env, args[argCallback]);
    asyncCtx->deferred = CommonNapi::CreatePromise(env, asyncCtx->callbackRef, result);
    napi_valuetype valueType = napi_undefined;
    bool notParamValid = argCount < argCallback || napi_typeof(env, args[argPixelParam], &valueType) != napi_ok ||
        valueType != napi_object ||
        extractor->GetFetchFrameArgs(asyncCtx, env, args[ARG_ZERO], args[ARG_ONE], args[ARG_TWO]) != MSERR_OK;
    if (notParamValid) {
        asyncCtx->SignError(MSERR_EXT_API20_PARAM_ERROR_OUT_OF_RANGE, "Parameter check failed");
    }

    if (extractor->state_ == HelperState::HELPER_STATE_HTTP_INTERCEPTED) {
        asyncCtx->SignError(MSERR_EXT_API20_IO_CLEARTEXT_NOT_PERMITTED, "Http plaintext access is not allowed.");
    }

    if (extractor->state_ != HelperState::HELPER_STATE_RUNNABLE && !asyncCtx->errFlag) {
        asyncCtx->SignError(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "Current state is not runnable, can't fetchFrame.");
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "JsFetchFrameAtTime", NAPI_AUTO_LENGTH, &resource);
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, [](napi_env env, void *data) {
        auto asyncCtx = reinterpret_cast<AVMetadataExtractorAsyncContext *>(data);
        CHECK_AND_RETURN_LOG(asyncCtx && !asyncCtx->errFlag && asyncCtx->innerHelper_, "Invalid context.");
        auto pixelMap = asyncCtx->innerHelper_->
            FetchScaledFrameYuv(asyncCtx->timeUs, asyncCtx->option, asyncCtx->param_);
        asyncCtx->pixel_ = pixelMap;
        if (asyncCtx->pixel_ == nullptr) {
            asyncCtx->SignError(MSERR_EXT_API9_UNSUPPORT_FORMAT, "FetchFrameByTime failed.");
        }
    }, CreatePixelMapComplete, static_cast<void *>(asyncCtx.get()), &asyncCtx->work));
    NAPI_CALL(env, napi_queue_async_work(env, asyncCtx->work));
    asyncCtx.release();
    MEDIA_LOGI("JsFetchFrameAtTime Out");
    return result;
}

void AVMetadataExtractorNapi::CreatePixelMapComplete(napi_env env, napi_status status, void *data)
{
    napi_value result = nullptr;

    MEDIA_LOGI("CreatePixelMapComplete In");
    auto context = static_cast<AVMetadataExtractorAsyncContext*>(data);
    CHECK_AND_RETURN_LOG(context != nullptr, "Invalid context.");

    if (status == napi_ok && context->errCode == napi_ok) {
        MEDIA_LOGI("set pixel map success");
        context->status = ERR_OK;
        result = Media::PixelMapNapi::CreatePixelMap(env, context->pixel_);
    } else {
        context->status = context->errCode == napi_ok ? MSERR_INVALID_VAL : context->errCode;
        MEDIA_LOGW("set pixel map failed");
        napi_get_undefined(env, &result);
    }

    CommonCallbackRoutine(env, context, result);
}

napi_value AVMetadataExtractorNapi::JsRelease(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVMetadataExtractorNapi::release");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGI("JsRelease In");

    auto promiseCtx = std::make_unique<AVMetadataExtractorAsyncContext>(env);
    napi_value args[1] = { nullptr };
    size_t argCount = 1;
    AVMetadataExtractorNapi *extractor
        = AVMetadataExtractorNapi::GetJsInstanceWithParameter(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(extractor != nullptr, result, "failed to GetJsInstance");
    promiseCtx->innerHelper_ = extractor->helper_;
    promiseCtx->callbackRef = CommonNapi::CreateReference(env, args[0]);
    promiseCtx->deferred = CommonNapi::CreatePromise(env, promiseCtx->callbackRef, result);

    if (extractor->dataSrcCb_ != nullptr) {
        extractor->dataSrcCb_->ClearCallbackReference();
        extractor->dataSrcCb_ = nullptr;
    }

    if (extractor->state_ == HelperState::HELPER_STATE_RELEASED) {
        promiseCtx->SignError(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "Has released once, can't release again.");
    }

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "JsRelease", NAPI_AUTO_LENGTH, &resource);
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, [](napi_env env, void *data) {
        auto promiseCtx = reinterpret_cast<AVMetadataExtractorAsyncContext *>(data);
        CHECK_AND_RETURN_LOG(promiseCtx && !promiseCtx->errFlag && promiseCtx->innerHelper_, "Invalid promiseCtx.");
        promiseCtx->innerHelper_->Release();
    }, MediaAsyncContext::CompleteCallback, static_cast<void *>(promiseCtx.get()), &promiseCtx->work));
    napi_queue_async_work_with_qos(env, promiseCtx->work, napi_qos_user_initiated);
    promiseCtx.release();
    MEDIA_LOGI("JsRelease Out");
    return result;
}

napi_value AVMetadataExtractorNapi::JsSetUrlSource(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVMetadataExtractorNapi::setUrlSource");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGI("JsSetUrlSource In");

    const int32_t maxArgs = ARG_TWO;
    size_t argCount = ARG_TWO;
    napi_value args[maxArgs] = { nullptr };
    AVMetadataExtractorNapi *extractor
        = AVMetadataExtractorNapi::GetJsInstanceWithParameter(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(extractor != nullptr, result, "failed to GetJsInstanceWithParameter");

    CHECK_AND_RETURN_RET_LOG(
        extractor->state_ == HelperState::HELPER_STATE_IDLE, result, "Has set source once, unsupport set again");

    napi_valuetype valueType = napi_undefined;
    if (argCount < ARG_ONE || napi_typeof(env, args[ARG_ZERO], &valueType) != napi_ok || valueType != napi_string) {
        return result;
    }

    extractor->url_ = CommonNapi::GetStringArgument(env, args[ARG_ZERO]);
    (void)CommonNapi::GetPropertyMap(env, args[1], extractor->header_);
    auto res = extractor->helper_->SetUrlSource(extractor->url_, extractor->header_);
    if (res == MSERR_OK) {
        extractor->state_ = HelperState::HELPER_STATE_RUNNABLE;
    } else if (res == MSERR_INVALID_OPERATION) {
        extractor->state_ = HelperState::HELPER_STATE_HTTP_INTERCEPTED;
    } else {
        extractor->state_ = HelperState::HELPER_ERROR;
    }
    extractor->helper_->SetAVMetadataCaller(AVMetadataCaller::AV_METADATA_EXTRACTOR);
    MEDIA_LOGI("0x%{public}06" PRIXPTR " JsSetUrlSource Out", FAKE_POINTER(extractor));
    return result;
}

napi_value AVMetadataExtractorNapi::JsSetAVFileDescriptor(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVMetadataExtractorNapi::set fd");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGI("JsSetAVFileDescriptor In");

    napi_value args[1] = { nullptr };
    size_t argCount = 1;
    AVMetadataExtractorNapi *extractor = AVMetadataExtractorNapi::GetJsInstanceWithParameter(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(extractor != nullptr, result, "failed to GetJsInstanceWithParameter");
    CHECK_AND_RETURN_RET_LOG(
        extractor->state_ == HelperState::HELPER_STATE_IDLE, result, "Has set source once, unsupport set again");
    napi_valuetype valueType = napi_undefined;
    if (argCount < 1 || napi_typeof(env, args[0], &valueType) != napi_ok || valueType != napi_object) {
        return result;
    }

    bool notValidParam = argCount < ARG_ONE || napi_typeof(env, args[0], &valueType) != napi_ok
        || valueType != napi_object || !CommonNapi::GetFdArgument(env, args[0], extractor->fileDescriptor_);
    CHECK_AND_RETURN_RET_LOG(!notValidParam, result, "Invalid file descriptor, return");
    CHECK_AND_RETURN_RET_LOG(extractor->helper_, result, "Invalid AVMetadataExtractorNapi.");

    auto fileDescriptor = extractor->fileDescriptor_;
    auto res = extractor->helper_->SetSource(fileDescriptor.fd, fileDescriptor.offset, fileDescriptor.length);
    extractor->state_ = res == MSERR_OK ? HelperState::HELPER_STATE_RUNNABLE : HelperState::HELPER_ERROR;
    extractor->helper_->SetAVMetadataCaller(AVMetadataCaller::AV_METADATA_EXTRACTOR);
    return result;
}

napi_value AVMetadataExtractorNapi::JsGetAVFileDescriptor(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVMetadataExtractorNapi::get fd");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGI("JsGetAVFileDescriptor In");

    AVMetadataExtractorNapi *extractor = AVMetadataExtractorNapi::GetJsInstance(env, info);
    CHECK_AND_RETURN_RET_LOG(extractor != nullptr, result, "failed to GetJsInstance");

    napi_value value = nullptr;
    (void)napi_create_object(env, &value);
    (void)CommonNapi::AddNumberPropInt32(env, value, "fd", extractor->fileDescriptor_.fd);
    (void)CommonNapi::AddNumberPropInt64(env, value, "offset", extractor->fileDescriptor_.offset);
    (void)CommonNapi::AddNumberPropInt64(env, value, "length", extractor->fileDescriptor_.length);

    MEDIA_LOGI("JsGetAVFileDescriptor Out");
    return value;
}

napi_value AVMetadataExtractorNapi::JsSetDataSrc(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVMetadataExtractorNapi::set dataSrc");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGI("JsSetDataSrc In");

    napi_value args[1] = { nullptr };
    size_t argCount = ARG_ONE;
    AVMetadataExtractorNapi *jsMetaHelper
        = AVMetadataExtractorNapi::GetJsInstanceWithParameter(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(jsMetaHelper != nullptr, result, "failed to GetJsInstanceWithParameter");

    CHECK_AND_RETURN_RET_LOG(
        jsMetaHelper->state_ == HelperState::HELPER_STATE_IDLE, result, "Has set source once, unsupport set again");

    napi_valuetype valueType = napi_undefined;
    bool notValidParam = argCount < 1 || napi_typeof(env, args[0], &valueType) != napi_ok || valueType != napi_object;
    CHECK_AND_RETURN_RET_LOG(!notValidParam, result, "Invalid dataSrc param, return");
    CHECK_AND_RETURN_RET_LOG(jsMetaHelper->helper_, result, "Invalid AVMetadataExtractorNapi.");
    (void)CommonNapi::GetPropertyInt64(env, args[0], "fileSize", jsMetaHelper->dataSrcDescriptor_.fileSize);
    CHECK_AND_RETURN_RET(
        jsMetaHelper->dataSrcDescriptor_.fileSize >= -1 && jsMetaHelper->dataSrcDescriptor_.fileSize != 0, result);
    MEDIA_LOGI("Recvive filesize is %{public}" PRId64 "", jsMetaHelper->dataSrcDescriptor_.fileSize);
    jsMetaHelper->dataSrcCb_
        = std::make_shared<HelperDataSourceCallback>(env, jsMetaHelper->dataSrcDescriptor_.fileSize);

    napi_value callback = nullptr;
    napi_ref ref = nullptr;
    napi_get_named_property(env, args[0], "callback", &callback);
    jsMetaHelper->dataSrcDescriptor_.callback = callback;
    napi_status status = napi_create_reference(env, callback, 1, &ref);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && ref != nullptr, result, "failed to create reference!");
    std::shared_ptr<AutoRef> autoRef = std::make_shared<AutoRef>(env, ref);
    const std::string callbackName = "readAt";
    jsMetaHelper->dataSrcCb_->SaveCallbackReference(callbackName, autoRef);
    auto res = jsMetaHelper->helper_->SetSource(jsMetaHelper->dataSrcCb_);
    jsMetaHelper->state_ = res == MSERR_OK ? HelperState::HELPER_STATE_RUNNABLE : HelperState::HELPER_ERROR;
    MEDIA_LOGI("JsSetDataSrc Out");
    return result;
}

napi_value AVMetadataExtractorNapi::JsGetDataSrc(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVMetadataExtractorNapi::get dataSrc");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGI("JsGetDataSrc In");

    AVMetadataExtractorNapi *jsMetaHelper = AVMetadataExtractorNapi::GetJsInstance(env, info);
    CHECK_AND_RETURN_RET_LOG(jsMetaHelper != nullptr, result, "failed to GetJsInstance");
    CHECK_AND_RETURN_RET_LOG(jsMetaHelper->dataSrcCb_ != nullptr, result, "failed to check dataSrcCb_");

    napi_value value = nullptr;
    int64_t fileSize;
    napi_value callback = nullptr;
    (void)napi_create_object(env, &value);
    (void)jsMetaHelper->dataSrcCb_->GetSize(fileSize);
    (void)CommonNapi::AddNumberPropInt64(env, value, "fileSize", fileSize);
    const std::string callbackName = "readAt";
    int32_t ret = jsMetaHelper->dataSrcCb_->GetCallback(callbackName, &callback);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, result, "failed to GetCallback");
    (void)HelperDataSourceCallback::AddNapiValueProp(env, value, "callback", callback);

    MEDIA_LOGI("JsGetDataSrc Out");
    return value;
}

int32_t AVMetadataExtractorNapi::GetFetchFrameArgs(std::unique_ptr<AVMetadataExtractorAsyncContext> &asyncCtx,
    napi_env env, napi_value timeUs, napi_value option, napi_value params)
{
    napi_status ret = napi_get_value_int64(env, timeUs, &asyncCtx->timeUs);
    CHECK_AND_RETURN_RET_LOG(ret == napi_ok, MSERR_INVALID_VAL, "failed to get timeUs");

    ret = napi_get_value_int32(env, option, &asyncCtx->option);
    CHECK_AND_RETURN_RET_LOG(ret == napi_ok, MSERR_INVALID_VAL, "failed to get option");

    int32_t width = 0;
    if (!CommonNapi::GetPropertyInt32(env, params, "width", width)) {
        MEDIA_LOGW("failed to get width");
    }

    int32_t height = 0;
    if (!CommonNapi::GetPropertyInt32(env, params, "height", height)) {
        MEDIA_LOGW("failed to get height");
    }

    PixelFormat colorFormat = PixelFormat::RGBA_8888;
    int32_t formatVal = 3;
    CommonNapi::GetPropertyInt32(env, params, "colorFormat", formatVal);
    colorFormat = static_cast<PixelFormat>(formatVal);
    if (colorFormat != PixelFormat::RGB_565 && colorFormat != PixelFormat::RGB_888 &&
        colorFormat != PixelFormat::RGBA_8888) {
        MEDIA_LOGE("formatVal is invalid");
        return MSERR_INVALID_VAL;
    }

    bool autoFlip = false;
    if (!CommonNapi::GetPropertyBool(env, params, "autoFlip", autoFlip)) {
        MEDIA_LOGW("failed to get autoFlip");
    }

    asyncCtx->param_.dstWidth = width;
    asyncCtx->param_.dstHeight = height;
    asyncCtx->param_.colorFormat = colorFormat;
    asyncCtx->param_.isSupportFlip = autoFlip;
    return MSERR_OK;
}

AVMetadataExtractorNapi* AVMetadataExtractorNapi::GetJsInstance(napi_env env, napi_callback_info info)
{
    size_t argCount = 0;
    napi_value jsThis = nullptr;
    napi_status status = napi_get_cb_info(env, info, &argCount, nullptr, &jsThis, nullptr);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && jsThis != nullptr, nullptr, "failed to napi_get_cb_info");

    AVMetadataExtractorNapi *extractor = nullptr;
    status = napi_unwrap(env, jsThis, reinterpret_cast<void **>(&extractor));
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && extractor != nullptr, nullptr, "failed to napi_unwrap");

    return extractor;
}

AVMetadataExtractorNapi* AVMetadataExtractorNapi::GetJsInstanceWithParameter(napi_env env, napi_callback_info info,
    size_t &argc, napi_value *argv)
{
    napi_value jsThis = nullptr;
    napi_status status = napi_get_cb_info(env, info, &argc, argv, &jsThis, nullptr);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && jsThis != nullptr, nullptr, "failed to napi_get_cb_info");

    AVMetadataExtractorNapi *extractor = nullptr;
    status = napi_unwrap(env, jsThis, reinterpret_cast<void **>(&extractor));
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && extractor != nullptr, nullptr, "failed to napi_unwrap");

    return extractor;
}

napi_value AVMetadataExtractorNapi::JSGetTimeByFrameIndex(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVMetadataExtractorNapi::JSGetTimeByFrameIndex");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGI("frame to time");

    napi_value args[ARG_TWO] = { nullptr };
    size_t argCount = ARG_TWO;
    AVMetadataExtractorNapi* extractor
        = AVMetadataExtractorNapi::GetJsInstanceWithParameter(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(extractor != nullptr, result, "failed to GetJsInstance");

    auto promiseCtx = std::make_unique<AVMetadataExtractorAsyncContext>(env);

    if (CommonNapi::CheckValueType(env, args[0], napi_number)) {
        auto res = napi_get_value_uint32(env, args[0], &promiseCtx->index_);
        if (res != napi_ok || static_cast<int32_t>(promiseCtx->index_) < 0) {
            promiseCtx->SignError(MSERR_EXT_API9_INVALID_PARAMETER, "frame index is not valid");
        }
    }

    promiseCtx->innerHelper_ = extractor->helper_;
    promiseCtx->callbackRef = CommonNapi::CreateReference(env, args[1]);
    promiseCtx->deferred = CommonNapi::CreatePromise(env, promiseCtx->callbackRef, result);

    if (extractor->state_ != HelperState::HELPER_STATE_RUNNABLE) {
        promiseCtx->SignError(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "Invalid state, please set source");
    }

    // async work
    napi_value resource = nullptr;
    napi_create_string_utf8(env, "JSGetTimeByFrameIndex", NAPI_AUTO_LENGTH, &resource);
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, [](napi_env env, void *data) {
        auto promiseCtx = reinterpret_cast<AVMetadataExtractorAsyncContext *>(data);
        CHECK_AND_RETURN_LOG(promiseCtx && !promiseCtx->errFlag && promiseCtx->innerHelper_, "Invalid promiseCtx.");
        auto res = promiseCtx->innerHelper_->GetTimeByFrameIndex(promiseCtx->index_, promiseCtx->timeStamp_);
        if (res != MSERR_EXT_API9_OK) {
            MEDIA_LOGE("JSGetTimeByFrameIndex get result SignError");
            promiseCtx->SignError(MSERR_EXT_API9_UNSUPPORT_FORMAT, "Demuxer getTimeByFrameIndex failed.");
        }
    }, GetTimeByFrameIndexComplete, static_cast<void *>(promiseCtx.get()), &promiseCtx->work));
    NAPI_CALL(env, napi_queue_async_work(env, promiseCtx->work));
    promiseCtx.release();
    return result;
}

void AVMetadataExtractorNapi::GetTimeByFrameIndexComplete(napi_env env, napi_status status, void *data)
{
    napi_value result = nullptr;
    auto context = static_cast<AVMetadataExtractorAsyncContext*>(data);

    if (status == napi_ok && context->errCode == napi_ok) {
        napi_create_int64(env, context->timeStamp_, &result);
        context->status = ERR_OK;
    } else {
        context->status = context->errCode == napi_ok ? MSERR_INVALID_VAL : context->errCode;
        napi_get_undefined(env, &result);
    }
    CommonCallbackRoutine(env, context, result);
}

napi_value AVMetadataExtractorNapi::JSGetFrameIndexByTime(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVMetadataExtractorNapi::JSGetFrameIndexByTime");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);
    MEDIA_LOGI("time to frame");

    napi_value args[ARG_TWO] = { nullptr };
    size_t argCount = ARG_TWO;
    AVMetadataExtractorNapi* extractor
        = AVMetadataExtractorNapi::GetJsInstanceWithParameter(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(extractor != nullptr, result, "failed to GetJsInstance");

    auto promiseCtx = std::make_unique<AVMetadataExtractorAsyncContext>(env);

    if (CommonNapi::CheckValueType(env, args[0], napi_number)) {
        int64_t timeStamp = 0;
        auto res = napi_get_value_int64(env, args[0], &timeStamp);
        if (res != napi_ok) {
            promiseCtx->SignError(MSERR_EXT_API9_INVALID_PARAMETER, "time stamp is not valid");
        }
        promiseCtx->timeStamp_ = static_cast<uint64_t>(timeStamp);
    }

    promiseCtx->innerHelper_ = extractor->helper_;
    promiseCtx->callbackRef = CommonNapi::CreateReference(env, args[1]);
    promiseCtx->deferred = CommonNapi::CreatePromise(env, promiseCtx->callbackRef, result);

    if (extractor->state_ != HelperState::HELPER_STATE_RUNNABLE) {
        promiseCtx->SignError(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "Invalid state, please set source");
    }

    // async work
    napi_value resource = nullptr;
    napi_create_string_utf8(env, "JSGetFrameIndexByTime", NAPI_AUTO_LENGTH, &resource);
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, [](napi_env env, void *data) {
        auto promiseCtx = reinterpret_cast<AVMetadataExtractorAsyncContext *>(data);
        CHECK_AND_RETURN_LOG(promiseCtx && !promiseCtx->errFlag && promiseCtx->innerHelper_, "Invalid promiseCtx.");
        auto res = promiseCtx->innerHelper_->GetFrameIndexByTime(promiseCtx->timeStamp_, promiseCtx->index_);
        if (res != MSERR_EXT_API9_OK) {
            MEDIA_LOGE("JSGetFrameIndexByTime get result SignError");
            promiseCtx->SignError(MSERR_EXT_API9_UNSUPPORT_FORMAT, "Demuxer getFrameIndexByTime failed.");
        }
    }, GetFrameIndexByTimeComplete, static_cast<void *>(promiseCtx.get()), &promiseCtx->work));
    NAPI_CALL(env, napi_queue_async_work(env, promiseCtx->work));
    promiseCtx.release();
    return result;
}

void AVMetadataExtractorNapi::GetFrameIndexByTimeComplete(napi_env env, napi_status status, void *data)
{
    napi_value result = nullptr;
    auto context = static_cast<AVMetadataExtractorAsyncContext*>(data);

    if (status == napi_ok && context->errCode == napi_ok) {
        napi_create_uint32(env, context->index_, &result);
        context->status = ERR_OK;
    } else {
        context->status = context->errCode == napi_ok ? MSERR_INVALID_VAL : context->errCode;
        napi_get_undefined(env, &result);
    }
    CommonCallbackRoutine(env, context, result);
}
} // namespace Media
} // namespace OHOS
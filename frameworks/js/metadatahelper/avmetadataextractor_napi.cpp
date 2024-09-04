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
static constexpr uint8_t ARG_TWO = 2;
}

namespace OHOS {
namespace Media {
thread_local napi_ref AVMetadataExtractorNapi::constructor_ = nullptr;

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
        DECLARE_NAPI_FUNCTION("fetchMetadata", JsResolveMetadata),
        DECLARE_NAPI_FUNCTION("fetchAlbumCover", JsFetchArtPicture),
        DECLARE_NAPI_FUNCTION("release", JsRelease),
        DECLARE_NAPI_FUNCTION("getTimeByFrameIndex", JSGetTimeByFrameIndex),
        DECLARE_NAPI_FUNCTION("getFrameIndexByTime", JSGetFrameIndexByTime),
        DECLARE_NAPI_GETTER_SETTER("fdSrc", JsGetAVFileDescriptor, JsSetAVFileDescriptor),
        DECLARE_NAPI_GETTER_SETTER("dataSrc", JsGetDataSrc, JsSetDataSrc),
    };

    napi_value constructor = nullptr;
    napi_status status = napi_define_class(env, LABEL.tag, NAPI_AUTO_LENGTH, Constructor, nullptr,
        sizeof(properties) / sizeof(properties[0]), properties, &constructor);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, nullptr, "Failed to define AVMetadataHelper class");

    status = napi_create_reference(env, constructor, 1, &constructor_);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok, nullptr, "Failed to create reference of constructor");

    status = napi_set_named_property(env, exports, LABEL.tag, constructor);
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

    AVMetadataExtractorNapi *napi = new(std::nothrow) AVMetadataExtractorNapi();
    CHECK_AND_RETURN_RET_LOG(napi != nullptr, result, "failed to new AVMetadataExtractorNapi");

    napi->env_ = env;
    napi->helper_ = AVMetadataHelperFactory::CreateAVMetadataHelper();
    CHECK_AND_RETURN_RET_LOG(napi->helper_ != nullptr, result, "failed to CreateMetadataHelper");

    status = napi_wrap(
        env, jsThis, reinterpret_cast<void *>(napi), AVMetadataExtractorNapi::Destructor, nullptr, nullptr);
    if (status != napi_ok) {
        MEDIA_LOGE("Failed to wrap native instance");
        delete napi;
        return result;
    }

    MEDIA_LOGI("0x%{public}06" PRIXPTR " Constructor", FAKE_POINTER(napi));
    return jsThis;
}

void AVMetadataExtractorNapi::Destructor(napi_env env, void *nativeObject, void *finalize)
{
    MEDIA_LOGI("0x%{public}06" PRIXPTR " Destructor", FAKE_POINTER(nativeObject));
    (void)finalize;
    CHECK_AND_RETURN(nativeObject != nullptr);
    AVMetadataExtractorNapi *napi = reinterpret_cast<AVMetadataExtractorNapi *>(nativeObject);
    if (napi != nullptr && napi->helper_ != nullptr) {
        napi->helper_->Release();
    }
    delete napi;
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

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "JsCreateAVMetadataExtractor", NAPI_AUTO_LENGTH, &resource);
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, [](napi_env env, void *data) {},
        MediaAsyncContext::CompleteCallback, static_cast<void *>(asyncContext.get()), &asyncContext->work));
    NAPI_CALL(env, napi_queue_async_work(env, asyncContext->work));
    asyncContext.release();
    MEDIA_LOGI("JsCreateAVMetadataExtractor Out");
    return result;
}

napi_value AVMetadataExtractorNapi::JsResolveMetadata(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVMetadataExtractorNapi::resolveMetadata");
    MEDIA_LOGI("JsResolveMetadata In");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    napi_value args[1] = { nullptr };
    size_t argCount = 1;
    AVMetadataExtractorNapi* napi = AVMetadataExtractorNapi::GetJsInstanceWithParameter(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(napi != nullptr, result, "failed to GetJsInstance");

    auto asyncCtx = std::make_unique<AVMetadataExtractorAsyncContext>(env);
    asyncCtx->napi = napi;
    asyncCtx->callbackRef = CommonNapi::CreateReference(env, args[0]);
    asyncCtx->deferred = CommonNapi::CreatePromise(env, asyncCtx->callbackRef, result);

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "JsResolveMetadata", NAPI_AUTO_LENGTH, &resource);
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, [](napi_env env, void *data) {
        auto asyncCtx = reinterpret_cast<AVMetadataExtractorAsyncContext *>(data);
        CHECK_AND_RETURN_LOG(asyncCtx && !asyncCtx->errFlag, "Invalid asyncCtx.");
        CHECK_AND_RETURN_LOG(asyncCtx->napi != nullptr, "Invalid napi object.");
        if (asyncCtx->napi->state_ != HelperState::HELPER_STATE_RUNNABLE) {
            asyncCtx->SignError(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "Can't fetchMetadata, please set source.");
            return;
        }
        CHECK_AND_RETURN_LOG(asyncCtx->napi->helper_ != nullptr, "Invalid metadata napi.");
        asyncCtx->metadata_ = asyncCtx->napi->helper_->GetAVMetadata();
        CHECK_AND_RETURN(asyncCtx->metadata_ == nullptr);
        MEDIA_LOGE("ResolveMetadata AVMetadata is nullptr");
        asyncCtx->SignError(MSERR_EXT_API9_UNSUPPORT_FORMAT, "failed to ResolveMetadata, AVMetadata is nullptr!");
    }, ResolveMetadataComplete, static_cast<void *>(asyncCtx.get()), &asyncCtx->work));
    NAPI_CALL(env, napi_queue_async_work(env, asyncCtx->work));
    asyncCtx.release();
    MEDIA_LOGI("JsResolveMetadata Out");
    return result;
}

void AVMetadataExtractorNapi::ResolveMetadataComplete(napi_env env, napi_status status, void *data)
{
    MEDIA_LOGI("ResolveMetadataComplete In");
    auto asyncCtx = static_cast<AVMetadataExtractorAsyncContext*>(data);
    CHECK_AND_RETURN_LOG(asyncCtx != nullptr, "asyncCtx is nullptr!");

    bool ret = true;
    napi_value result = nullptr;
    napi_value location = nullptr;
    napi_value customInfo = nullptr;
    napi_create_object(env, &result);
    napi_create_object(env, &location);
    napi_create_object(env, &customInfo);
    std::shared_ptr<Meta> metadata = asyncCtx->metadata_;
    if (status != napi_ok || asyncCtx->errCode != napi_ok) {
        asyncCtx->status = asyncCtx->errCode == napi_ok ? MSERR_INVALID_VAL : asyncCtx->errCode;
        MEDIA_LOGI("Resolve meta data failed");
        napi_get_undefined(env, &result);
        CommonCallbackRoutine(env, asyncCtx, result);
        return;
    }
    for (const auto &key : g_Metadata) {
        if (metadata->Find(key) == metadata->end()) {
            MEDIA_LOGE("failed to find key: %{public}s", key.c_str());
            continue;
        }
        MEDIA_LOGE("success to find key: %{public}s", key.c_str());
        if (key == "latitude" || key == "longitude") {
            CHECK_AND_CONTINUE_LOG(CommonNapi::SetPropertyByValueType(env, location, metadata, key),
                "SetProperty failed, key: %{public}s", key.c_str());
            continue;
        }
        if (key == "customInfo") {
            std::shared_ptr<Meta> customData = std::make_shared<Meta>();
            ret = metadata->GetData(key, customData);
            CHECK_AND_CONTINUE_LOG(ret, "GetData failed, key %{public}s", key.c_str());
            for (auto iter = customData->begin(); iter != customData->end(); ++iter) {
                AnyValueType type = customData->GetValueType(iter->first);
                CHECK_AND_CONTINUE_LOG(type == AnyValueType::STRING, "key is not string");
                CHECK_AND_CONTINUE_LOG(CommonNapi::SetPropertyByValueType(env, customInfo, customData, iter->first),
                    "SetProperty failed, key: %{public}s", key.c_str());
            }
            continue;
        }
        CHECK_AND_CONTINUE_LOG(CommonNapi::SetPropertyByValueType(env, result, metadata, key),
            "SetProperty failed, key: %{public}s", key.c_str());
    }
    napi_set_named_property(env, result, "location", location);
    napi_set_named_property(env, result, "customInfo", customInfo);
    asyncCtx->status = ERR_OK;

    CommonCallbackRoutine(env, asyncCtx, result);
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
    MEDIA_LOGI("JsFetchArtPicture In");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    napi_value args[1] = { nullptr };
    size_t argCount = 1;
    AVMetadataExtractorNapi* napi
        = AVMetadataExtractorNapi::GetJsInstanceWithParameter(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(napi != nullptr, result, "failed to GetJsInstance");

    auto asyncCtx = std::make_unique<AVMetadataExtractorAsyncContext>(env);
    asyncCtx->napi = napi;
    asyncCtx->callbackRef = CommonNapi::CreateReference(env, args[0]);
    asyncCtx->deferred = CommonNapi::CreatePromise(env, asyncCtx->callbackRef, result);

    // async work
    napi_value resource = nullptr;
    napi_create_string_utf8(env, "JsFetchArtPicture", NAPI_AUTO_LENGTH, &resource);
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, [](napi_env env, void *data) {
        MEDIA_LOGI("JsFetchArtPicture task start");
        auto context = reinterpret_cast<AVMetadataExtractorAsyncContext *>(data);
        CHECK_AND_RETURN_LOG(context && context->napi, "Invalid context.");
        if (context->napi->state_ != HelperState::HELPER_STATE_RUNNABLE) {
            context->SignError(
                MSERR_EXT_API9_OPERATE_NOT_PERMIT, "Can't fetchAlbumCover, please set fdSrc or dataSrc.");
            return;
        }
        auto sharedMemory = context->napi->helper_->FetchArtPicture();
        context->artPicture_ = ConvertMemToPixelMap(sharedMemory);
        if (context->artPicture_ == nullptr) {
            context->SignError(MSERR_EXT_API9_UNSUPPORT_FORMAT, "Failed to fetchAlbumCover");
        }
    }, FetchArtPictureComplete, static_cast<void *>(asyncCtx.get()), &asyncCtx->work));
    NAPI_CALL(env, napi_queue_async_work(env, asyncCtx->work));
    asyncCtx.release();
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
    napi_value result[2] = {0};
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

napi_value AVMetadataExtractorNapi::JsRelease(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVMetadataExtractorNapi::Release");
    MEDIA_LOGI("JsRelease In");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    napi_value args[1] = { nullptr };
    size_t argCount = 1;
    AVMetadataExtractorNapi *napi = AVMetadataExtractorNapi::GetJsInstanceWithParameter(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(napi != nullptr, result, "failed to GetJsInstance");

    auto asyncCtx = std::make_unique<AVMetadataExtractorAsyncContext>(env);
    asyncCtx->napi = napi;
    asyncCtx->callbackRef = CommonNapi::CreateReference(env, args[0]);
    asyncCtx->deferred = CommonNapi::CreatePromise(env, asyncCtx->callbackRef, result);

    napi_value resource = nullptr;
    napi_create_string_utf8(env, "JsRelease", NAPI_AUTO_LENGTH, &resource);
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, [](napi_env env, void *data) {
        auto asyncCtx = reinterpret_cast<AVMetadataExtractorAsyncContext *>(data);
        CHECK_AND_RETURN_LOG(asyncCtx && !asyncCtx->errFlag, "Invalid asyncCtx.");
        CHECK_AND_RETURN_LOG(asyncCtx->napi != nullptr, "Invalid napi object.");
        if (asyncCtx->napi->state_ == HelperState::HELPER_STATE_RELEASED) {
            asyncCtx->SignError(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "Has released once, can't release again.");
            return;
        }
        CHECK_AND_RETURN_LOG(asyncCtx->napi->helper_, "PromiseCtx has invalid data.");
        asyncCtx->napi->helper_->Release();
    }, MediaAsyncContext::CompleteCallback, static_cast<void *>(asyncCtx.get()), &asyncCtx->work));
    napi_queue_async_work_with_qos(env, asyncCtx->work, napi_qos_user_initiated);
    asyncCtx.release();
    MEDIA_LOGI("JsRelease Out");
    return result;
}

napi_value AVMetadataExtractorNapi::JsSetAVFileDescriptor(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVMetadataExtractorNapi::SetFileDescriptor");
    MEDIA_LOGI("JsSetAVFileDescriptor In");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    napi_value args[1] = { nullptr };
    size_t argCount = 1;
    AVMetadataExtractorNapi *napi = AVMetadataExtractorNapi::GetJsInstanceWithParameter(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(napi != nullptr, result, "failed to GetJsInstanceWithParameter");
    CHECK_AND_RETURN_RET_LOG(
        napi->state_ == HelperState::HELPER_STATE_IDLE, result, "Has set source once, unsupport set again");
    napi_valuetype valueType = napi_undefined;
    bool notValidParam = argCount < 1 || napi_typeof(env, args[0], &valueType) != napi_ok || valueType != napi_object ||
        !CommonNapi::GetFdArgument(env, args[0], napi->fileDescriptor_);
    CHECK_AND_RETURN_RET_LOG(!notValidParam, result, "Invalid file descriptor, return");
    CHECK_AND_RETURN_RET_LOG(napi->helper_, result, "Invalid AVMetadataExtractorNapi.");

    auto fileDescriptor = napi->fileDescriptor_;
    auto res = napi->helper_->SetSource(fileDescriptor.fd, fileDescriptor.offset, fileDescriptor.length);
    napi->state_ = res == MSERR_OK ? HelperState::HELPER_STATE_RUNNABLE : HelperState::HELPER_ERROR;
    return result;
}

napi_value AVMetadataExtractorNapi::JsGetAVFileDescriptor(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVMetadataExtractorNapi::get fd");
    MEDIA_LOGI("JsGetAVFileDescriptor In");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    AVMetadataExtractorNapi *napi = AVMetadataExtractorNapi::GetJsInstance(env, info);
    CHECK_AND_RETURN_RET_LOG(napi != nullptr, result, "failed to GetJsInstance");

    napi_value value = nullptr;
    (void)napi_create_object(env, &value);
    (void)CommonNapi::AddNumberPropInt32(env, value, "fd", napi->fileDescriptor_.fd);
    (void)CommonNapi::AddNumberPropInt64(env, value, "offset", napi->fileDescriptor_.offset);
    (void)CommonNapi::AddNumberPropInt64(env, value, "length", napi->fileDescriptor_.length);

    MEDIA_LOGI("JsGetAVFileDescriptor Out");
    return value;
}

napi_value AVMetadataExtractorNapi::JsSetDataSrc(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVMetadataExtractorNapi::set dataSrc");
    MEDIA_LOGI("JsSetDataSrc In");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    napi_value args[1] = { nullptr };
    size_t argCount = 1;
    AVMetadataExtractorNapi *napi
        = AVMetadataExtractorNapi::GetJsInstanceWithParameter(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(napi != nullptr, result, "failed to GetJsInstanceWithParameter");

    CHECK_AND_RETURN_RET_LOG(
        napi->state_ == HelperState::HELPER_STATE_IDLE, result, "Has set source once, unsupport set again");

    napi_valuetype valueType = napi_undefined;
    bool notValidParam = argCount < 1 || napi_typeof(env, args[0], &valueType) != napi_ok || valueType != napi_object ||
        !CommonNapi::GetFdArgument(env, args[0], napi->fileDescriptor_);
    CHECK_AND_RETURN_RET_LOG(!notValidParam, result, "Invalid file descriptor, return");
    CHECK_AND_RETURN_RET_LOG(napi->helper_, result, "Invalid AVMetadataExtractorNapi.");
    (void)CommonNapi::GetPropertyInt64(env, args[0], "fileSize", napi->dataSrcDescriptor_.fileSize);
    CHECK_AND_RETURN_RET(napi->dataSrcDescriptor_.fileSize >= -1 && napi->dataSrcDescriptor_.fileSize != 0, result);
    MEDIA_LOGI("Recvive filesize is %{public}" PRId64 "", napi->dataSrcDescriptor_.fileSize);
    napi->dataSrcCb_
        = std::make_shared<HelperDataSourceCallback>(env, napi->dataSrcDescriptor_.fileSize);

    napi_value callback = nullptr;
    napi_ref ref = nullptr;
    napi_get_named_property(env, args[0], "callback", &callback);
    napi->dataSrcDescriptor_.callback = callback;
    napi_status status = napi_create_reference(env, callback, 1, &ref);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && ref != nullptr, result, "failed to create reference!");
    std::shared_ptr<AutoRef> autoRef = std::make_shared<AutoRef>(env, ref);
    const std::string callbackName = "readAt";
    napi->dataSrcCb_->SaveCallbackReference(callbackName, autoRef);
    auto res = napi->helper_->SetSource(napi->dataSrcCb_);
    napi->state_ = res == MSERR_OK ? HelperState::HELPER_STATE_RUNNABLE : HelperState::HELPER_ERROR;
    MEDIA_LOGI("JsSetDataSrc Out");
    return result;
}

napi_value AVMetadataExtractorNapi::JsGetDataSrc(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVMetadataExtractorNapi::get dataSrc");
    MEDIA_LOGI("JsGetDataSrc In");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    AVMetadataExtractorNapi *napi = AVMetadataExtractorNapi::GetJsInstance(env, info);
    CHECK_AND_RETURN_RET_LOG(napi != nullptr, result, "failed to GetJsInstance");
    CHECK_AND_RETURN_RET_LOG(napi->dataSrcCb_ != nullptr, result, "failed to check dataSrcCb_");

    napi_value value = nullptr;
    int64_t fileSize;
    napi_value callback = nullptr;
    (void)napi_create_object(env, &value);
    (void)napi->dataSrcCb_->GetSize(fileSize);
    (void)CommonNapi::AddNumberPropInt64(env, value, "fileSize", fileSize);
    const std::string callbackName = "readAt";
    int32_t ret = napi->dataSrcCb_->GetCallback(callbackName, &callback);
    CHECK_AND_RETURN_RET_LOG(ret == MSERR_OK, result, "failed to GetCallback");
    (void)HelperDataSourceCallback::AddNapiValueProp(env, value, "callback", callback);

    MEDIA_LOGI("JsGetDataSrc Out");
    return value;
}

AVMetadataExtractorNapi* AVMetadataExtractorNapi::GetJsInstance(napi_env env, napi_callback_info info)
{
    size_t argCount = 0;
    napi_value jsThis = nullptr;
    napi_status status = napi_get_cb_info(env, info, &argCount, nullptr, &jsThis, nullptr);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && jsThis != nullptr, nullptr, "failed to napi_get_cb_info");

    AVMetadataExtractorNapi *napi = nullptr;
    status = napi_unwrap(env, jsThis, reinterpret_cast<void **>(&napi));
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && napi != nullptr, nullptr, "failed to napi_unwrap");

    return napi;
}

AVMetadataExtractorNapi* AVMetadataExtractorNapi::GetJsInstanceWithParameter(napi_env env, napi_callback_info info,
    size_t &argc, napi_value *argv)
{
    napi_value jsThis = nullptr;
    napi_status status = napi_get_cb_info(env, info, &argc, argv, &jsThis, nullptr);
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && jsThis != nullptr, nullptr, "failed to napi_get_cb_info");

    AVMetadataExtractorNapi *napi = nullptr;
    status = napi_unwrap(env, jsThis, reinterpret_cast<void **>(&napi));
    CHECK_AND_RETURN_RET_LOG(status == napi_ok && napi != nullptr, nullptr, "failed to napi_unwrap");

    return napi;
}

napi_value AVMetadataExtractorNapi::JSGetTimeByFrameIndex(napi_env env, napi_callback_info info)
{
    MediaTrace trace("AVMetadataExtractorNapi::JSGetTimeByFrameIndex");
    MEDIA_LOGI("frame to time");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    size_t argCount = 2;
    napi_value args[ARG_TWO] = { nullptr };
    AVMetadataExtractorNapi* napi
        = AVMetadataExtractorNapi::GetJsInstanceWithParameter(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(napi != nullptr, result, "failed to GetJsInstance");

    auto asyncCtx = std::make_unique<AVMetadataExtractorAsyncContext>(env);
    asyncCtx->napi = napi;
    asyncCtx->callbackRef = CommonNapi::CreateReference(env, args[1]);
    asyncCtx->deferred = CommonNapi::CreatePromise(env, asyncCtx->callbackRef, result);

    if (CommonNapi::CheckValueType(env, args[0], napi_number)) {
        auto res = napi_get_value_uint32(env, args[0], &asyncCtx->index_);
        if (res != napi_ok || static_cast<int32_t>(asyncCtx->index_) < 0) {
            asyncCtx->SignError(MSERR_EXT_API9_INVALID_PARAMETER, "frame index is not valid");
        }
    }

    // async work
    napi_value resource = nullptr;
    napi_create_string_utf8(env, "JSGetTimeByFrameIndex", NAPI_AUTO_LENGTH, &resource);
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, [](napi_env env, void *data) {
        auto asyncCtx = reinterpret_cast<AVMetadataExtractorAsyncContext *>(data);
        CHECK_AND_RETURN_LOG(asyncCtx && !asyncCtx->errFlag, "Invalid asyncCtx.");
        CHECK_AND_RETURN_LOG(asyncCtx->napi != nullptr, "Invalid napi object.");
        if (asyncCtx->napi->state_ != HelperState::HELPER_STATE_RUNNABLE) {
            asyncCtx->SignError(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "Has released once, can't release again.");
            return;
        }
        auto helper = asyncCtx->napi->helper_;
        CHECK_AND_RETURN_LOG(helper, "PromiseCtx has invalid data.");
        if (helper->GetTimeByFrameIndex(asyncCtx->index_, asyncCtx->timeStamp_) != MSERR_EXT_API9_OK) {
            MEDIA_LOGE("JSGetTimeByFrameIndex get result SignError");
            asyncCtx->SignError(MSERR_EXT_API9_UNSUPPORT_FORMAT, "Demuxer getTimeByFrameIndex failed.");
        }
    }, GetTimeByFrameIndexComplete, static_cast<void *>(asyncCtx.get()), &asyncCtx->work));
    NAPI_CALL(env, napi_queue_async_work(env, asyncCtx->work));
    asyncCtx.release();
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
    MEDIA_LOGI("time to frame");
    napi_value result = nullptr;
    napi_get_undefined(env, &result);

    size_t argCount = 2;
    napi_value args[ARG_TWO] = { nullptr };
    AVMetadataExtractorNapi* napi
        = AVMetadataExtractorNapi::GetJsInstanceWithParameter(env, info, argCount, args);
    CHECK_AND_RETURN_RET_LOG(napi != nullptr, result, "failed to GetJsInstance");

    auto asyncCtx = std::make_unique<AVMetadataExtractorAsyncContext>(env);
    asyncCtx->napi = napi;
    asyncCtx->callbackRef = CommonNapi::CreateReference(env, args[1]);
    asyncCtx->deferred = CommonNapi::CreatePromise(env, asyncCtx->callbackRef, result);

    if (CommonNapi::CheckValueType(env, args[0], napi_number)) {
        int64_t timeStamp = 0;
        auto res = napi_get_value_int64(env, args[0], &timeStamp);
        if (res != napi_ok) {
            asyncCtx->SignError(MSERR_EXT_API9_INVALID_PARAMETER, "time stamp is not valid");
        }
        asyncCtx->timeStamp_ = static_cast<uint64_t>(timeStamp);
    }

    // async work
    napi_value resource = nullptr;
    napi_create_string_utf8(env, "JSGetFrameIndexByTime", NAPI_AUTO_LENGTH, &resource);
    NAPI_CALL(env, napi_create_async_work(env, nullptr, resource, [](napi_env env, void *data) {
        auto asyncCtx = reinterpret_cast<AVMetadataExtractorAsyncContext *>(data);
        CHECK_AND_RETURN_LOG(asyncCtx && !asyncCtx->errFlag, "Invalid asyncCtx.");
        CHECK_AND_RETURN_LOG(asyncCtx->napi != nullptr, "Invalid napi object.");
        if (asyncCtx->napi->state_ != HelperState::HELPER_STATE_RUNNABLE) {
            asyncCtx->SignError(MSERR_EXT_API9_OPERATE_NOT_PERMIT, "Invalid state, please set source");
            return;
        }
        auto helper = asyncCtx->napi->helper_;
        CHECK_AND_RETURN_LOG(helper, "PromiseCtx has invalid data.");
        if (helper->GetFrameIndexByTime(asyncCtx->timeStamp_, asyncCtx->index_) != MSERR_EXT_API9_OK) {
            MEDIA_LOGE("JSGetFrameIndexByTime get result SignError");
            asyncCtx->SignError(MSERR_EXT_API9_UNSUPPORT_FORMAT, "Demuxer getFrameIndexByTime failed.");
        }
    }, GetFrameIndexByTimeComplete, static_cast<void *>(asyncCtx.get()), &asyncCtx->work));
    NAPI_CALL(env, napi_queue_async_work(env, asyncCtx->work));
    asyncCtx.release();
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
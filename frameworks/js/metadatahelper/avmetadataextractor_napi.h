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

#ifndef AV_META_DATA_EXTRACTOR_NAPI_H
#define AV_META_DATA_EXTRACTOR_NAPI_H

#include "media_errors.h"
#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "helper_data_source_callback.h"
#include "common_napi.h"
#include "audio_info.h"
#include "audio_effect.h"
#include "task_queue.h"
#include "avmetadatahelper.h"

namespace OHOS {
namespace Media {
struct AVMetadataExtractorAsyncContext;
class AVMetadataExtractorNapi {
public:
    __attribute__((visibility("default"))) static napi_value Init(napi_env env, napi_value exports);

private:
    static napi_value Constructor(napi_env env, napi_callback_info info);
    static void Destructor(napi_env env, void *nativeObject, void *finalize);
    static napi_value JsCreateAVMetadataExtractor(napi_env env, napi_callback_info info);
    static napi_value JsSetUrlSource(napi_env env, napi_callback_info info);
    static napi_value JsResolveMetadata(napi_env env, napi_callback_info info);
    static napi_value JsFetchArtPicture(napi_env env, napi_callback_info info);
    static napi_value JsFetchFrameAtTime(napi_env env, napi_callback_info info);
    static napi_value JsRelease(napi_env env, napi_callback_info info);
    /**
     * fdSrc: AVFileDescriptor
     */
    static napi_value JsGetAVFileDescriptor(napi_env env, napi_callback_info info);
    static napi_value JsSetAVFileDescriptor(napi_env env, napi_callback_info info);
    /**
     * dataSrc: DataSrcDescriptor
     */
    static napi_value JsSetDataSrc(napi_env env, napi_callback_info info);
    static napi_value JsGetDataSrc(napi_env env, napi_callback_info info);

    static AVMetadataExtractorNapi *GetJsInstance(napi_env env, napi_callback_info info);
    static AVMetadataExtractorNapi *GetJsInstanceWithParameter(
        napi_env env, napi_callback_info info, size_t &argc, napi_value *argv);
    static void FetchArtPictureComplete(napi_env env, napi_status status, void *data);
    static void CreatePixelMapComplete(napi_env env, napi_status status, void *data);
    static void CommonCallbackRoutine(
        napi_env env, AVMetadataExtractorAsyncContext *&asyncContext, const napi_value &valueParam);
    static void HandleMetaDataResult(napi_env env, AVMetadataExtractorAsyncContext* &promiseCtx, napi_value &result);
    static std::string StringifyMeta(Any value);
    static void ResolveMetadataComplete(napi_env env, napi_status status, void *data);
    static void GetTimeByFrameIndexComplete(napi_env env, napi_status status, void *data);
    static void GetFrameIndexByTimeComplete(napi_env env, napi_status status, void *data);
    static napi_value JSGetTimeByFrameIndex(napi_env env, napi_callback_info info);
    static napi_value JSGetFrameIndexByTime(napi_env env, napi_callback_info info);
    
    AVMetadataExtractorNapi();
    ~AVMetadataExtractorNapi();
    int32_t GetFetchFrameArgs(std::unique_ptr<AVMetadataExtractorAsyncContext> &asyncCtx,
        napi_env env, napi_value timeUs, napi_value option, napi_value params);

private:
    static thread_local napi_ref constructor_;
    napi_env env_ = nullptr;
    std::shared_ptr<AVMetadataHelper> helper_ = nullptr;
    std::shared_ptr<HelperDataSourceCallback> dataSrcCb_ = nullptr;
    struct AVFileDescriptor fileDescriptor_;
    struct AVDataSrcDescriptor dataSrcDescriptor_;
    std::mutex mutex_;
    PixelMapParams param_;
    HelperState state_ { HelperState::HELPER_STATE_IDLE };
    std::string url_ = "";
    std::map<std::string, std::string> header_;
};

struct AVMetadataExtractorAsyncContext : public MediaAsyncContext {
    explicit AVMetadataExtractorAsyncContext(napi_env env) : MediaAsyncContext(env) {}
    ~AVMetadataExtractorAsyncContext() = default;

    AVMetadataExtractorNapi *napi = nullptr;
    std::string opt_ = "";
    std::shared_ptr<Meta> metadata_ = nullptr;
    std::shared_ptr<PixelMap> artPicture_ = nullptr;
    std::shared_ptr<PixelMap> pixel_ = nullptr;
    std::shared_ptr<AVMetadataHelper> innerHelper_ = nullptr;
    int32_t status = 0;
    int32_t option = 0;
    int64_t timeUs = 0;
    uint64_t timeStamp_;
    uint32_t index_;
    PixelMapParams param_;
};
}  // namespace Media
}  // namespace OHOS
#endif  // AV_META_DATA_EXTRACTOR_NAPI_H
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

#include "avmedia_source.h"
#include "media_dfx.h"
#include "media_log.h"
#include "native_media_source_impl.h"
#include "native_media_source_loader_callback_impl.h"
#include "native_media_source_loading_request_impl.h"
#include "native_mfmagic.h"

namespace {
    constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, LOG_DOMAIN_PLAYER, "NativeMediaSource" };
}

using namespace OHOS;
using namespace OHOS::Media;

OH_AVHttpHeader *OH_AVHttpHeader_Create(void)
{
    OH_AVHttpHeader *header = new(std::nothrow) OH_AVHttpHeader();
    CHECK_AND_RETURN_RET_LOG(header != nullptr, nullptr, "create OH_AVHttpHeader failed!");
    return header;
}

OH_AVErrCode OH_AVHttpHeader_Destroy(OH_AVHttpHeader *header)
{
    CHECK_AND_RETURN_RET_LOG(header != nullptr, AV_ERR_INVALID_VAL, "input header is nullptr!");
    delete header;
    return AV_ERR_OK;
}

OH_AVErrCode OH_AVHttpHeader_AddRecord(OH_AVHttpHeader *header, const char *key, const char *value)
{
    CHECK_AND_RETURN_RET_LOG(header != nullptr, AV_ERR_INVALID_VAL, "input header is nullptr!");
    CHECK_AND_RETURN_RET_LOG(key != nullptr, AV_ERR_INVALID_VAL, "input key is nullptr!");
    CHECK_AND_RETURN_RET_LOG(value != nullptr, AV_ERR_INVALID_VAL, "input value is nullptr!");
    CHECK_AND_RETURN_RET_LOG(std::string(key).length() > 0, AV_ERR_INVALID_VAL, "input key is empty!");
    CHECK_AND_RETURN_RET_LOG(std::string(value).length() > 0, AV_ERR_INVALID_VAL, "input value is empty!");
    std::lock_guard<std::mutex> lock(header->recordsMutex);
    auto result = header->records.emplace(key, value);
    if (!result.second) {
        return AV_ERR_INVALID_VAL;
    }
    return AV_ERR_OK;
}

OH_AVErrCode OH_AVHttpHeader_GetCount(OH_AVHttpHeader *header, uint32_t *count)
{
    CHECK_AND_RETURN_RET_LOG(header != nullptr, AV_ERR_INVALID_VAL, "input header is nullptr!");
    CHECK_AND_RETURN_RET_LOG(count != nullptr, AV_ERR_INVALID_VAL, "input count is nullptr!");
    std::lock_guard<std::mutex> lock(header->recordsMutex);
    *count = static_cast<int>(header->records.size());
    return AV_ERR_OK;
}

OH_AVErrCode OH_AVHttpHeader_GetRecord(OH_AVHttpHeader *header, uint32_t index, const char **key, const char **value)
{
    CHECK_AND_RETURN_RET_LOG(header != nullptr, AV_ERR_INVALID_VAL, "input header is nullptr!");
    CHECK_AND_RETURN_RET_LOG(key != nullptr, AV_ERR_INVALID_VAL, "input key is nullptr!");
    CHECK_AND_RETURN_RET_LOG(value != nullptr, AV_ERR_INVALID_VAL, "input value is nullptr!");

    std::lock_guard<std::mutex> lock(header->recordsMutex);
    CHECK_AND_RETURN_RET_LOG(static_cast<size_t>(index) < header->records.size(),
        AV_ERR_INVALID_VAL, "input index is invalid!");
    auto it = header->records.begin();
    std::advance(it, index);
    char* keycopy = strdup(it->first.c_str());
    CHECK_AND_RETURN_RET_LOG(keycopy != nullptr, AV_ERR_INVALID_VAL, "strdup failed for key!");
    *value = strdup(it->second.c_str());
    if (*value == nullptr) {
        MEDIA_LOGI("strdup failed for value!");
        free(keycopy);
        keycopy = nullptr;
        return AV_ERR_INVALID_VAL;
    }
    *key = keycopy;
    return AV_ERR_OK;
}

OH_AVErrCode OH_AVMediaSource_SetMimeType(OH_AVMediaSource *source, const char *mimetype)
{
    CHECK_AND_RETURN_RET_LOG(source != nullptr, AV_ERR_INVALID_VAL, "input source is nullptr!");
    CHECK_AND_RETURN_RET_LOG(mimetype != nullptr, AV_ERR_INVALID_VAL, "input mimetype is nullptr!");
    CHECK_AND_RETURN_RET_LOG(std::string(mimetype).length() > 0, AV_ERR_INVALID_VAL, "mimetype is empty!");
    CHECK_AND_RETURN_RET_LOG(!strcmp(mimetype, "application/m3u8"), AV_ERR_UNSUPPORTED_FORMAT,
        "mimetype is un supported!");
    MediaSourceObject* mediasourceObj = static_cast<MediaSourceObject*>(source);
    CHECK_AND_RETURN_RET_LOG(mediasourceObj->mediasource_ != nullptr, AV_ERR_INVALID_VAL, "source is null");
    mediasourceObj->mediasource_->SetMimeType(std::string(mimetype));
    return AV_ERR_OK;
}

OH_AVErrCode OH_AVMediaSource_EnableOfflineCache(OH_AVMediaSource *source, bool enable)
{
    CHECK_AND_RETURN_RET_LOG(source != nullptr, AV_ERR_INVALID_VAL, "input source is nullptr!");
    MediaSourceObject* mediasourceObj = static_cast<MediaSourceObject*>(source);
    CHECK_AND_RETURN_RET_LOG(mediasourceObj->mediasource_ != nullptr, AV_ERR_INVALID_VAL, "source is null");
    mediasourceObj->mediasource_->enableOfflineCache(std::string(mimetype));
    return AV_ERR_OK;
}

OH_AVMediaSource *OH_AVMediaSource_CreateWithUrl(const char *url, OH_AVHttpHeader *header)
{
    CHECK_AND_RETURN_RET_LOG(url != nullptr, nullptr, "input url is nullptr!");
    CHECK_AND_RETURN_RET_LOG(header != nullptr, nullptr, "input header is nullptr!");

    std::map<std::string, std::string> recordsCopy;
    {
        std::lock_guard<std::mutex> lock(header->recordsMutex);
        recordsCopy = header->records;
    }
    std::shared_ptr<AVMediaSource> avMediaSource = std::make_shared<AVMediaSource>(url, recordsCopy);
    CHECK_AND_RETURN_RET_LOG(avMediaSource != nullptr, nullptr, "create AVMediaSource failed!");

    MediaSourceObject* mediasourceObj = new(std::nothrow) MediaSourceObject(avMediaSource);
    CHECK_AND_RETURN_RET_LOG(mediasourceObj != nullptr, nullptr, "create MediaSourceObject failed!");

    return static_cast<OH_AVMediaSource *>(mediasourceObj);
}

OH_AVErrCode OH_AVMediaSourceLoadingRequest_GetUrl(OH_AVMediaSourceLoadingRequest *request, const char **url)
{
    CHECK_AND_RETURN_RET_LOG(request != nullptr, AV_ERR_INVALID_VAL, "input request is nullptr!");
    CHECK_AND_RETURN_RET_LOG(url != nullptr, AV_ERR_INVALID_VAL, "input url is nullptr!");
    MediaSourceLoadingRequestObject* requestObj = reinterpret_cast<MediaSourceLoadingRequestObject*>(request);
    CHECK_AND_RETURN_RET_LOG(requestObj->request_ != nullptr, AV_ERR_INVALID_VAL, "request is null");
    std::string urlTmp = requestObj->request_->GetUrl();
    char* urlCopy = static_cast<char*>(malloc(urlTmp.size() + 1));
    CHECK_AND_RETURN_RET_LOG(urlCopy != nullptr, AV_ERR_INVALID_VAL, "malloc failed");
    int ret = memcpy_s(urlCopy, urlTmp.size() + 1, urlTmp.c_str(), urlTmp.size() + 1);
    if (ret != 0) {
        free(urlCopy);
        MEDIA_LOGI("memcpy_s failed");
        return AV_ERR_INVALID_VAL;
    }
    *url = urlCopy;
    return AV_ERR_OK;
}

OH_AVErrCode OH_AVMediaSourceLoadingRequest_GetHttpHeader(OH_AVMediaSourceLoadingRequest *request,
    OH_AVHttpHeader **header)
{
    CHECK_AND_RETURN_RET_LOG(request != nullptr, AV_ERR_INVALID_VAL, "input request is nullptr!");
    CHECK_AND_RETURN_RET_LOG(header != nullptr, AV_ERR_INVALID_VAL, "input header is nullptr!");
    MediaSourceLoadingRequestObject* requestObj = reinterpret_cast<MediaSourceLoadingRequestObject*>(request);
    CHECK_AND_RETURN_RET_LOG(requestObj->request_ != nullptr, AV_ERR_INVALID_VAL, "request is null");
    std::map<std::string, std::string> headerMap = requestObj->request_->GetHeader();
    OH_AVHttpHeader* headerTmp = OH_AVHttpHeader_Create();
    CHECK_AND_RETURN_RET_LOG(headerTmp != nullptr, AV_ERR_INVALID_VAL, "create OH_AVHttpHeader failed!");
    for (const auto& pair : headerMap) {
        OH_AVHttpHeader_AddRecord(headerTmp, pair.first.c_str(), pair.second.c_str());
    }
    *header = headerTmp;
    return AV_ERR_OK;
}

int32_t OH_AVMediaSourceLoadingRequest_RespondData(
    OH_AVMediaSourceLoadingRequest *request, int64_t uuid, int64_t offset, const uint8_t *data, uint64_t dataSize)
{
    CHECK_AND_RETURN_RET_LOG(request != nullptr, -1, "input request is nullptr!");
    CHECK_AND_RETURN_RET_LOG(data != nullptr, -1, "input data is nullptr!");
    CHECK_AND_RETURN_RET_LOG(dataSize != 0, -1, "dataSize is zero!");

    if (dataSize > static_cast<uint64_t>(INT32_MAX)) {
        MEDIA_LOGE("dataSize %{public}" PRIu64 " exceeds INT32_MAX!", dataSize);
        return -1;
    }

    MediaSourceLoadingRequestObject* requestObj = reinterpret_cast<MediaSourceLoadingRequestObject*>(request);
    CHECK_AND_RETURN_RET_LOG(requestObj->request_ != nullptr, -1, "request is null");

    auto buffer = std::make_shared<AVSharedMemoryBase>(static_cast<int32_t>(dataSize),
        AVSharedMemory::FLAGS_READ_WRITE, "userBuffer");
    CHECK_AND_RETURN_RET_LOG(buffer != nullptr, -1, "get buffer fail");
    buffer->Init();
    buffer->Write(data, dataSize);
    return requestObj->request_->RespondData(uuid, offset, buffer);
}

void OH_AVMediaSourceLoadingRequest_RespondHeader(
    OH_AVMediaSourceLoadingRequest *request, int64_t uuid, OH_AVHttpHeader *header, const char *redirectUrl)
{
    CHECK_AND_RETURN_LOG(request != nullptr, "input request is nullptr!");
    MediaSourceLoadingRequestObject* requestObj = reinterpret_cast<MediaSourceLoadingRequestObject*>(request);
    CHECK_AND_RETURN_LOG(requestObj->request_ != nullptr, "request is null");
    std::map<std::string, std::string> headerMap;
    if (header != nullptr) {
        headerMap = header->records;
    }
    std::string redirectUrlStr = (redirectUrl != nullptr) ? std::string(redirectUrl) : "";
    requestObj->request_->RespondHeader(uuid, headerMap, redirectUrlStr);
}

void OH_AVMediaSourceLoadingRequest_FinishLoading(
    OH_AVMediaSourceLoadingRequest *request, int64_t uuid, AVLoadingRequestError error)
{
    CHECK_AND_RETURN_LOG(request != nullptr, "input request is nullptr!");
    MediaSourceLoadingRequestObject* requestObj = reinterpret_cast<MediaSourceLoadingRequestObject*>(request);
    CHECK_AND_RETURN_LOG(requestObj->request_ != nullptr, "request is null");
    requestObj->request_->FinishLoading(uuid, static_cast<int32_t>(error));
}

OH_AVMediaSourceLoader *OH_AVMediaSourceLoader_Create(void)
{
    std::shared_ptr<MediaSourceLoaderCallback> callback =
        std::make_shared<MediaSourceLoaderCallback>();
    CHECK_AND_RETURN_RET_LOG(callback != nullptr, nullptr, "failed to create MediaSourceLoaderCallback");

    AVMediaSourceLoader *loader = new (std::nothrow) AVMediaSourceLoader(callback);
    CHECK_AND_RETURN_RET_LOG(loader != nullptr, nullptr, "failed to create AVMediaSourceLoader");

    return loader;
}

OH_AVErrCode OH_AVMediaSourceLoader_SetSourceOpenCallback(OH_AVMediaSourceLoader *loader,
    OH_AVMediaSourceLoaderOnSourceOpenedCallback callback, void *userData)
{
    CHECK_AND_RETURN_RET_LOG(loader != nullptr, AV_ERR_INVALID_VAL, "media source loader is nullptr");

    AVMediaSourceLoader *loaderObj = reinterpret_cast<AVMediaSourceLoader *>(loader);
    CHECK_AND_RETURN_RET_LOG(loaderObj->callback_ != nullptr, AV_ERR_INVALID_VAL, "media source loader is nullptr");

    NativeOnSourceOpenedCallback *openCallback = new (std::nothrow) NativeOnSourceOpenedCallback(callback, userData);
    CHECK_AND_RETURN_RET_LOG(openCallback != nullptr, AV_ERR_INVALID_VAL, "openCallback is nullptr");

    loaderObj->callback_->SetSourceOpenCallback(openCallback);
    return AV_ERR_OK;
}

OH_AVErrCode OH_AVMediaSourceLoader_SetSourceReadCallback(OH_AVMediaSourceLoader *loader,
    OH_AVMediaSourceLoaderOnSourceReadCallback callback, void *userData)
{
    CHECK_AND_RETURN_RET_LOG(loader != nullptr, AV_ERR_INVALID_VAL, "media source loader is nullptr");

    AVMediaSourceLoader *loaderObj = reinterpret_cast<AVMediaSourceLoader *>(loader);
    CHECK_AND_RETURN_RET_LOG(loaderObj->callback_ != nullptr, AV_ERR_INVALID_VAL, "media source loader is nullptr");

    NativeOnSourceReadCallback *readCallback = new (std::nothrow) NativeOnSourceReadCallback(callback, userData);
    CHECK_AND_RETURN_RET_LOG(readCallback != nullptr, AV_ERR_INVALID_VAL, "readCallback is nullptr");

    loaderObj->callback_->SetSourceReadCallback(readCallback);
    return AV_ERR_OK;
}

OH_AVErrCode OH_AVMediaSourceLoader_SetSourceCloseCallback(OH_AVMediaSourceLoader *loader,
    OH_AVMediaSourceLoaderOnSourceClosedCallback callback, void *userData)
{
    CHECK_AND_RETURN_RET_LOG(loader != nullptr, AV_ERR_INVALID_VAL, "media source loader is nullptr");

    AVMediaSourceLoader *loaderObj = reinterpret_cast<AVMediaSourceLoader *>(loader);
    CHECK_AND_RETURN_RET_LOG(loaderObj->callback_ != nullptr, AV_ERR_INVALID_VAL, "media source loader is nullptr");

    NativeOnSourceClosedCallback *closeCallback = new (std::nothrow) NativeOnSourceClosedCallback(callback, userData);
    CHECK_AND_RETURN_RET_LOG(closeCallback != nullptr, AV_ERR_INVALID_VAL, "closeCallback is nullptr");

    loaderObj->callback_->SetSourceCloseCallback(closeCallback);
    return AV_ERR_OK;
}

OH_AVErrCode OH_AVMediaSourceLoader_Destroy(OH_AVMediaSourceLoader *loader)
{
    CHECK_AND_RETURN_RET_LOG(loader != nullptr, AV_ERR_INVALID_VAL, "media source loader is nullptr");
    AVMediaSourceLoader *loaderObj = reinterpret_cast<AVMediaSourceLoader *>(loader);
    if (loaderObj->callback_ != nullptr) {
        loaderObj->callback_->Release();
    }
    delete loaderObj;
    loaderObj = nullptr;
    return AV_ERR_OK;
}

OH_AVErrCode OH_AVMediaSource_SetMediaSourceLoader(OH_AVMediaSource *source, OH_AVMediaSourceLoader *loader)
{
    CHECK_AND_RETURN_RET_LOG(source != nullptr, AV_ERR_INVALID_VAL, "media source is nullptr");
    CHECK_AND_RETURN_RET_LOG(loader != nullptr, AV_ERR_INVALID_VAL, "media source loader is nullptr");

    MediaSourceObject *mediaSourceObj = reinterpret_cast<MediaSourceObject *>(source);
    CHECK_AND_RETURN_RET_LOG(mediaSourceObj->mediasource_ != nullptr, AV_ERR_INVALID_VAL, "media source is nullptr");

    AVMediaSourceLoader *loaderObj = reinterpret_cast<AVMediaSourceLoader *>(loader);
    mediaSourceObj->mediasource_->mediaSourceLoaderCb_ = loaderObj->callback_;
    return AV_ERR_OK;
}

class NativeAVDataSource : public OHOS::Media::IMediaDataSource {
public:
    explicit NativeAVDataSource(OH_AVDataSource* dataSource)
        : dataSource_(dataSource) {}

    virtual ~NativeAVDataSource() = default;

    int32_t ReadAt(const std::shared_ptr<AVSharedMemory> &mem, uint32_t length, int64_t pos = -1)
    {
        if (mem == nullptr || dataSource_ == nullptr) {
            MEDIA_LOGE("NativeAVDataSource ReadAt mem or dataSource_ is nullptr");
            return 0;
        }
        std::shared_ptr<AVBuffer> buffer = AVBuffer::CreateAVBuffer(
            mem->GetBase(), mem->GetSize(), mem->GetSize()
        );
        OH_AVBuffer avBuffer(buffer);
        return dataSource_->readAt(&avBuffer, length, pos);
    }

    int32_t GetSize(int64_t &size)
    {
        if (dataSource_ == nullptr) {
            MEDIA_LOGE("NativeAVDataSource GetSize dataSource_ is nullptr");
            return 0;
        }
        size = dataSource_->size;
        return 0;
    }

    int32_t ReadAt(int64_t pos, uint32_t length, const std::shared_ptr<AVSharedMemory> &mem)
    {
        return ReadAt(mem, length, pos);
    }

    int32_t ReadAt(uint32_t length, const std::shared_ptr<AVSharedMemory> &mem)
    {
        return ReadAt(mem, length);
    }

private:
    OH_AVDataSource* dataSource_ = nullptr;
};

OH_AVMediaSource *OH_AVMediaSource_CreateWithDataSource(OH_AVDataSource *dataSource)
{
    CHECK_AND_RETURN_RET_LOG(dataSource != nullptr, nullptr, "input dataSource is nullptr!");
    CHECK_AND_RETURN_RET_LOG(dataSource->readAt != nullptr, nullptr, "datasrc readAt is null");
    std::shared_ptr<IMediaDataSource> avDataSource = std::make_shared<NativeAVDataSource>(dataSource);
    CHECK_AND_RETURN_RET_LOG(avDataSource != nullptr, nullptr, "create avDataSource failed!");

    std::shared_ptr<AVMediaSource> avMediaSource = std::make_shared<AVMediaSource>(avDataSource);
    CHECK_AND_RETURN_RET_LOG(avMediaSource != nullptr, nullptr, "create AVMediaSource failed!");

    MediaSourceObject* mediasourceObj = new(std::nothrow) MediaSourceObject(avMediaSource);
    CHECK_AND_RETURN_RET_LOG(mediasourceObj != nullptr, nullptr, "create MediaSourceObject failed!");

    return static_cast<OH_AVMediaSource *>(mediasourceObj);
}

OH_AVMediaSource *OH_AVMediaSource_CreateWithFd(int32_t fd, int64_t offset, int64_t size)
{
    FileDescriptor fileDescriptor;
    fileDescriptor.fd = fd;
    fileDescriptor.offset = offset;
    fileDescriptor.size = size;

    std::shared_ptr<AVMediaSource> avMediaSource = std::make_shared<AVMediaSource>(fileDescriptor);
    CHECK_AND_RETURN_RET_LOG(avMediaSource != nullptr, nullptr, "create AVMediaSource failed!");

    MediaSourceObject* mediasourceObj = new(std::nothrow) MediaSourceObject(avMediaSource);
    CHECK_AND_RETURN_RET_LOG(mediasourceObj != nullptr, nullptr, "create MediaSourceObject failed!");

    return static_cast<OH_AVMediaSource *>(mediasourceObj);
}

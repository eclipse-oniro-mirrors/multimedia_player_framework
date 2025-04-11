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
#include <array>
#include <iostream>
#include <memory>
#include "AVImageGenerator_ani.h"
#include "AVImageGenerator_enum.h"
#include "image_type.h"
#include "media_ani_log.h"
#include "media_ani_utils.h"

namespace OHOS {
namespace Media {

AVImageGeneratorAni::AVImageGeneratorAni() {};

AVImageGeneratorAni::~AVImageGeneratorAni() {};

ani_status AVImageGeneratorAni::AVImageGeneratorInit(ani_env *env)
{
    static const char *className = "L@ohos/multimedia/media/media/AVImageGeneratorHandle;";
    ani_class cls;
    if (ANI_OK != env->FindClass(className, &cls)) {
        ANI_ERR_LOG("Failed to find class: %{public}s", className);
        return (ani_status)ANI_ERROR;
    }

    std::array methods = {
        ani_native_function {"fetchFrameByTimeAsync", nullptr,
            reinterpret_cast<void *>(AVImageGeneratorAni::FetchFrameByTime)},
        ani_native_function {"releaseAsync", ":V", reinterpret_cast<void *>(AVImageGeneratorAni::Release)},
        ani_native_function {"setFdSrc", nullptr, reinterpret_cast<void *>(AVImageGeneratorAni::SetFdSrc)},
        ani_native_function {"getFdSrc", nullptr, reinterpret_cast<void *>(AVImageGeneratorAni::GetFdSrc)},
    };

    if (ANI_OK != env->Class_BindNativeMethods(cls, methods.data(), methods.size())) {
        ANI_ERR_LOG("Failed to bind native methods to: %{public}s", className);
        return (ani_status)ANI_ERROR;
    };
    return ANI_OK;
}

ani_object AVImageGeneratorAni::Constructor([[maybe_unused]] ani_env *env)
{
    auto nativeAVImageGenerator = std::make_unique<AVImageGeneratorAni>();
    nativeAVImageGenerator->helperPtr = AVMetadataHelperFactory::CreateAVMetadataHelper();
    static const char *className = "L@ohos/multimedia/media/media/AVImageGeneratorHandle;";
    ani_class cls;
    if (ANI_OK != env->FindClass(className, &cls)) {
        ANI_ERR_LOG("Failed to find class: %{public}s", className);
        ani_object nullobj = nullptr;
        return nullobj;
    }

    ani_method ctor;
    if (ANI_OK != env->Class_FindMethod(cls, "<ctor>", "J:V", &ctor)) {
        ANI_ERR_LOG("Failed to find method: %{public}s", "ctor");
        ani_object nullobj = nullptr;
        return nullobj;
    }

    ani_object AVImageGenerator_object;
    if (ANI_OK != env->Object_New(cls, ctor, &AVImageGenerator_object,
        reinterpret_cast<ani_long>(nativeAVImageGenerator.release()))) {
        ANI_ERR_LOG("New Media Fail");
    }
    return AVImageGenerator_object;
}

AVImageGeneratorAni* AVImageGeneratorAni::Unwrapp(ani_env *env, ani_object object)
{
    ani_long helper;
    if (ANI_OK != env->Object_GetFieldByName_Long(object, "nativeAVImageGenerator", &helper)) {
        return nullptr;
    }
    return reinterpret_cast<AVImageGeneratorAni*>(helper);
}

ani_object AVImageGeneratorAni::FetchFrameByTime(ani_env *env, ani_object object, ani_double timeUs,
    ani_enum_item avImageQueryOptions, ani_object param)
{
    auto AVImageGeneratorAni = Unwrapp(env, object);
    if (AVImageGeneratorAni == nullptr || AVImageGeneratorAni->helperPtr == nullptr) {
        ANI_ERR_LOG("AVImageGeneratorAni is nullptr");
        return {};
    }
    auto asyncCtx = std::make_unique<AVImageGeneratorAsyncContext>();
    asyncCtx->ani = AVImageGeneratorAni;
    if (asyncCtx->ani->helperPtr == nullptr) {
        ANI_ERR_LOG("Invalid AVImageGenerator.");
    };
    int32_t value = static_cast<int32_t>(timeUs);

    int32_t enumValue;
    AVImageGeneratorEnumAni::EnumGetValueInt32(env, avImageQueryOptions, enumValue);
    int32_t width;
    int32_t height;
    int32_t colorFormat;
    AVImageGeneratorAni::ParseParamsInner(env, param, width, height, colorFormat);

    OHOS::Media::PixelMapParams Map;
    Map.dstWidth = width;
    Map.dstHeight = height;
    if (colorFormat == 0) {
        Map.colorFormat = PixelFormat::RGB_565;
    } else if (colorFormat == 1) {
        Map.colorFormat = PixelFormat::RGBA_8888;
    } else {
        Map.colorFormat = PixelFormat::RGB_888;
    }

    auto pixelMap = asyncCtx->ani->helperPtr->FetchFrameYuv(value, enumValue, Map);
    asyncCtx->ani->pixel_ = pixelMap;
    ani_object pixel_map = PixelMapAni::CreatePixelMap(env, asyncCtx->ani->pixel_);
    return pixel_map;
}

void AVImageGeneratorAni::ParseParamsInner(ani_env *env, ani_object param, int32_t &width, int32_t &height,
    int32_t &colorFormat)
{
    static const char *className = "L@ohos/multimedia/media/media/ParamsInner;";
    ani_class cls;
    if (ANI_OK != env->FindClass(className, &cls)) {
        ANI_ERR_LOG("Failed to find class: %{public}s", className);
    }
    ani_method widthGetter;
    if (ANI_OK != env->Class_FindMethod(cls, "<get>width", nullptr, &widthGetter)) {
        ANI_ERR_LOG("Class_FindMethod Fail");
    }
    ani_double Paramswidth;
    if (ANI_OK != env->Object_CallMethod_Double(param, widthGetter, &Paramswidth)) {
        ANI_ERR_LOG("Object_CallMethod_double Fail");
    }
    width = static_cast<int32_t>(Paramswidth);

    ani_method heightGetter;
    if (ANI_OK != env->Class_FindMethod(cls, "<get>height", nullptr, &heightGetter)) {
        ANI_ERR_LOG("Class_FindMethod Fail");
    }

    ani_double Paramsheight;
    if (ANI_OK != env->Object_CallMethod_Double(param, heightGetter, &Paramsheight)) {
        ANI_ERR_LOG("Object_CallMethod_double Fail");
    }
    height = static_cast<int32_t>(Paramsheight);

    ani_ref ParamscolorFormat;
    ani_status statusParamscolorFormat = env->Object_GetPropertyByName_Ref(param, "colorFormat", &ParamscolorFormat);
    if (statusParamscolorFormat != ANI_OK) {
        ANI_ERR_LOG("Failed to get 'ParamscolorFormat'");
    }

    ani_status statuscolorFormat = AVImageGeneratorEnumAni::EnumGetValueInt32(env,
        static_cast<ani_enum_item>(ParamscolorFormat), colorFormat);
    if (statuscolorFormat != ANI_OK) {
        ANI_ERR_LOG("Failed to get 'colorFormat'");
    }
}

void AVImageGeneratorAni::Release(ani_env *env, ani_object object)
{
    auto AVImageGeneratorAni = Unwrapp(env, object);
    if (AVImageGeneratorAni == nullptr || AVImageGeneratorAni->helperPtr == nullptr) {
        ANI_ERR_LOG("AVImageGeneratorAni is nullptr");
        return;
    }
    auto promiseCtx = std::make_unique<AVImageGeneratorAsyncContext>();
    promiseCtx->ani = AVImageGeneratorAni;
    if (promiseCtx->ani->state_ != HelperState::HELPER_STATE_RUNNABLE) {
        ANI_ERR_LOG("Current state is not runnable, can't fetchFrame.");
        return;
    }
    if (promiseCtx->ani->helperPtr == nullptr) {
        ANI_ERR_LOG("Invalid AVImageGenerator.");
        return;
    };
    promiseCtx->ani->helperPtr->Release();
}

void AVImageGeneratorAni::SetFdSrc(ani_env *env, ani_object object, ani_int fd, ani_int offset, ani_int size)
{
    auto AVImageGeneratorAni = Unwrapp(env, object);
    if (AVImageGeneratorAni == nullptr || AVImageGeneratorAni->helperPtr == nullptr) {
        ANI_ERR_LOG("AVImageGeneratorAni is nullptr");
        return;
    }
    auto aVImageGeneratorAni = std::make_unique<AVImageGeneratorAsyncContext>();
    ANI_CHECK_RETURN_LOG(aVImageGeneratorAni->ani->helperPtr != nullptr, "failed to GetJsInstanceWithParameter");

    ANI_CHECK_RETURN_LOG(aVImageGeneratorAni->ani->state_ == HelperState::HELPER_STATE_IDLE,
        "Has set source once, unsupport set again");
    int32_t curFd;
    ani_status statusCurFd = env->Object_GetPropertyByName_Int(object, "fd", &curFd);
    if (statusCurFd != ANI_OK) {
        ANI_ERR_LOG("Failed to get 'curFd'");
    }
    int32_t curOffset;
    ani_status statuscurOffset = env->Object_GetPropertyByName_Int(object, "offset", &curOffset);
    if (statuscurOffset != ANI_OK) {
        ANI_ERR_LOG("Failed to get 'curFd'");
    }
    int32_t curSize;
    ani_status statusCurSize = env->Object_GetPropertyByName_Int(object, "length", &curSize);
    if (statusCurSize != ANI_OK) {
        ANI_ERR_LOG("Failed to get 'curFd'");
    }
    AVImageGeneratorAni->fileDescriptor_.fd = curFd;
    AVImageGeneratorAni->fileDescriptor_.offset = curOffset;
    AVImageGeneratorAni->fileDescriptor_.length = curSize;
    auto fileDescriptor = aVImageGeneratorAni->ani->fileDescriptor_;
    auto res = AVImageGeneratorAni->helperPtr->SetSource(fileDescriptor.fd, fileDescriptor.offset,
        fileDescriptor.length);
    aVImageGeneratorAni->ani->state_ = res == MSERR_OK ?
        HelperState::HELPER_STATE_RUNNABLE : HelperState::HELPER_ERROR;
    return;
}

ani_object AVImageGeneratorAni::GetFdSrc(ani_env *env, ani_object object)
{
    ani_object result = {};
    auto AVImageGeneratorAni = Unwrapp(env, object);
    if (AVImageGeneratorAni == nullptr || AVImageGeneratorAni->helperPtr == nullptr) {
        ANI_ERR_LOG("AVImageGeneratorAni is nullptr");
        return result;
    }

    auto aVImageGeneratorAni = std::make_unique<AVImageGeneratorAsyncContext>();
    result = MediaAniUtils::CreateAVFdSrcDescriptor(env, AVImageGeneratorAni->fileDescriptor_);
    return result;
}

}
}

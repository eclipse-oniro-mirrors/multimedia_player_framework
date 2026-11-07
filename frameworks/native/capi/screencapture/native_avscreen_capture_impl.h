/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef NATIVE_AVSCREEN_CAPTURE_IMPL_H
#define NATIVE_AVSCREEN_CAPTURE_IMPL_H

#include <surface/window.h>
#include "native_window.h"

struct NativeBufferRef {
    NativeBufferRef() noexcept = default;
    ~NativeBufferRef() noexcept
    {
        if (buf_ != nullptr) {
            OH_NativeBuffer_Unreference(buf_);
        }
    }
    NativeBufferRef(const NativeBufferRef &) = delete;
    NativeBufferRef &operator=(const NativeBufferRef &) = delete;
    NativeBufferRef(NativeBufferRef &&o) noexcept : buf_(o.buf_)
    {
        o.buf_ = nullptr;
    }
    NativeBufferRef &operator=(NativeBufferRef &&o) noexcept
    {
        if (this != &o) {
            if (buf_ != nullptr) {
                OH_NativeBuffer_Unreference(buf_);
            }
            buf_ = o.buf_;
            o.buf_ = nullptr;
        }
        return *this;
    }
    static NativeBufferRef Acquire(OH_NativeBuffer *buf) noexcept
    {
        NativeBufferRef r;
        if (OH_NativeBuffer_Reference(buf) == 0) {
            r.buf_ = buf;
        }
        return r;
    }
    OH_NativeBuffer *get() const noexcept
    {
        return buf_;
    }
    OH_NativeBuffer *release() noexcept
    {
        auto b = buf_;
        buf_ = nullptr;
        return b;
    }
    explicit operator bool() const noexcept
    {
        return buf_ != nullptr;
    }

private:
    OH_NativeBuffer *buf_ = nullptr;
};

#endif // NATIVE_AVSCREEN_CAPTURE_IMPL_H

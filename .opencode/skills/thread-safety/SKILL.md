---
name: thread-safety
description: Enforce thread-safe coding practices - prevent data races, deadlocks, and ensure proper synchronization in multithreaded code
---

# Thread Safety Skill

This skill enforces thread-safe coding practices for all multithreaded code.

## Core Rules

### 1. Shared Data Protection

**ALL shared mutable data MUST be protected.**

```cpp
// BAD - unprotected shared data
int counter = 0;
void increment() { counter++; }  // Data race!

// GOOD - protected with mutex
std::mutex mutex_;
int counter = 0;
void increment() {
    std::lock_guard<std::mutex> lock(mutex_);
    counter++;
}
```

### 2. Mutex Rules

| Rule | Description |
|------|-------------|
| Always lock | Never access shared data without lock |
| Lock order | Always acquire locks in fixed global order |
| Lock scope | Minimize lock scope, release ASAP |
| Never recurse manually | Use std::recursive_mutex if re-entry needed, or refactor to avoid |

### 3. Deadlock Prevention

**Pattern to avoid:**
```cpp
// BAD - potential deadlock (lock order conflict)
void transfer(Account& a, Account& b, int amount) {
    std::lock_guard<std::mutex> lockA(a.mutex);
    std::lock_guard<std::mutex> lockB(b.mutex);  // Deadlock if another thread does b→a
    a.balance -= amount;
    b.balance += amount;
}

// GOOD - use std::lock for simultaneous acquisition
void transfer(Account& a, Account& b, int amount) {
    std::unique_lock<std::mutex> lockA(a.mutex, std::defer_lock);
    std::unique_lock<std::mutex> lockB(b.mutex, std::defer_lock);
    std::lock(lockA, lockB);  // Acquires both atomically
    a.balance -= amount;
    b.balance += amount;
}
```

### 4. Lock Order Convention

When multiple locks needed, always acquire in this order:
1. Higher-level locks before lower-level
2. Data structure locks before element locks
3. Alphabetical order by variable name (last resort only)

### 5. Atomic Operations

Use `std::atomic` for simple shared counters/flags:

```cpp
// GOOD for simple counters
std::atomic<int> counter{0};
counter.fetch_add(1);  // Atomic operation

// BAD for complex operations
std::atomic<std::map<int, int>> data;  // Wrong! atomic doesn't protect map operations
```

### 6. Thread-Safe Data Structures

| Use | Avoid |
|-----|-------|
| Thread-safe queues | Raw containers with external lock |
| lock-free structures | Multiple locks for single operation |
| Concurrent hash maps | Global lock for fine-grained data |

### 7. Callback Safety

```cpp
// BAD - callback may access destroyed object
class Handler {
    void start() {
        thread_ = std::thread([this]() {
            process();  // 'this' may be destroyed!
        });
    }
};

// GOOD - use shared_ptr for lifetime
// NOTE: Object MUST already be managed by shared_ptr before calling shared_from_this()
// Otherwise std::bad_weak_ptr is thrown. Ensure at least one shared_ptr exists.
class Handler : public std::enable_shared_from_this<Handler> {
    void start() {
        auto self = shared_from_this();
        thread_ = std::thread([self]() {
            self->process();
        });
    }
};
```

### 8. Thread Join vs Detach

| Scenario | Use |
|----------|-----|
| Need result/cleanup | `join()` |
| Fire-and-forget | `detach()` (rarely, usually bad) |
| Background service | Thread pool or worker class |

**Always join before destruction:**
```cpp
class Worker {
    std::thread thread_;
    std::atomic<bool> running_{true};
    std::mutex mutex_;
    std::condition_variable cv_;
    
    ~Worker() {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            running_ = false;
        }
        cv_.notify_one();  // Wake thread so it can exit
        if (thread_.joinable()) {
            thread_.join();  // MUST join before destruction
        }
    }
};
```

### 9. Condition Variable Usage

```cpp
// BAD - missed wakeup
std::mutex mutex;
std::condition_variable cv;
bool ready = false;

void wait() {
    std::unique_lock<std::mutex> lock(mutex);
    if (!ready) {  // BAD - condition not in loop
        cv.wait(lock);
    }
}

// GOOD - wait in loop
void wait() {
    std::unique_lock<std::mutex> lock(mutex);
    while (!ready) {  // GOOD - loop handles spurious wakeup
        cv.wait(lock);
    }
}
```

### 10. RAII Lock Guards

Always use RAII-style locks:

```cpp
// GOOD
std::lock_guard<std::mutex> lock(mutex_);
std::unique_lock<std::mutex> lock(mutex_);

// BAD - manual lock/unlock
mutex_.lock();
doSomething();
mutex_.unlock();  // Exception skips unlock!
```

## Common Pitfalls Checklist

Before submitting multithreaded code, verify:

| Check | Question |
|-------|----------|
| Data race | Is all shared mutable data protected? |
| Deadlock | Is lock acquisition order consistent? |
| Lifetime | Are callbacks capturing safe references? |
| Join | Are all threads joined before destruction? |
| Spurious wakeup | Are condition waits in loops? |
| Lock scope | Is lock held minimal time? |
| Atomic misuse | Are atomics used only for simple ops? |

## Project-Specific Patterns

For this OpenHarmony media framework:

### MessageQueue Pattern
```cpp
void PostMessage(const Message& msg) {
    std::lock_guard<std::mutex> lock(mutex_);
    queue_.push(msg);
    cv_.notify_one();
}

void ProcessMessages() {
    while (running_) {
        std::unique_lock<std::mutex> lock(mutex_);
        while (queue_.empty() && running_) {
            cv_.wait(lock);
        }
        if (!running_) break;
        auto msg = queue_.front();
        queue_.pop();
        lock.unlock();  // Release before handling
        handleMessage(msg);
    }
}
```

### State Machine Thread Safety
```cpp
// Use atomic for state
std::atomic<DownloadState> state_;

// Use mutex for complex operations
int32_t Start() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (state_.load() != DOWNLOAD_IDLE) {
        return DOWNLOAD_ERROR_INVALID_OPERATION;
    }
    state_.store(DOWNLOAD_PREPARING);
    // ... start task
}
```

## Summary

1. Protect all shared data
2. Use consistent lock order
3. Prefer RAII locks
4. Join threads before destruction
5. Wait on condition in loop
6. Use atomic for simple counters
7. Capture shared_ptr in callbacks
8. Minimize lock scope
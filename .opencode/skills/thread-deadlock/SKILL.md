---
name: thread-deadlock
description: Prevent deadlock in multithreaded code - enforce lock ordering, timeout strategies, and deadlock detection patterns
---

# Thread Deadlock Prevention Skill

This skill enforces deadlock prevention strategies in all multithreaded code.

## Deadlock Causes

Four necessary conditions ( Coffman conditions):
1. Mutual exclusion - resources not shareable
2. Hold and wait - holding while requesting
3. No preemption - cannot force release
4. Circular wait - circular resource dependency

**Prevent any ONE condition to avoid deadlock.**

## Prevention Strategies

### Strategy 1: Lock Ordering (Most Recommended)

Establish global lock order, always acquire in that order.

```cpp
// Define hierarchy levels
enum LockLevel {
    LEVEL_NETWORK = 1,
    LEVEL_FILE    = 2,
    LEVEL_MEMORY  = 3,
    LEVEL_LOG     = 4
};

// Always acquire from low to high level
class ResourceManager {
    std::mutex networkMutex_;
    std::mutex fileMutex_;
    
    void transferData() {
        // GOOD - LEVEL_NETWORK (1) before LEVEL_FILE (2)
        std::lock_guard<std::mutex> netLock(networkMutex_);
        std::lock_guard<std::mutex> fileLock(fileMutex_);
        // ... safe operation
    }
    
    void reverseOperation() {
        // BAD - would deadlock if called simultaneously with transferData
        std::lock_guard<std::mutex> fileLock(fileMutex_);
        std::lock_guard<std::mutex> netLock(networkMutex_);
    }
};
```

### Strategy 2: Simultaneous Acquisition

Use `std::lock()` for multiple locks atomically:

```cpp
void transfer(Account& a, Account& b, int amount) {
    std::unique_lock<std::mutex> lockA(a.mutex, std::defer_lock);
    std::unique_lock<std::mutex> lockB(b.mutex, std::defer_lock);
    std::lock(lockA, lockB);  // Atomically acquires both
    // No deadlock possible
}
```

### Strategy 3: Lock Timeout

Use timed lock attempts, fallback on failure:

```cpp
bool tryTransfer(Account& a, Account& b, int amount) {
    std::unique_lock<std::mutex> lockA(a.mutex, std::defer_lock);
    std::unique_lock<std::mutex> lockB(b.mutex, std::defer_lock);
    
    if (!lockA.try_lock_for(std::chrono::milliseconds(100))) {
        return false;  // Failed to get first lock
    }
    if (!lockB.try_lock_for(std::chrono::milliseconds(100))) {
        lockA.unlock();  // Release and retry later
        return false;
    }
    // Both acquired safely
    return true;
}
```

### Strategy 4: Lock hierarchy wrapper

```cpp
class HierarchicalMutex {
    int level_;
    std::mutex mutex_;
    static thread_local int currentLevel_;  // thread_local: each thread tracks its own level
    
public:
    explicit HierarchicalMutex(int level) : level_(level) {}
    
    void lock() {
        if (currentLevel_ >= level_) {
            throw std::logic_error("Lock order violation");
        }
        int previousLevel = currentLevel_;
        mutex_.lock();
        currentLevel_ = level_;
    }
    
    void unlock() {
        currentLevel_ = 0;  // Or restore previous level if tracking stack
        mutex_.unlock();
    }
};
thread_local int HierarchicalMutex::currentLevel_{0};
```

## Code Review Checklist

| Pattern | Check |
|---------|-------|
| Single lock | Safe (no deadlock alone) |
| Two locks | Must use std::lock or order |
| Lock callback | Is callback acquiring other locks? |
| Lock in loop | Can loop create circular wait? |
| External call | Does external function lock? |

## Dangerous Patterns

### Pattern 1: Lock then call unknown function
```cpp
// BAD - unknown function may lock other mutex
std::lock_guard<std::mutex> lock(mutex_);
processData();  // What locks does processData acquire?

// GOOD - release lock before calling unknown
std::unique_lock<std::mutex> lock(mutex_);
auto data = extractData();
lock.unlock();  // Explicitly release before calling unknown function
processData(data);
```

### Pattern 2: Locking in callbacks
```cpp
// BAD - callback may acquire locks
void notifyListeners() {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto& listener : listeners_) {
        listener->onEvent();  // Listener may lock its own mutex
    }
}

// GOOD - copy data, release lock, then notify
void notifyListeners() {
    std::vector<std::shared_ptr<Listener>> copy;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        copy = listeners_;
    }
    for (auto& listener : copy) {
        listener->onEvent();  // Safe, no lock held
    }
}
```

### Pattern 3: Recursive locking attempt
```cpp
// BAD - std::mutex does NOT support recursive lock
void outer() {
    std::lock_guard<std::mutex> lock(mutex_);
    inner();  // inner tries to lock same mutex → deadlock
}
void inner() {
    std::lock_guard<std::mutex> lock(mutex_);
}

// Option 1: Use std::recursive_mutex
std::recursive_mutex mutex_;

// Option 2: Refactor to avoid recursion
```

## Testing Deadlock

### Unit test approach
```cpp
TEST(DeadlockTest, ConcurrentTransfer) {
    Account a, b;
    auto task = [&](Account& from, Account& to) {
        for (int i = 0; i < 1000; i++) transfer(from, to, 1);
    };
    std::thread t1([&]() { task(a, b); });
    std::thread t2([&]() { task(b, a); });
    
    // Use timeout to distinguish deadlock from slow execution
    auto future1 = std::async(std::launch::async, [&]() { t1.join(); });
    auto future2 = std::async(std::launch::async, [&]() { t2.join(); });
    EXPECT_EQ(future1.wait_for(std::chrono::seconds(5)), std::future_status::ready);
    EXPECT_EQ(future2.wait_for(std::chrono::seconds(5)), std::future_status::ready);
}
```

### Detection tools
- Thread sanitizer: `-fsanitize=thread`
- Helgrind (Valgrind): `valgrind --tool=helgrind`
- Static analysis: clang thread safety analysis

## Project Examples

### HiPlayerImpl lock order
```cpp
// Recommended hierarchy for this project:
// 1. PlayerServer::mutex_ (service-level, singleton-like)
// 2. HiPlayerImpl::mutex_ (player instance level)
// 3. Engine::mutex_ (engine internal level)
// 4. MessageQueue::mutex_ (per-queue)

// Example: SetSource() should lock in order 2→3
int32_t HiPlayerImpl::SetSource(const std::string& source) {
    std::lock_guard<std::mutex> lock(mutex_);  // Level 2
    if (engine_ != nullptr) {
        // Don't hold both locks simultaneously - let engine manage itself
        return engine_->SetSource(source);
    }
    return MSERR_INVALID_OPERATION;
}
```

## Quick Reference

| Situation | Solution |
|-----------|----------|
| Two mutexes | `std::lock(a, b)` |
| Multiple mutexes | Define hierarchy order |
| Unknown function call | Release lock first |
| Callback notification | Copy + release + notify |
| Need timeout | `try_lock_for()` |
| Recursive need | `std::recursive_mutex` |

## Summary

1. Establish lock hierarchy
2. Use `std::lock` for multiple locks
3. Release before unknown calls
4. Never hold lock during callback
5. Consider timeout strategy
6. Test concurrent scenarios
//
// Created by Szymon on 23/02/2022.
//

#ifndef JSICRYPTOEXAMPLE_DISPATCHQUEUE_H
#define JSICRYPTOEXAMPLE_DISPATCHQUEUE_H

#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <vector>

namespace margelo {

// taken from
// https://github.com/embeddedartistry/embedded-resources/blob/master/examples/cpp/dispatch.cpp
namespace DispatchQueue {
class dispatch_queue {
typedef std::function<void (void)> fp_t;

public:
explicit dispatch_queue(std::string name, size_t thread_cnt = 1);
~dispatch_queue();

// dispatch and copy
void dispatch(const fp_t& op);
// dispatch and move
void dispatch(fp_t&& op);

// Deleted operations
dispatch_queue(const dispatch_queue& rhs) = delete;
dispatch_queue& operator=(const dispatch_queue& rhs) = delete;
dispatch_queue(dispatch_queue&& rhs) = delete;
dispatch_queue& operator=(dispatch_queue&& rhs) = delete;

private:
std::string name_;
std::mutex lock_;
std::vector<std::thread> threads_;
std::queue<fp_t> q_;
std::condition_variable cv_;
bool quit_ = false;

void dispatch_thread_handler(void);
};
}  // namespace DispatchQueue

}  // namespace margelo

#endif  // JSICRYPTOEXAMPLE_DISPATCHQUEUE_H

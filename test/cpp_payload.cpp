#include <cstdio>
#include <stdexcept>

static int g_ctor_called = 0;

__attribute__((constructor))
static void cpp_ctor() {
    g_ctor_called = 1;
}

extern "C" {

int cpp_throw_catch(int x) {
    try {
        if (x == 0)
            throw std::runtime_error("test exception from reflectively loaded .so");
        if (x == 1)
            throw 42;
        return 0;
    } catch (const std::runtime_error &e) {
        printf("[cpp] caught runtime_error: %s\n", e.what());
        return 1;
    } catch (int val) {
        printf("[cpp] caught int: %d\n", val);
        return 2;
    } catch (...) {
        printf("[cpp] caught unknown exception\n");
        return 3;
    }
}

int cpp_nested_throw() {
    try {
        try {
            throw std::logic_error("nested inner");
        } catch (const std::logic_error &e) {
            printf("[cpp] inner catch: %s\n", e.what());
            throw std::runtime_error("rethrown outer");
        }
    } catch (const std::runtime_error &e) {
        printf("[cpp] outer catch: %s\n", e.what());
        return 1;
    }
    return 0;
}

int cpp_ctor_ok() {
    return g_ctor_called;
}

void cpp_run(const void *user_data, unsigned int user_data_len) {
    printf("[cpp] constructor was %scalled\n", g_ctor_called ? "" : "NOT ");

    int r1 = cpp_throw_catch(0);
    int r2 = cpp_throw_catch(1);
    int r3 = cpp_throw_catch(99);
    int r4 = cpp_nested_throw();

    printf("[cpp] results: throw_catch=%d,%d,%d nested=%d\n", r1, r2, r3, r4);

    if (user_data && user_data_len > 0)
        printf("[cpp] user_data: %.*s\n", user_data_len, (const char *)user_data);
}

}

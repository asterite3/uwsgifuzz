#include <sstream>

#include "src/libfuzzer/libfuzzer_macro.h"
#include "fuzz_proto/http.pb.h"

extern "C" int run_fuzz_input(const uint8_t *Data, size_t Size);

DEFINE_PROTO_FUZZER(const uwsgifuzz::HttpRequest& input) {
    std::stringstream ss;

    ss << input.method() << ' ' << input.uri() << ' ' << input.version() << "\r\n";
    for (int i = 0; i < input.headers_size(); i++) {
        ss << input.headers(i).key() << ": " << input.headers(i).value() << "\r\n";
    }

    ss << "\r\n" << input.body();

    //printf("fuzz %s\n", ss.str().c_str());
    std::string s = ss.str();
    run_fuzz_input((const uint8_t *) s.c_str(), s.length());
}
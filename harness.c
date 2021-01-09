#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "uwsgi.h"

int fuzzer_inited = 0;

extern char **environ;
//extern struct uwsgi_server uwsgi;

int uwsgi_init(int argc, char *argv[], char *envp[]);

/*int LLVMFuzzerInitialize(int *_argc, char ***_argv) {
    uwsgi_init(*argc, *argv, environ);
    return 0;
}*/

int external_uwsgi_proto_http_parser(struct wsgi_request *wsgi_req);

void fuzzer_init() {
    char * argv[] = {
         "./uwsgi", "--logto", "/run/user/1000/fuzzlog", "--http-socket", ":5001", "--module", "testapp:app"
    };
    uwsgi_init(sizeof(argv)/ sizeof(char *), argv, environ);
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (fuzzer_inited == 0) {
        fuzzer_init();
        fuzzer_inited = 1;
    }
    if (Size > 4080) {
        return 0;
    }
    FILE * fuzz_file = fopen("/tmp/fuzz", "w");
    if (fuzz_file == NULL) {
        perror("fopen");
        abort();
    }
    int n_written = fwrite(Data, 1, Size, fuzz_file);
    if (n_written != Size) {
        perror("fwrite");
        abort();
    }
    fclose(fuzz_file);
    struct wsgi_request req;
    //struct wsgi_request * wsgi_req = uwsgi.wsgi_req;//&uwsgi.workers[1].cores[0].req;
    struct wsgi_request * wsgi_req = &req;
    //printf("run %p %p %d\n", wsgi_req, &uwsgi, getpid());
    //int mywid=1,core_id=0;
    //printf("RUN wsgi_req %d %ld %p\n", mywid, core_id,&uwsgi.workers[mywid].cores[core_id].req);
    struct uwsgi_socket fake_sock;

    memset(&req, 0, sizeof(struct wsgi_request));
    memset(&fake_sock, 0, sizeof(struct uwsgi_socket));
    //printf("uwsgi.wsgi_req = %p\n", uwsgi.wsgi_req);
    //uwsgi.wsgi_req = wsgi_req;
    //printf("uwsgi.wsgi_req = %p\n", uwsgi.wsgi_req);
    
    fake_sock.name = "hui";

    wsgi_req_setup(wsgi_req, 0, &fake_sock);
    uwsgi_proto_http_setup(wsgi_req->socket);

    wsgi_req->fd = open("/tmp/fuzz", O_RDONLY);
    //printf("pp %d\n", wsgi_req->proto_parser_pos);
    wsgi_req_recv(0, wsgi_req);
    uwsgi_close_request(wsgi_req);
    //close(wsgi_req->fd);
    //printf("DONE OK\n");
    //DoSomethingInterestingWithMyAPI(Data, Size);
    return 0;  // Non-zero return values are reserved for future use.
}
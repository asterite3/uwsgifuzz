#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

//#include "uwsgi.h"
#include "plugins/http/common.h"

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

struct corerouter_peer *new_cr_peer() {
    struct corerouter_peer *old_peers = NULL, *peers = NULL; 
    
    /*while(peers) {
        old_peers = peers;
        peers = peers->next;
    }*/

    peers = uwsgi_calloc(sizeof(struct corerouter_peer));
    peers->session = NULL;//cs;
    peers->fd = -1;
    // create input buffer
    size_t bufsize = 65535;//cs->corerouter->buffer_size;
    if (!bufsize) bufsize = uwsgi.page_size;
    peers->in = uwsgi_buffer_new(bufsize);
    // add timeout
    //peers->current_timeout = cs->corerouter->socket_timeout;
    //    peers->timeout = cr_add_timeout(cs->corerouter, peers);
    peers->prev = old_peers;

    

    return peers;
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

    struct corerouter_peer *main_peer = new_cr_peer();
    struct http_session * hr = uwsgi_calloc(sizeof(struct http_session));
    struct corerouter_session * cs = (struct corerouter_session *) hr;
    cs->main_peer = main_peer;
    main_peer->session = cs;
    cs->ugs = uwsgi_calloc(sizeof(struct uwsgi_gateway_socket));
    cs->ugs->mode = UWSGI_HTTP_NOSSL;
    //printf("uwsgi.wsgi_req = %p\n", uwsgi.wsgi_req);
    //uwsgi.wsgi_req = wsgi_req;
    //printf("uwsgi.wsgi_req = %p\n", uwsgi.wsgi_req);
    
    fake_sock.name = "hui";

    int res = hr_read(main_peer);
    if (main_peer->prev != NULL) {
        struct corerouter_peer * new_peer = main_peer->prev;
        uwsgi_buffer_destroy(new_peer->in);
        if (new_peer->out) {
            uwsgi_buffer_destroy(new_peer->out);
        }
        free(new_peer);
    }
    uwsgi_buffer_destroy(main_peer->in);
    free(main_peer);
    free(cs->ugs);
    free(hr);
    if (res <= 0) {
        return 0;
    }

    wsgi_req_setup(wsgi_req, 0, &fake_sock);
    uwsgi_proto_uwsgi_setup(wsgi_req->socket);

    wsgi_req->fd = open("/run/user/1000/fuzz_buf", O_RDONLY);
    //printf("pp %d\n", wsgi_req->proto_parser_pos);
    wsgi_req_recv(0, wsgi_req);
    uwsgi_close_request(wsgi_req);
    //close(wsgi_req->fd);
    //printf("DONE OK\n");
    //DoSomethingInterestingWithMyAPI(Data, Size);
    return 0;  // Non-zero return values are reserved for future use.
}
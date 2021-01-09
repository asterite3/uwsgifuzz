#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

//#include "uwsgi.h"
#include "plugins/http/common.h"

int fuzzer_inited = 0;

extern char **environ;

FILE * fuzz_buf_file;
int fuzz_fd;
int buf_fd;
FILE * fuzz_file;
//extern struct uwsgi_server uwsgi;

int uwsgi_init(int argc, char *argv[], char *envp[]);

/*int LLVMFuzzerInitialize(int *_argc, char ***_argv) {
    uwsgi_init(*argc, *argv, environ);
    return 0;
}*/
int external_uwsgi_proto_http_parser(struct wsgi_request *wsgi_req);

void fuzzer_init() {
    fuzz_buf_file = NULL;
    char * argv[] = {
         "./uwsgi", /*"--logto", "/run/user/1000/fuzzlog", */"--http", ":0       ", "--module", "testapp:app"
    };
    uwsgi_init(sizeof(argv)/ sizeof(char *), argv, environ);
    buf_fd = memfd_create("fuzz_buf", 0);
    if (buf_fd < 0) {
        perror("memfd_create");
        abort();
    }
    fuzz_buf_file = fdopen(buf_fd, "w");
    if (fuzz_buf_file == NULL) {
        perror("fdopen");
        abort();
    }
    fuzz_fd = memfd_create("fuzz", 0);
    if (fuzz_fd < 0) {
        perror("memfd_create");
        abort();
    }
    fuzz_file = fdopen(fuzz_fd, "w");
    if (fuzz_file == NULL) {
        perror("fdopen");
        abort();
    }
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

    /*if (Size > 4080) {
        return 0;
    }*/
    if (lseek(fuzz_fd, 0, SEEK_SET)) {
        perror("lseek");
        abort();
    }
    if (lseek(buf_fd, 0, SEEK_SET)) {
        perror("lseek");
        abort();
    }
    if (ftruncate(fuzz_fd, 0)) {
        perror("ftruncate");
    }
    if (ftruncate(buf_fd, 0)) {
        perror("ftruncate");
    }
    /*FILE * fuzz_file = fopen("/tmp/fuzz", "w");
    if (fuzz_file == NULL) {
        perror("fopen");
        abort();
    }*/
    int n_written = fwrite(Data, 1, Size, fuzz_file);
    if (n_written != Size) {
        perror("fwrite");
        abort();
    }
    if (fflush(fuzz_file)) {
        perror("fflush");
        abort();
    }

    if (lseek(fuzz_fd, 0, SEEK_SET)) {
        perror("lseek");
        abort();
    }
    //fclose(fuzz_file);
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
    /*struct stat statbuf;
    char buf[10000];
    if (fstat(buf_fd, &statbuf)) {
        perror("fstat");
        abort();
    }
    if (lseek(buf_fd, 0, SEEK_SET)) {
        perror("lseek");
        abort();
    }
    fprintf(stderr, "%ld\n", statbuf.st_size);
    int n_read = read(buf_fd, buf, statbuf.st_size);
    if (n_read != statbuf.st_size) {
        printf("read %d, expected %d\n", n_read, statbuf.st_size);
        perror("read");
        abort();
    }
    fprintf(stderr, "||||\n");
    fwrite(buf, 1, statbuf.st_size, stderr);
    fprintf(stderr, "||||\n");
    lseek(buf_fd, 0, SEEK_SET);*/

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

    if (lseek(buf_fd, 0, SEEK_SET)) {
        perror("lseek");
        abort();
    }

    wsgi_req->fd = dup(buf_fd);//open("/run/user/1000/fuzz_buf", O_RDONLY);
    //printf("pp %d\n", wsgi_req->proto_parser_pos);
    wsgi_req_recv(0, wsgi_req);
    uwsgi_close_request(wsgi_req);
    //close(wsgi_req->fd);
    //printf("DONE OK\n");
    //DoSomethingInterestingWithMyAPI(Data, Size);
    return 0;  // Non-zero return values are reserved for future use.
}
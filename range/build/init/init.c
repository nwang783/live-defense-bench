/* web-01's PID 1: a minimal SysV-style init. It runs the start scripts in /etc/rc2.d in order, then
 * reaps orphans until the container stops. Like sysvinit, it shows itself as "init [2]" in ps.
 * Built in the Dockerfile; no range material is in it. */
#include <dirent.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define RCDIR "/etc/rc2.d"

static int cmp(const void *a, const void *b) { return strcmp(*(char *const *)a, *(char *const *)b); }

static void on_term(int sig) { (void)sig; _exit(0); }

static void on_chld(int sig) { (void)sig; }

static void start(const char *path) {
    pid_t p = fork();
    if (p == 0) {
        sigset_t none;
        sigemptyset(&none);
        sigprocmask(SIG_SETMASK, &none, NULL);
        setsid();
        execl(path, path, "start", (char *)0);
        _exit(127);
    }
    if (p > 0)
        while (waitpid(p, NULL, 0) < 0 && errno == EINTR) {}
}

int main(int argc, char **argv) {
    (void)argc;
    const char *title = "init [2]";
    size_t n = strlen(argv[0]);
    if (n >= strlen(title)) {
        memset(argv[0], 0, n);
        memcpy(argv[0], title, strlen(title));
    }
    signal(SIGTERM, on_term);
    signal(SIGINT, on_term);
    signal(SIGCHLD, on_chld);
    chdir("/");

    char *names[256];
    int count = 0;
    DIR *d = opendir(RCDIR);
    if (d) {
        struct dirent *e;
        while ((e = readdir(d)) && count < 256)
            if (e->d_name[0] == 'S') names[count++] = strdup(e->d_name);
        closedir(d);
    }
    qsort(names, count, sizeof(char *), cmp);
    for (int i = 0; i < count; i++) {
        char path[512];
        snprintf(path, sizeof path, "%s/%s", RCDIR, names[i]);
        start(path);
    }
    for (;;)
        if (wait(NULL) < 0 && errno == ECHILD) pause();
}

/*
 * TODO: Include your name and Andrew ID here.
 */

/*
 * TODO: Delete this comment and replace it with your own.
 * tsh - A tiny shell program with job control
 * <The line above is not a sufficient documentation.
 *  You will need to write your program documentation.
 *  Follow the 15-213/18-213/15-513 style guide at
 *  http://www.cs.cmu.edu/~213/codeStyle.html.>
 */

#include "csapp.h"
#include "tsh_helper.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/*
 * If DEBUG is defined, enable contracts and printing on dbg_printf.
 */
#ifdef DEBUG
/* When debugging is enabled, these form aliases to useful functions */
#define dbg_printf(...) printf(__VA_ARGS__)
#define dbg_requires(...) assert(__VA_ARGS__)
#define dbg_assert(...) assert(__VA_ARGS__)
#define dbg_ensures(...) assert(__VA_ARGS__)
#else
/* When debugging is disabled, no code gets generated for these */
#define dbg_printf(...)
#define dbg_requires(...)
#define dbg_assert(...)
#define dbg_ensures(...)
#endif

/* Function prototypes */
void eval(const char *cmdline);

void sigchld_handler(int sig);
void sigtstp_handler(int sig);
void sigint_handler(int sig);
void sigquit_handler(int sig);
void cleanup(void);
bool builtin_command(struct cmdline_tokens *token);
bool redirection(struct cmdline_tokens *token);
void do_bgfg(char **argv);

/*
 * TODO: Delete this comment and replace it with your own.
 * <Write main's function header documentation. What does main do?>
 * "Each function should be prefaced with a comment describing the purpose
 *  of the function (in a sentence or two), the function's arguments and
 *  return value, any error cases that are relevant to the caller,
 *  any pertinent side effects, and any assumptions that the function makes."
 */
int main(int argc, char **argv) {
    char c;
    char cmdline[MAXLINE_TSH]; // Cmdline for fgets
    bool emit_prompt = true;   // Emit prompt (default)

    // Redirect stderr to stdout (so that driver will get all output
    // on the pipe connected to stdout)
    if (dup2(STDOUT_FILENO, STDERR_FILENO) < 0) {
        perror("dup2 error");
        exit(1);
    }

    // Parse the command line
    while ((c = getopt(argc, argv, "hvp")) != EOF) {
        switch (c) {
        case 'h': // Prints help message
            usage();
            break;
        case 'v': // Emits additional diagnostic info
            verbose = true;
            break;
        case 'p': // Disables prompt printing
            emit_prompt = false;
            break;
        default:
            usage();
        }
    }

    // Create environment variable
    if (putenv("MY_ENV=42") < 0) {
        perror("putenv error");
        exit(1);
    }

    // Set buffering mode of stdout to line buffering.
    // This prevents lines from being printed in the wrong order.
    if (setvbuf(stdout, NULL, _IOLBF, 0) < 0) {
        perror("setvbuf error");
        exit(1);
    }

    // Initialize the job list
    init_job_list();

    // Register a function to clean up the job list on program termination.
    // The function may not run in the case of abnormal termination (e.g. when
    // using exit or terminating due to a signal handler), so in those cases,
    // we trust that the OS will clean up any remaining resources.
    if (atexit(cleanup) < 0) {
        perror("atexit error");
        exit(1);
    }

    // Install the signal handlers
    Signal(SIGINT, sigint_handler);   // Handles Ctrl-C
    Signal(SIGTSTP, sigtstp_handler); // Handles Ctrl-Z
    Signal(SIGCHLD, sigchld_handler); // Handles terminated or stopped child

    Signal(SIGTTIN, SIG_IGN);
    Signal(SIGTTOU, SIG_IGN);

    Signal(SIGQUIT, sigquit_handler);

    // Execute the shell's read/eval loop
    while (true) {
        if (emit_prompt) {
            printf("%s", prompt);

            // We must flush stdout since we are not printing a full line.
            fflush(stdout);
        }

        if ((fgets(cmdline, MAXLINE_TSH, stdin) == NULL) && ferror(stdin)) {
            perror("fgets error");
            exit(1);
        }

        if (feof(stdin)) {
            // End of file (Ctrl-D)
            printf("\n");
            return 0;
        }

        // Remove any trailing newline
        char *newline = strchr(cmdline, '\n');
        if (newline != NULL) {
            *newline = '\0';
        }

        // Evaluate the command line
        eval(cmdline);
    }

    return -1; // control never reaches here
}

/*
 * TODO: Delete this comment and replace it with your own.
 * <What does eval do?>
 *
 * NOTE: The shell is supposed to be a long-running process, so this function
 *       (and its helpers) should avoid exiting on error.  This is not to say
 *       they shouldn't detect and print (or otherwise handle) errors!
 */
void eval(const char *cmdline) {
    parseline_return parse_result;
    struct cmdline_tokens token;

    // Parse command line
    parse_result = parseline(cmdline, &token);
    int bg = parse_result;

    // new definition
    pid_t pid;
    jid_t jid;
    sigset_t mark, pre_mark, mark_all;
    sigfillset(&mark_all);
    sigemptyset(&mark);
    sigemptyset(&pre_mark);
    sigaddset(&mark, SIGCHLD);
    if (parse_result == PARSELINE_ERROR || parse_result == PARSELINE_EMPTY) {
        return;
    }

    if (!builtin_command(&token)) {
        // sigprocmask(SIG_BLOCK, &mark_all, &pre_mark);
        sigprocmask(SIG_BLOCK, &mark_all, &pre_mark);
        if ((pid = fork()) == 0) { // child
            // create new pid group to handle CTRL C
            setpgid(0, 0);
            sigprocmask(SIG_SETMASK, &pre_mark, NULL);
            // fail to redirect, end child process
            if (!redirection(&token)) {
                // sio_printf("rediction failed, end child process\n");
                exit(0);
            }

            if (execve(token.argv[0], token.argv, environ) < 0) {
                if (errno == EACCES)
                    sio_printf("%s: Permission denied\n", cmdline);
                else
                    printf("%s: No such file or directory\n", cmdline);
                exit(0);
            }

        } else if (pid < 0) {
            sio_printf("fork failed \n");
            sigprocmask(SIG_SETMASK, &pre_mark, NULL);
            _exit(1); // TODO use exit(1)?
        }

        // parent
        int state = bg ? BG : FG;
        add_job(pid, state, cmdline);

        // foreground job
        if (!bg) {
            sigset_t emptymask;
            sigemptyset(&emptymask);
            while ((jid = fg_job()) != 0) {

                sigsuspend(&emptymask);
            }
        }
        // background job
        else {
            jid = job_from_pid(pid);
            sio_printf("[%d] (%d) %s \n", jid, pid, cmdline);
        }
    }
    sigprocmask(SIG_SETMASK, &pre_mark, NULL);
    return;
}

/*****************
 * Signal handlers
 *****************/

/*
 * TODO: Delete this comment and replace it with your own.
 * <What does sigchld_handler do?>
 */
void sigchld_handler(int sig) {
    int olderr = errno;
    sigset_t mark_all, pre_mark;
    sigfillset(&mark_all);
    int status;
    int pid;
    int jid;
    sigprocmask(SIG_BLOCK, &mark_all, &pre_mark);
    while ((pid = waitpid(-1, &status, WNOHANG | WUNTRACED)) > 0) {
        // normal exit
        if (WIFEXITED(status)) {
            jid = job_from_pid(pid);
            bool dele_res = delete_job(jid);
            if (!dele_res) {
                sio_printf("fail to delete job %d when normally exits\n", jid);
            }

        }
        // exit by signal
        else if (WIFSIGNALED(status)) {
            jid = job_from_pid(pid);
            sio_printf("Job [%d] (%d) terminated by signal %d\n", jid, pid,
                       WTERMSIG(status));
            bool dele_res = delete_job(jid);
            if (!dele_res) {
                sio_printf("fail to delete job %d when exited by signal \n",
                           jid);
            }
        }
        // exit by stop
        else if (WIFSTOPPED(status)) {
            jid = job_from_pid(pid);
            job_set_state(jid, ST);
            sio_printf("Job [%d] (%d) stopped by signal %d\n", jid, pid,
                       WSTOPSIG(status));

        } else {
            jid = job_from_pid(pid);
            bool dele_res = delete_job(jid);
            if (!dele_res) {
                sio_printf("fail to delete job %d \n", jid);
            }
        }
    }
    sigprocmask(SIG_SETMASK, &pre_mark, NULL);
    errno = olderr;
    return;
}

/*
 *
 * <handle ctrl c by keyboard, quit current programs >
 * TODO: How to handle the background process cause we only kill the fg process
 * group here, leaving bg child process.
 */
void sigint_handler(int sig) {
    sigset_t mark_all, pre_mark;
    sigfillset(&mark_all);
    sigemptyset(&pre_mark);
    int olderr = errno;
    sigprocmask(SIG_BLOCK, &mark_all, &pre_mark);
    jid_t jid = fg_job(); // use job_list, block requiring.
    if (jid != 0) {
        pid_t pid = job_get_pid(jid);
        int kill_error = kill(-pid, sig);
        if (kill_error == -1) {
            sio_eprintf("sigint_handler failed on pid %d\n", pid);
        }
    }
    sigprocmask(SIG_SETMASK, &pre_mark, NULL);
    errno = olderr;
    return;
}

/*
 *
 * <handle ctrl z by keyboard, quit current programs>
 */
void sigtstp_handler(int sig) {
    int olderr = errno;
    sigset_t mark_all, pre_mark;
    sigfillset(&mark_all);
    sigemptyset(&pre_mark);
    sigprocmask(SIG_BLOCK, &mark_all, &pre_mark);
    jid_t jid = fg_job();
    if (jid != 0) {
        pid_t pid = job_get_pid(jid);
        int kill_error = kill(-pid, sig);
        if (kill_error == -1) {
            sio_eprintf("sigtstp_handler failed on pid %d\n", pid);
        }
    }
    sigprocmask(SIG_SETMASK, &pre_mark, NULL);
    errno = olderr;
    return;
}

/*
 * cleanup - Attempt to clean up global resources when the program exits. In
 * particular, the job list must be freed at this time, since it may contain
 * leftover buffers from existing or even deleted jobs.
 */
void cleanup(void) {
    // Signals handlers need to be removed before destroying the joblist
    Signal(SIGINT, SIG_DFL);  // Handles Ctrl-C
    Signal(SIGTSTP, SIG_DFL); // Handles Ctrl-Z
    Signal(SIGCHLD, SIG_DFL); // Handles terminated or stopped child

    destroy_job_list();
}

bool builtin_command(struct cmdline_tokens *token) {
    int olderror = errno;
    sigset_t mark_all, pre_mark;
    sigfillset(&mark_all);
    sigemptyset(&pre_mark);
    // TODO: why set block here
    if (token->builtin == BUILTIN_QUIT) {
        exit(0);
    }

    else if (token->builtin == BUILTIN_NONE) {
        errno = olderror;
        return false;
    }
    // fg bg cmd
    else if (token->builtin == BUILTIN_BG || token->builtin == BUILTIN_FG) {
        do_bgfg(token->argv);
        errno = olderror;
        return 1;
    }

    // list job
    else if (token->builtin == BUILTIN_JOBS) {
        if (token->outfile != NULL) {
            // redirect job list to outfile
            int fd =
                open(token->outfile, O_CREAT | O_TRUNC | O_WRONLY, DEF_MODE);
            if (fd != -1) {
                sigprocmask(SIG_BLOCK, &mark_all, &pre_mark);
                list_jobs(fd);
                sigprocmask(SIG_SETMASK, &pre_mark, NULL);
                errno = olderror;
                return true;
            }
            // unsuccessfully open outfiles
            else {
                if (errno == EACCES) {
                    sio_eprintf("%s: Permission denied\n", token->outfile);
                } else {
                    sio_eprintf("%s: No such file or directory\n",
                                token->outfile);
                }
                errno = olderror;
                return true;
            }
        }
        // output to STDERR_FILENO, because no assigned output files
        else {
            sigprocmask(SIG_BLOCK, &mark_all, &pre_mark);
            list_jobs(STDERR_FILENO);
            sigprocmask(SIG_SETMASK, &pre_mark, NULL);
            errno = olderror;
            return true;
        }
    }

    return false;
}

bool redirection(struct cmdline_tokens *token) {
    int olderror = errno;

    // printf("input=%s\n", token->infile);
    // printf("output=%s\n", token->outfile);
    // printf("-------------------\n");

    if (token->infile != NULL) {
        int fd_in = open(token->infile, O_RDONLY, DEF_MODE);
        // printf("fd_in%d\n:", fd_in);
        if (fd_in != -1) {
            if (dup2(fd_in, STDIN_FILENO) == -1) {
                sio_printf("dup process errors:%s\n", token->infile);
                errno = olderror;
                return false;
            }
            // errno = olderror;
            // return true;
            // fail to open input files
        } else {
            if (errno == EACCES) {
                sio_eprintf("%s: Permission denied\n", token->infile);
            } else {
                sio_eprintf("%s: No such file or directory\n", token->infile);
            }

            errno = olderror;
            return false;
        }
    }

    if (token->outfile != NULL) {
        int fd_out =
            open(token->outfile, O_WRONLY | O_CREAT | O_TRUNC, DEF_MODE);
        // printf("fd_out%d\n:", fd_out);
        if (fd_out != -1) {
            if (dup2(fd_out, STDOUT_FILENO) == -1) {
                sio_printf("dup process errors:%s\n", token->outfile);
                errno = olderror;
                return false;
            }

            // return true;

            // fail to open output files
        } else {
            if (errno == EACCES) {
                sio_eprintf("%s: Permission denied\n", token->outfile);
            } else {
                sio_eprintf("%s: No such file or directory\n", token->outfile);
            }
            errno = olderror;
            return false;
        }
    }

    errno = olderror;
    return true;
}

void do_bgfg(char **argv) {
    sigset_t pre_mark, mark_all;
    sigfillset(&mark_all);
    sigemptyset(&pre_mark);

    // sio_printf("0=%s:\n", argv[0]);
    // sio_printf("1=%s:\n", argv[1]);

    if (argv[1] == NULL) {
        sio_printf("%s command requires PID or %%jobid argument\n", argv[0]);
        return;
    }
    pid_t pid;
    jid_t jid;
    char *tempStr = NULL;
    int base = 10;
    sigprocmask(SIG_BLOCK, &mark_all, &pre_mark);
    // extract id
    if (argv[1][0] == '%') {
        jid = (jid_t)strtol(&argv[1][1], &tempStr, base);
        // pid = job_get_pid(jid);
        // sio_printf("jid=%d\n", jid);
    } else {
        pid = (pid_t)strtol(&argv[1][0], &tempStr, base);
        jid = job_from_pid(pid);
        if (jid == 0) {
            sio_printf("%s: argument must be a PID or %%jobid\n", argv[0]);
            sigprocmask(SIG_SETMASK, &pre_mark, NULL);
            return;
        }
    }

    // check job existances
    if (!job_exists(jid)) {
        sio_printf("%%%d: No such job\n", jid);
        sigprocmask(SIG_SETMASK, &pre_mark, NULL);
        return;
    }
    pid = job_get_pid(jid);
    sigprocmask(SIG_SETMASK, &pre_mark, NULL);

    // create new job
    char *bg = "bg";
    char *fg = "fg";
    job_state state_con;

    if (strcmp(argv[0], bg) == 0) {
        state_con = BG;
    } else if (strcmp(argv[0], fg) == 0) {
        state_con = FG;
    } else {
        sio_printf("wrong given cmd neither bg nor fg %s", argv[0]);
        return;
    }
    const char *cmdline;
    sigprocmask(SIG_BLOCK, &mark_all, &pre_mark);
    cmdline = job_get_cmdline(jid);

    // sio_printf("state=%d\n", state_con);

    if (state_con == FG) {
        // sio_printf("-----dubuger-------\n");
        job_set_state(jid, state_con);
        kill(-pid, SIGCONT);
        sigset_t emptymask;
        sigemptyset(&emptymask);
        while ((pid = fg_job() != 0)) {
            sigsuspend(&pre_mark);
        }
    } else if (state_con == BG) {

        job_set_state(jid, state_con);
        kill(-pid, SIGCONT);
        sio_printf("[%d] (%d) %s\n", jid, pid, cmdline);
    }
    sigprocmask(SIG_SETMASK, &pre_mark, NULL);

    return;
}
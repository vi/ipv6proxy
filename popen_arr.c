#define _GNU_SOURCE // execvpe 
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>

#include "popen_arr.h"


// Implemented by Vitaly _Vi Shukela in 2013, License=MIT

struct popen2_data {
    int socket;
    FILE fd;
};

static void interpret_mode(const char* mode, int* in, int* out, int* close_on_exec)
{
    *in = 0;
    *out = 0;
    *close_on_exec = 0;
    if(strstr(mode, "r")) *in=1;
    if(strstr(mode, "w")) *out=1;
    if(strstr(mode, "+")) { *in = 1; *out = 1; }
    if(strstr(mode, "e")) { *close_on_exec = 1; }
}

static int popen2_impl(FILE** in_and_or_out,  const char* program, const char* const argv[], const char* const envp[], int lookup_path, const char* mode)
{
	int in, out, close_on_exec;
	interpret_mode(mode, &in, &out, &close_on_exec);
	
	int socket_type_and_flags = SOCK_STREAM;
	if(close_on_exec) {
	    // Since Linux 2.6.27, socketpair() supports the SOCK_NONBLOCK and SOCK_CLOEXEC flags described in socket(2).
	    socket_type_and_flags |= SOCK_CLOEXEC;
	}
	
	int sv[2] = {-1, -1};
	int ret = socketpair(AF_UNIX, socket_type_and_flags, 0, sv);
	
	if (ret == -1) return -1;
	
	if (!in) {
	    shutdown(sv[0], SHUT_RD);
	    shutdown(sv[1], SHUT_WR);
	}
	
	if (!out) {
	    shutdown(sv[0], SHUT_WR);
	    shutdown(sv[1], SHUT_RD);
	}
	
	if (in_and_or_out) {
	   *in_and_or_out = fdopen(sv[0], mode);
	}
	
	if(in_and_or_out && !*in_and_or_out) {
	    int saved_errno = errno;
	    close(sv[0]);
	    close(sv[1]);
	    errno = saved_errno;
	    return -1;
	}
	
	int childpid = fork();
	if (!childpid) {
	   close(sv[0]);
	   if (in) {
	       dup2(sv[1], 1);
	   }
	   if (out) {
	       dup2(sv[1], 0);
	   }
	   if ((in && (sv[1] == 1)) || (out && (sv[1] == 0))) {
	       // avoid closing sv[1] as it got lucky FD
	   } else {
	       close(sv[1]);
	   }
	   
	   if (lookup_path) {
	       if (envp) {
	           execvpe(program, (char**)argv, (char**)envp);
	       } else {
	           execvp (program, (char**)argv);
	       }
	   } else {
	       if (envp) {
	           execve(program, (char**)argv, (char**)envp);
	       } else {
	           execv (program, (char**)argv);
	       }
	   }
	   _exit(ENOSYS);
	}
	close(sv[1]);
    
    return childpid;
}


int popen2_arr  (FILE** in_or_out,  const char* program, const char* const argv[], const char* const envp[], const char* mode)
{
    return popen2_impl(in_or_out, program, argv, envp, 0, mode);
}
int popen2_arr_p(FILE** in_or_out,  const char* program, const char* const argv[], const char* const envp[], const char* mode)
{
    return popen2_impl(in_or_out, program, argv, envp, 1, mode);
}

FILE* popen_arr(const char* program,
                const char* const argv[],
                const char *mode)
{
    FILE* f = NULL;
    int ret = popen2_impl(&f, program, argv, NULL, 1, mode);
    (void)ret;
    return f;
}
    

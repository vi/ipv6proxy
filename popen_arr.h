#pragma once

struct FILE;

// Implemented by Vitaly _Vi Shukela in 2013, License=MIT

/**
 * For and exec the program, enabling stdio access to stdin and stdout of the program
 * You may close opened streams with fclose.
 * You should waitpid for the returned PID to collect the zombie or use signal(SIGCHLD, SIG_IGN);
 * 
 * @arg in  stdin of the program, to be written to. If NULL then not redirected
 * @arg out stdout of the program, to be read from. If NULL then not redirected
 * @arg program full path of the program, without reference to $PATH
 * @arg argv NULL terminated array of strings, program arguments (includiong program name)
 * @arg envp NULL terminated array of environment variables, NULL => preserve environment
 * @return PID of the program or -1 if failed
 */
int popen2_arr  (FILE** in_an_or_out,  const char* program, const char* const argv[], const char* const envp[], const char* mode);

/** like popen2_arr, but uses execvp/execvpe instead of execve/execv, so looks up $PATH */
int popen2_arr_p(FILE** in_and_or_out,  const char* program, const char* const argv[], const char* const envp[], const char* mode);

/**
 * Simplified interface to popen2_arr.
 * You may close the returned stream with fclose.
 * Note: the procedure does no signal handling except of signal(SIGPIPE, SIG_IGN);
 * You should wait(2) after closing the descriptor to collect zombie process or use signal(SIGCHLD, SIG_IGN)
 * 
 * @arg program program name, can rely on $PATH
 * @arg argv program arguments, NULL-terminated const char* array
 * @arg mode - like in popen, "r" to catch stdout, "w" to catch stdin, "r+" to catch both and 
 *             can contain "e" for close-on-exec flag 
 * @return FILE* instance or NULL if error
 */
FILE* popen_arr(const char* program,
                const char* const argv[],
                const char *mode);

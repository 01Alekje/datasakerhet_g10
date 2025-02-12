/* $Header: https://svn.ita.chalmers.se/repos/security/edu/course/computer_security/trunk/lab/login_linux/login_linux.c 585 2013-01-19 10:31:04Z pk@CHALMERS.SE $ */

/* gcc -std=gnu99 -Wall -g -o mylogin login_linux.c -lcrypt */

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <string.h>
#include <signal.h>
#include <pwd.h>
#include <sys/types.h>
#include <crypt.h>
/* Uncomment next line in step 2 */
#include "pwent.h"

#define TRUE 1
#define FALSE 0
#define LENGTH 16

char **environ;

void holup() {
	printf("\nStop here criminal entity!\n");
}

void sighandler() {
	signal(SIGINT, holup);
	signal(SIGTSTP, holup);
	signal(SIGQUIT, holup);

	/* add signalhandling routines here */
	/* see 'man 2 signal' */
}

void update_pwd();

int main(int argc, char *argv[]) {

	//struct passwd *passwddata; /* this has to be redefined in step 2 */
	mypwent *passwddata;
	/* see pwent.h */

	char important1[LENGTH] = "**IMPORTANT 1**";

	char user[LENGTH];

	char important2[LENGTH] = "**IMPORTANT 2**";

	char *hashed_pass;

	//char   *c_pass; //you might want to use this variable later...
	char prompt[] = "password: ";
	char *user_pass;

	sighandler();

	while (TRUE) {
		/* check what important variable contains - do not remove, part of buffer overflow test */
		printf("Value of variable 'important1' before input of login name: %s\n",
				important1);
		printf("Value of variable 'important2' before input of login name: %s\n",
				important2);

		printf("login: ");
		fflush(NULL); /* Flush all  output buffers */
		__fpurge(stdin); /* Purge any data in stdin buffer */

		if (fgets(user, LENGTH, stdin) == NULL) /* gets() is vulnerable to buffer */
			exit(0); /*  overflow attacks.  */

		/* check to see if important variable is intact after input of login name - do not remove */
		printf("Value of variable 'important 1' after input of login name: %*.*s\n",
				LENGTH - 1, LENGTH - 1, important1);
		printf("Value of variable 'important 2' after input of login name: %*.*s\n",
				LENGTH - 1, LENGTH - 1, important2);

		// replace \n with \0
		user[strcspn(user, "\n")] = '\0';

		user_pass = getpass(prompt);
		passwddata = mygetpwnam(user);

		if (passwddata == NULL) {
			printf("No matching user was found!\n");
		} else if (passwddata->pwfailed < 4) {

			if (passwddata != NULL) {
				/* You have to encrypt user_pass for this to work */
				/* Don't forget to include the salt */

				hashed_pass = crypt(user_pass, passwddata->passwd_salt);

				if (hashed_pass != NULL && strcmp(hashed_pass, passwddata->passwd) == 0) {

					printf(" You're in !\n");
					printf("Failed login attempts: %d\n", passwddata->pwfailed);

					// reset failed login attempts on successful login
					passwddata->pwfailed = 0;
					passwddata->pwage++;
					mysetpwent(passwddata->pwname, passwddata);

					if(passwddata->pwage > 10) {
						printf("Password age exceeded 10, please change password! \n");
						printf("Do you want to change your password? [y/n]");

						char answer = getchar();
						if (answer == 'y') {
							update_pwd(passwddata->pwname);
						}
					}

					/*  check UID, see setuid(2) */
					if (setuid(passwddata->uid) == -1) {
						printf("Could not set UID, something is wrong!");
						return 0;
					}
					/*  start a shell, use execve(2) */
					char *argv[] = { "sh", "-i", NULL };
					execve("/bin/sh", argv, environ);

				} else {
					printf("Login Incorrect\n");
					passwddata->pwfailed++;  
					mysetpwent(passwddata->pwname, passwddata);
				}
			} else {
				// login credentials incorrect
				printf("Login Incorrect!\n");
			}
		} else {
			// this user cannot be logged in, too many failed attempts
			printf("Too many failed login attempts!");
		}
	}
	return 0;
}

void update_pwd(char *username) {
    char *new_pwd;
    char *repeat_pwd;
    char *temp_pwd;

    new_pwd = getpass("Enter new password: ");

	// new_pwd seems to be somehow overwritten by secondary getpass()
    temp_pwd = strdup(new_pwd);

    repeat_pwd = getpass("Repeat new password: ");

    if (strcmp(temp_pwd, repeat_pwd) == 0) {
        mypwent *passwddata = mygetpwnam(username);

        char *hashed_pass = crypt(temp_pwd, passwddata->passwd_salt);

        passwddata->passwd = hashed_pass;
        passwddata->pwage = 0;
        mysetpwent(username, passwddata);

        printf("Password updated!\n");
    } else {
        printf("Passwords don't match!\n");
    }
    
    free(new_pwd);
	free(repeat_pwd);
    free(temp_pwd);
}

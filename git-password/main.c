//
//  main.c
//  git-password
//
//  Copyright (C) 2011 by Samuel Kadolph
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in
//  all copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
//  THE SOFTWARE.

#include <pwd.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/sysctl.h>
#include <unistd.h>

#include <CoreFoundation/CoreFoundation.h>
#include <Security/SecKeychain.h>
#include <Security/SecKeychainSearch.h>

static void fatal(const char * message, FILE * terminal)
{
	char * fatal;
	asprintf(&fatal, "fatal: %s\n", message);
	fputs(fatal, terminal);
	exit(-1);
}

static void security_fatal(OSStatus status, FILE * terminal)
{
	const char * message = CFStringGetCStringPtr(SecCopyErrorMessageString(status, NULL), CFStringGetSystemEncoding());
	fatal(message, terminal);
}

static void security(OSStatus status, FILE * terminal)
{
	if (status != 0)
		security_fatal(status, terminal);
}

static UInt32 len(const char * string)
{
	return (UInt32)strlen(string);
}

static char * trim_trailing_whitespace(char * string)
{	
	size_t length = strlen(string);

	if (string[length - 1] == '\n')
		string[length - 1] = 0;

	return string;
}

static int is_git_calling_us(FILE * terminal)
{
	int name[] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL };
	pid_t parent_pid = getppid();
	struct kinfo_proc * processes = NULL;
	size_t size = 0;

	if (sysctl(name, 3, NULL, &size, NULL, 0) != 0) fatal("sysctl failed", terminal);
	if ((processes = malloc(size)) == NULL) fatal("unable to allocate memory", terminal);
	if (sysctl(name, 3, processes, &size, NULL, 0) != 0) fatal("sysctl failed", terminal);

	for (int i = 0; i < size / sizeof(struct kinfo_proc); i++)
	{
		struct extern_proc process = processes[i].kp_proc;
		if (parent_pid == process.p_pid && strcmp(process.p_comm, "git-remote-https") == 0) return 1;
	}

	return 0;
}

static char * git_config(char * key, FILE * terminal)
{
	FILE * pipe;
	char buffer[1024];
	char * command, * result;
	int count;

	if (asprintf(&command, "git config %s", key) < 0) fatal("command generation failed", terminal);

	if ((pipe = popen(command, "r")) == NULL) fatal("popen failed", terminal);
	fgets(buffer, sizeof(buffer), pipe);
	count = sizeof(buffer);

	if (pclose(pipe) != 0) fatal("reading from git failed", terminal);	
	if ((result = malloc(count)) == NULL) fatal("unable to allocate memory", terminal);
	strncpy(result, buffer, count);
	trim_trailing_whitespace(result);

	free(command);

	return result;
}

static char * git_origin_url(FILE * terminal)
{
	return git_config("remote.origin.url", terminal);
}

static struct KeyChainItem
{
	char * username;
	char * password;
};
typedef struct KeyChainItem KeyChainItem;

static KeyChainItem * find_keychain_item(char * repository, bool include_password, FILE * terminal)
{
	SecKeychainItemRef item;
	SecKeychainAttributeInfo * info;
	SecKeychainAttributeList * attributes;
	void * password;
	UInt32 password_length;
	OSStatus status;
	KeyChainItem * result = NULL;

	status = SecKeychainFindGenericPassword(NULL, len(repository), repository, 0, NULL, NULL, NULL, &item);
	switch(status)
	{
		case errSecSuccess:
			result = malloc(sizeof(KeyChainItem));

			security(SecKeychainAttributeInfoForItemID(NULL, CSSM_DL_DB_RECORD_GENERIC_PASSWORD, &info), terminal);

			if (include_password)
				security(SecKeychainItemCopyAttributesAndData(item, info, NULL, &attributes, &password_length, &password), terminal);
			else
				security(SecKeychainItemCopyAttributesAndData(item, info, NULL, &attributes, NULL, NULL), terminal);

			for (int i = 0; i < attributes->count; i++)
			{
				SecKeychainAttribute attribute = attributes->attr[i];

				if (attribute.tag == kSecAccountItemAttr)
				{
					result->username = malloc(attribute.length + 1);
					strncpy(result->username, attribute.data, attribute.length);
					result->username[attribute.length] = 0;
				}
			}

			if (include_password)
			{
				result->password = malloc(password_length + 1);
				strncpy(result->password, password, password_length);
				result->password[password_length] = 0;
			}
			else
			{
				result->password = NULL;
			}

			if (include_password)
				SecKeychainItemFreeAttributesAndData(attributes, password);
			else
				SecKeychainItemFreeAttributesAndData(attributes, NULL);

			SecKeychainFreeAttributeInfo(info);

			break;
		case errSecItemNotFound:
			break;
		default:
			security(status, terminal);
	}

	return result;
}

static void create_keychain_item(char * repository, char * username, char * password, FILE * terminal)
{
	SecItemClass class = kSecGenericPasswordItemClass;
	SecKeychainAttribute attributes[] =
	{
		{ kSecLabelItemAttr, len(repository), repository },
		{ kSecDescriptionItemAttr, 23, "git repository password" },
		{ kSecAccountItemAttr, len(username), username },
		{ kSecServiceItemAttr, len(repository), repository }
	};
	SecKeychainAttributeList attribute_list = { 4, attributes };

	security(SecKeychainItemCreateFromContent(class, &attribute_list, len(password), password, NULL, NULL, NULL), terminal);
}

static char * prompt(const char * prompt)
{
	char * temp = getpass(prompt);
	char * value = malloc(strlen(temp) + 1);

	strncpy(value, temp, strlen(temp) + 1);
	value[strlen(temp) + 1] = 0;

	return value;
}

static char * get_username(FILE * terminal, const char* prompt_str)
{
	char * repository = git_origin_url(terminal), * username = NULL, * password = NULL;
	KeyChainItem * item = find_keychain_item(repository, false, terminal);

	if (item)
	{
		username = item->username;
	}
	else
	{
		username = prompt(prompt_str);
		password = prompt("Password: ");
		create_keychain_item(repository, username, password, terminal);
	}

	return username;
}

static char * get_password(FILE * terminal, const char* prompt_str)
{
	char * repository = git_origin_url(terminal), * password = NULL;
	KeyChainItem * item = find_keychain_item(repository, true, terminal);

	if (item)
	{
		password = item->password;
	}
	else
	{
		password = prompt(prompt_str);
		create_keychain_item(repository, "", password, terminal);
	}

	return password;
}

int main(int argc, const char * argv[])
{
	FILE * terminal = fdopen(2, "r+");

	if      (!is_git_calling_us(terminal))         fatal("Can only be used by git (git is not the caller)", terminal);
	if      (argc != 2)                            fatal("Can only be used by git (wrong number of args)",  terminal);
	if      (strncmp(argv[1], "Username", 8) == 0) printf("%s", get_username(terminal, argv[1]));
	else if (strncmp(argv[1], "Password", 8) == 0) printf("%s", get_password(terminal, argv[1]));
	else {
        fprintf(stderr, "Expected Username or Password, got '%s'\n", argv[1]);
        fatal("Can only be used by git (prompts were bad)", terminal);
    }
	return 0;
}

//
//  main.c
//  git-password
//
//  Created by Samuel Kadolph on 11-03-24.
//  Copyright 2011 Samuel Kadolph. All rights reserved.
//

#include <pwd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
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

static KeyChainItem * find_keychain_item(char * repository, FILE * terminal)
{
	SecKeychainItemRef item;
	SecKeychainAttributeInfo * info;
	SecKeychainAttributeList * attributes;
	void * password;
	UInt32 passwordLen;
	OSStatus status;
	KeyChainItem * result = NULL;

	status = SecKeychainFindGenericPassword(NULL, len(repository), repository, 0, NULL, NULL, NULL, &item);
	switch(status)
	{
		case errSecSuccess:
			result = malloc(sizeof(KeyChainItem));

			security(SecKeychainAttributeInfoForItemID(NULL, CSSM_DL_DB_RECORD_GENERIC_PASSWORD, &info), terminal);
			security(SecKeychainItemCopyAttributesAndData(item, info, NULL, &attributes, &passwordLen, &password), terminal);

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

			result->password = malloc(passwordLen + 1);
			strncpy(result->password, password, passwordLen);
			result->password[passwordLen] = 0;

			SecKeychainItemFreeAttributesAndData(attributes, password);
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

static char * prompt(char * prompt)
{
	char * temp = getpass(prompt);
	char * value = malloc(strlen(temp) + 1);

	strncpy(value, temp, strlen(temp) + 1);
	value[strlen(temp) + 1] = 0;

	return value;
}

static char * get_username(FILE * terminal)
{
	char * repository = git_origin_url(terminal), * username = NULL, * password = NULL;
	KeyChainItem * item = find_keychain_item(repository, terminal);

	if (item)
	{
		username = item->username;
	}
	else
	{
		username = prompt("Username: ");
		password = prompt("Password: ");
		create_keychain_item(repository, username, password, terminal);
	}

	return username;
}

static char * get_password(FILE * terminal)
{
	char * repository = git_origin_url(terminal), * password = NULL;
	KeyChainItem * item = find_keychain_item(repository, terminal);

	if (item)
	{
		password = item->password;
	}
	else
	{
		password = prompt("Password: ");
		create_keychain_item(repository, "", password, terminal);
	}
	
	return password;
}

int main(int argc, const char * argv[])
{
	FILE * terminal = fdopen(2, "r+");

	if (argc != 2) fatal("can only be called by git", terminal);
	if (strcmp(argv[1], "Username: ") == 0) printf("%s", get_username(terminal));
	else if (strcmp(argv[1], "Password: ") == 0) printf("%s", get_password(terminal));
	else fatal("can only be called by git", terminal);

	return(0);
}

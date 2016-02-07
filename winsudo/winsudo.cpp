// usermode_processtoken.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

void intro(void) {
	printf("\n winSudo\n\tCreated by @_xpn_\n\n");
}

DWORD ListTokens(TOKEN_COLLECTION *collection) {
	
	DWORD count;

	printf("Tokens collected\n");
	printf("------------------\n");
	printf("Delegation:\n");

	for (int i = 0; collection[i].token != NULL; i++) {
		if (collection[i].impersonationLevel == SecurityDelegation) {
			printf("[%d] - %s\n", i, collection[i].username);
		}
	}

	printf("\nImpersonate:\n");

	for (count = 0; collection[count].token != NULL; count++) {
		if (collection[count].impersonationLevel == SecurityImpersonation) {
			printf("[%d] - %s\n", count, collection[count].username);
		}
	}

	return count;
}

int main()
{
	TOKEN_COLLECTION *collection;
	DWORD option, count;

	intro();
	
	// Grab a list of user tokens
	collection = ListAllProcessTokens();
	if (collection == NULL) {
		printf("[X] Could not retrieve tokens\n");
		return 0;
	}

	// Show the user a list of collected tokens
	count = ListTokens(collection);

	printf("\nSelect a user ID to impersonate: ");
	scanf_s("%d", &option);

	if (option > count) {
		printf("Invalid User ID, please enter a value between 0 and %d\n", count-1);
		return 0;
	}

	ImpersonateUser(collection[option].token);

	return 0;
}


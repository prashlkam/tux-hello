/*
 * SPDX-FileCopyrightText: 2026 Tux Hello contributors
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

/*
 * th-pamtest: minimal pamtester replacement so the integration tests do not
 * depend on pamtester (which some distributions, e.g. Arch, don't package).
 *
 *   th-pamtest [-r RHOST] [-c CONFDIR] SERVICE USER
 *
 * -c uses pam_start_confdir() (Linux-PAM >= 1.4) to read SERVICE from CONFDIR
 * instead of /etc/pam.d, which lets the tests run without root.
 *
 * Runs pam_authenticate() and exits 0 on PAM_SUCCESS, 1 otherwise.
 * Build: cc -o th-pamtest th-pamtest.c -lpam -lpam_misc
 */
#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <stdio.h>
#include <string.h>

static struct pam_conv conv = { misc_conv, NULL };

int main(int argc, char **argv)
{
	const char *rhost = NULL;
	const char *confdir = NULL;
	int i = 1;

	while (argc - i >= 2 && argv[i][0] == '-') {
		if (strcmp(argv[i], "-r") == 0)
			rhost = argv[i + 1];
		else if (strcmp(argv[i], "-c") == 0)
			confdir = argv[i + 1];
		else
			break;
		i += 2;
	}
	if (argc - i != 2) {
		fprintf(stderr, "usage: %s [-r RHOST] [-c CONFDIR] SERVICE USER\n", argv[0]);
		return 2;
	}

	pam_handle_t *pamh = NULL;
	int rc = confdir
		? pam_start_confdir(argv[i], argv[i + 1], &conv, confdir, &pamh)
		: pam_start(argv[i], argv[i + 1], &conv, &pamh);
	if (rc != PAM_SUCCESS) {
		fprintf(stderr, "pam_start: %s\n", pam_strerror(pamh, rc));
		return 2;
	}
	if (rhost)
		pam_set_item(pamh, PAM_RHOST, rhost);

	rc = pam_authenticate(pamh, 0);
	printf("th-pamtest: %s: %s\n", argv[i], pam_strerror(pamh, rc));
	pam_end(pamh, rc);
	return rc == PAM_SUCCESS ? 0 : 1;
}

/*
 * rhel-log-parser: parses RHEL git log via revision walk and compares it
 *		    with upstream entries to produce reports of RHEL-only
 *		    patches and RHEL-matching-upstream patches.
 *
 * Copyright (c) 2016-2019 Rafael Aquini, Red Hat.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <getopt.h>
#include <limits.h>
#include <assert.h>
#include <memory.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <regex.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/fcntl.h>
#include <sys/mount.h>
#include <sys/statfs.h>
#include <git2.h>
#include "asprintf.h"

/*
 * constants to help on assembling SHA-1 hash strings + NULL terminator
 */
#define SHASH_SZ	17
#define HASH_SZ		41

typedef struct lnode lnode_t;
struct lnode {
	lnode_t	*next;
	void	*data;
};

typedef struct list list_t;
struct list {
	int	size;
	int	(*match)(const void *key1, const void *key2);
	void	(*destroy)(void *data);
	lnode_t	*head;
	lnode_t	*tail;
};

static int __list_add(list_t *list, lnode_t *node, const void *data)
{
	lnode_t *new_node = calloc(1, sizeof(lnode_t));

	if (!new_node)
		return -ENOMEM;

	if (!node) {
		if (list->size == 0)
			list->tail = new_node;

		new_node->next = list->head;
		list->head = new_node;
	} else {
		if (!node->next)
			list->tail = new_node;

		new_node->next = node->next;
		node->next = new_node;
	}

	new_node->data = (void *)data;
	list->size++;

	return 0;
}

static void __list_del(list_t *list, lnode_t *node)
{
	lnode_t *free_ptr = NULL;

	if (list->size == 0)
		return;

	if (!node || (node == list->head)) {
		free_ptr = list->head;
		list->head = list->head->next;
	} else {
		lnode_t *ptr = list->head;
		while (ptr) {
			if (node == ptr->next) {
				free_ptr = node;
				ptr->next = free_ptr->next;
				break;
			}
			ptr = ptr->next;
		}
	}

	if (free_ptr) {
		if (list->destroy != NULL)
			list->destroy(free_ptr->data);

		free(free_ptr);
		list->size--;
	}
}

static inline void list_add_tail(list_t *list, const void *data)
{
        __list_add(list, list->tail, data);
}

static inline void list_del_head(list_t *list)
{
        __list_del(list, NULL);
}

static inline void list_del_node(list_t *list, lnode_t *node)
{
        __list_del(list, node);
}

static void list_init(list_t *list, void (*destroy)(void *data),
			int (*match)(const void *key1, const void *key2))
{
	list->size = 0;
	list->destroy = destroy;
	list->match = match;
	list->head = NULL;
	list->tail = NULL;
}

static void list_destroy(list_t *list)
{
	while (list->size > 0)
		list_del_head(list);
}

void list_add_unique(list_t *list, const void *data)
{
	lnode_t *node = list->head;
	for (int i = 0; i < list->size; i++) {
		if (list->match && list->match(node->data, data))
			return;

		node = node->next;
	}
	list_add_tail(list, data);
}

typedef struct commit_data commit_data_t;
struct commit_data {
	char *summary;
	char *commit_id;
};

typedef struct rhel_data rhel_data_t;
struct rhel_data {
	commit_data_t rhel;
	commit_data_t upstream;
	char *author_email;
	char *o_subject;
	list_t *upstream_ref;
};

/* Description of long options for getopt_long. */
static const struct option l_opts[] = {
	{ "ancestor",	 1, NULL, 'a' },
	{ "upstream",	 1, NULL, 'u' },
	{ "rhel",	 1, NULL, 'r' },
	{ "rhel-ref",	 1, NULL, 'z' },
	{ "help",	 0, NULL, 'h' },
	{ "fullhash",	 0, NULL, 'f' },
	{ "matches",	 0, NULL, 'm' },
	{ "only",	 0, NULL, 'o' },
};

/* Description of short options for getopt_long. */
static const char* const s_opts = "a:u:r:z:hfmo";

/* */
static const char* const usage_template =
	"Usage: %s [options] [path,...]\n"
	"*  -a, --ancestor <git-tag>  : common ancestor tag between RHEL and Upstream\n"
	"*  -r, --rhel <git-repo>     : load RHEL data from git\n"
	"*  -u, --upstream <git-repo> : load linux upstream data from git\n"
	"   -z, --rhel-ref <git-ref>  : use <git-ref> instead of 'master' as rev-walker reference\n"
	"   -m, --matches             : print out RHEL patches with upstream matches\n"
	"   -o, --only                : print out RHEL patches without upstream matches\n"
	"   -f, --fullhash            : toggle to print out full SHA-1 hashes\n"
	"   -h, --help                : Print this information screen.\n"
	"  Options marked with (*) have to be declared\n";

static char *rhel_ref = "refs/heads/master";

static void print_usage(const char *program_name)
{
	fprintf(stderr, usage_template, program_name);
	return;
}

void __free_upstream(void *data)
{
	commit_data_t *ptr = data;
	free(ptr->summary);
	free(ptr->commit_id);
	free(ptr);
}

void __free_rhel(void *data)
{
	rhel_data_t *ptr = data;
	free(ptr->rhel.summary);
	free(ptr->rhel.commit_id);
	free(ptr->o_subject);
	free(ptr->author_email);
	list_destroy(ptr->upstream_ref);
	free(ptr);
}

int __hash_match(const void *s1, const void *s2)
{
	return !(strcmp(s1, s2));
}

char *__re_match(const char regex[], const char *input)
{
	regex_t re;
	regmatch_t *matches;
	size_t ngroups, i;
	int ret;
	char *retstr = NULL;

	/* Compile regular expression */
	ret = regcomp(&re, regex, REG_EXTENDED|REG_NEWLINE|REG_ICASE);
	if (ret) {
		fprintf(stderr, "Could not compile regex\n");
		exit(EXIT_FAILURE);
	}

	ngroups = re.re_nsub + 1;
	matches = malloc(ngroups * sizeof(regmatch_t));

	/* Execute regular expression */
	ret = regexec(&re, input, ngroups, matches, 0);

	for (i = 0; i < ngroups; i++)
		if (matches[i].rm_so == -1)
			break;

	if (!ret) {
		size_t size = matches[i-1].rm_eo - matches[i-1].rm_so;
		retstr = strndup(input+matches[i-1].rm_so, size);
	}

	/* Free memory allocated to the pattern buffer by regcomp() */
	regfree(&re);

	return retstr;
}

void __git_error(const char *func, const char *msg, int exit_status)
{
	const git_error *e = giterr_last();

        fprintf(stderr, "%s: %s: error %d: %s\n",
		func, msg, e->klass, e->message);

	if (exit_status)
		exit(exit_status);
}


static inline char *__strdup(const char *string)
{
	size_t size = strlen(string);
	return strndup(string, size);
}

/* if set, limits rhel_load_data() commit list to the specified paths */
static int path_match = 0;
git_diff_options diffopts = GIT_DIFF_OPTIONS_INIT;

bool commit_modifies_paths(git_diff_options *diffopts,
			   git_commit * commit, git_repository *repo)
{
	git_tree *commit_tree = NULL, *parent_tree = NULL;
	git_commit *parent = NULL;
	git_diff *diff = NULL;
	bool ret = false;

	if (git_commit_parent(&parent, commit, 0) < 0) {
		__git_error(__func__, "git_commit_parent", 0);
		return false;
	}

	if (git_commit_tree(&commit_tree, commit) < 0) {
		__git_error(__func__, "git_commit_tree", 0);
		return false;
	}

	if (git_commit_tree(&parent_tree, parent) < 0) {
		__git_error(__func__, "git_commit_tree", 0);
		return false;
	}

	if (git_diff_tree_to_tree(&diff, repo,
				  parent_tree, commit_tree, diffopts) < 0) {
		__git_error(__func__, "git_diff_tree_to_tree", 0);
		return false;
	}

	/*
	 * If ndeltas is non-zero, this commit touches paths that the
	 * user is interested in.
	 */
	ret = !!git_diff_num_deltas(diff);
	git_diff_free(diff);

	return ret;
}

static void load_upstream_data(const char *repo_dir,
				 const char *range, list_t *list)
{
	int ret;
	git_repository *repo;
	git_revwalk *walker;
	git_oid oid;
	git_commit *commit = NULL;
	commit_data_t *upstream_commit = NULL;

	git_libgit2_init();

	ret = git_repository_open(&repo, repo_dir);
	if (ret < 0)
		__git_error(__func__, "git_repository_open", EXIT_FAILURE);

	ret = git_revwalk_new(&walker, repo);
	if (ret < 0)
		__git_error(__func__, "git_revwalk_new", EXIT_FAILURE);

	/*
	 * Be sure we'll be walking the history of the master branch,
	 * as it's not always guranteed it is the one checked out
	 * at the git_repository_open() time.
	 */
	ret = git_revwalk_push_ref(walker, "refs/heads/master");
	if (ret < 0)
		__git_error(__func__, "git_revwalk_push_ref", EXIT_FAILURE);

	ret = git_revwalk_push_range(walker, range);
	if (ret < 0)
		__git_error(__func__, "git_revwalk_push_range", EXIT_FAILURE);

	git_revwalk_sorting(walker, GIT_SORT_TIME | GIT_SORT_REVERSE);

	while (git_revwalk_next(&oid, walker) == 0) {
		ret = git_commit_lookup(&commit, repo, &oid);
		if (ret < 0) {
			__git_error(__func__, "git_commit_lookup", 0);
			continue;
		}

		if (path_match && !commit_modifies_paths(&diffopts, commit, repo))
			goto next;

		upstream_commit = calloc(1, sizeof(commit_data_t));

		upstream_commit->commit_id = __strdup(git_oid_tostr_s(git_commit_id(commit)));
		upstream_commit->summary = __strdup(git_commit_summary(commit));

		list_add_tail(list, upstream_commit);
next:
		git_commit_free(commit);
	}

	git_revwalk_free(walker);
	git_repository_free(repo);
	git_libgit2_shutdown();
}

static void load_rhel_data(const char *repo_dir, const char *range, list_t *list)
{
	int ret;
	git_repository *repo;
	git_revwalk *walker;
	git_oid oid;
	git_commit *commit = NULL;
	rhel_data_t *rh_commit = NULL;

	git_libgit2_init();

	ret = git_repository_open(&repo, repo_dir);
	if (ret < 0)
		__git_error(__func__, "git_repository_open", EXIT_FAILURE);

	ret = git_revwalk_new(&walker, repo);
	if (ret < 0)
		__git_error(__func__, "git_revwalk_new", EXIT_FAILURE);

	/*
	 * Be sure we'll be walking the history of the master branch,
	 * as it's not always guranteed it is the one checked out
	 * at the git_repository_open() time.
	 */
	ret = git_revwalk_push_ref(walker, rhel_ref);
	if (ret < 0)
		__git_error(__func__, "git_revwalk_push_ref", EXIT_FAILURE);

	ret = git_revwalk_push_range(walker, range);
	if (ret < 0)
		__git_error(__func__, "git_revwalk_push_range", EXIT_FAILURE);

	git_revwalk_sorting(walker, GIT_SORT_TIME | GIT_SORT_REVERSE);

	while (git_revwalk_next(&oid, walker) == 0) {
		const git_signature *author;
		char *str;

		ret = git_commit_lookup(&commit, repo, &oid);
		if (ret < 0) {
			__git_error(__func__, "git_commit_lookup", 0);
			continue;
		}

		if (path_match && !commit_modifies_paths(&diffopts, commit, repo))
			goto next;

		rh_commit = calloc(1, sizeof(rhel_data_t));
		/* skip tagging commits that are not originated from mail list */
		if ((str = __re_match("^O-Subject: (.*)$",
		     git_commit_message(commit))) != NULL) {
			rh_commit->o_subject = str;
		} else {
			free(rh_commit);
			goto next;
		}

		rh_commit->upstream_ref = calloc(1, sizeof(list_t));
		list_init(rh_commit->upstream_ref, NULL, __hash_match);

		/* most ordinary commits and cherry-picks will match here */
		if ((str = __re_match("^commit ([a-f0-9]{40})",
		     git_commit_message(commit))) != NULL)
			list_add_unique(rh_commit->upstream_ref, str);

		/*
		 * Some RHEL developers had used some flamboyant different
		 * ways to declare upstream references for their patches,
		 * like kenrel.org URLs, hand crafted headers, and whatnot.
		 * We try to get these here. Unfortunately, we cannot just get
		 * the most generic REGEX '[a-f0-9]{40}' in place to match the
		 * SHA-1 hashes, because that will match some of the Message-ID
		 * headers saved by patchwork, introducing another layer of
		 * complexity and false positives to sort out later.
		 */
		if ((str = __re_match("picked from .* ([a-f0-9]{40})",
		     git_commit_message(commit))) != NULL)
			list_add_unique(rh_commit->upstream_ref, str);

		if ((str = __re_match(".*kernel.org/.*([a-f0-9]{40})",
		     git_commit_message(commit))) != NULL)
			list_add_unique(rh_commit->upstream_ref, str);

		if ((str = __re_match("Upstrea.*: ([a-f0-9]{40})",
		     git_commit_message(commit))) != NULL)
			list_add_unique(rh_commit->upstream_ref, str);

		if ((str = __re_match("commit.* ([a-f0-9]{40})",
		     git_commit_message(commit))) != NULL)
			list_add_unique(rh_commit->upstream_ref, str);

		author = git_commit_author(commit);
		rh_commit->author_email = __strdup(author->email);
		rh_commit->rhel.commit_id = __strdup(git_oid_tostr_s(git_commit_id(commit)));
		rh_commit->rhel.summary = __strdup(git_commit_summary(commit));

		list_add_tail(list, rh_commit);
next:
		git_commit_free(commit);
	}

	git_revwalk_free(walker);
	git_repository_free(repo);
	git_libgit2_shutdown();
}

void print_upstream_list(list_t *list)
{
	lnode_t *node = list->head;

	for (int i = 0; i < list->size; i++) {
		commit_data_t *data = node->data;
		printf("%s %s\n", data->commit_id, data->summary);
		node = node->next;
	}
}

void print_rhel_list(list_t *list)
{
	lnode_t *node = list->head;

	for (int i = 0; i < list->size; i++) {
		rhel_data_t *data = node->data;
		printf("%s %s\n", data->rhel.commit_id, data->rhel.summary);

		if (data->o_subject)
			printf("\t\t -> %s\n", data->o_subject);

		if (data->author_email)
			printf("\t\t -> %s\n", data->author_email);

		if (data->upstream_ref->size > 0) {
			lnode_t *ptr = data->upstream_ref->head;
			printf("\t\t -> upstream ref:\n");
			for (int j=0; j < data->upstream_ref->size; j++) {
				printf("\t\t\t * %s\n", (char *)ptr->data);
				ptr = ptr->next;
			}
		}
		node = node->next;
	}
}

commit_data_t *lookup_upstream(list_t *list, const char *hash)
{
	lnode_t *node = list->head;

	for (int i = 0; i < list->size; i++) {
		commit_data_t *data = node->data;
		if (__hash_match(hash, data->commit_id))
			return data;
		node = node->next;
	}
	return NULL;
}

void print_rhel_only_list(list_t *rhel, bool short_hash)
{
	char hash[HASH_SZ];
	lnode_t *node = rhel->head;
	size_t size = (short_hash) ? SHASH_SZ : HASH_SZ;

	for (int i = 0; i < rhel->size; i++) {
		rhel_data_t *data = node->data;
		if (!data->upstream_ref->size) {
			memset(&hash, '\0', size);
			printf("%s %s\n",
				strncpy(hash, data->rhel.commit_id, size-1),
				data->rhel.summary);
		}
		node = node->next;
	}
}

void print_rhel_match_list(list_t *rhel, list_t *upstream, bool short_hash)
{
	lnode_t *node = rhel->head;
	char hash_r[HASH_SZ], hash_u[HASH_SZ];
	size_t size = (short_hash) ? SHASH_SZ : HASH_SZ;

	for (int i = 0; i < rhel->size; i++) {
		rhel_data_t *data = node->data;
		if (data->upstream_ref->size > 0) {
			lnode_t *ptr = data->upstream_ref->head;
			for (int j=0; j < data->upstream_ref->size; j++) {
				commit_data_t *uptr = lookup_upstream(upstream, ptr->data);
				if (uptr) {
					memset(&hash_u, '\0', size);
					memset(&hash_r, '\0', size);
					printf("%s %s %s\n",
						strncpy(hash_u, uptr->commit_id, size-1),
						strncpy(hash_r, data->rhel.commit_id, size-1),
						data->rhel.summary);
				}
				ptr = ptr->next;
			}
		}
		node = node->next;
	}
}

void print_rhel_and_refs(list_t *rhel, list_t *upstream, bool short_hash)
{
	char hash[HASH_SZ];
	lnode_t *node = rhel->head;
	size_t size = (short_hash) ? SHASH_SZ : HASH_SZ;

	for (int i = 0; i < rhel->size; i++) {
		rhel_data_t *data = node->data;
		memset(&hash, '\0', size);
		printf("* RHEL commit: %s %s\n",
			 strncpy(hash, data->rhel.commit_id, size-1),
			 data->rhel.summary);
		printf(" -     O-Subject: %s\n", data->o_subject);
		printf(" -   author addr: %s\n", data->author_email);
		if (data->upstream_ref->size > 0) {
			lnode_t *ptr = data->upstream_ref->head;
			printf(" - Upstream refs:\n");
			for (int j=0; j < data->upstream_ref->size; j++) {
				commit_data_t *uptr = lookup_upstream(upstream, ptr->data);
				if (uptr) {
					memset(&hash, '\0', size);
					printf("\t-> %s %s\n",
						strncpy(hash, uptr->commit_id, size-1),
						uptr->summary);
				} else {
					printf("\t-> %s\n", (char *)ptr->data);
				}
				ptr = ptr->next;
			}
		}
		node = node->next;
		printf("=================\n");
	}
}

typedef enum __rep_mode {
	RHEL_ONLY_PATCHES,
	UPSTREAM_MATCHES,
	__MODES,
} rep_mode_t;

int main(int argc, char *argv[])
{
	char *rhel_repo, *upstream_repo, *range;
	list_t upstream, rhel;
	int opt, preq = 0;
	rep_mode_t mode = __MODES;
	bool short_hash = true;

	while ((opt = getopt_long(argc, argv, s_opts, l_opts, NULL)) != -1) {
		switch (opt) {
		case 'a':
			opt = asprintf(&range, "%s..HEAD", optarg);
			preq += 1;
			break;
		case 'z':
			opt = asprintf(&rhel_ref, "refs/heads/%s", optarg);
			break;
		case 'r':
			list_init(&rhel, __free_rhel, NULL);
			rhel_repo = strdup(optarg);
			preq += 1;
			break;
		case 'u':
			list_init(&upstream, __free_upstream, NULL);
			upstream_repo = strdup(optarg);
			preq += 1;
			break;
		case 'f':
			short_hash = false;
			break;
		case 'm':
			mode = UPSTREAM_MATCHES;
			break;
		case 'o':
			mode = RHEL_ONLY_PATCHES;
			break;
		case 'h':
			print_usage(argv[0]);
			return -1;
		case '?':
		case -1:
			/* done with options */
			break;
		}
	}

	if (preq < 3) {
		print_usage(argv[0]);
		return -1;
	}

	if (optind < argc) {
		diffopts.pathspec.strings = &argv[optind];
		diffopts.pathspec.count = argc - optind;
		path_match = 1;
	}

	load_rhel_data(rhel_repo, range, &rhel);
	load_upstream_data(upstream_repo, range, &upstream);

	switch (mode) {
	case RHEL_ONLY_PATCHES:
		print_rhel_only_list(&rhel, short_hash);
		break;
	case UPSTREAM_MATCHES:
		print_rhel_match_list(&rhel, &upstream, short_hash);
		break;
	default:
		print_rhel_and_refs(&rhel, &upstream, short_hash);
		break;
	}

	list_destroy(&upstream);
	list_destroy(&rhel);

	return 0;
}

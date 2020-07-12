/*
 * rhel-find-fixes: parses the RHEL git log via revision walk and compares it
 *		    with upstream entries carrying "Fixes" tag to find out
 *		    matches with the commits backported into RHEL and
 *		    produce a fix-candidate patch-list.
 *
 * Copyright (c) 2019 Rafael Aquini, Red Hat.
 */
#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <stdarg.h>
#include <stddef.h>
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
#include <time.h>
#include "asprintf.h"

/*
 * constants to help on assembling SHA-1 hash strings + NULL terminator
 */
#define SHASH_SZ	17
#define HASH_SZ		41
#define MAX_THREADS     4

//TODO ask how is best way to not use this global

int thread_index = 0; 
pthread_mutex_t lock;

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

static void list_init(list_t *list, void (*destroy)(void *data),
			int (*match)(const void *key1, const void *key2))
{
	list->size = 0;
	list->destroy = destroy;
	list->match = match;
	list->head = NULL;
	list->tail = NULL;
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
	char *id;
	char *summary;
	list_t *refs;
	char* rhel_log;
};

typedef struct rhel_data rhel_data_t;
struct rhel_data {
	char *author_email;
	char *o_subject;
	commit_data_t commit;
};

typedef struct upstream_data upstream_data_t;
struct upstream_data {
	commit_data_t *fix;
	commit_data_t commit;
};
/* Description of long options for getopt_long. */
static const struct option l_opts[] = {
	{ "ancestor",	 1, NULL, 'a' },
	{ "upstream",	 1, NULL, 'u' },
	{ "rhel",	 1, NULL, 'r' },
	{ "rhel-ref",	 1, NULL, 'z' },
	{ "short-hash",	 0, NULL, 's' },
	{ "check-merged",0, NULL, 'c' },
	{ "help",	 0, NULL, 'h' },
};

/* Description of short options for getopt_long. */
static const char* const s_opts = "a:u:r:z:d:sch";

/* */
static const char* const usage_template =
	"Usage: %s [ options ] [path,...]\n"
	"*  -a, --ancestor <git-tag>  : common ancestor tag between RHEL and upstream\n"
	"*  -u, --upstream <git-repo> : load linux upstream data from git\n"
	"*  -r, --rhel <git-repo>     : load RHEL data from git\n"
	"   -z, --rhel-ref <branch>   : look into a RHEL ref different than master\n"
	"   -s, --short-hash          : toggle to print out short SHA-1 hashes\n"
	"   -c, --check-merged        : look into the RHEL logs to try and see if each patch has already been merged.\n"
	"   -h, --help                : Print this information screen.\n"
	" Options marked with (*) must be declared, others are optional\n";

char *rhel_ref = "refs/heads/master";

static void print_usage(const char *program_name)
{
	fprintf(stderr, usage_template, program_name);
	return;
}

#define ERROR_EXIT(msg)							 \
	do {								 \
		perror(msg);						 \
		exit(EXIT_FAILURE);					 \
	} while (0)

#ifdef DEBUG
#define DPRINTF(...)    fprintf(stderr, __VA_ARGS__)
#define GIT_ERROR_DEBUG(msg)						 \
	do {								 \
		__git_error_print(__FILE__, __LINE__, msg);		 \
	} while (0)
#else
#define DPRINTF(...)
#define GIT_ERROR_DEBUG(msg)
#endif

#define GIT_ERROR_EXIT(msg)						 \
	do {								 \
		__git_error_print(__FILE__, __LINE__, msg);		 \
		exit(EXIT_FAILURE);					 \
	} while (0)

void __git_error_print(const char* file, int line, const char *msg)
{
		const git_error *err = giterr_last();
		char *str = NULL;

		asprintf(&str, "[%s:%d] %s: %s (error: %d)\n",
			  file, line, msg, err->message, err->klass);
		fprintf(stderr, str);
		if (str)
			free(str);
}

void __free_upstream(void *data)
{
	upstream_data_t *ptr = data;
	free(ptr->commit.summary);
	free(ptr->commit.id);
	free(ptr->fix);
	free(ptr);
}

int __hash_match(const void *s1, const void *s2)
{
	return !(strcmp(s1, s2));
}

static regex_t fixes_re;
static regex_t backports_re;
static regex_t kernelurl_re;
static regex_t upstream_re;

void init_regular_expressions(void)
{
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
	if (regcomp(&fixes_re, "^[:space:]*Fixes. ([a-f0-9]+)",
		    REG_EXTENDED|REG_NEWLINE|REG_ICASE))
		ERROR_EXIT("Could not compile regex\n");

	if (regcomp(&backports_re, "commit ([0-9a-f]{40})",
		    REG_EXTENDED|REG_NEWLINE|REG_ICASE))
		ERROR_EXIT("Could not compile regex\n");

	if (regcomp(&kernelurl_re, ".*kernel.org/.*([a-f0-9]{40})",
		    REG_EXTENDED|REG_NEWLINE|REG_ICASE))
		ERROR_EXIT("Could not compile regex\n");

	if (regcomp(&upstream_re, "Upstrea.*: ([a-f0-9]{40})",
		    REG_EXTENDED|REG_NEWLINE|REG_ICASE))
		ERROR_EXIT("Could not compile regex\n");
}

void free_regular_expressions(void)
{
	regfree(&fixes_re);
	regfree(&backports_re);
	regfree(&kernelurl_re);
	regfree(&upstream_re);
}

/* This will only return the last sub-expression in the match, for now */
char *regex_match(regex_t *re, const char *input)
{
	regmatch_t *matches;
	size_t ngroups, i;
	int ret;
	char *retstr = NULL;

	ngroups = re->re_nsub + 1;
	matches = malloc(ngroups * sizeof(regmatch_t));

	/* Execute regular expression */
	ret = regexec(re, input, ngroups, matches, 0);

	for (i = 0; i < ngroups; i++)
		if (matches[i].rm_so == -1)
			break;

	if (!ret) {
		size_t size = matches[i-1].rm_eo - matches[i-1].rm_so;
		retstr = strndup(input+matches[i-1].rm_so, size);
	}

	free(matches);

	return retstr;
}

static char *__strdup(const char *string)
{
	size_t size = strlen(string);
	return strndup(string, size);
}

static void load_upstream_fixes(const char *repo_dir,
				const char *range, list_t *list)
{
	int ret;
	git_repository *repo;
	git_revwalk *walker;
	git_oid oid;

	//printf("Inside load_upstream");
	git_libgit2_init();
	//git_libgit2_opts(GIT_OPT_ENABLE_CACHING,1);
	ret = git_repository_open(&repo, repo_dir);
	if (ret < 0)
		GIT_ERROR_EXIT("git_repository_open");

	ret = git_revwalk_new(&walker, repo);
	if (ret < 0)
		GIT_ERROR_EXIT("git_revwalk_new");

	/*
	 * Be sure we'll be walking the history of the master branch,
	 * as it's not always guranteed it is the one checked out
	 * at the git_repository_open() time.
	 */
	ret = git_revwalk_push_ref(walker, "refs/heads/master");
	if (ret < 0)
		GIT_ERROR_EXIT("git_revwalk_push_ref");

	ret = git_revwalk_push_range(walker, range);
	if (ret < 0)
		GIT_ERROR_EXIT("git_revwalk_push_range");

	git_revwalk_sorting(walker, GIT_SORT_TIME | GIT_SORT_REVERSE);

	while (git_revwalk_next(&oid, walker) == 0) {
		char *str;
		size_t len;
		git_oid aux;
		git_commit *c = NULL;
		git_commit *commit = NULL;
		upstream_data_t *upstream;
		commit_data_t *fix;

		ret = git_commit_lookup(&commit, repo, &oid);
		if (ret < 0) {
			GIT_ERROR_DEBUG("git_commit_lookup");
			continue;
		}

		/* TODO: refactor this to grab multiple Fixes tags, if it's the case */
		if ((str = regex_match(&fixes_re,
					git_commit_message(commit))) == NULL)
			goto next;

		if ((len = strlen(str)) < 4)
			goto next;

		if ((ret = git_oid_fromstrp(&aux, str)) != 0)
			goto next;

		if ((ret = git_commit_lookup_prefix(&c, repo, &aux, len)) != 0)
			goto next;

		fix = calloc(1, sizeof(commit_data_t));
		fix->id = __strdup(git_oid_tostr_s(git_commit_id(commit)));
		fix->summary = __strdup(git_commit_summary(commit));

		upstream = calloc(1, sizeof(upstream_data_t));
		upstream->commit.id = __strdup(git_oid_tostr_s(git_commit_id(c)));
		upstream->commit.summary = __strdup(git_commit_summary(c));
		upstream->fix = fix;

		list_add_tail(list, upstream);

		git_commit_free(c);
next:
		git_commit_free(commit);
		free(str);
	}

	git_revwalk_free(walker);
	git_repository_free(repo);
	git_libgit2_shutdown();
}

/* if set, limits rhel_load_data() commit list to the specified paths */
static int path_match = 0;
git_diff_options diffopts = GIT_DIFF_OPTIONS_INIT;


bool commit_modifies_paths(git_diff_options *diffopts, git_commit *commit)
{
	int i, ret, ret2;
	git_tree *commit_tree = NULL, *parent_tree = NULL;
	git_tree_entry *commit_ent, *parent_ent;
	git_commit *parent = NULL;
	bool modified = false;

	/* If no paths were specified, all commits are interesting. */
	if (diffopts->pathspec.count == 0)
		return true;

	if (git_commit_parent(&parent, commit, 0) < 0) {
		GIT_ERROR_DEBUG("git_commit_parent");
		return false;
	}

	if (git_commit_tree(&commit_tree, commit) < 0) {
		GIT_ERROR_DEBUG("git_commit_tree");
		git_commit_free(parent);
		return false;
	}

	if (git_commit_tree(&parent_tree, parent) < 0) {
		GIT_ERROR_DEBUG("git_commit_tree");
		git_tree_free(commit_tree);
		git_commit_free(parent);
		return false;
	}

	for (i = 0; i < (int)diffopts->pathspec.count; i++) {
		ret = git_tree_entry_bypath(&parent_ent, parent_tree,
		diffopts->pathspec.strings[i]);
		ret2 = git_tree_entry_bypath(&commit_ent, commit_tree,
		diffopts->pathspec.strings[i]);
		/*
		 * If the path only exists in one revision, that means
		 * it was "changed".  If it doesn't exist in either
		 * revision, skip it.
		 */
		if (ret == GIT_ENOTFOUND && ret2 == GIT_ENOTFOUND)
			continue;
		/* path exists in only commit or parent */
		if (ret != ret2) {
			 modified = true;
		} else {
		/* If the file changed, then the hash will change */
		if (!git_oid_equal(git_tree_entry_id(parent_ent),
					git_tree_entry_id(commit_ent)))
			modified = true;
		}
		if (!ret)
			git_tree_entry_free(parent_ent);
		if (!ret2)
			git_tree_entry_free(commit_ent);
		if (modified)
			break;
	}

	git_tree_free(commit_tree);
	git_tree_free(parent_tree);
	git_commit_free(parent);
	return modified;
}

static void load_rhel_backports(const char *repo_dir, const char *range, list_t *list)
{
	int ret;
	git_repository *repo;
	git_revwalk *walker;
	git_oid oid;

	//printf("Inside load_rhel");
	git_libgit2_init();
	ret = git_repository_open(&repo, repo_dir);
	if (ret < 0)
		GIT_ERROR_EXIT("git_repository_open");

	ret = git_revwalk_new(&walker, repo);
	if (ret < 0)
		GIT_ERROR_EXIT("git_revwalk_new");

	/*
	 * Be sure we'll be walking the history of the master branch,
	 * as it's not always guranteed it is the one checked out
	 * at the git_repository_open() time.
	 */
	ret = git_revwalk_push_ref(walker, rhel_ref);
	if (ret < 0)
		GIT_ERROR_EXIT("git_revwalk_push_ref");

	ret = git_revwalk_push_range(walker, range);
	if (ret < 0)
		GIT_ERROR_EXIT("git_revwalk_push_range");

	git_revwalk_sorting(walker, GIT_SORT_TIME | GIT_SORT_REVERSE);

	while (git_revwalk_next(&oid, walker) == 0) {
		const char *commit_msg = NULL;
		const char *str = NULL;
		git_commit *commit = NULL;

		ret = git_commit_lookup(&commit, repo, &oid);
		if (ret < 0) {
			GIT_ERROR_DEBUG("git_commit_lookup");
			continue;
		}

		if (path_match && !commit_modifies_paths(&diffopts, commit))
			goto next;

		commit_msg = git_commit_message(commit);

		if ((str = regex_match(&backports_re, commit_msg)) != NULL)
			list_add_unique(list, str);

		if ((str = regex_match(&kernelurl_re, commit_msg)) != NULL)
			list_add_unique(list, str);

		if ((str = regex_match(&upstream_re, commit_msg)) != NULL)
			list_add_unique(list, str);

		list_add_unique(list, __strdup(git_oid_tostr_s(git_commit_id(commit))));
next:
		git_commit_free(commit);
	}
	git_revwalk_free(walker);
	git_repository_free(repo);
	git_libgit2_shutdown();
}

lnode_t *list_lookup(list_t *list, const char *hash)
{
	lnode_t *node = list->head;

	for (int i = 0; i < list->size; i++) {
		upstream_data_t *data = node->data;
		if (__hash_match(hash, data->commit.id))
			return node;

		node = node->next;
	}
	return NULL;
}

lnode_t *list_lookup2(list_t *list, const char *hash)
{
	lnode_t *node = list->head;

	for (int i = 0; i < list->size; i++) {
		if (__hash_match(hash, node->data))
			return node;

		node = node->next;
	}
	return NULL;
}

void match_and_filter_fixes(list_t *rhel_list, list_t *upstream, list_t *fixes)
{
	lnode_t *node = rhel_list->head;

	/*
	 * 1st pass: walk over RHEL-backport list matching with their
	 * related upstream references, and populate a fix-candidates
	 * list from the initial matches.
	 */
	for (int i = 0; i < rhel_list->size; i++) {
		const char *hash = node->data;
		lnode_t *ptr = list_lookup(upstream, hash);
		if (ptr) {
			upstream_data_t *data = ptr->data;
			commit_data_t *candidate = data->fix;
			list_add_tail(fixes, candidate);
		}
		node = node->next;
	}

	/*
	 * 2nd pass: walk over the fix-candidates list populated earlier,
	 * and remove fixes that are already backported into RHEL
	 */
	node = fixes->head;
	for (int i = 0; i < fixes->size; i++) {
		commit_data_t *fix = node->data;
		lnode_t *n = list_lookup2(rhel_list, fix->id);
		if (n) {
			lnode_t *ptr = node;
			node = node->next;
			list_del_node(fixes, ptr);
			continue;
		}
		node = node->next;
	}
}


char* write_file(FILE* f)
{
	char* rhel_log = malloc(sizeof(char)*100);
	strcpy(rhel_log,"    ***Mentions in RHEL log->:");
    	char c = fgetc(f);
       	int i = 0;	
   	while (c != '\n' && c != EOF) {	 
        	rhel_log[i+30] = c; 
		c = fgetc(f); 
		i++;
	}
	rhel_log[i+30] = '\0';
	return rhel_log;	
}

void create_grep(char* command,char* hash, FILE* path)
{
	int i = 0;
	int j = 0;
	char c;
	
	while(command[i] != '"'){
		i++;
	}
	i++;

	for(j = 0;j<40;j++){
		command[i] = hash[j];
		i++;
	}
	i+=5;
	c = fgetc(path);
	while(c != '\n' && c != EOF){
		command[i] = c;
		i++;
		c = fgetc(path);
	}
	command[i] = '\0';
}

void create_file(char* command, char* hash)
{
	int i = 0;
	int j = 0;
	
	while(command[i] != '\0'){
		i++;
	}
	i-=40;
	for(j = 0;j<40;j++){
		command[i] = hash[j];
		i++;
	}
	command[i] = '\0';
}

typedef struct log_args{
	char*rhel_repo;
	char*upstream_repo;
	list_t fixes;
}log_args_t;

commit_data_t* get_fix(list_t fixes, int index){
	lnode_t* node = fixes.head;
	int track = 0;
	while(track < index){
		node = node->next;
		track++;
	}
	return node->data;
}

inline void print_fix(commit_data_t* fix){
	printf("%.*s %s\n%s\n",HASH_SZ-1,fix->id,fix->summary,fix->rhel_log);
}

void* check_rhel_log(void* arg){
	log_args_t* args = (log_args_t*)arg;
	char* rhel_path = args->rhel_repo;
	char* upstream_path = args->upstream_repo;
	list_t fixes = args->fixes;
	commit_data_t* fix;
	FILE* output;
	char* command = malloc(sizeof(char)*200);
	char* filecommand = malloc(sizeof(char)*200);
	strcpy(filecommand,"cd ");
	strcat(filecommand,upstream_path);
	strcat(filecommand," && git diff-tree --no-commit-id --name-only -r bd40b17ca49d7d110adf456e647701ce74de2241\0");
	strcpy(command,"cd ");
	strcat(command,rhel_path);
	strcat(command, " && git log --grep=\"bd40b17ca49d7d110adf456e647701ce74de2241\" -- \0");
	//printf("thread started");
	pthread_mutex_lock(&lock);
	while(thread_index < fixes.size){
		fix = get_fix(fixes, thread_index);
		//printf("%d / %d\n", thread_index+1, fixes.size);
		thread_index++;
		pthread_mutex_unlock(&lock);
		create_file(filecommand, fix->id);
		output = popen(filecommand, "r");
		if(output == NULL){
			printf("failure");
		}
		create_grep(command,fix->id, output);
		pclose(output);
		output = popen(command, "r");
		//printf("   %s\n   %s\n",filecommand,command);
		if(output != NULL){
			fix->rhel_log = write_file(output);
			pclose(output);
		}else{
			printf("FAILED popen\n");
		}
		print_fix(fix);
		pthread_mutex_lock(&lock);
	}
	pthread_mutex_unlock(&lock);
	free(command);
	free(filecommand);
	return NULL;
}

void print_fixes(list_t *fixes, bool short_hash)
{
	int size = (short_hash) ? SHASH_SZ : HASH_SZ;
	lnode_t *node = fixes->head;
		
	for (int i = 0; i < fixes->size; i++) {
		commit_data_t *fix = node->data;
		printf("%.*s %s\n", size-1,
			fix->id, fix->summary);
		node = node->next;
	}
}



typedef struct thread_args{
	char* repo;
	char* range;
	list_t list;
}thread_args_t;


void* thread_start(void* args){
	thread_args_t* a = (thread_args_t*)args;
	load_rhel_backports(a->repo,a->range,&a->list);
	return NULL;
}

int main(int argc, char *argv[])
{
	char *upstream_repo, *range;
	list_t upstream_fixes, candidates;
	int opt, preq = 0;
	bool short_hash = false;
	bool check_merged = false;
	time_t start = time(0);
	
	pthread_t rhel_thread;
	thread_args_t args;

	while ((opt = getopt_long(argc, argv, s_opts, l_opts, NULL)) != -1) {
		switch (opt) {
		case 'a':
			asprintf(&range, "%s..HEAD", optarg);
			asprintf(&args.range,"%s..HEAD",optarg);
			preq += 1;
			break;
		case 'r':
			//list_init(&rhel_backports, NULL, __hash_match);
			//rhel_repo = strdup(optarg);
			list_init(&args.list, NULL, __hash_match);
			args.repo = strdup(optarg);
			preq += 1;
			break;
		case 'u':
			list_init(&upstream_fixes, __free_upstream, NULL);
			upstream_repo = strdup(optarg);
			preq += 1;
			break;
		case 'z':
			asprintf(&rhel_ref, "refs/heads/%s", optarg);
			break;
		case 's':
			short_hash = true;
			break;
		case 'c':
			check_merged = true;
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

	init_regular_expressions();
	pthread_create(&rhel_thread,NULL,thread_start,(void*)&args);
	
	load_upstream_fixes(upstream_repo, range, &upstream_fixes);
	
	pthread_join(rhel_thread,NULL);

	list_init(&candidates, NULL, NULL);
	match_and_filter_fixes(&args.list, &upstream_fixes, &candidates);
	if(check_merged == true && short_hash == true){
		printf("Cannot use -c and -s turning off merge check");
		check_merged = false;
	}
	if(check_merged == true){
		if(pthread_mutex_init(&lock, NULL) != 0){
			return -1;
		}
		pthread_t thread_pool[MAX_THREADS];
		log_args_t thread_pool_args[MAX_THREADS];
		int i;
		for(i=0;i<MAX_THREADS;i++){
			thread_pool_args[i] = (log_args_t){args.repo,upstream_repo,candidates};
			pthread_create(&thread_pool[i],NULL,check_rhel_log,&thread_pool_args[i]);
		}
		for(i=0;i<MAX_THREADS;i++){
			pthread_join(thread_pool[i],NULL);
		}
	}else{
		print_fixes(&candidates, short_hash);
	}
	list_destroy(&upstream_fixes);
	list_destroy(&args.list);
	list_destroy(&candidates);
	pthread_mutex_destroy(&lock);
	free_regular_expressions();
	
	time_t end = time(0);
	printf("%lu\n", (unsigned long)end - (unsigned long)start);
	
	return 0;
}

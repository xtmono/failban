#define _XOPEN_SOURCE 700
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <sys/queue.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <regex.h>
#include <syslog.h>
#include "enum_str.h"
#include "ini.h"

#define MAX(x, y) (((x) > (y)) ? (x) : (y))
#define MIN(x, y) (((x) < (y)) ? (x) : (y))

// Logger
#define LOG(LOG_LEVEL, ...)	syslog(LOG_LEVEL, __VA_ARGS__)

// Type definitions
#define MAX_PATTERN_SIZE	1024
#define MAX_MSG_SIZE		2048
#define MAX_ARGS			256
#define PORTS_MAX			8
#define CONF_FILE			"/etc/failban.conf"

ENUM_TO_STR(proto_type, PROTO_SSH, PROTO_HTTP, PROTO_IKEV2, PROTO_MAX);
typedef enum proto_type proto_type_t;

typedef struct {
	char *proto;
	char *port;
} proto_port_t;

typedef struct {
	int verbose;

	time_t bantime;
	time_t findtime;
	int maxretry;

	char *banfile;
	char *nfttable;
	char *nftchain;

	char *proto_search[PROTO_MAX];
	proto_port_t *proto_ports[PROTO_MAX][PORTS_MAX];
} config_t;

typedef struct log_entry {
	time_t epoch;
	char *ip;
	proto_type_t proto;
	STAILQ_ENTRY(log_entry) entries;
} log_entry_t;
typedef STAILQ_HEAD(log_head, log_entry) log_head_t;

// Global variables
config_t config;
log_head_t log_list;
pid_t logread_pid = 0;
volatile sig_atomic_t proc_running = 1;

// Implementations
int exec_prog(char **output, const char *program, ...) {
	int pipefd[2];
	if (pipe(pipefd) == -1) {
		perror("pipe");
		return -1;
	}

	pid_t pid = fork();
	if (pid == -1) {
		perror("fork");
		close(pipefd[STDIN_FILENO]);
		close(pipefd[STDOUT_FILENO]);
		return -1;
	} else if (pid == 0) {
		// Child process
		close(pipefd[STDIN_FILENO]);
		if (dup2(pipefd[STDOUT_FILENO], STDOUT_FILENO) == -1) {
			perror("dup2 child stdout");
			exit(EXIT_FAILURE);
		}
		if (dup2(pipefd[STDOUT_FILENO], STDERR_FILENO) == -1) {
			perror("dup2 child stderr");
			exit(EXIT_FAILURE);
		}
		close(pipefd[STDOUT_FILENO]);

		char *argv[MAX_ARGS];
		int i = 0;

		va_list args;
		va_start(args, program);
		argv[i++] = (char *)program;
		while (i < MAX_ARGS - 1 && (argv[i] = va_arg(args, char *)) != NULL)
			i++;
		argv[i] = NULL;
		va_end(args);

		execvp(program, argv);

		perror("execvp");
		exit(EXIT_FAILURE);
	} else {
		// Parent process
		close(pipefd[STDOUT_FILENO]);

		ssize_t len = MAX_MSG_SIZE;
		char *console = malloc(len + 1);

		ssize_t bytes_read = 0;
		ssize_t total_read = 0;
		while (1) {
			bytes_read = read(pipefd[STDIN_FILENO], console + total_read, len - total_read);
			if (bytes_read <= 0)
				break;
			total_read += bytes_read;

			if (len <= total_read) {
				len *= 2;
				char *temp = realloc(console, len + 1);
				if (temp == NULL)
					break;
				console = temp;
			}
		}
		console[total_read] = '\0';
		if (output != NULL)
			*output = console;
		else
			free(console);

		close(pipefd[STDIN_FILENO]);

		int status;
		waitpid(pid, &status, 0);
		if (WIFEXITED(status))
			return WEXITSTATUS(status);
		return -1;
	}
}

static void config_proto_ports(const char *value, proto_port_t *proto_ports[]) {
	char *str = strdup(value);
	char *saveptr, *saveptr_in;

	int i = 0;
	for (char *token = strtok_r(str, ", \t", &saveptr);
			token != NULL && i < PORTS_MAX; token = strtok_r(NULL, ", \t", &saveptr)) {
		char *proto = strtok_r(token, ":", &saveptr_in);
		char *port = strtok_r(NULL, ":", &saveptr_in);
		if (proto != NULL && port != NULL) {
			proto_port_t *pp = malloc(sizeof(proto_port_t));
			proto_ports[i++] = pp;

			pp->proto = malloc(strlen(proto) + 1);
			strcpy(pp->proto, proto);
			pp->port = malloc(strlen(port) + 1);
			strcpy(pp->port, port);
		}
	}

	free(str);
}

static int config_handler(void* user, const char* section, const char* name, const char* value) {
	config_t* config = (config_t*)user;

	if (strcmp(section, "") == 0) {
		if (strcmp(name, "verbose") == 0) {
			config->verbose = atoi(value);
		} else if (strcmp(name, "bantime") == 0) {
			config->bantime = (time_t)atoi(value);
		} else if (strcmp(name, "findtime") == 0) {
			config->findtime = (time_t)atoi(value);
		} else if (strcmp(name, "maxretry") == 0) {
			config->maxretry = atoi(value);
		} else if (strcmp(name, "banfile") == 0) {
			config->banfile = malloc(strlen(value) + 1);
			strcpy(config->banfile, value);
		} else if (strcmp(name, "nfttable") == 0) {
			config->nfttable = malloc(strlen(value) + 1);
			strcpy(config->nfttable, value);
		} else if (strcmp(name, "nftchain") == 0) {
			config->nftchain = malloc(strlen(value) + 1);
			strcpy(config->nftchain, value);
		}
	} else if (strcmp(section, "proto_search") == 0) {
		if (strcmp(name, "ssh") == 0) {
			config->proto_search[PROTO_SSH] = malloc(strlen(value) + 1);
			strcpy(config->proto_search[PROTO_SSH], value);
		} else if (strcmp(name, "http") == 0) {
			config->proto_search[PROTO_HTTP] = malloc(strlen(value) + 1);
			strcpy(config->proto_search[PROTO_HTTP], value);
		} else if (strcmp(name, "ikev2") == 0) {
			config->proto_search[PROTO_IKEV2] = malloc(strlen(value) + 1);
			strcpy(config->proto_search[PROTO_IKEV2], value);
		}
	} else if (strcmp(section, "proto_ports") == 0) {
		if (strcmp(name, "ssh") == 0) {
			config_proto_ports(value, &config->proto_ports[PROTO_SSH][0]);
		} else if (strcmp(name, "http") == 0) {
			config_proto_ports(value, &config->proto_ports[PROTO_HTTP][0]);
		} else if (strcmp(name, "ikev2") == 0) {
			config_proto_ports(value, &config->proto_ports[PROTO_IKEV2][0]);
		}
	}

	return 1;
}

static void config_free(config_t* config) {
	if (config->banfile != NULL)
		free(config->banfile);
	if (config->nfttable != NULL)
		free(config->nfttable);
	if (config->nftchain != NULL)
		free(config->nftchain);

	for (proto_type_t proto = 0; proto < PROTO_MAX; proto++) {
		if (config->proto_search[proto] != NULL)
			free(config->proto_search[proto]);

		proto_port_t *pp;
		for (int i = 0; i < PORTS_MAX && (pp = config->proto_ports[proto][i]) != NULL; i++) {
			free(pp->port);
			free(pp->proto);
			free(pp);
		}
	}
}

void ban_ip(const char *ip, const char *proto, const char *port) {
	char pattern[MAX_PATTERN_SIZE];
	snprintf(pattern, sizeof(pattern), ".* ip saddr %s %s dport %s .*drop", ip, proto, port);

	regex_t regex;
	char errbuf[256];
	int retcode = regcomp(&regex, pattern, REG_EXTENDED);
	if (retcode != 0) {
		regerror(retcode, &regex, errbuf, sizeof(errbuf));
		LOG(LOG_ERR, "Regex compile error: %s, %s", errbuf, pattern);
		exit(EXIT_FAILURE);
	}

	char *output = NULL;
	if (exec_prog(&output, "nft", "list", "chain", "inet", config.nfttable, config.nftchain, NULL) == 0) {
		char *saveptr;
		for (char *line = strtok_r(output, "\n", &saveptr);
				line != NULL; line = strtok_r(NULL, "\n", &saveptr)) {
			if (regexec(&regex, line, 0, NULL, 0) == 0)
				goto end;
		}
	}

	exec_prog(NULL, "nft", "add", "rule", "inet", config.nfttable, config.nftchain,
			"iifname", "wan", "ip", "saddr", ip, proto, "dport", port, "counter", "drop", NULL);
	LOG(LOG_WARNING, "Add to blacklist for %s:%s (%s)", ip, port, proto);

end:
	if (output != NULL)
		free(output);
	regfree(&regex);
}

void unban_ip(const char *ip, const char *proto, const char *port) {
	char pattern[MAX_PATTERN_SIZE];
	snprintf(pattern, sizeof(pattern), ".* ip saddr %s %s dport %s .*handle (\\d+)", ip, proto, port);

	regex_t regex;
	char errbuf[256];
	int retcode = regcomp(&regex, pattern, REG_EXTENDED);
	if (retcode != 0) {
		regerror(retcode, &regex, errbuf, sizeof(errbuf));
		LOG(LOG_ERR, "Regex compile error: %s, %s", errbuf, pattern);
		exit(EXIT_FAILURE);
	}

	char *output = NULL;
	if (exec_prog(&output, "nft", "--handle", "list", "chain", "inet", config.nfttable, config.nftchain, NULL) == 0) {
		char *saveptr;
		regmatch_t regmatch[2];
		for (char *line = strtok_r(output, "\n", &saveptr);
				line != NULL; line = strtok_r(NULL, "\n", &saveptr)) {
			if (regexec(&regex, line, 2, regmatch, 0) == 0) {
				int len = regmatch[1].rm_eo - regmatch[1].rm_so;
				char *handle = malloc(len + 1);
				strncpy(handle, line + regmatch[1].rm_so, len);
				handle[len] = '\0';

				exec_prog(NULL, "nft", "delete", "rule", "inet", config.nfttable, config.nftchain,
						"handle", handle, NULL);
				LOG(LOG_WARNING, "Delete to blacklist for %s:%s (%s)", ip, port, proto);

				free(handle);
				goto end;
			}
		}
	}

end:
	if (output != NULL)
		free(output);
	regfree(&regex);
}

void clear_log_list() {
    log_entry_t *ent, *next;
    for (ent = STAILQ_FIRST(&log_list); ent != NULL; ent = next) {
        next = STAILQ_NEXT(ent, entries);
        free(ent->ip);
        free(ent);
    }
	STAILQ_INIT(&log_list);
}

void release_log_list(void) {
	time_t now = time(NULL);

	log_entry_t *ent, *tmp_ent, *prev = NULL;
	for (ent = STAILQ_FIRST(&log_list); ent != NULL; ) {
		tmp_ent = STAILQ_NEXT(ent, entries);
		if (now > ent->epoch + config.findtime) {
			if (prev == NULL) {
				STAILQ_REMOVE_HEAD(&log_list, entries);
			} else {
				prev->entries.stqe_next = ent->entries.stqe_next;
				if (ent->entries.stqe_next == NULL)
					log_list.stqh_last = &prev->entries.stqe_next;
			}
			if (config.verbose)
				LOG(LOG_DEBUG, "Delete bantime: %lld, ip: %s, proto: %d", (long long)ent->epoch, ent->ip, ent->proto);
			free(ent->ip);
			free(ent);
		} else {
			prev = ent;
		}
		ent = tmp_ent;
	}
}

void clear_ban_list(void) {
	unlink(config.banfile);
}

void release_ban_list(void) {
	FILE *fp = fopen(config.banfile, "r+");
	if (fp == NULL)
		return;

	char line[MAX_MSG_SIZE];
	long long epoch;
	char ip[32], proto_str[16];

	time_t now = time(NULL);

	long write_pos = 0;
	while (fgets(line, sizeof(line), fp) != NULL) {
		sscanf(line, "%lld %31s %15s", &epoch, ip, proto_str);

		if (now > (time_t)epoch + config.bantime) {
			proto_type_t proto = str_to_proto_type(proto_str);
			proto_port_t *pp;
			for (int i = 0; i < PORTS_MAX && (pp = config.proto_ports[proto][i]) != NULL; i++)
				unban_ip(ip, pp->proto, pp->port);
		} else {
			long read_pos = ftell(fp);
			fseek(fp, write_pos, SEEK_SET);
			fputs(line, fp);
			write_pos = ftell(fp);
			fseek(fp, read_pos, SEEK_SET);
		}
	}
	fseek(fp, write_pos, SEEK_SET);
	if (ftruncate(fileno(fp), write_pos) == -1) {
		LOG(LOG_WARNING, "Failed to truncate ban file");
	}

	fclose(fp);
}

void update_ban_list(time_t epoch, char *ip, proto_type_t proto) {
	FILE *fp = fopen(config.banfile, "r+");
	if (fp == NULL) {
		fp = fopen(config.banfile, "w+");
		if (fp == NULL)
			return;
	}

	char line[MAX_MSG_SIZE];
	long long f_epoch;
	char f_ip[32], f_proto[16];

	long write_pos = 0;
	while (fgets(line, sizeof(line), fp) != NULL) {
		sscanf(line, "%lld %31s %15s", &f_epoch, f_ip, f_proto);

		if (strcmp(f_ip, ip) != 0 || strcmp(f_proto, proto_type_to_str(proto)) != 0) {
			long read_pos = ftell(fp);
			fseek(fp, write_pos, SEEK_SET);
			fputs(line, fp);
			write_pos = ftell(fp);
			fseek(fp, read_pos, SEEK_SET);
		}
	}
	fseek(fp, write_pos, SEEK_SET);
	if (ftruncate(fileno(fp), write_pos) == -1) {
		LOG(LOG_WARNING, "Failed to truncate ban file");
	}

	char datetime[MAX_PATTERN_SIZE];
	struct tm *ts = localtime(&epoch);
	strftime(datetime, sizeof(datetime), "%Y-%m-%dT%H:%M:%S", ts);
	fprintf(fp, "%lld %s %s %s\n", (long long)epoch, ip, proto_type_to_str(proto), datetime);

	fclose(fp);
}

void check_failures(const proto_type_t proto, const char *line) {
	regex_t regex;
	regmatch_t regmatch[2];
	int retcode, len = 0;
	char errbuf[256];

	char datetime[MAX_PATTERN_SIZE] = { 0 };
	const char *date_pattern =
	    "^([[:alpha:]]{3}[[:space:]]+[[:alpha:]]{3}[[:space:]]+[0-9]{1,2}[[:space:]]"
		"+[0-9]{2}:[0-9]{2}:[0-9]{2}[[:space:]]+[0-9]{4})";
	retcode = regcomp(&regex, date_pattern, REG_EXTENDED);
	if (retcode != 0) {
		regerror(retcode, &regex, errbuf, sizeof(errbuf));
		LOG(LOG_ERR, "Regex compile error: %s, %s", errbuf, date_pattern);
		exit(EXIT_FAILURE);
	}
	retcode = regexec(&regex, line, 2, regmatch, 0);
	if (retcode == 0) {
		len = regmatch[1].rm_eo - regmatch[1].rm_so;
		strncpy(datetime, line + regmatch[1].rm_so, len);
		datetime[len] = '\0';
	}
	regfree(&regex);

	char *ip = NULL;
	const char *ip_pattern = "([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})";
	retcode = regcomp(&regex, ip_pattern, REG_EXTENDED);
	if (retcode != 0) {
		regerror(retcode, &regex, errbuf, sizeof(errbuf));
		LOG(LOG_ERR, "Regex compile error: %s, %s", errbuf, ip_pattern);
		exit(EXIT_FAILURE);
	}

	const char *cursor = line;
	while (1) {
		retcode = regexec(&regex, cursor, 2, regmatch, 0);
		if (retcode != 0)
			break;

		len = regmatch[1].rm_eo - regmatch[1].rm_so;
		if (ip != NULL)
			free(ip);
		ip = malloc(len + 1);
		strncpy(ip, cursor + regmatch[1].rm_so, len);
		ip[len] = '\0';
		cursor += regmatch[1].rm_eo;
	}
	regfree(&regex);
	if (ip == NULL) {
		LOG(LOG_WARNING, "Invalid IP addr format: %s", line);
		return;
	}

	struct tm tm_info;
	if (strptime(datetime, "%a %b %d %H:%M:%S %Y", &tm_info) == NULL) {
		LOG(LOG_WARNING, "Invalid datetime format: %s", datetime);
		free(ip);
		return;
	}
	time_t epoch = mktime(&tm_info);

	time_t now = time(NULL);
	if (now > epoch + config.findtime) {
		if (config.verbose)
			LOG(LOG_DEBUG, "Skip old log entry: %s, ip: %s, proto: %d", datetime, ip, proto);
		free(ip);
		return;
	}

	log_entry_t *new_ent = malloc(sizeof(log_entry_t));
	new_ent->epoch = epoch;
	new_ent->ip = ip;
	new_ent->proto = proto;
	STAILQ_INSERT_TAIL(&log_list, new_ent, entries);
	if (config.verbose)
		LOG(LOG_DEBUG, "Insert bantime: %lld, ip: %s, proto: %d", (long long)epoch, ip, proto);

	int count = 0;
	log_entry_t *ent;
	STAILQ_FOREACH(ent, &log_list, entries) {
		if (strcmp(ent->ip, ip) == 0 && ent->proto == proto)
			count++;
	}

	if (count > config.maxretry) {
		proto_port_t *pp;
		for (int i = 0; i < PORTS_MAX && (pp = config.proto_ports[proto][i]) != NULL; i++)
			ban_ip(ip, pp->proto, pp->port);
		update_ban_list(epoch, ip, proto);
	}
}

int logread() {
	int pipefd[2];
	if (pipe(pipefd) == -1) {
		perror("pipe");
		return -1;
	}

	logread_pid = fork();
	if (logread_pid == -1) {
		perror("fork");
		close(pipefd[STDIN_FILENO]);
		close(pipefd[STDOUT_FILENO]);
		return -1;
	} else if (logread_pid == 0) {
		// Child process
		close(pipefd[STDIN_FILENO]);
		if (dup2(pipefd[STDOUT_FILENO], STDOUT_FILENO) == -1) {
			perror("dup2");
			exit(EXIT_FAILURE);
		}
		close(pipefd[STDOUT_FILENO]);

		execlp("logread", "logread", "-f", NULL);

		perror("execlp");
		exit(EXIT_FAILURE);
	} else {
		// Parent process
		close(pipefd[STDOUT_FILENO]);

		FILE *pipe_fp = fdopen(pipefd[STDIN_FILENO], "r");
		if (pipe_fp == NULL) {
			perror("fdopen");
			close(pipefd[STDIN_FILENO]);
			return -1;
		}

		regex_t regex[PROTO_MAX];
		char errbuf[256];
		for (proto_type_t i = 0; i < PROTO_MAX; i++) {
			int retcode = regcomp(&regex[i], config.proto_search[i], REG_EXTENDED);
			if (retcode != 0) {
				regerror(retcode, &regex[i], errbuf, sizeof(errbuf));
				LOG(LOG_ERR, "Regex compile error: %s, %s", errbuf, config.proto_search[i]);
				exit(EXIT_FAILURE);
			}
		}

		fd_set readfds;
		struct timeval timeout;
		char line[MAX_MSG_SIZE];
		time_t last_cleanup = time(NULL);

		while (proc_running) {
			FD_ZERO(&readfds);
			FD_SET(pipefd[STDIN_FILENO], &readfds);
			timeout.tv_sec = config.findtime / 2;
			timeout.tv_usec = 0;

			time_t now = time(NULL);
			if (now >= last_cleanup + timeout.tv_sec) {
				if (config.verbose)
					LOG(LOG_DEBUG, "Periodic cleanup of log_list and ban_list");
				release_log_list();
				release_ban_list();
				last_cleanup = now;
			}

			switch (select(pipefd[STDIN_FILENO] + 1, &readfds, NULL, NULL, &timeout)) {
				case -1:
					perror("select");
					goto cleanup;
				case 0:
					// Timeout, loop will repeat and check time above
					break;
				default:
					if (fgets(line, sizeof(line), pipe_fp) != NULL) {
						size_t len = strlen(line);
						if (len > 0 && line[len - 1] == '\n')
							line[len - 1] = '\0';
						if (config.verbose)
							printf("LOG: %s\n", line);
						for (proto_type_t i = 0; i < PROTO_MAX; i++) {
							if (regexec(&regex[i], line, 0, NULL, 0) == 0) {
								if (config.verbose)
									LOG(LOG_DEBUG, "Matched proto: %d", i);
								check_failures(i, line);
							}
						}
					} else {
						if (feof(pipe_fp) || ferror(pipe_fp)) {
							LOG(LOG_ERR, "logread pipe closed or error");
							goto cleanup;
						}
					}
					break;
			}
		}

cleanup:
		for (proto_type_t i = 0; i < PROTO_MAX; i++)
			regfree(&regex[i]);
		fclose(pipe_fp);

		if (proc_running == 0) {
			int status;
			waitpid(logread_pid, &status, 0);
			return 0;
		} else {
			return -1;
		}
	}
}

static void create_nftables() {
	exec_prog(NULL, "nft", "add", "chain", "inet", config.nfttable, config.nftchain,
			"{ type filter hook prerouting priority mangle; policy accept; }", NULL);
}

static void delete_nftables() {
	if (exec_prog(NULL, "nft", "list", "chain", "inet", config.nfttable, config.nftchain, NULL) == 0) {
		LOG(LOG_INFO, "Clear all blacklist");
		exec_prog(NULL, "nft", "delete", "chain", "inet", config.nfttable, config.nftchain, NULL);
	}
}

static void cleanup_proc(int signo) {
	(void)signo;

	// Stop main proc
	proc_running = 0;

	// Stop child proc
	if (logread_pid > 0)
		kill(logread_pid, SIGTERM);

	clear_log_list();
	clear_ban_list();

	delete_nftables();

	LOG(LOG_INFO, "Exit failban");
	closelog();

	config_free(&config);

	exit(EXIT_SUCCESS);
}

int main(int argc, char *argv[]) {
	const char *config_file = CONF_FILE;
	int opt;

	// Parse command line options
	while ((opt = getopt(argc, argv, "e:h")) != -1) {
		switch (opt) {
			case 'e':
				config_file = optarg;
				break;
			case 'h':
				fprintf(stderr, "Usage: %s [-e config_file] [-h]\n", argv[0]);
				fprintf(stderr, "Options:\n");
				fprintf(stderr, "  -e <file>  Path to configuration file (default: %s)\n", CONF_FILE);
				fprintf(stderr, "  -h         Show this help message\n");
				return 0;
			default:
				fprintf(stderr, "Usage: %s [-e config_file] [-h]\n", argv[0]);
				return 1;
		}
	}

	openlog("failban", LOG_CONS | LOG_PID, LOG_DAEMON);
	LOG(LOG_INFO, "Start failban");

	signal(SIGHUP, cleanup_proc);
	signal(SIGINT, cleanup_proc);
	signal(SIGTERM, cleanup_proc);

	if (ini_parse(config_file, config_handler, &config) < 0) {
		LOG(LOG_ERR, "Can't load '%s'", config_file);
		printf("Can't load '%s'\n", config_file);
		return 1;
	}

	// Reset nftables chain
	delete_nftables();
	create_nftables();

	// Reset ban list file
	clear_ban_list();

	// Initialize log list
	STAILQ_INIT(&log_list);

	// Find and block bad IPs from system log
	logread();

	return 0;
}

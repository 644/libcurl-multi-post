#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <curl/multi.h>
#include <limits.h>
#include <regex.h>
#include <unistd.h>

char *get_proxy(const char *filename)
{
	FILE *f;
	size_t lineno = 0;
	size_t selectlen;
	char selected[256];
	char current[256];
	selected[0] = '\0';
	struct timespec spec;
	clock_gettime(CLOCK_REALTIME, &spec);
	srand48(spec.tv_nsec);
	f = fopen(filename, "r");
	while(fgets(current, sizeof(current), f)) {
		if(drand48() < 1.0 / ++lineno)
			strcpy(selected, current);
	}
	fclose(f);
	selectlen = strlen(selected);
	if(selectlen > 0 && selected[selectlen-1] == '\n')
		selected[selectlen-1] = '\0';

	return strdup(selected);
}

static int my_trace(CURL *handle, curl_infotype type, char *data, size_t size, void *userp)
{
	const char *text;
	(void)handle;
	(void)userp;
	regex_t regex;
	int reti;
	char msgbuf[100];
  
	reti = regcomp(&regex, "Connection #[0-9]* to host secure.runescape.com left intact", 0);
	if(reti)
		fprintf(stderr, "Could not compile regex\n");

	switch(type) {
	case CURLINFO_TEXT:
		reti = regexec(&regex, data, 0, NULL, 0);
		if(!reti)
			printf("|%s", data);

		regfree(&regex);
	default:
		return 0;
	}
}

static void init(CURLM *cm, int i, char *url)
{
	char *rp = get_proxy("/root/proxy_list.txt");
	char proxy_ip[32];
	snprintf(proxy_ip, 32, "socks5://%s", rp);
	CURL *eh = curl_easy_init();
	struct curl_slist *chunk = NULL;
	char displayname[] = "displayname=";
	char nurl[128];
	snprintf(nurl, 128, "https://secure.runescape.com/m=account-creation/a=235/g=oldscape/check_displayname.ajax?displayname=%s", url);
  
	chunk = curl_slist_append(chunk, "Host: secure.runescape.com");
	chunk = curl_slist_append(chunk, "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:58.0) Gecko/20100101 Firefox/58.0");
	chunk = curl_slist_append(chunk, "Accept: application/json, text/javascript, */*; q=0.01");
	chunk = curl_slist_append(chunk, "Accept-Language: en-US,en;q=0.5");
	chunk = curl_slist_append(chunk, "Referer: https://secure.runescape.com/m=account-creation/a=235/g=oldscape/create_account");
	chunk = curl_slist_append(chunk, "Content-Type: application/x-www-form-urlencoded; charset=UTF-8");
	chunk = curl_slist_append(chunk, "X-Requested-With: XMLHttpRequest");
	curl_easy_setopt(eh, CURLOPT_HTTPHEADER, chunk);
	curl_easy_setopt(eh, CURLOPT_PROXY, proxy_ip);
	curl_easy_setopt(eh, CURLOPT_HEADER, 0L);
	curl_easy_setopt(eh, CURLOPT_TIMEOUT, 15L);
	curl_easy_setopt(eh, CURLOPT_URL, nurl);
	curl_easy_setopt(eh, CURLOPT_PRIVATE, nurl);
	curl_easy_setopt(eh, CURLOPT_POSTFIELDS, displayname);
	curl_easy_setopt(eh, CURLOPT_DEBUGFUNCTION, my_trace);
	curl_easy_setopt(eh, CURLOPT_VERBOSE, 1L);
 
	curl_multi_add_handle(cm, eh);
}
 
int main(int argc, char **argv)
{
	#define MAX argc-1
	#define CNT argc-1
	CURLM *cm;
	CURLMsg *msg;
	long L;
	unsigned int C = 0;
	int M, Q, U = -1;
	fd_set R, W, E;
	struct timeval T;
  
	curl_global_init(CURL_GLOBAL_ALL);
	
	cm = curl_multi_init();
	curl_multi_setopt(cm, CURLMOPT_MAXCONNECTS, (long)MAX);
	
	for(C = 0; C < MAX; ++C)
		init(cm, C, argv[C+1]);
 
	while(U) {
		curl_multi_perform(cm, &U);
 
		if(U) {
			FD_ZERO(&R);
			FD_ZERO(&W);
			FD_ZERO(&E);
 
			if(curl_multi_fdset(cm, &R, &W, &E, &M)) {
				fprintf(stderr, "E: curl_multi_fdset\n");
				return EXIT_FAILURE;
			}
 
			if(curl_multi_timeout(cm, &L)) {
				fprintf(stderr, "E: curl_multi_timeout\n");
				return EXIT_FAILURE;
			}

			if(L == -1)
				L = 100;
 
			if(M == -1) {
				sleep((unsigned int)L / 1000);
			}
			else {
				T.tv_sec = L/1000;
				T.tv_usec = (L%1000)*1000;
 
				if(0 > select(M + 1, &R, &W, &E, &T)) {
					fprintf(stderr, "E: select(%i,,,,%li): %i: %s\n", M + 1, L, errno, strerror(errno));
					return EXIT_FAILURE;
				}
			}
		}
 
		while((msg = curl_multi_info_read(cm, &Q))) {
			if(msg->msg == CURLMSG_DONE) {
				char *url;
				CURL *e = msg->easy_handle;
				curl_easy_getinfo(msg->easy_handle, CURLINFO_PRIVATE, &url);
				if(msg->data.result != 0)
					printf("PROXY FAILURE\n");

				curl_multi_remove_handle(cm, e);
				curl_easy_cleanup(e);
			}
			else {
				fprintf(stderr, "E: CURLMsg (%d)\n", msg->msg);
			}
			if(C < CNT) {
				C++;
				init(cm, C, argv[C+1]);
				U++;
			}
		}
	}
	curl_multi_cleanup(cm);
	curl_global_cleanup();
	return EXIT_SUCCESS;
}

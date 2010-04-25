#include "agent_private.h"

#include <unistd.h>
#include <sys/select.h>


int agent_wait(agent *a)
{
	fd_set rfds;
	struct timeval tv;
	int ret;

	/* Wait for 1 second */
	tv.tv_sec = 1;
	tv.tv_usec = 0;

	FD_ZERO(&rfds);
	FD_SET(a->in, &rfds);
	ret = select(a->in+1, &rfds, NULL, NULL, &tv);

	if (ret == -1) {
		perror("select");
		return 2;
	} else if (ret == 0) {
		return 1;
	} else {
		/* Data arrived */
		return AGENT_OK;
	}
}

/* Will either fail or complete successfully returning 0 */
static int agent_read(const int fd, void *data, size_t len) 
{
	static char buff[300];
	static char *buff_pos = buff;
	static int buffered = 0;
	void *data_pos = data;
	int ret;


	for (;;) {
		/* Copy all buffered data */
		if (buffered) {
			const size_t to_go = buffered < len ? buffered : len;
			memcpy(data_pos, buff_pos, to_go);
			len -= to_go;
			buffered -= to_go;
			data_pos += to_go;
			buff_pos += to_go;			
		}
		if (len == 0)
			return AGENT_OK;

		/* Need some more; buffered is empty now */
		buff_pos = buff;
		buffered = read(fd, buff, sizeof(buff));
		if (buffered == 0) {
			return AGENT_ERR_DISCONNECT;
		}

		if (buffered < 0) {
			return AGENT_ERR_DISCONNECT;
		}
	}

	ret = read(fd, data, len);
	if (ret == 0) {
		/* End-of-file - second end was closed! */
		return AGENT_ERR_DISCONNECT;
	}
	printf("len: %zd ret: %d\n", len, ret);
	assert(ret == len);
	if (ret != len) 
		return 1;

/*	fd_set rfds;
	FD_ZERO(&rfds);
	FD_SET(fd, &rfds);
	if (select(fd+1, &rfds, NULL, NULL, NULL) == -1) {
		perror("select");
		return 1;
	}*/
	return AGENT_OK;
}

/* Will either fail or complete successfully returning 0 */
static int agent_write(const int fd, const void *buf, const size_t len)
{
	int ret;
	ret = write(fd, buf, len);
	if (ret == -1) {
		/* Probably errno == EPIPE. That is - second
		 * end disconnected */
		return AGENT_ERR_DISCONNECT;
	}
	assert(ret == len);
	if (ret != len) 
		return 1;
	return AGENT_OK;
}

#define _send(field)	  \
	do { \
		ret = agent_write(fd, &a->shdr.field, sizeof(a->shdr.field)); \
		if (ret != 0) \
			return ret; \
	} while (0);

#define _recv(field)	  \
	do { \
		ret = agent_read(fd, &a->rhdr.field, sizeof(a->rhdr.field)); \
		if (ret != 0) \
			return ret; \
	} while (0);

int agent_hdr_send(const agent *a) 
{
	const int fd = a->out;
	ssize_t ret = 1;

	_send(protocol_version);
	_send(type);
	_send(status);
	_send(int_arg);
	_send(num_arg);

	ret = agent_write(fd, a->shdr.str_arg, sizeof(a->shdr.str_arg));
	if (ret != 0) {
		return ret;
	}

	return AGENT_OK;
}

int agent_hdr_recv(agent *a) 
{
	const int fd = a->in;
	ssize_t ret = 1;
	
	_recv(protocol_version);
	_recv(type);
	_recv(status);
	_recv(int_arg);
	_recv(num_arg);

	ret = agent_read(fd, a->rhdr.str_arg, sizeof(a->rhdr.str_arg));
	if (ret != 0) {
		return ret;
	}

	if (a->rhdr.protocol_version != AGENT_PROTOCOL_VERSION) {
		return AGENT_ERR_PROTOCOL_MISMATCH;
	}
	return AGENT_OK;
}

int agent_hdr_set(agent *a, int status, 
                  int int_arg, const num_t *num_arg, const char *str_arg)
{
	assert(a);

	a->shdr.protocol_version = AGENT_PROTOCOL_VERSION;
	a->shdr.status = status;
	a->shdr.int_arg = int_arg;
	
	if (num_arg) {
		a->shdr.num_arg = *num_arg;
	} else {
		a->shdr.num_arg = num_i(0);
	}

	if (str_arg) {
		const int length = strlen(str_arg);
		assert(length < sizeof(a->shdr.str_arg));
		if (length >= sizeof(a->shdr.str_arg))
			return 1;
		strncpy(a->shdr.str_arg, str_arg, sizeof(a->shdr.str_arg) - 1);
	} else {
		memset(a->shdr.str_arg, 0, sizeof(a->shdr.str_arg));
	}
	

	return AGENT_OK;
}

int agent_query(agent *a, int request)
{
	int ret;

	/* Prepare header struct; 
	 * don't touch alternate parameters */
	a->shdr.type = request;
	ret = agent_hdr_send(a);
	if (ret != 0) {
		a->error = 1;
		return ret;
	}


	/* Might hang? */
	ret = agent_hdr_recv(a);
	if (ret != 0) {
		a->error = 1;
		return ret;
	}

	return a->rhdr.status;
}

void agent_hdr_debug(const struct agent_header *hdr)
{
	printf("{Proto: %08X Type: %d Status: %d IArg: %d SArg: %s NArg: ", 
	       hdr->protocol_version, hdr->type, hdr->status, hdr->int_arg, hdr->str_arg);
	num_print_dec(hdr->num_arg);
	printf("}\n");
}


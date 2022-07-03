/* Creates/opens a TUN interface and relays data to a given end point.

For creating TUN interfaces, root privileges are needed.  They are not needed
for using it, if the TUN interface has sufficient access rights.

On GNU/Linux the ip command can be used to create a TUN device:
$ sudo ip tuntap add tun0 mode tun user <username> group <groupname>

The above command creates a TUN device with the name tun0 and assigns the user
<username> and group <groupname> to able to use it for reading/writing.
*/


#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <signal.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <event.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#define LOG(...) \
	(void)fprintf(stderr, __VA_ARGS__)

/* MTU_MAX supported */
#define MTU_MAX 9216
#define CHNL_MAX 4

/* main event loop */
static struct event_base *ev_base;

/* events for reading and writing TUN interface */
static struct event *ev_treads[CHNL_MAX];
static struct event *ev_twrites[CHNL_MAX];

/* events for sending and receiving from UDP socket */
static struct event *ev_swrites[CHNL_MAX];
static struct event *ev_sreads[CHNL_MAX];

/* Descriptors the TUN interface and UDP socket */
static int tun;
static int sock;

struct Buffer {
	ssize_t size;
	char data[MTU_MAX];
};

/* buffer for data read from TUN */
static struct Buffer ins[CHNL_MAX];

/* buffer for data wrote to TUN */
static struct Buffer outs[CHNL_MAX];

/* Catch a signal and quit the event loop */
static void event_sig_cb(evutil_socket_t fd, short flags, void *cls)
{
	int sig = fd;

	switch (fd) {
	case SIGINT:
	case SIGTERM:
		break;
	default:
		assert(0);
	}
	event_base_loopexit(ev_base, 0);
}

static struct sockaddr_in destaddr;
struct sockaddr_in bindaddr;
uint16_t destport;
uint16_t bindport;

/* read from the TUN and schedule a write to the sock */
static void ev_tread_cb(evutil_socket_t tun, short flags, void *cls)
{
	unsigned chnl = (uintptr_t)cls;
	struct event *ev_tread = ev_treads[chnl];
	struct event *ev_swrite = ev_swrites[chnl];
	struct Buffer *in = &ins[chnl];

	assert(chnl < CHNL_MAX);
	assert(0 == (EV_TIMEOUT & flags));
	assert(0 != (EV_READ & flags));

	in->size = read(tun, &in->data[0], sizeof(in->data));
	if (in->size <= 0) {
		LOG("tun read ret: %zd\n",  in->size);
		event_add(ev_tread, 0);
		return;
	}
	assert(in->size < sizeof(in->data));
	/* write to the socket */
	event_add(ev_swrite, 0);
}

static void ev_swrite_cb(evutil_socket_t fd, short flags, void *cls)
{
	ssize_t ret;
	unsigned chnl = (uintptr_t)cls;
	struct event *ev_tread = ev_treads[chnl];
	struct Buffer *in = &ins[chnl];

	assert(chnl < CHNL_MAX);
	assert(0 == (EV_TIMEOUT & flags));
	assert(0 != (EV_WRITE & flags));

	ret = sendto(sock, &in->data[0], in->size, 0, (const struct sockaddr *)&destaddr, sizeof(destaddr));
	if (-1 == ret)
		LOG("sock send ret: %zd\n", ret);
	/* resume reading from TUN */
	event_add(ev_tread, 0);
}

/* read data from the sock and schedule a write to TUN */
static void ev_sread_cb(evutil_socket_t tun, short flags, void *cls)
{
	unsigned chnl = (uintptr_t)cls;
	struct event *ev_sread = ev_sreads[chnl];
	struct event *ev_twrite = ev_twrites[chnl];
	struct Buffer *out = &outs[chnl];

	assert(chnl < CHNL_MAX);
	assert(0 == (EV_TIMEOUT & flags));
	assert(0 != (EV_READ & flags));

	out->size = recvfrom(sock, &out->data[0], sizeof(out->data), 0, 0, 0);
	if (out->size <= 0 || out->size == sizeof(out->data)) {
		LOG("sock read ret:%zd\n", out->size);
		event_add(ev_sread, 0);
		return;
	}
	/* write to the socket */
	event_add(ev_twrite, 0);
}

static void ev_twrite_cb(evutil_socket_t fd, short flags, void *cls)
{
	ssize_t ret;
	unsigned chnl = (uintptr_t)cls;
	struct event *ev_sread= ev_sreads[chnl];
	struct Buffer *out = &outs[chnl];

	assert(chnl < CHNL_MAX);
	assert(0 == (EV_TIMEOUT & flags));
	assert(0 != (EV_WRITE & flags));

	ret = write(tun, &out->data[0], out->size);
	if (ret <= 0)
		LOG("tun write ret: %zd", ret);
	/* resume reading from socket */
	event_add(ev_sread, 0);
}

/* Opens the TUN device so that we can read/write to it.  If we do not have
   CAP_SYS_NETADMIN capability, we are restricted to use the TUN device
   allocated for us.  Note: the code in this function is taken from
   http://backreference.org/2010/03/26/tuntap-interface-tutorial/
*/
static int open_tun(const char *dev)
{
	struct ifreq ifr = {};
	int fd, err;

	if ((fd = open("/dev/net/tun", O_RDWR)) < 0)
		return fd;

	/* Flags: IFF_TUN   - TUN device (no Ethernet headers)
	 *        IFF_TAP   - TAP device
	 *
	 *        IFF_NO_PI - Do not provide packet information
	*/
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
	strncpy(ifr.ifr_name, dev, IFNAMSIZ);

	if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
		close(fd);
		return err;
	}
	return fd;
}

/* creates and configures an UDP socket to the tunnel end point */
static int create_udpsock(const char *bindipstr, const char *bindportstr,
		const char *destipstr, const char *destportstr)
{
	int sock;
	int flags;
	int ret;

	if (1 != sscanf(destportstr, "%hu", &destport)) {
		LOG("Invalid port: %s\n", destportstr);
		return -1;
	}
	if (1 != sscanf(bindportstr, "%hu", &bindport)) {
		LOG("Invalid port: %s\n", bindportstr);
		return -2;
	}
	ret = inet_pton(AF_INET, bindipstr, &bindaddr.sin_addr);
	if (1 != ret) {
		LOG("Invalid bind IP address or not support: %s, ret: %d\n", bindipstr, ret);
		return -3;
	}
	ret = inet_pton(AF_INET, destipstr, &destaddr.sin_addr);
	if (1 != ret) {
		LOG("Invalid destination IP address or not support: %s, ret: %d\n", destipstr, ret);
		return -4;
	}
	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock < 0)
		return sock;
	destaddr.sin_family = AF_INET;
	bindaddr.sin_family = AF_INET;
	destaddr.sin_port = htons(destport);
	bindaddr.sin_port = htons(bindport);
	ret = bind(sock, (const struct sockaddr *)&bindaddr, sizeof(bindaddr));
	LOG("sock bind: %d\n", ret);
	assert(0 == ret);
	/* make socket non blocking */
	flags = fcntl(sock, F_GETFL);
	assert(0 <= flags);
	flags |= O_NONBLOCK;
	ret = fcntl(sock, F_SETFL, flags);
	assert(-1 != ret);
	return sock;
}

int main (int argc, const char *argv[])
{
	struct event_config *ev_cfg;
	struct event *ev_sigint;
	struct event *ev_sigterm;
	const char *tun_name;
	const char *bindipstr;
	const char *bindportstr;
	const char *destipstr;
	const char *destportstr;
	int ret;

	if (argc < 6) {
		LOG("ttun tun_dev IP port DEST-IP dest-port\n");
		return 1;
	}
	tun_name = argv[1];
	bindipstr = argv[2];
	bindportstr = argv[3];
	destipstr = argv[4];
	destportstr = argv[5];
	tun = -1;
	sock = -1;
	ev_sigint = 0;
	ev_sigterm = 0;
	/* initialize libevent */
	event_enable_debug_mode();
	ev_cfg = event_config_new();
	assert(0 != ev_cfg);
	/* EV_FEATURE_O1: O(1) event triggering */
	ret = event_config_require_features(ev_cfg, EV_FEATURE_O1);
	assert(0 == ret);
	/* EV_FEATURE_FDS: both sockets and files can be used */
	ret = event_config_require_features(ev_cfg, EV_FEATURE_FDS);
	assert(0 == ret);
	ev_base = event_base_new_with_config(ev_cfg);
	assert(0 != ev_base);
	/* event for catching interrupt signal */
	ev_sigint = evsignal_new(ev_base, SIGINT, &event_sig_cb, 0);
	ret = evsignal_add(ev_sigint, 0);
	assert(0 == ret);
	ev_sigterm = evsignal_new(ev_base, SIGTERM, &event_sig_cb, 0);
	ret = evsignal_add(ev_sigterm, 0);
	assert(0 == ret);
	/* create the UDP sock */
	sock = create_udpsock(bindipstr, bindportstr, destipstr, destportstr);
	if (sock < 0) {
		ret = 2;
		goto cleanup;
	}
	tun = open_tun(tun_name);
	if (tun < 0) {
		ret =3;
		goto cleanup;
	}

	for (int i = 0; i != CHNL_MAX; i++) {
		void *cls = (void *)(uintptr_t)i;
		ev_treads[i] = event_new(ev_base, tun, EV_READ, &ev_tread_cb, cls);
		ev_sreads[i] = event_new(ev_base, sock, EV_READ, &ev_sread_cb, cls);
		ev_twrites[i] = event_new(ev_base, tun, EV_WRITE, &ev_twrite_cb, cls);
		ev_swrites[i] = event_new(ev_base, sock, EV_WRITE, &ev_swrite_cb, cls);
		assert(0 != ev_treads[i]);
		assert(0 != ev_sreads[i]);
		assert(0 != ev_twrites[i]);
		assert(0 != ev_swrites[i]);
		/* only add read events; write events are added after reading */
		ret = event_add(ev_treads[i], 0);
		assert(0 == ret);
		ret = event_add(ev_sreads[i], 0);
		assert(0 == ret);
	}
	ret = event_base_dispatch(ev_base);
	assert(0 == ret);

cleanup:
	if (0 <= tun)
		close(tun);
	if (0 <= sock)
		close(sock);
#define event_free_not_null(ev) if (ev) event_free(ev)
	event_free_not_null(ev_sigint);
	event_free_not_null(ev_sigterm);
	for (int i = 0; i != CHNL_MAX; i++) {
		event_free_not_null(ev_treads[i]);
		event_free_not_null(ev_twrites[i]);
		event_free_not_null(ev_sreads[i]);
		event_free_not_null(ev_swrites[i]);
	}
#undef event_free_not_null
	event_base_free(ev_base);
	event_config_free(ev_cfg);
	return ret;
}

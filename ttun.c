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
#include <errno.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <unistd.h>
#include <event.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#define LOG(...) \
	fprintf(stderr, __VA_ARGS__)

/* MTU_MAX supported */
#define MTU_MAX 9216
#define CHNL_MAX 2

/* main event loop */
static struct event_base *ev_bases[CHNL_MAX];

/* events for reading and writing TUN interface */
static struct event *ev_treads[CHNL_MAX];
static struct event *ev_twrites[CHNL_MAX];

/* events for sending and receiving from UDP socket */
static struct event *ev_swrites[CHNL_MAX];
static struct event *ev_sreads[CHNL_MAX];

/* Descriptors the TUN interface and UDP socket */
static int tuns[CHNL_MAX];
static int socks[CHNL_MAX];

struct Buffer {
	ssize_t size;
	char data[MTU_MAX];
};

/* buffer for data read from TUN */
static struct Buffer ins[CHNL_MAX];

/* buffer for data wrote to TUN */
static struct Buffer outs[CHNL_MAX];

static struct sockaddr_in destaddr;
struct sockaddr_in bindaddr;
uint16_t destport;
uint16_t bindport;

/* read from the TUN and schedule a write to the sock */
static void ev_tread_cb(evutil_socket_t _, short flags, void *cls)
{
	unsigned chnl = (uintptr_t)cls;
	struct event *ev_tread = ev_treads[chnl];
	struct event *ev_swrite = ev_swrites[chnl];
	int tun = tuns[chnl];
	struct Buffer *in = &ins[chnl];

	assert(chnl < CHNL_MAX);
	assert(0 == (EV_TIMEOUT & flags));
	assert(0 != (EV_READ & flags));

	in->size = read(tun, &in->data[0], sizeof(in->data));
	//LOG("tun read chnl: %d, size: %zd\n", chnl, in->size);
	if (in->size <= 0) {
		LOG("tun read ret: %zd, errno: %d\n", in->size, errno);
		event_add(ev_tread, 0);
		return;
	}
	assert(in->size < sizeof(in->data));
	/* write to the socket */
	event_add(ev_swrite, 0);
}

static void ev_swrite_cb(evutil_socket_t _, short flags, void *cls)
{
	ssize_t ret;
	unsigned chnl = (uintptr_t)cls;
	struct event *ev_tread = ev_treads[chnl];
	int sock = socks[chnl];
	struct Buffer *in = &ins[chnl];

	assert(chnl < CHNL_MAX);
	assert(0 == (EV_TIMEOUT & flags));
	assert(0 != (EV_WRITE & flags));

	ret = sendto(sock, &in->data[0], in->size, 0, (const struct sockaddr *)&destaddr, sizeof(destaddr));
	//LOG("sock sendto chnl: %d, ret: %zd\n", chnl, ret);
	if (-1 == ret)
		LOG("sock send ret: %zd, errno: %d\n", ret, errno);
	/* resume reading from TUN */
	event_add(ev_tread, 0);
}

/* read data from the sock and schedule a write to TUN */
static void ev_sread_cb(evutil_socket_t _, short flags, void *cls)
{
	unsigned chnl = (uintptr_t)cls;
	struct event *ev_sread = ev_sreads[chnl];
	struct event *ev_twrite = ev_twrites[chnl];
	int sock = socks[chnl];
	struct Buffer *out = &outs[chnl];

	assert(chnl < CHNL_MAX);
	assert(0 == (EV_TIMEOUT & flags));
	assert(0 != (EV_READ & flags));

	out->size = recvfrom(sock, &out->data[0], sizeof(out->data), 0, 0, 0);
	//LOG("sock recvfrom chnl: %d, size: %zd\n", chnl, out->size);
	if (out->size <= 0 || out->size == sizeof(out->data)) {
		LOG("sock read ret: %zd, errno: %d\n", out->size, errno);
		event_add(ev_sread, 0);
		return;
	}
	/* write to the socket */
	event_add(ev_twrite, 0);
}

static void ev_twrite_cb(evutil_socket_t _, short flags, void *cls)
{
	ssize_t ret;
	unsigned chnl = (uintptr_t)cls;
	struct event *ev_sread= ev_sreads[chnl];
	int tun = tuns[chnl];
	struct Buffer *out = &outs[chnl];

	assert(chnl < CHNL_MAX);
	assert(0 == (EV_TIMEOUT & flags));
	assert(0 != (EV_WRITE & flags));

	ret = write(tun, &out->data[0], out->size);
	//LOG("tun write chnl: %d, ret: %zd\n", chnl, ret);
	if (ret <= 0)
		LOG("tun write ret: %zd, errno: %d\n", ret, errno);
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
	int ret;
	int flags;

	if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
		LOG("open /dev/net/tun failed: %d, errno: %d\n", fd, errno);
		return fd;
	}

	/* Flags: IFF_TUN   - TUN device (no Ethernet headers)
	 *        IFF_TAP   - TAP device
	 *
	 *        IFF_NO_PI - Do not provide packet information
	 *        IFF_MULTI_QUEUE - Create a queue of multiqueue device
	*/
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE;
	strncpy(ifr.ifr_name, dev, IFNAMSIZ);

	if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
		LOG("ioctl /dev/net/tun failed: %d, errno: %d\n", err, errno);
		close(fd);
		return err;
	}
	flags = fcntl(fd, F_GETFL);
	assert(0 <= flags);
	flags |= O_NONBLOCK;
	ret = fcntl(fd, F_SETFL, flags);
	assert(-1 != ret);
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
	assert(0 <= sock);
	int enable = 1;
	setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, (const char*)&enable, sizeof(enable));
	destaddr.sin_family = AF_INET;
	bindaddr.sin_family = AF_INET;
	destaddr.sin_port = htons(destport);
	bindaddr.sin_port = htons(bindport);
	ret = bind(sock, (const struct sockaddr *)&bindaddr, sizeof(bindaddr));
	if (ret < 0) {
		LOG("sock bind: %d, errno: %d\n", ret, errno);
		close(sock);
		return -5;
	}
	/* make socket non blocking */
	flags = fcntl(sock, F_GETFL);
	assert(0 <= flags);
	flags |= O_NONBLOCK;
	ret = fcntl(sock, F_SETFL, flags);
	assert(-1 != ret);
	return sock;
}

pthread_t ts[CHNL_MAX];
static void *chnl_handler(void *data) {
	unsigned chnl = (uintptr_t)data;
	assert(chnl < CHNL_MAX);

	int ret = event_base_dispatch(ev_bases[chnl]);
	LOG("event-base-dispatch ret: %d\n", ret);

	pthread_exit(0);
}

int main (int argc, const char *argv[])
{
	struct event_config *ev_cfg;
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

	/* initialize libevent */
	//event_enable_debug_mode();
	ev_cfg = event_config_new();
	assert(0 != ev_cfg);
	/* EV_FEATURE_O1: O(1) event triggering */
	ret = event_config_require_features(ev_cfg, EV_FEATURE_O1);
	assert(0 == ret);
	/* EV_FEATURE_FDS: both sockets and files can be used */
	ret = event_config_require_features(ev_cfg, EV_FEATURE_FDS);
	assert(0 == ret);

	for (int i = 0; i != CHNL_MAX; i++) {
		ev_bases[i] = event_base_new_with_config(ev_cfg);
		assert(0 != ev_bases[i]);
	}

	for (int i = 0; i != CHNL_MAX; i++) {
		socks[i] = -1;
		tuns[i] = -1;
	}
	/* create the UDP sock */
	for (int i = 0; i != CHNL_MAX; i++) {
		socks[i] = create_udpsock(bindipstr, bindportstr, destipstr, destportstr);
		if (socks[i] < 0) {
			ret = 2;
			goto cleanup;
		}
	}
	for (int i = 0; i != CHNL_MAX; i++) {
		tuns[i] = open_tun(tun_name);
		if (tuns[i] < 0) {
			ret =3;
			goto cleanup;
		}
	}

	for (int i = 0; i != CHNL_MAX; i++) {
		void *cls = (void *)(uintptr_t)i;
		ev_treads[i] = event_new(ev_bases[i], tuns[i], EV_READ, &ev_tread_cb, cls);
		ev_sreads[i] = event_new(ev_bases[i], socks[i], EV_READ, &ev_sread_cb, cls);
		ev_twrites[i] = event_new(ev_bases[i], tuns[i], EV_WRITE, &ev_twrite_cb, cls);
		ev_swrites[i] = event_new(ev_bases[i], socks[i], EV_WRITE, &ev_swrite_cb, cls);
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
	for (int i = 0; i != CHNL_MAX; i++) {
		ret = pthread_create(&ts[i], 0, chnl_handler, (void *)(uintptr_t)i);
		assert(0 == ret);
	}
	for (int i = 0; i != CHNL_MAX; i++) {
		pthread_join(ts[i], 0);
	}
cleanup:
	for (int i = 0; i != CHNL_MAX; i++) {
		if (0 <= tuns[i])
			close(tuns[i]);
		if (0 <= socks[i])
			close(socks[i]);
	}
#define event_free_not_null(ev) if (ev) event_free(ev)
	for (int i = 0; i != CHNL_MAX; i++) {
		event_free_not_null(ev_treads[i]);
		event_free_not_null(ev_twrites[i]);
		event_free_not_null(ev_sreads[i]);
		event_free_not_null(ev_swrites[i]);
	}
#undef event_free_not_null
	for (int i = 0; i != CHNL_MAX; i++)
		event_base_free(ev_bases[i]);
	event_config_free(ev_cfg);
	return ret;
}

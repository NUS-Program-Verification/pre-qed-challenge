/* whether the system defaults to 32bit off_t but can do 64bit when requested */
/* #undef UPNP_LARGEFILE_SENSITIVE */

/* see upnpconfig.h */
/* #undef UPNP_HAVE_DEBUG */

/* see upnpconfig.h */
#define UPNP_HAVE_CLIENT 1

/* see upnpconfig.h */
#define UPNP_HAVE_DEVICE 1

/* see upnpconfig.h */
#define UPNP_HAVE_WEBSERVER 1

/* see upnpconfig.h */
#define UPNP_HAVE_SSDP 1

/* see upnpconfig.h */
#define UPNP_HAVE_OPTSSDP 1

/* see upnpconfig.h */
#define UPNP_HAVE_SOAP 1

/* see upnpconfig.h */
#define UPNP_HAVE_GENA 1

/* see upnpconfig.h */
#define UPNP_HAVE_TOOLS 1

/* see upnpconfig.h */
#define UPNP_ENABLE_IPV6 1

/* see upnpconfig.h */
/* #undef UPNP_ENABLE_UNSPECIFIED_SERVER */

/* see upnpconfig.h */
/* #undef UPNP_ENABLE_OPEN_SSL */

/* see upnpconfig.h */
/* #undef UPNP_ENABLE_BLOCKING_TCP_CONNECTIONS */

/* see upnpconfig.h */
#define IXML_HAVE_SCRIPTSUPPORT 1

/* see upnpconfig.h */
/* #undef UPNP_ENABLE_POST_WRITE */

/* see upnpconfig.h */
#define UPNP_MINISERVER_REUSEADDR 1

/* On Windows, select the network interface by its adapter name (GUID) instead
 * of the friendly name (see UpnpGetIfInfo in upnp/src/api/upnpapi.c). */
/* #undef UPNP_ADAPTER_UUID_NAME */

/* Type for storing the length of struct sockaddr */
/* #undef socklen_t */

/* Defines if strnlen is available on your system */
#define HAVE_STRNLEN 1

/* Defines if strndup is available on your system */
#define HAVE_STRNDUP 1

/* Define if backtrace( */
#define HAVE_BACKTRACE 1

/* Use pthread_rwlock_t */
#define UPNP_USE_RWLOCK 1


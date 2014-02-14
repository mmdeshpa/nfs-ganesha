/*
 * definition des codes d'error
 *
 *
 * Copyright CEA/DAM/DIF  (2008)
 * contributeur : Philippe DENIEL   philippe.deniel@cea.fr
 *                Thomas LEIBOVICI  thomas.leibovici@cea.fr
 *
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 *
 * ---------------------------------------
 *
 *
 */

#ifndef _LOGS_H
#define _LOGS_H

#include <stdio.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/param.h>
#include <syslog.h>
#include <inttypes.h>

#ifndef LIBLOG_NO_THREAD
#include <errno.h>
#include <pthread.h>
#endif

#include "config_parsing.h"
#include "display.h"

#include "display.h"
#include "nlm_list.h"

/* these macros gain a few percent of speed on gcc, especially with so many log
 * entries
 */
#if (__GNUC__ >= 3)
/* the strange !! is to ensure that __builtin_expect() takes either 0 or 1 as
 * its first argument
 */
#ifndef likely
#define likely(x)   __builtin_expect(!!(x), 1)
#endif
#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif
#else
#ifndef likely
#define likely(x) (x)
#endif
#ifndef unlikely
#define unlikely(x) (x)
#endif
#endif

/* The maximum size of a log buffer */
#define LOG_BUFF_LEN 2048
#define STR_LEN 256


/* Define the maximum length of a user time/date format. */
#define MAX_TD_USER_LEN 64
/* Define the maximum overall time/date format length, should have room for both
 * user date and user time format plus room for blanks around them.
 */
#define MAX_TD_FMT_LEN (MAX_TD_USER_LEN * 2 + 4)


/*
 * Log message severity constants
 */
typedef enum log_levels {
	NIV_NULL,
	NIV_FATAL,
	NIV_MAJ,
	NIV_CRIT,
	NIV_WARN,
	NIV_EVENT,
	NIV_INFO,
	NIV_DEBUG,
	NIV_MID_DEBUG,
	NIV_FULL_DEBUG,
	NB_LOG_LEVEL
} log_levels_t;

/*
 * Log components used throughout the code.
 */
typedef enum log_components {
	COMPONENT_ALL = 0,	/* Used for changing logging for all
				 * components */
	COMPONENT_LOG,		/* Keep this first, some code depends on it
				 * being the first component */
	COMPONENT_LOG_EMERG,	/* Component for logging emergency log
				 * messages - avoid infinite recursion */
	COMPONENT_MEMALLOC,
	COMPONENT_MEMLEAKS,
	COMPONENT_FSAL,
	COMPONENT_NFSPROTO,
	COMPONENT_NFS_V4,
	COMPONENT_NFS_V4_PSEUDO,
	COMPONENT_FILEHANDLE,
	COMPONENT_NFS_SHELL,
	COMPONENT_DISPATCH,
	COMPONENT_CACHE_INODE,
	COMPONENT_CACHE_INODE_GC,
	COMPONENT_CACHE_INODE_LRU,
	COMPONENT_HASHTABLE,
	COMPONENT_HASHTABLE_CACHE,
	COMPONENT_LRU,
	COMPONENT_DUPREQ,
	COMPONENT_RPCSEC_GSS,
	COMPONENT_INIT,
	COMPONENT_MAIN,
	COMPONENT_IDMAPPER,
	COMPONENT_NFS_READDIR,
	COMPONENT_NFS_V4_LOCK,
	COMPONENT_NFS_V4_XATTR,
	COMPONENT_NFS_V4_REFERRAL,
	COMPONENT_MEMCORRUPT,
	COMPONENT_CONFIG,
	COMPONENT_CLIENTID,
	COMPONENT_STDOUT,
	COMPONENT_SESSIONS,
	COMPONENT_PNFS,
	COMPONENT_RPC_CACHE,
	COMPONENT_RW_LOCK,
	COMPONENT_NLM,
	COMPONENT_RPC,
	COMPONENT_NFS_CB,
	COMPONENT_THREAD,
	COMPONENT_NFS_V4_ACL,
	COMPONENT_STATE,
	COMPONENT_9P,
	COMPONENT_9P_DISPATCH,
	COMPONENT_FSAL_UP,
	COMPONENT_DBUS,
	COMPONENT_COUNT
} log_components_t;

/**
 * @brief Define an index each of the log fields that are configurable.
 *
 * Ganesha log messages have several "header" fields used in every
 * message. Some of those fields may be configured (mostly display or
 * not display).
 *
 */
enum log_flag_index_t {
	LF_DATE = 0,		/*< Date field. */
	LF_TIME,		/*< Time field. */
	LF_EPOCH,		/*< Server Epoch field (distinguishes server
				    instance. */
	LF_HOSTAME,		/*< Server host name field. */
	LF_PROGNAME,		/*< Ganesha program name field. */
	LF_PID,			/*< Ganesha process identifier. */
	LF_THREAD_NAME,		/*< Name of active thread logging message. */
	LF_FILE_NAME,		/*< Source file name message occured in. */
	LF_LINE_NUM,		/*< Source line number message occurred in. */
	LF_FUNCTION_NAME,	/*< Function name message occurred in. */
	LF_COMPONENT,		/*< Log component. */
	LF_LEVEL,		/*< Log level. */
	LF_IP,			/*< Client's IP Address. */
	LF_COUNT		/*< Total number of FLAGs */
};


typedef struct loglev {
	log_levels_t value;
	char *str;
	char *short_str;
	int syslog_level;
} log_level_t;

extern log_level_t tabLogLevel[NB_LOG_LEVEL];

#define NIV_MAJOR NIV_MAJ

/* Limits on log messages */
#define LOG_MAX_STRLEN 2048
#define LOG_LABEL_LEN 50
#define LOG_MSG_LEN   255

typedef struct {
	int numero;
	char label[LOG_LABEL_LEN];
	char msg[LOG_MSG_LEN];
} family_error_t;

/* Error family type */
typedef struct {
	int num_family;
	char name_family[STR_LEN];
	family_error_t *tab_err;
} family_t;

typedef family_error_t status_t;
typedef family_error_t errctx_t;

typedef struct {
	int err_family;
	int ctx_family;
	errctx_t contexte;
	status_t status;
} log_error_t;

#define ERR_NULL -1

/* Error codes */
#define ERR_SYS 0
#define SUCCES                    0
#define ERR_FAILURE               1
#define EVNT                      2
#define ERR_EVNT                  2
#define ERR_PTHREAD_KEY_CREATE    3
#define ERR_MALLOC                4
#define ERR_SIGACTION             5
#define ERR_PTHREAD_ONCE          6
#define ERR_FILE_LOG              7
#define ERR_GETHOSTBYNAME         8
#define ERR_MMAP                  9
#define ERR_SOCKET               10
#define ERR_BIND                 11
#define ERR_CONNECT              12
#define ERR_LISTEN               13
#define ERR_ACCEPT               14
#define ERR_RRESVPORT            15
#define ERR_GETHOSTNAME          16
#define ERR_GETSOCKNAME          17
#define ERR_IOCTL                18
#define ERR_UTIME                19
#define ERR_XDR                  20
#define ERR_CHMOD                21
#define ERR_SEND                 22
#define ERR_GETHOSTBYADDR        23
#define ERR_PREAD                24
#define ERR_PWRITE               25
#define ERR_STAT                 26
#define ERR_GETPEERNAME          27
#define ERR_FORK                 28
#define ERR_GETSERVBYNAME        29
#define ERR_MUNMAP               30
#define ERR_STATVFS              31
#define ERR_OPENDIR              32
#define ERR_READDIR              33
#define ERR_CLOSEDIR             34
#define ERR_LSTAT                35
#define ERR_GETWD                36
#define ERR_CHDIR                37
#define ERR_CHOWN                38
#define ERR_MKDIR                39
#define ERR_OPEN                 40
#define ERR_READ                 41
#define ERR_WRITE                42
#define ERR_UTIMES               43
#define ERR_READLINK             44
#define ERR_SYMLINK              45
#define ERR_SYSTEM               46
#define ERR_POPEN                47
#define ERR_LSEEK                48
#define ERR_PTHREAD_CREATE       49
#define ERR_RECV                 50
#define ERR_FOPEN                51
#define ERR_GETCWD               52
#define ERR_SETUID               53
#define ERR_RENAME               54
#define ERR_UNLINK		 55
#define ERR_SELECT               56
#define ERR_WAIT                 57
#define ERR_SETSID               58
#define ERR_SETGID		 59
#define ERR_GETGROUPS            60
#define ERR_SETGROUPS            61
#define ERR_UMASK                62
#define ERR_CREAT                63
#define ERR_SETSOCKOPT           64
#define ERR_DIRECTIO             65
#define ERR_GETRLIMIT            66
#define ERR_SETRLIMIT            67
#define ERR_TRUNCATE		 68
#define ERR_PTHREAD_MUTEX_INIT   69
#define ERR_PTHREAD_COND_INIT    70
#define ERR_FCNTL                71

#define ERR_POSIX 1

static status_t __attribute__ ((__unused__)) tab_systeme_status[] = {
	{
	0, "NO_ERROR", "No errors"}, {
	EPERM, "EPERM", "Reserved to root"}, {
	ENOENT, "ENOENT", "No such file or directory"}, {
	ESRCH, "ESRCH", "No such process"}, {
	EINTR, "EINTR", "interrupted system call"}, {
	EIO, "EIO", "I/O error"}, {
	ENXIO, "ENXIO", "No such device or address"}, {
	E2BIG, "E2BIG", "Arg list too long"}, {
	ENOEXEC, "ENOEXEC", "Exec format error"}, {
	EBADF, "EBADF", "Bad file number"}, {
	ECHILD, "ECHILD", "No children"}, {
	EAGAIN, "EAGAIN", "Resource temporarily unavailable"}, {
	ENOMEM, "ENOMEM", "Not enough core"}, {
	EACCES, "ENOMEM", "Permission denied"}, {
	EFAULT, "EFAULT", "Bad address"}, {
	ENOTBLK, "ENOTBLK", "Block device required"}, {
	EBUSY, "EBUSY", "Mount device busy"}, {
	EEXIST, "EEXIST", "File exists"}, {
	EXDEV, "EXDEV", "Cross-device link"}, {
	ENODEV, "ENODEV", "No such device"}, {
	ENOTDIR, "ENOTDIR", "Not a directory"}, {
	EISDIR, "EISDIR", "Is a directory"}, {
	EINVAL, "EINVAL", "Invalid argument"}, {
	ENFILE, "ENFILE", "File table overflow"}, {
	EMFILE, "EMFILE", "Too many open files"}, {
	ENOTTY, "ENOTTY", "Inappropriate ioctl for device"}, {
	ETXTBSY, "ETXTBSY", "Text file busy"}, {
	EFBIG, "EFBIG", "File too large"}, {
	ENOSPC, "ENOSPC", "No space left on device"}, {
	ESPIPE, "ESPIPE", "Illegal seek"}, {
	EROFS, "EROFS", "Read only file system"}, {
	EMLINK, "EMLINK", "Too many links"}, {
	EPIPE, "EPIPE", "Broken pipe"}, {
	EDOM, "EDOM", "Math arg out of domain of func"}, {
	ERANGE, "ERANGE", "Math result not representable"}, {
	ENOMSG, "ENOMSG", "No message of desired type"}, {
	EIDRM, "EIDRM", "Identifier removed"}, {
	ERR_NULL, "ERR_NULL", ""}
};

/* other codes families */
#define ERR_LRU           10
#define ERR_HASHTABLE     11
#define ERR_FSAL          13
#define ERR_CACHE_INODE   16

/* Define max number of clients for the array.
 * 31 because 31 is a prime and can be used for hashing.  */
#define MAX_CLIENTS 31


/* Define max facilities */
#define MAX_FACILITIES 5

/* previously at log_macros.h */
typedef void (*cleanup_function) (void);
typedef struct cleanup_list_element {
	struct cleanup_list_element *next;
	cleanup_function clean;
} cleanup_list_element;

typedef enum log_type {
	SYSLOG = 0,
	FILELOG,
	STDERRLOG,
	STDOUTLOG,
	TESTLOG
} log_type_t;

typedef enum log_header_t {
	LH_NONE,
	LH_COMPONENT,
	LH_ALL
} log_header_t;

struct log_facility;

typedef int (lf_function_t) (struct log_facility *facility, log_levels_t level,
			     struct display_buffer *buffer, char *compstr,
			     char *message);

/**
 * @brief Define the structure for a log facility.
 *
 */
struct log_facility {
	struct glist_head lf_list;	/*< List of log facilities */
	struct glist_head lf_active;	/*< This is an active facility */
	char *lf_name;			/*< Name of log facility */
	log_levels_t lf_max_level;	/*< Max log level for this facility */
	log_header_t lf_headers;	/*< If time stamp etc. are part of msg
					 */
	lf_function_t *lf_func;	/*< Function that describes facility   */
	void *lf_private;	/*< Private info for facility          */
};


typedef struct log_component_info {
	log_components_t comp_value;
	const char *comp_name;
	const char *comp_str;
	log_levels_t comp_log_level;
	int comp_env_set;
} log_component_info;

/**
 * @brief Description of a flag tha controls a log field.
 *
 */
struct log_flag {
        int lf_idx;             /*< The log field index this flag controls. */
        int lf_val;          /*< True/False value for the flag. */
        int lf_ext;             /*< Extended value for the flag,
                                    if it has one. */
        char *lf_name;          /*< Name of the flag. */
};




/* This structure will be the defining point of all the information about client specific settings. */
typedef struct per_client_logging {
        /* this would declare the array of components for the specified IP.  */
        struct log_component_info LogComponents[COMPONENT_COUNT];
        
        /* Flags associated with the logs. */
        struct log_flag tab_log_flag[LF_COUNT];
        
        /* Define a const string. */
        char const_log_str[LOG_BUFF_LEN];
        char date_time_fmt[MAX_TD_FMT_LEN];
        char user_date_fmt[MAX_TD_USER_LEN];
        char user_time_fmt[MAX_TD_USER_LEN];
        
        /* Create a log facilities structure specific to clients. */
        struct log_facility facilities[MAX_FACILITIES];
        
        /* IP of the configured client. Set to NULL for the first node.  */
        char *ip;
        
        /* The next pointer of the linked list */
        struct per_client_logging *next;
        
        /* The next pointer in case of collision */
        struct per_client_logging *collision_next;
        
        /* The list of facilities. */
        struct glist_head facility_list;
        
        /* The list of active facilities */
        struct glist_head active_facility_list;

}client_t;

/* Allocates buffer containing debug info to be printed.
 * Returned buffer needs to be freed. Returns number of
 * characeters in size if size != NULL.
 */
char *get_debug_info(int *size);

/* Function prototypes */

void SetNamePgm(const char *nom);
void SetNameHost(const char *nom);
void SetDefaultLogging(struct per_client_logging *logClient, const char *name);
void SetNameFunction(const char *nom);	/* thread safe */

/* AddFamilyError : not thread safe */
int AddFamilyError(int num_family, char *nom_family, family_error_t *tab_err);

char *ReturnNameFamilyError(int num_family);

void InitLogging();
/*void ReadLogEnvironment(); */
void SetLevelDebug(struct per_client_logging *logClient, int level_to_set);
void Log_FreeThreadContext();
void init_node (struct per_client_logging **logClient);
int ReturnLevelAscii(const char *LevelInAscii);
char *ReturnLevelInt(int level);

int display_LogError(struct display_buffer *dspbuf, int num_family,
		     int num_error, int status);

static inline void MakeLogError(char *buffer, size_t size, int num_family,
				int num_error, int status, int line)
{
	struct display_buffer dspbuf = { size, buffer, buffer };
	(void)display_LogError(&dspbuf, num_family, num_error, status);
}

/* previously at log_macros.h */
void RegisterCleanup(cleanup_list_element *clean);
void Cleanup(void);
void Fatal(void);

/* This function is primarily for setting log level from config, it will
 * not override log level set from environment.
 */
void SetComponentLogLevel(struct per_client_logging *logClient, log_components_t component, int level_to_set);

void DisplayLogComponentLevel(log_components_t component, char *file, int line,
			      char *function, log_levels_t level, char *format,
			      ...)
			      __attribute__ ((format(printf, 6, 7)));
			      /* 6=format 7=params */

void DisplayErrorComponentLogLine(log_components_t component, char *file,
				  int line, char *function, int num_family,
				  int num_error, int status);

int read_log_config(config_file_t in_config);
void reread_log_config();

void deactivate_log_facility(struct per_client_logging *logClient, struct log_facility *facility);
void activate_log_facility(struct per_client_logging *logClient, struct log_facility *facility);
int register_log_facility(struct per_client_logging *logClient, struct log_facility *facility);
int unregister_log_facility(struct per_client_logging *logClient, struct log_facility *facility);
int activate_custom_log_facility(struct per_client_logging *logClient, struct log_facility *facility);
void set_const_log_str(struct per_client_logging *logClient);


/* Did not find any code which was using this definition. Hence did not change. */
#define ReturnLevelComponent(component) LogComponents[component].comp_log_level

/*extern log_component_info
	__attribute__ ((__unused__)) LogComponents[COMPONENT_COUNT];  */
	
/* Define clientIP */
extern pthread_key_t 
    __attribute__ ((__unused__)) clientIP;


#define LogAlways(component, format, args...) \
	do { \
        struct per_client_logging *logClient = pthread_getspecific(clientIP); \
		if (likely(logClient->LogComponents[component].comp_log_level \
		    <= NIV_FULL_DEBUG)) \
			DisplayLogComponentLevel(component, (char *) __FILE__, \
						 __LINE__, \
						 (char *) __func__, \
						 NIV_NULL, format, ## args); \
	} while (0)

#define LogTest(format, args...) \
    struct per_client_logging *logClient = pthread_getspecific(clientIP); \
	DisplayLogComponentLevel(COMPONENT_ALL, (char *) __FILE__, \
				 __LINE__,  (char *) __func__, \
				 NIV_NULL, format, ## args)

#define LogFatal(component, format, args...) \
	do { \
	    struct per_client_logging *logClient = pthread_getspecific(clientIP); \
		if (likely(logClient->LogComponents[component].comp_log_level \
		    >= NIV_FATAL)) \
			DisplayLogComponentLevel(component, (char *) __FILE__, \
						 __LINE__, \
						 (char *) __func__, \
						 NIV_FATAL, format, ## args); \
	} while (0)

#define LogMajor(component, format, args...) \
	do { \
	    struct per_client_logging *logClient = pthread_getspecific(clientIP); \
		if (likely(logClient->LogComponents[component].comp_log_level \
		    >= NIV_MAJOR)) \
			DisplayLogComponentLevel(component, (char *) __FILE__, \
						 __LINE__, \
						 (char *) __func__, \
						 NIV_MAJ, format, ## args); \
	} while (0)

#define LogCrit(component, format, args...) \
	do { \
	    struct per_client_logging *logClient = pthread_getspecific(clientIP); \
		if (likely(logClient->LogComponents[component].comp_log_level \
		    >= NIV_CRIT)) \
			DisplayLogComponentLevel(component, (char *) __FILE__, \
						 __LINE__, \
						 (char *) __func__, \
						 NIV_CRIT, format, ## args); \
	} while (0)

#define LogWarn(component, format, args...) \
	do { \
	    struct per_client_logging *logClient = pthread_getspecific(clientIP); \
		if (likely(logClient->LogComponents[component].comp_log_level \
		    >= NIV_WARN)) \
			DisplayLogComponentLevel(component, (char *) __FILE__, \
						 __LINE__, \
						 (char *) __func__, \
						 NIV_WARN, format, ## args); \
	} while (0)

#define LogEvent(component, format, args...) \
	do { \
	    struct per_client_logging *logClient = pthread_getspecific(clientIP); \
		if (likely(logClient->LogComponents[component].comp_log_level \
		    >= NIV_EVENT)) \
			DisplayLogComponentLevel(component, (char *) __FILE__,\
						 __LINE__, \
						 (char *) __func__, \
						 NIV_EVENT, format, ## args); \
	} while (0)

#define LogInfo(component, format, args...) \
	do { \
	    struct per_client_logging *logClient = pthread_getspecific(clientIP); \
		if (unlikely(logClient->LogComponents[component].comp_log_level \
		    >= NIV_INFO)) \
			DisplayLogComponentLevel(component, (char *) __FILE__,\
						 __LINE__, \
						 (char *) __func__, \
						 NIV_INFO, format, ## args); \
	} while (0)

#define LogDebug(component, format, args...) \
	do { \
	    struct per_client_logging *logClient = pthread_getspecific(clientIP); \
		if (unlikely(logClient->LogComponents[component].comp_log_level \
		    >= NIV_DEBUG)) \
			DisplayLogComponentLevel(component, (char *) __FILE__,\
						 __LINE__, \
						 (char *) __func__, \
						 NIV_DEBUG, format, ## args); \
	} while (0)

#define LogMidDebug(component, format, args...) \
	do { \
	    struct per_client_logging *logClient = pthread_getspecific(clientIP); \
		if (unlikely(logClient->LogComponents[component].comp_log_level \
		    >= NIV_MID_DEBUG)) \
			DisplayLogComponentLevel(component, (char *) __FILE__,\
						 __LINE__, \
						 (char *) __func__, \
						 NIV_MID_DEBUG, \
						 format, ## args); \
	} while (0)

#define LogFullDebug(component, format, args...) \
	do { \
	    struct per_client_logging *logClient = pthread_getspecific(clientIP); \
		if (unlikely(logClient->LogComponents[component].comp_log_level \
		    >= NIV_FULL_DEBUG)) \
			DisplayLogComponentLevel(component, (char *) __FILE__,\
						 __LINE__, \
						 (char *) __func__, \
						 NIV_FULL_DEBUG, \
						 format, ## args); \
	} while (0)

#define \
LogFullDebugOpaque(component, format, buf_size, value, length, args...) \
	do { \
	    struct per_client_logging *logClient = pthread_getspecific(clientIP); \
		if (unlikely(logClient->LogComponents[component].comp_log_level \
		    >= NIV_FULL_DEBUG)) { \
			char buf[buf_size]; \
			struct display_buffer dspbuf = {buf_size, buf, buf}; \
			\
			(void) display_opaque_value(&dspbuf, value, length); \
			\
			DisplayLogComponentLevel(component, (char *) __FILE__,\
						 __LINE__, \
						 (char *) __func__, \
						 NIV_FULL_DEBUG, \
						 format, buf, ## args); \
		} \
	} while (0)

#define LogFullDebugBytes(component, format, buf_size, value, length, args...) \
	do { \
	    struct per_client_logging *logClient = pthread_getspecific(clientIP); \
		if (unlikely(logClient->LogComponents[component].comp_log_level \
		    >= NIV_FULL_DEBUG)) { \
			char buf[buf_size]; \
			struct display_buffer dspbuf = {buf_size, buf, buf}; \
			\
			(void) display_opaque_bytes(&dspbuf, value, length); \
			\
			DisplayLogComponentLevel(component, (char *) __FILE__, \
						 __LINE__, \
						 (char *) __func__, \
						 NIV_FULL_DEBUG, \
						 format, buf, ## args); \
		} \
	} while (0)

#define LogAtLevel(component, level, format, args...) \
	do { \
	    struct per_client_logging *logClient = pthread_getspecific(clientIP); \
		if (unlikely(logClient->LogComponents[component].comp_log_level \
		    >= level)) \
			DisplayLogComponentLevel(component, (char *) __FILE__,\
						 __LINE__, \
						 (char *) __func__, \
						 level, format, ## args); \
	} while (0)

#define LogError(component, a, b, c) \
	do { \
	    struct per_client_logging *logClient = pthread_getspecific(clientIP); \
		if (unlikely(logClient->LogComponents[component].comp_log_level \
		    >= NIV_CRIT)) \
			DisplayErrorComponentLogLine(component, \
						     (char *) __FILE__, \
						     __LINE__, \
						     (char *) __func__, \
						     a, b, c); \
	} while (0)

/*
#define isLevel(component, level) \
    do { \
        struct per_client_logging *client = pthread_getspecific(clientIP); \
	    (unlikely(client->LogComponents[component].comp_log_level >= level)); \
	} while(0)


#define isInfo(component) \
    do { \
        struct per_client_logging *client = pthread_getspecific(clientIP); \
	    (unlikely(client->LogComponents[component].comp_log_level >= NIV_INFO)); \
    } while(0)
    
#define isDebug(component) \
    do { \
        struct per_client_logging *client = pthread_getspecific(clientIP); \
	    (unlikely(client->LogComponents[component].comp_log_level >= NIV_DEBUG)); \
	} while(0)

#define isMidDebug(component) \
    do { \
        struct per_client_logging *client = pthread_getspecific(clientIP); \
	    (unlikely(client->LogComponents[component].comp_log_level >= NIV_MID_DEBUG)); \
	} while(0)

#define isFullDebug(component) \
    do { \
        struct per_client_logging *client = pthread_getspecific(clientIP); \
	    (unlikely(client->LogComponents[component].comp_log_level >= NIV_FULL_DEBUG)); \
	} while(0)   */

static inline int isLevel(log_components_t component, log_levels_t level) {
        struct per_client_logging *logClient = pthread_getspecific(clientIP);
        return (unlikely(logClient->LogComponents[component].comp_log_level >= level));
}

static inline int isInfo(log_components_t component) {
        struct per_client_logging *logClient = pthread_getspecific(clientIP);
        return (unlikely(logClient->LogComponents[component].comp_log_level >= NIV_INFO));
}

	
static inline int isDebug(log_components_t component) {
        struct per_client_logging *logClient = pthread_getspecific(clientIP);
        return (unlikely(logClient->LogComponents[component].comp_log_level >= NIV_DEBUG));
}


static inline int isMidDebug(log_components_t component) {
        struct per_client_logging *logClient = pthread_getspecific(clientIP);
        return (unlikely(logClient->LogComponents[component].comp_log_level >= NIV_MID_DEBUG));
}

static inline int isFullDebug(log_components_t component) {
       struct per_client_logging *logClient = pthread_getspecific(clientIP);
       return (unlikely(logClient->LogComponents[component].comp_log_level >= NIV_FULL_DEBUG));
}


/* Use either the first component, or if it is not at least at level,
 * use the second component.
 */
#define LogDebugAlt(comp1, comp2, format, args...) \
	do { \
	    struct per_client_logging *logClient = pthread_getspecific(clientIP); \
		if (unlikely(logClient->LogComponents[comp1].comp_log_level \
		    >= NIV_DEBUG) || \
		    unlikely(logClient->LogComponents[comp2].comp_log_level \
		    >= NIV_DEBUG)) { \
			log_components_t component = \
			    logClient->LogComponents[comp1].comp_log_level \
				>= NIV_DEBUG ? comp1 : comp2; \
			\
			DisplayLogComponentLevel(component, (char *) __FILE__, \
						 __LINE__, \
						 (char *)__func__, \
						 NIV_DEBUG, \
						 "%s: DEBUG: " format, \
						 logClient->LogComponents[component] \
						     .comp_str, ## args); \
		} \
	} while (0)

#define LogMidDebugAlt(comp1, comp2, format, args...) \
	do { \
	    struct per_client_logging *logClient = pthread_getspecific(clientIP); \
		if (unlikely(logClient->LogComponents[comp1].comp_log_level \
		    >= NIV_MID_DEBUG) || \
		    unlikely(logClient->LogComponents[comp2].comp_log_level \
		    >= NIV_MID_DEBUG)) { \
			log_components_t component = \
			    logClient->LogComponents[comp1].comp_log_level \
				>= NIV_MID_DEBUG ? comp1 : comp2; \
			\
			DisplayLogComponentLevel(component, (char *) __FILE__, \
						 __LINE__, \
						 (char *)__func__, \
						 NIV_MID_DEBUG, \
						 "%s: MID DEBUG: " format, \
						 logClient->LogComponents[component] \
						     .comp_str, ## args); \
		} \
	} while (0)

#define LogFullDebugAlt(comp1, comp2, format, args...) \
	do { \
	    struct per_client_logging *logClient = pthread_getspecific(clientIP); \
		if (unlikely(logClient->LogComponents[comp1].comp_log_level \
		    >= NIV_FULL_DEBUG) || \
		    unlikely(logClient->LogComponents[comp2].comp_log_level \
		    >= NIV_FULL_DEBUG)) { \
			log_components_t component = \
			    logClient->LogComponents[comp1].comp_log_level \
				>= NIV_FULL_DEBUG ? comp1 : comp2; \
			\
			DisplayLogComponentLevel(component, (char *) __FILE__, \
						 __LINE__, \
						 (char *)__func__, \
						 NIV_FULL_DEBUG, \
						 "%s: FULLDEBUG: " format, \
						 logClient->LogComponents[component] \
						     .comp_str, ## args); \
		} \
	} while (0)

/*
 *  Re-export component logging to TI-RPC internal logging
 */
void rpc_warnx(/* const */ char *fmt, ...);

#endif

/* Dummy unistd.h */

#include <io.h>
#include <fcntl.h>

#define write(fd, buf, len) _write((fd), (buf), (len))
#define read(fd, buf, len)  _read((fd), (buf), (len))
#define close(fd)           _close((fd))
#define mktemp(template)    _mktemp((template))
#define mkstemp(template)   _open(_mktemp(template), _O_RDWR|_O_CREAT, 0600)
#define unlink(name)        _unlink((name))

#define O_RDONLY        _O_RDONLY
#define O_WRONLY        _O_WRONLY
#define O_RDWR          _O_RDWR
#define O_APPEND        _O_APPEND
#define O_CREAT         _O_CREAT
#define O_TRUNC         _O_TRUNC
#define O_EXCL          _O_EXCL

#include <process.h>

#define getpid() _getpid()

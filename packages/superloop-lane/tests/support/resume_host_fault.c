/* Synthetic OS failures for the real private receiver. No identity is spoofed. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static int control_bound=0;
static int fault(const char *name) {
    const char *value=getenv("RESUME_FIXTURE_FAULT");
    return value && !strcmp(value,name);
}
static void hit(const char *stage) {
    const char *path=getenv("RESUME_FIXTURE_HIT");
    if (!path) _exit(122);
    int fd=open(path,O_WRONLY|O_CREAT|O_APPEND|O_CLOEXEC,0600);
    if (fd<0 || write(fd,stage,strlen(stage))<0 || write(fd,"\n",1)!=1) _exit(122);
    close(fd);
}
ssize_t read(int fd,void *bytes,size_t size) {
    ssize_t (*next)(int,void*,size_t)=dlsym(RTLD_NEXT,"read");
    char link[64],path[8192];
    snprintf(link,sizeof link,"/proc/self/fd/%d",fd);
    ssize_t n=readlink(link,path,sizeof path-1);
    if(n>=0) {
        path[n]=0;
        if (fault("inspector") && strstr(path,"/R/launch/runtime.env")) {
            hit("inspector read");errno=EIO;return -1;
        }
    }
    return next(fd,bytes,size);
}
static int same_start(long pid);
static void pause_launcher(void) {
    const char *text=getenv("RESUME_FIXTURE_LAUNCHER");
    char *end=NULL;long pid=text?strtol(text,&end,10):0;
    if(pid<=1 || !end || *end || !same_start(pid) || kill((pid_t)pid,SIGSTOP)) _exit(123);
}
int bind(int fd,const struct sockaddr *address,socklen_t length) {
    int (*next)(int,const struct sockaddr*,socklen_t)=dlsym(RTLD_NEXT,"bind");
    if(fault("readiness") && address->sa_family==AF_UNIX &&
       strstr(((const struct sockaddr_un*)address)->sun_path,".container-R.sock")) {
        hit("helper client bind");errno=EADDRINUSE;return -1;
    }
    if(fault("credential") && address->sa_family==AF_UNIX &&
       strstr(((const struct sockaddr_un*)address)->sun_path,".container-R.sock")) pause_launcher();
    int result=next(fd,address,length);
    if(result==0 && address->sa_family==AF_UNIX &&
       strstr(((const struct sockaddr_un*)address)->sun_path,".control-R.sock")) control_bound=1;
    return result;
}
static int same_start(long pid) {
    const char *expected=getenv("RESUME_FIXTURE_LAUNCHER_START");
    char path[64],data[8192];snprintf(path,sizeof path,"/proc/%ld/stat",pid);
    int fd=open(path,O_RDONLY|O_CLOEXEC);if(fd<0)return 0;
    ssize_t n=read(fd,data,sizeof data-1);close(fd);if(n<=0)return 0;data[n]=0;
    char *end=strrchr(data,')');if(!end || !expected)return 0;
    char *save=NULL,*word=strtok_r(end+2," ",&save);
    for(int field=3;word && field<22;field++)word=strtok_r(NULL," ",&save);
    return word && !strcmp(word,expected);
}
int pthread_create(pthread_t *thread,const pthread_attr_t *attr,
                   void *(*start)(void*),void *argument) {
    int (*next)(pthread_t*,const pthread_attr_t*,void *(*)(void*),void*)=dlsym(RTLD_NEXT,"pthread_create");
    static unsigned count=0;
    if(fault("helper-pin") && ++count==2) {
        hit("helper pin hash reader start");return EAGAIN;
    }
    if(fault("credential") && control_bound && ++count==2) {
        hit("authority thread start after host pause");return EAGAIN;
    }
    return next(thread,attr,start,argument);
}

/* Return an injected error only after the real intent directory fsync succeeds. */
int fsync(int fd) {
    int (*next)(int)=dlsym(RTLD_NEXT,"fsync");
    int result=next(fd);
    static int fired=0;
    const char *home=getenv("RESUME_FIXTURE_INTENT_HOME");
    if(result || fired || !home)return result;
    char link[64],actual[8192],wanted[8192],record[8192];
    snprintf(link,sizeof link,"/proc/self/fd/%d",fd);
    ssize_t n=readlink(link,actual,sizeof actual-1);if(n<0)return result;actual[n]=0;
    if(snprintf(wanted,sizeof wanted,"%s/runs",home)>=(int)sizeof wanted || strcmp(actual,wanted))return result;
    if(snprintf(record,sizeof record,"%s/.reservation-R.json",wanted)>=(int)sizeof record)return result;
    int input=open(record,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);if(input<0)return result;
    size_t bound=4*1024*1024;char *data=malloc(bound+1);if(!data){close(input);return result;}
    n=read(input,data,bound);close(input);
    int intent=0;if(n>0){data[n]=0;intent=strstr(data,"\"dispatch_intent\":")!=NULL;}
    free(data);
    if(intent){fired=1;hit("persisted intent fsync");errno=EIO;return -1;}
    return result;
}

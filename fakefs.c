/*
 * by adventuresin9 
 *  
 * A basic example of a sythetic file system. 
 * It place an entry in /srv, and mounts to /n. 
 * The files it provides are examples of procedurally 
 * generated content. 
 *  
 * tyme uses time() to give a silly message 
 * backtalk uses getuser() for a personal response 
 * i-ching uses ntruerand() to generate hexagrams 
 * rot13 will take in text and do a rot13 encryption, 
 *   and when read sends back the encrypted text 
 * honeypot creates a file in $home called 'fakelog' 
 *   and logs all reads and writes of honeypot to it
 * sat.jpg fetches an image from noaa.gov 
 */

/* basic libraries */
#include <u.h>
#include <libc.h>

/* needed for 9P and files */
#include <fcall.h>
#include <thread.h>
#include <9p.h>


/* size of the rot13 file buffer */

enum{
	RotBufSize = 10 * 1024,
	SatBufSize = 300 * 1024,
};


static void	fsstart(Srv*);
static void	fsopen(Req *r);
static void	fsread(Req *r);
static void	fswrite(Req *r);
static void	fsend(Srv *s);
static char*	timefunc(Req*);
static char*	tbfunc(Req*);
static char*	icfunc(Req*);
static char*	rrfunc(Req*);
static char*	rwfunc(Req*);
static char*	rhpot(Req*);
static char*	whpot(Req*);
static char*	rsat(Req*);


/* This holds the information for the fake files */

typedef struct Fakefile Fakefile;

struct Fakefile {
	char *name;
	char* (*fakeread)(Req*);  /* function pointer for reads */
	char* (*fakewrite)(Req*);	/* function pointer for writes */
	int mode;
};

/*
 * Here the fake files are specified 
 * the name they will appear as in the file system 
 * the function that is called when they are read 
 * and write and the permission mode they are given 
 */
Fakefile files[] = {
	{ "tyme",		timefunc,	nil,	0444 },
	{ "backtalk",	tbfunc,		nil,	0444 },
	{ "i-ching",	icfunc,		nil,	0444 },
	{ "rot13",		rrfunc,		rwfunc,	0666 },
	{ "honeypot",	rhpot,		whpot,	0666 },
	{ "sat.jpg",	rsat,		nil,	0444 },
};

/*
 * setting the function that will 
 * be called for 9P requests 
 * other than the defaults 
 */
Srv s = {
	.start	= fsstart,
	.read	= fsread,
	.write	= fswrite,
	.end	= fsend,
};


char *srvname = "fakefs";
char *mntpt = "/n";
char *rotbuf;
int	logfd;
uchar *satbuf;
ulong satstamp;
int satlen;


/*
 * not called by a 9P request
 * called when the service is started
 */
static void
fsstart(Srv *)
{
/*
 * This builds the fake directory
 * and fills it with the fake files
 * setting the owner and permissions
 */
	File *root;
	File *fakedir;
	char *user, logpath[128], logbuf[128];
	int i;

	user = getuser();

/*
 * sets up a file system at Srv.tree 
 * see 'man 2 9p' for Srv struct 
 * see 'man 2 9file' for Tree and alloctree() 
 */
	s.tree = alloctree(user, user, 0555, nil);
	if(s.tree == nil)
		sysfatal("alloctree failed");

/*
 * sets a file as a directory called "fake" 
 * see 'man 2 9file' for createfile() 
 */
	root = s.tree->root;

	if((fakedir = createfile(root, "fake", user, DMDIR|0555, nil)) == nil)
		sysfatal("createfile failed");

/*
 * loops through files[] and makes files with 
 * files.name and files.mode  The last argument 
 * in create file sets File->aux to point to the 
 * files[i] to later get the function pointers 
 * fakeread and fakewrite 
 */
	for(i = 0; i < nelem(files); i++)
		if(createfile(fakedir, files[i].name, user, files[i].mode, files + i) == nil)
			sysfatal("failed on %s", files[i].name);

/*
 * Sets up the log file used by 
 * honeypot to log user access 
 */
	sprint(logpath, "/usr/%s/fakelog", user);

	if(access(logpath, AWRITE))
		logfd = create(logpath, OWRITE, 0666);
	else
		logfd = open(logpath, OWRITE);

	seek(logfd, 0, 2);
	sprint(logbuf, "%s - fsstart!!\n", ctime(time(0)));
	fprint(logfd, logbuf);


/* set up buffer for rot13 and sat.jpg file */

	rotbuf = emalloc9p(RotBufSize);
	satbuf = emalloc9p(SatBufSize);
}


/*
 * not called by 9P request 
 * called when service is finished 
 * 'rm /srv/fakefs' and all open 
 * descriptors are closed, 
 *  no windows have /n/fake 
 */
static void
fsend(Srv *)
{
	char logbuf[128];

/* log the exit */

	seek(logfd, 0, 2);
	sprint(logbuf, "%s - fsend!!\n", ctime(time(0)));
	fprint(logfd, logbuf);
	close(logfd);


/* free the rot13 and sat buffer */

	free(rotbuf);
	free(satbuf);

/* send exit signals */

	postnote(PNGROUP, getpid(), "shutdown");
	exits(nil);
}


/* used for Read requests */
static void
fsread(Req *r)
{
	Fakefile *f;

	r->ofcall.count = 0;

/* fetch the Fakefile pointer from aux */

	f = r->fid->file->aux;

/* respond with the results of the   */
/* fakeread() function from Fakefile */

	respond(r, f->fakeread(r));
}


/* used for Write requests */
static void
fswrite(Req *r)
{
	Fakefile *f;

/* fetch the Fakefile pointer from aux */

	f = r->fid->file->aux;

/* respond with the results of the    */
/* fakewrite() function from Fakefile */

	respond(r, f->fakewrite(r));

}


/* main() and usage() */

static void
usage(void)
{
	fprint(2, "usage: %s [-s srvname] [-m mntpt]\n", argv0);
	exits("usage");
}


void
main(int argc, char *argv[])
{
	ARGBEGIN {
		case 's':
			srvname = EARGF(usage());
			break;
		case 'm':
			mntpt = EARGF(usage());
			break;
		default:
			usage();
			break;
	} ARGEND


	fprint(2, "srvname: %s\nmntpt: %s\n", srvname, mntpt);

	if(access("/mnt/web/clone", AREAD))
		fprint(2, "no webfs, sat.jpg will fail\n");


	postmountsrv(&s, srvname, mntpt, MBEFORE);
	exits(nil);
}





/* functions called for reading and writing */


/* read tyme file */
static char*
timefunc(Req *r)
{
	char buf[128];

	snprint(buf, sizeof(buf), "And it came to pass, in \n%ld seconds of\nthe reign of Unix...\n", time(0));

	readstr(r, buf);
	return nil;
}


/* read backtalk file */
static char*
tbfunc(Req *r)
{
	char buf[128];

	snprint(buf, sizeof(buf), "I'm sorry %s, I'm afraid I can't do that.\n", getuser());

	readstr(r, buf);
	return nil;
}


/* read i-ching file */
static char*
icfunc(Req *r)
{
/*
 * this loops 6 times, getting a number from 6 to 9 
 * then sorts by even or odd, formats it  
 * and appends it to the buffer 
 */
	char *even = "___   ___";
	char *odd = "_________";
	char buf[128], *p;
	int i;
	ulong d;

	p = buf;

	for (i = 0; i < 6; i++){
		d = 6 + ntruerand(4);
		if (d % 2)
			p = seprint(p, buf + sizeof buf, "%s %d\n", odd, d);
		else
			p = seprint(p, buf + sizeof buf, "%s %d\n", even, d);
	}
	
	readstr(r, buf);
	return nil;
}


/* write rot13 file */
static char*
rwfunc(Req *r)
{
	int n, i;

/*
 * let the service know I'm writing 
 * everything incoming... 
 */
	n = r->ofcall.count = r->ifcall.count;

/*
 * ...but don't actually write more 
 * than the buffer size, -1 to allow 
 * for ending null character 
 */
	if(n > RotBufSize - 1)
		n = (RotBufSize - 1);

	memset(rotbuf, 0, RotBufSize);
	memmove(rotbuf, r->ifcall.data, n);

/* do the rot13 encryption */

	for(i = 0; i < n; i++){
		if((rotbuf[i]>='A' && rotbuf[i]<'N') || (rotbuf[i]>='a' && rotbuf[i]<'n')){
			rotbuf[i] += 13;
		} else if((rotbuf[i]>'M' && rotbuf[i]<='Z') || (rotbuf[i]>'m' && rotbuf[i]<='z')){
			rotbuf[i] -= 13;
		}
	}

	return nil;
}


/* read rot13 file */
static char*
rrfunc(Req *r)
{
/* just need to read the rot13 buffer */

	readstr(r, rotbuf);
	return nil;
}


/* read honeypot file */
static char*
rhpot(Req *r)
{
	char tell[128];

/* Text to be read back from the "file" */

	readstr(r, "Juicy corporate secrets\n");

/* seek to the end of fakelog */
/* and make log entry         */

	sprint(tell, "%s - %s - read the honeypot\n", ctime(time(0)), getuser());
	fprint(logfd, tell);

	return(r, nil);
}


/* write honeypot file */
static char*
whpot(Req *r)
{
	char tell[128];

/* let service know we are writing */
/* everything so it doesn't error  */

	r->ofcall.count = r->ifcall.count;

/* seek to the end of fakelog */
/* and make log entry         */

	seek(logfd, 0, 2);
	sprint(tell, "%s - %s - write the honeypot\n", ctime(time(0)), getuser());
	fprint(logfd, tell);

/* send back a string which will be used */
/* as an error message for respond()     */

	return(r, "Authorities Have Been Notified");
}

static char*
rsat(Req *r)
{

	char *saturl = "url https://cdn.star.nesdis.noaa.gov/GOES18/ABI/SECTOR/pnw/13/600x600.jpg";

	int n, i, clonefd, ctlfd, bodyfd, cnum;
	char buf[32];

/*
 * Some programs do successive reads
 * So not pound the web site, check 
 * if current image is new enough
 * and use old image at old length
 */
	if((time(0) - satstamp) < 20){
		readbuf(r, satbuf, satlen);	
		seek(logfd, 0, 2);
		fprint(logfd, "%s - sat old data\n", ctime(time(0)));
		return(nil);
	}

	
/* check for existence of webfs */

	if(access("/mnt/web/clone", AREAD))
		return("run webfs first");

	clonefd = open("/mnt/web/clone", OREAD);


/* get fresh webfs directory */

	n = read(clonefd, buf, sizeof(buf));

	if(n < 1)
		return("clone read failed");


/* clone returns with a digit newline */
/* turing it into an int fixes that   */

	cnum = atoi(buf);


/* make sure ctl is really there */

	n = sprint(buf, "/mnt/web/%d/ctl", cnum);

	if(access(buf, AWRITE))
		return("can't find ctl");

	ctlfd = open(buf, OWRITE);


/* load the url for the image we want */

	n = write(ctlfd, saturl, strlen(saturl));


/* or clear the image buffer for fresh image */

	memset(satbuf, 0, SatBufSize);


/* open body to read what was downloaded by webfs */

	n = sprint(buf, "/mnt/web/%d/body", cnum);

	bodyfd = open(buf, OREAD);

/*
 * reading successive small bytes works best
 * standard read() automatically keeps track
 * of offset for successive reads
 * pointer math on satbuf to manually move
 * for successive reads
 */
	i = 0;
	n = 0;
	while((i = read(bodyfd, satbuf+n, 1024)) > 0)
		n = n + i;
		
	satstamp = time(0);
	satlen = n;

	seek(logfd, 0, 2);
	fprint(logfd, "%s - sat read done with %d\n",ctime(time(0)), n);

/*
 * use readbuf() since this isn't text 
 * and may contain null bytes
 */
	readbuf(r, satbuf, n);	

	close(clonefd);
	close(ctlfd);
	close(bodyfd);

	return nil;
}


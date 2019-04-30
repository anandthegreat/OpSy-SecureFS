#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/sha.h>
#include "filesys.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <math.h>
// #include <libexplain/open.h>

void trimLeadingSpaces(char *str, char ch)      //to remove leading white spaces
{
    char *p, *q;
    int done=0;
    for (q = p = str; *p; p++){
      if (*p != ch || done==1){
        *q++ = *p;
        done=1;
      }
      else {
        done=1;
      }
    }
    *q = '\0';
}


void trimTrailingSpaces(char *str)
{
    int index, i;
    index = -1;
    i = 0;
    while(str[i] != '\0')
    {
        if(str[i] != ' ' && str[i] != '\t' && str[i] != '\n')
        {
            index= i;
        }
        i++;
    }
    str[index + 1] = '\0';
}

void removeSubstring(char *s,const char *toremove)
{
  while(( s=strstr(s,toremove)) )
    memmove(s,s+strlen(toremove)+4,5+strlen(s+strlen(toremove)));
}

char* merkel_tree (unsigned char strings[][20], size_t str_count) {             //strings[] contains blockwise hashes
  if (str_count == 0) {
    return NULL;
  }
  if (str_count == 1) {
    return (char*)strings[0];
  }
  size_t parentList_count = str_count/2 + str_count%2;
  unsigned char parentList[parentList_count][SHA_DIGEST_LENGTH];
  unsigned char buff[40];

  for (int i = 0; i < str_count - 1; i += 2) {
      memmove(buff,strings[i], 20);
      memmove(buff+20,strings[i+1],20);
      SHA1((unsigned char*)buff, 40, (unsigned char*)parentList[i/2]);
  }

  if (str_count % 2) {
    SHA1((unsigned char*)strings[str_count - 1], 20, (unsigned char*)parentList[str_count/2]);
  }

  return merkel_tree(parentList, parentList_count);
}


char* merkel4file(char* filename) {
  int fd = open(filename, O_RDONLY, 0666);
  if(fd==-1) {
    return NULL;
  }
  // printf("%s %s\n","In merkel tree for file",filename );

  size_t file_size = lseek(fd, 0, SEEK_END);
  lseek(fd, 0, SEEK_SET);
  size_t totBlocks = file_size/64 + (bool)(file_size%64);
  unsigned char hblocks[totBlocks][SHA_DIGEST_LENGTH];    //SHA_DIGEST_LENGTH=20
  int tot_read;

  unsigned char buffer[64];
  for (int i = 0; i < totBlocks; i++) {
    if(!(tot_read = read(fd, buffer, 64))) {
      return NULL;
    }
    SHA1((unsigned char*)buffer, tot_read, (unsigned char*)hblocks[i]);
  }

  return merkel_tree(hblocks, totBlocks);
}



static int filesys_inited = 0;

/* returns 20 bytes unique hash of the buffer (buf) of length (len)
 * in input array sha1.
 */
void get_sha1_hash (const void *buf, int len, const void *sha1)
{
	SHA1 ((unsigned char*)buf, len, (unsigned char*)sha1);
}

/* Build an in-memory Merkle tree for the file.
 * Compare the integrity of file with respect to
 * root hash stored in secure.txt. If the file
 * doesn't exist, create an entry in secure.txt.
 * If an existing file is going to be truncated
 * update the hash in secure.txt.
 * returns -1 on failing the integrity check.
 */

int s_open (const char *pathname, int flags, mode_t mode)
{
	assert (filesys_inited);
  int fd=open("secure.txt",O_RDWR);
  double fileSize=lseek(fd,0,SEEK_END);                                         //filesize of secure.txt
  // printf("filesize is: %f\n", fileSize);
  lseek(fd,0,SEEK_SET);
  char* secureContents=(char*)malloc(((int)fileSize)*sizeof(char));             //store contents on secure.txt                                                         //
  read(fd, secureContents,(int)fileSize);
  lseek(fd,0,SEEK_SET);
  char* secureContents2=(char*)malloc(((int)fileSize)*sizeof(char));            //store contents on secure.txt                                                         //
  read(fd, secureContents2,(int)fileSize);
  lseek(fd,0,SEEK_SET);
  char *filenameInSecure=strstr(secureContents2, pathname);                     // check if file entry exists secure.txt
  if(filenameInSecure!=NULL)                                                    //If entry exist in secure.txt
  {
    strtok(filenameInSecure, " ");
    char *storedHash=strtok(NULL, " ");
    // printf("pathname is not null");
    // checks if file tampered
    char* hashValueCalculated=merkel4file((char*)pathname);
    if(strcmp(storedHash,"00000000000000000000")==0)
    { /*The file was initially empty but now some data has been written,
      so update it's hash in secure.txt and open the file without
      throwing any integrity check error    */
      char *temp=(char*)malloc(57*sizeof(char));
      memmove(temp,pathname,strlen(pathname));
      for(int i=0;i<33-strlen(pathname);i++){
        memmove(temp+strlen(pathname)+i," ",1);
      }
      memmove(temp+33,"00000000000000000000    ",24);
      removeSubstring(secureContents,temp);            //remove the 00...00 hash
      close(fd);
      if(remove("secure.txt")!=0){
        printf("%s\n","Not Able To Delete secure.txt");
        exit(0);
      }
      fd=open("secure.txt", O_RDWR | O_CREAT , 0666);
    	if(fd==-1){
    		perror("Unable to open/create secure.txt");
    	}
      fileSize-=57;
      int ret=write(fd,secureContents,(int)fileSize);
      if(ret==-1){
        printf("write failed");
        exit(0);
      }
      free(temp);
      //-------------------NOW UPDATE THE HASH------------------
      char* hashValueCalculated=merkel4file((char*)pathname);                   //Calculate root of merkle to store in secure.txt
      memmove(secureContents+(int)fileSize,pathname,strlen(pathname));
      for(int i=0;i<33-strlen(pathname);i++){
        memmove(secureContents+strlen(pathname)+i+(int)fileSize," ",1);
      }
      // printf("%s\n","hooooooooo");
      memmove(secureContents+(int)fileSize+33,hashValueCalculated,20);          //possible segmentation fault
      // printf("%s\n","kooooooooo" );
      memmove(secureContents+(int)fileSize+53,"    ",4);
      close(fd);
      if(remove("secure.txt")!=0){
        printf("%s\n","Not Able To Delete secure.txt");
        exit(0);
      }
      fd=open("secure.txt", O_RDWR | O_CREAT , 0666);
    	if(fd==-1){
    		perror("Unable to open/create secure.txt");
    	}
      ret=write(fd,secureContents,(int)fileSize+57);
      fileSize+=57;
      if(ret==-1){
        printf("write failed");
        exit(0);
      }
      //-------------------------------
      close(fd);
      return open(pathname,flags,mode);
      //-------------------------------
    }
    else if(strcmp(hashValueCalculated,storedHash)!=0)        // check integrity
    {
      close(fd);
      return -1;
    }
    else{
      close(fd);
      free(secureContents);
      free(secureContents2);
      return open(pathname, flags, mode);
    }

  }

  else
  {
    /*If entry does not exist in secure.txt, compute hash & create entry
      or if the file is empty, create its entry in secure.txt
      with hash = "00000000000000000000" */

    // printf("else%s\n",pathname);
    char* hashValueCalculated=merkel4file((char*)pathname);          //Calculate root of merkle to store in secure.txt
    if(hashValueCalculated!=NULL)
      printf("hashValueCalculated is: %s\n",hashValueCalculated );
    else hashValueCalculated="00000000000000000000";

    memmove(secureContents+(int)fileSize,pathname,strlen(pathname));
    for(int i=0;i<33-strlen(pathname);i++){
      memmove(secureContents+strlen(pathname)+i+(int)fileSize," ",1);
    }
    memmove(secureContents+(int)fileSize+33,hashValueCalculated,20);
    memmove(secureContents+(int)fileSize+53,"    ",4);


    close(fd);
    if(remove("secure.txt")!=0){
      printf("%s\n","Not Able To Delete secure.txt");
      exit(0);
    }

    fd=open("secure.txt", O_RDWR | O_CREAT , 0666);
  	if(fd==-1){
  		perror("Unable to open/create secure.txt");
  	}
    int ret=write(fd,secureContents,(int)fileSize+57);
    if(ret==-1){
      printf("write failed");
      exit(0);
    }
    // free(secureContents);
  }
  // }
  close(fd);

  return open(pathname, flags, mode);
}

/* SEEK_END should always return the file size
 * updated through the secure file system APIs.
 */
int s_lseek (int fd, long offset, int whence)
{
	assert (filesys_inited);
  struct stat sb;
  if(fstat(fd,&sb)==-1){
    perror("stat");
  }
  ino_t fdInode = sb.st_ino;        //get the inode of the fd passed as argument

  char tempFileName[32];
  struct stat sb2;
  ino_t tempInode;
  int fileINDEX=-1;
  for(int i=0;i<8;i++){
    snprintf(tempFileName,32,"foo_%d.txt",i);
    if(stat(tempFileName,&sb2)==-1){
      perror("stat2");
    }
    tempInode=sb2.st_ino;
    if(tempInode==fdInode)
    {
      fileINDEX=i;
      break;
    }
  }

  int xd=open("FILESIZES.txt",O_RDONLY,0666);
  lseek(xd,33*fileINDEX,SEEK_SET);
  char currentFileSize[32];
  read(xd,currentFileSize,32);
  currentFileSize[32]='\0';
  trimTrailingSpaces(currentFileSize);
  int currSizeInInt=atoi(currentFileSize);
  close(xd);

  if(whence==SEEK_END){
    return lseek (fd, currSizeInInt+offset, SEEK_SET);
  }
	return lseek (fd, offset, whence);
}

/* read the blocks that needs to be updated
 * check the integrity of the blocks
 * modify the blocks
 * update the in-memory Merkle tree and root in secure.txt
 * returns -1 on failing the integrity check.
 */

ssize_t s_write (int fd, const void *buf, size_t count)
{
	assert (filesys_inited);
  struct stat sb;
  if(fstat(fd,&sb)==-1){
    perror("stat");
  }
  ino_t fdInode = sb.st_ino;                                                    //get the inode of the fd passed as argument

  char tempFileName[32];
  struct stat sb2;
  ino_t tempInode;
  int fileINDEX=-1;
  for(int i=0;i<8;i++){
    snprintf(tempFileName,32,"foo_%d.txt",i);
    if(stat(tempFileName,&sb2)==-1){
      perror("stat2");
    }
    tempInode=sb2.st_ino;
    if(tempInode==fdInode)
    {
      fileINDEX=i;
      break;
    }
  }
  /*now tempFileName contains the name of file which is pointed by fd
    check its integrity*/
  int securefd=open("secure.txt",O_RDWR, 0666);
  // if(securefd<0){
  //   fprintf(stderr, "%s\n", explain_open("secure.txt", O_RDWR, 0));
  //   exit(EXIT_FAILURE);
  // }

  double fileSizeW=lseek(securefd,0,SEEK_END);                                  //filesize of secure.txt
  lseek(securefd,0,SEEK_SET);
  char* secureContentsW=(char*)malloc(((int)fileSizeW)*sizeof(char));           //store contents on secure.txt                                                         //
  read(securefd, secureContentsW,(int)fileSizeW);
  lseek(securefd,0,SEEK_SET);
  char *filenameInSecureW=strstr(secureContentsW, tempFileName);                // check if file entry exists secure.txt
  int curPtr=lseek(fd,0,SEEK_CUR);
  int filsiz=lseek(fd,0,SEEK_END);
  if(curPtr!=filsiz){
    if(filenameInSecureW!=NULL)                                                   //If entry exist in secure.txt
    {
      strtok(filenameInSecureW, " ");
      char *storedHashW=strtok(NULL, " ");
      char *hashValueCalculatedW=merkel4file((char*)tempFileName);
      if(hashValueCalculatedW!=NULL){
        if(strcmp(hashValueCalculatedW,storedHashW)!=0)                        // check integrity
        {
          // printf("%s\n","integrity corrupted");
          return -1;
        }
      }
    }
  }

  free(secureContentsW);
  close(securefd);

  //integrity check done
  int xd=open("FILESIZES.txt",O_RDWR,0666);
  lseek(xd,33*fileINDEX,SEEK_SET);
  char currentFileSize[32];
  read(xd,currentFileSize,32);
  currentFileSize[32]='\0';
  trimTrailingSpaces(currentFileSize);
  int currSizeInInt=atoi(currentFileSize);
  currSizeInInt+=count;
  char toBeWritten[32];
  snprintf(toBeWritten,32,"%d",currSizeInInt);
  lseek(xd,33*fileINDEX,SEEK_SET);
  write(xd,toBeWritten,strlen(toBeWritten));
  close(xd);


  return write (fd, buf, count);
}

/* check the integrity of blocks containing the
 * requested data.
 * returns -1 on failing the integrity check.
 */
ssize_t s_read (int fd, void *buf, size_t count)
{
	assert (filesys_inited);
	return read (fd, buf, count);
}

/* destroy the in-memory Merkle tree */
int s_close (int fd)
{
	assert (filesys_inited);
	return close (fd);
}

/* Creates the secure.txt file if it doesn’t exist
 * Check the integrity of all files in secure.txt
 * remove the non-existent files from secure.txt
 * returns 1, if an/any existing file is tampered
 * return 0 on successful initialization */
int filesys_init (void)
{
	int fd=open("secure.txt", O_RDWR | O_CREAT,0666);
	if(fd==-1){
		perror("Unable to open/create secure.txt");
	}
	char* filenHash=(char*)malloc(53*sizeof(char));		                            //32 byte file name+ 1 space + 20 byte hash
  char* duplicatefilenHash=(char*)malloc(53*sizeof(char));
  char* filename;
  char* storedHash;
  char* hashValueCalculated;

  double fileSize = lseek(fd, 0, SEEK_END);
  // printf("filsize is: %f\n",fileSize );
  lseek(fd, 0, SEEK_SET);
  int numRecords=(fileSize/57);                                                 //How many files/hashes are present in secure.txt
  // printf("num records is : %d\n",numRecords);
  int count=0;

  while(count<numRecords && read(fd, filenHash, 53)!=-1){
    strcpy(duplicatefilenHash,filenHash);
    filename=strtok(duplicatefilenHash," ");                                    //get filename
    storedHash=strtok(NULL, " ");                                               //Get hash value corresponding to the above filename
    trimLeadingSpaces(storedHash, ' ');
    hashValueCalculated=merkel4file(filename);                                  //Calculate hash value for the above filename to check against stored hashvalue

    /*
			Pseudocode:
			-----------
			if(hashValueCalculated==NULL)
				remove the <file> <its_hashcode> from secure.txt
			else if(hashValueCalculated!=hashValueInFile)
				return 1;
      else
        return 0;

		*/
    if(hashValueCalculated==NULL){
      // printf("%s file does not exist or is empty\n", filename);
      char* secureContents=(char*)malloc(((int)fileSize)*sizeof(char));
      int currPtr=lseek(fd, 0, SEEK_CUR);
      lseek(fd,0,SEEK_SET);
      read(fd, secureContents,fileSize);
      lseek(fd,0,SEEK_SET);
      removeSubstring(secureContents, filenHash);
      close(fd);
      if(remove("secure.txt")!=0){
        printf("%s\n","Not Able To Delete secure.txt");
        exit(0);
      }

      fd=open("secure.txt", O_RDWR | O_CREAT , 0666);
    	if(fd==-1){
    		perror("Unable to open/create secure.txt");
    	}
      fileSize-=57;
      int ret=write(fd,secureContents,(int)fileSize);
      if(ret==-1){
        printf("write failed");
        exit(0);
      }
      lseek(fd,currPtr-57,SEEK_SET);
      free(secureContents);
      // numRecords-=1;                                                         //check if there is a need to uncomment
    }
    else {
      if(strcmp(hashValueCalculated,storedHash)!=0){
        return 1;
      }
    }

    if(count==numRecords-1)
      break;
    count+=1;
		lseek(fd, 4, SEEK_CUR);	          	//We are using 4 Spaces between 2 hashes. So this will then read the 'filename hash' of next file.
  }
  free(filenHash);
  free(duplicatefilenHash);
	/*Structure of secure.txt is "filename hash"
	* Open secure.txt here
	* Traverse the file for filenames. Open every file, read its contents, compute its SHA1.
	* Compare this computed SHA1 with with the stored SHA1. If it is not the same, return 0.
	* Else, return 1, filesys initialized.*/
	filesys_inited = 1;
	return 0;
}

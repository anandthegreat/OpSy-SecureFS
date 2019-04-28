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

void removeSubstring(char *s,const char *toremove)
{
  while(( s=strstr(s,toremove)) )
    memmove(s,s+strlen(toremove)+4,5+strlen(s+strlen(toremove)));
}

char* merkel_tree (unsigned char strings[][20], size_t str_count) {                         //strings[] contains blockwise hashes
  if (str_count == 0) {
    return NULL;
  }
  if (str_count == 1) {
    return (char*)strings[0];
  }

  // printf("%s %d\n","str_count is: ",(int)str_count );
  size_t parentList_count = str_count/2 + str_count%2;
  unsigned char parentList[parentList_count][SHA_DIGEST_LENGTH];

  // for (int i = 0; i < parentList_count; i++) {
  //   parentList[i] = (char*)malloc(20*sizeof(char));
  // }

  unsigned char buff[40];

  for (int i = 0; i < str_count - 1; i += 2) {
      // printf("strings[i] is %s strings[i+1] is %s\n", strings[i],strings[i+1] );
      memmove(buff,strings[i], 20);
      // strncpy((char*)buff, (char*)strings[i], 20);
      memmove(buff+20,strings[i+1],20);
      // strncat((char*)buff, (char*)strings[i+1], 20);                                            //segmentation fault in this line
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
  printf("%s %s\n","In merkel tree for file",filename );

  size_t file_size = lseek(fd, 0, SEEK_END);
  lseek(fd, 0, SEEK_SET);
  size_t totBlocks = file_size/64 + (bool)(file_size%64);
  unsigned char hblocks[totBlocks][SHA_DIGEST_LENGTH];                                   //SHA_DIGEST_LENGTH=20
  int tot_read;
  // printf("total blocks are: %ld\n",totBlocks );

  unsigned char buffer[64];
  for (int i = 0; i < totBlocks; i++) {
    if(!(tot_read = read(fd, buffer, 64))) {
      return NULL;
    }
    // blocks[i] = (char*)malloc(20*sizeof(char));
    SHA1((unsigned char*)buffer, tot_read, (unsigned char*)hblocks[i]);
  }

  // printf("totblocks: %d \n",(int)totBlocks);
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
  int fd=open("secure.txt",flags, mode);
  double fileSize=lseek(fd,0,SEEK_END);                                         //filesize of secure.txt
  lseek(fd,0,SEEK_SET);
  char* secureContents=(char*)malloc(((int)fileSize)*sizeof(char));             //store contents on secure.txt                                                         //
  read(fd, secureContents,fileSize);
  lseek(fd,0,SEEK_SET);

  if( (access( pathname, F_OK ) != -1 ) && !feof(fopen(pathname, "r")))         // check if file exists and is not empty(pathname)
  {
    // printf("secure contents : %s\n", secureContents);
    // printf("pathname: %s\n", pathname);
    char *filenameInSecure=strstr(secureContents, pathname);                    //  check if file entry exists secure.txt
    // printf("fn in secure: %s",filenameInSecure);
    if(filenameInSecure!=NULL)                                                  //If entry exist in secure.txt
    {
      strtok(filenameInSecure, " ");
      char *storedHash=strtok(NULL, " ");
      // printf("stored hash : %s",storedHash);
      printf("pathname is not null");
      // checks if file tampered
      char* hashValueCalculated=merkel4file((char*)pathname);
      if(strcmp(hashValueCalculated,storedHash)!=0)                             // check integrity
        return -1;
      else
        return open(pathname,  flags, mode);
    }
    else
    {                                                                           //If entry does not exist in secure.txt
      printf("else%s\n",pathname);
      // printf("%ld\n",strlen(pathname));
      char* hashValueCalculated=merkel4file((char*)pathname);                   //Calculate root of merkle to store in secure.txt
      if(hashValueCalculated!=NULL)
        printf("hashValueCalculated is: %s\n",hashValueCalculated );
      // strcat(secureContents,pathname);
      // strcat(secureContents," ");
      // strcat(secureContents,hashValueCalculated);
      // strcat(secureContents,"    ");
      //
      // close(fd);
      // if(remove("secure.txt")!=0){
      //   printf("%s\n","Not Able To Delete secure.txt");
      //   exit(0);
      // }
      //
      // fd=open("secure.txt", O_RDWR | O_CREAT , 0666);
    	// if(fd==-1){
    	// 	perror("Unable to open/create secure.txt");
    	// }
      //
      // int ret=write(fd,secureContents,(int)fileSize);
      // if(ret==-1){
      //   printf("write failed");
      //   exit(0);
      // }

    }
  }
  free(secureContents);
  // else printf("%s %s\n","Error in opening file/cannot read.",pathname);
  return open(pathname, flags, mode);
}

/* SEEK_END should always return the file size
 * updated through the secure file system APIs.
 */
int s_lseek (int fd, long offset, int whence)
{
	assert (filesys_inited);
	return lseek (fd, offset, SEEK_SET);
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
  printf("filsize is: %f\n",fileSize );
  lseek(fd, 0, SEEK_SET);
  int numRecords=(fileSize/57);                                                 //How many files/hashes are present in secure.txt
  printf("num records is : %d\n",numRecords);
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
      printf("%s file does not exist or is empty\n", filename);
      char* secureContents=(char*)malloc(((int)fileSize)*sizeof(char));
      int currPtr=lseek(fd, 0, SEEK_CUR);
      lseek(fd,0,SEEK_SET);
      read(fd, secureContents,fileSize);
      lseek(fd,0,SEEK_SET);
      // printf("+++++++++++++%s",secureContents);
      // printf("*************%s----\n",filenHash );
      removeSubstring(secureContents, filenHash);
      // printf("=============%s----",secureContents);

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
      // printf("-------------%s----",secureContents);
      lseek(fd,currPtr-57,SEEK_SET);
      // free(secureContents);
      // numRecords-=1;                                                         //check if there is a need to uncomment
    }
    else {
      printf("%s\n", hashValueCalculated);
      // if(strcmp(hashValueCalculated,storedHash)!=0){
      //   return 1;
      // }
    }

    if(count==numRecords-1)
      break;
    count+=1;
		lseek(fd, 4, SEEK_CUR);	          	//We are using 4 Spaces between 2 hashes. So this will then read the 'filename hash' of next file.
  }

	/*Structure of secure.txt is "filename hash"
	* Open secure.txt here
	* Traverse the file for filenames. Open every file, read its contents, compute its SHA1.
	* Compare this computed SHA1 with with the stored SHA1. If it is not the same, return 0.
	* Else, return 1, filesys initialized.*/
	filesys_inited = 1;
	return 0;
}

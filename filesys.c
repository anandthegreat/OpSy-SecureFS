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


char* merkel_tree (char* strings[], size_t str_count) {
  if (str_count == 0) {
    return NULL;
  }
  if (str_count == 1) {
    return strings[0];
  }

  size_t parentList_count = str_count/2 + str_count%2;
  char* parentList[parentList_count];
  
  for (int i = 0; i < parentList_count; i++) {
    parentList[i] = (char*)malloc(20*sizeof(char));
  }

  char* buff = (char*)malloc(41*sizeof(char)); 
  
  for (int i = 0; i < str_count - 1; i += 2) {
    strncpy(buff, strings[i], 20);
    strncat(buff, strings[i+1], 20);
    SHA1((unsigned char*)buff, 40, (unsigned char*)parentList[i/2]);
  }

  if (str_count % 2) {
    SHA1((unsigned char*)strings[str_count - 1], 20, (unsigned char*)parentList[str_count/2]);
  }

  return merkel_tree(parentList, parentList_count);
} 


char* merkel4file(char* filename) {
  int fd = open(filename, O_RDONLY, 0);
  
  if(fd==-1)		
  	return NULL;		//check if correct
  
  size_t file_size = lseek(fd, 0, SEEK_END);
  lseek(fd, 0, SEEK_SET);
  size_t totBlocks = file_size/64 + (bool)(file_size%64);
  char* hblocks[totBlocks];
  int tot_read;
  char* buffer = (char*)malloc(64*sizeof(char));
  
  for (int i = 0; i < totBlocks; i++) {
    if(!(tot_read = read(fd, buffer, 64))) {
      return NULL;
    }

    hblocks[i] = (char*)malloc(20*sizeof(char));
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
	return open (pathname, flags, mode);
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

/* Creates the secure.txt file if it doesn’t exist */
/* Check the integrity of all files in secure.txt
 * remove the non-existent files from secure.txt
 * returns 1, if an/any existing file is tampered
 * return 0 on successful initialization
 */
int filesys_init (void)
{
	int fd=open("secure.txt", O_RDONLY | O_CREAT);
	if(fd==-1){
		perror("Unable to open/create secure.txt");
	}

	char filenHash[53];		//32 byte file name+ 1 space + 20 byte hash
	char filename[32];
	char* hash;

	lseek(fd, 0, SEEK_SET);	//start reading the file from beginning
	while(read(fd, filenHash, 53)!=-1){
		filename=strtok(filenHash," ");
		hashValueInFile=
		hashValueCalculated=merkel4file(filename);	

		/*
			Pseudocode:
			-----------
			if(hashValueCalculated==NULL)
				remove the <file> <its_hashcode> from secure.txt 
			else if(hashValueCalculated!=hashValueInFile)
				return 1;
			
		*/

		lseek(fd, 4, SEEK_CUR);		//We are using 4 Spaces between 2 hashes 
	}
	
	/*Structure of secure.txt is "filename hash"
	* Open secure.txt here
	* Traverse the file for filenames. Open every file, read its contents, compute its SHA1.
	* Compare this computed SHA1 with with the stored SHA1. If it is not the same, return 0.
	* Else, return 1, filesys initialized.*/
	filesys_inited = 1;
	return 0;
}

//SiFive Open Source Cryptographic Library
//The software library for accessing to cryptographic algorithms on SiFive RISC-V
/*Copyright 2019 SiFive

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/
//commontest.c
//contains routines shared among different tests

//#define VERBOSE
#define MAX_LINE 20000
#include <soscl_test_config.h>

#include <stdio.h>
#include <string.h>
#include <soscl/soscl_config.h>
#include <soscl/soscl_retdefs.h>
#include <soscl/soscl_types.h>
#include <soscl/soscl_defs.h>
#include <soscl/soscl_string.h>
#include <soscl_commontest.h>

int hex(char c1,char c2)
{
  int value;
  value=0;
  if(c1>='A' && c1<='F')
    value=(c1-'A'+10);
  if(c1>='a' && c1<='f')
    value=(c1-'a'+10);
  if(c1>='0' && c1<='9')
    value=(c1-'0');
  value*=16;
  if(c2>='A' && c2<='F')
    value+=(c2-'A'+10);
  if(c2>='a' && c2<='f')
    value+=(c2-'a'+10);
  if(c2>='0' && c2<='9')
    value+=(c2-'0');
  return(value);
}

int decimal(char c1,char c2)
{
  return((c1-'0')*10+(c2-'0'));
}


void parse_next(char *temp_string,int *temp_len,int *i,char c,char *line)
{
  while((line[*i]!=c)&& (*i<(int)strlen(line)))
    {
      temp_string[*temp_len]=line[*i];
      (*temp_len)++;
      (*i)++;
    }
  temp_string[*temp_len]='\0';
  //skip the char position
  (*i)++;
}

void skip_next(int *i,char c,char *line)
{
  while((line[*i]!=c)&& (*i<(int)strlen(line)))
    (*i)++;
  //skip the char position
  (*i)++;
}

void read_hexa_array(uint8_t *array,int *array_len,int *i,char *line)
{
  char temp_string[MAX_LINE];
  int temp_len,l,k;
  //looking for the [
    skip_next(i,'[',line);
  //looking for the ]
  //maybe empty field
  temp_len=0;
  parse_next(temp_string,&temp_len,i,']',line);
  //checking if hexadecimal or chars
  
  if(temp_len>=2 && temp_string[0]=='0' && temp_string[1]=='x')
    {
      for(l=0,k=2;k<temp_len;k+=2,l++)
	array[l]=hex(temp_string[k],temp_string[k+1]);
      *array_len=l;
    }
    else
      {
	soscl_memcpy(array,temp_string,temp_len);
	*array_len=temp_len;
      }
}

void read_hexa_aligned_array(uint8_t *array,int *array_len,int *i,char *line)
{
  char temp_string[MAX_LINE];
  char temp_temp_string[MAX_LINE+3];
  int temp_len,l,k;
  //looking for the [
    skip_next(i,'[',line);
  //looking for the ]
  //maybe empty field
  temp_len=0;
  parse_next(temp_string,&temp_len,i,']',line);
  //checking if hexadecimal or chars
  if(temp_len>=2 && temp_string[0]=='0' && temp_string[1]=='x')
    {
      if(temp_len%2)
	{
	  sprintf(temp_temp_string,"0x0%s",&(temp_string[2]));
	  for(l=0,k=2;k<temp_len+1;k+=2,l++)
	    array[l]=hex(temp_temp_string[k],temp_temp_string[k+1]);
	}
      else
	for(l=0,k=2;k<temp_len;k+=2,l++)
	  array[l]=hex(temp_string[k],temp_string[k+1]);
      *array_len=l;
    }
    else
      {
	soscl_memcpy(array,temp_string,temp_len);
	*array_len=temp_len;
      }
}

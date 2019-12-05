#define MAX_LINE 20000
int hex(char c1,char c2);
int decimal(char c1,char c2);
void skip_next(int *i,char c,char *line);
void read_hexa_array(uint8_t *array,int *array_len,int *i,char *line);
void read_hexa_aligned_array(uint8_t *array,int *array_len,int *i,char *line);
void parse_next(char *temp_string,int *temp_len,int *i,char c,char *line);
